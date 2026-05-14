import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { enforcePolicy, isPolicyConfigured } from "../policy.js";

describe("enforcePolicy", () => {
  beforeEach(() => {
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "");
    vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "");
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  describe("default (no env)", () => {
    it("allows any command when no policy is set", () => {
      expect(() => enforcePolicy("ls -la")).not.toThrow();
      expect(() => enforcePolicy("rm -rf /tmp/foo")).not.toThrow();
      expect(() => enforcePolicy("anything; goes")).not.toThrow();
    });

    it("isPolicyConfigured returns false", () => {
      expect(isPolicyConfigured()).toBe(false);
    });
  });

  describe("whitelist only", () => {
    it("allows commands that match a whitelist pattern", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls( .*)?,^df.*,^uptime$");
      expect(() => enforcePolicy("ls")).not.toThrow();
      expect(() => enforcePolicy("ls -la /var/log")).not.toThrow();
      expect(() => enforcePolicy("df -h")).not.toThrow();
      expect(() => enforcePolicy("uptime")).not.toThrow();
    });

    it("blocks commands that match none of the whitelist patterns", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls( .*)?,^df.*");
      expect(() => enforcePolicy("rm -rf /")).toThrow(/does not match any pattern in SSH_MCP_COMMAND_WHITELIST/);
      expect(() => enforcePolicy("cat /etc/passwd")).toThrow(/SSH_MCP_COMMAND_WHITELIST/);
    });

    it("error message includes the configured patterns", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls,^df");
      expect(() => enforcePolicy("rm foo")).toThrow(/Configured patterns: \^ls, \^df/);
    });
  });

  describe("blacklist only", () => {
    it("allows commands that don't match any blacklist pattern", () => {
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "^rm ,^shutdown,^reboot");
      expect(() => enforcePolicy("ls -la")).not.toThrow();
      expect(() => enforcePolicy("df -h")).not.toThrow();
    });

    it("blocks commands that match a blacklist pattern", () => {
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "^rm ,^shutdown");
      expect(() => enforcePolicy("rm -rf /")).toThrow(/SSH_MCP_COMMAND_BLACKLIST/);
      expect(() => enforcePolicy("shutdown now")).toThrow(/SSH_MCP_COMMAND_BLACKLIST/);
    });

    it("error message identifies which pattern matched", () => {
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "^ls,^rm ,^cat ");
      expect(() => enforcePolicy("rm -rf /tmp")).toThrow(/pattern "\^rm "/);
    });

    it("preserves trailing whitespace in patterns (^rm blocks rm but not rmdir)", () => {
      // This was a real bug: trim() stripped the trailing space and ^rm matched rmdir.
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "^rm ");
      expect(() => enforcePolicy("rm -rf /tmp")).toThrow();
      expect(() => enforcePolicy("rmdir /tmp/empty")).not.toThrow();
    });
  });

  describe("both whitelist and blacklist", () => {
    it("requires the command to pass both checks", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls,^find ,^cat ");
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "/etc/shadow");
      // In whitelist, not in blacklist -> allowed
      expect(() => enforcePolicy("ls /var/log")).not.toThrow();
      expect(() => enforcePolicy("cat /var/log/messages")).not.toThrow();
      // In whitelist but ALSO in blacklist -> blocked by blacklist
      expect(() => enforcePolicy("cat /etc/shadow")).toThrow(/SSH_MCP_COMMAND_BLACKLIST/);
      // Not in whitelist -> blocked by whitelist before blacklist even runs
      expect(() => enforcePolicy("rm /etc/shadow")).toThrow(/SSH_MCP_COMMAND_WHITELIST/);
    });
  });

  describe("regex handling", () => {
    it("ignores empty / whitespace entries between commas", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls,,  ,^df");
      expect(() => enforcePolicy("ls")).not.toThrow();
      expect(() => enforcePolicy("df")).not.toThrow();
      expect(() => enforcePolicy("rm")).toThrow();
    });

    it("skips malformed regexes without disabling the whole policy", () => {
      // First pattern is malformed (unclosed group); second is valid.
      // The malformed one should be dropped with a stderr warning; ^df should still enforce.
      const errSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "(unclosed,^df");
      try {
        expect(() => enforcePolicy("df -h")).not.toThrow();
        expect(() => enforcePolicy("rm foo")).toThrow(/SSH_MCP_COMMAND_WHITELIST/);
        expect(errSpy).toHaveBeenCalled();
      } finally {
        errSpy.mockRestore();
      }
    });

    it("patterns without ^/$ are substring matches", () => {
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "passwd");
      expect(() => enforcePolicy("cat /etc/passwd")).toThrow();
      expect(() => enforcePolicy("ls -la")).not.toThrow();
    });
  });

  describe("isPolicyConfigured", () => {
    it("returns true when whitelist is set", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls");
      expect(isPolicyConfigured()).toBe(true);
    });

    it("returns true when blacklist is set", () => {
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "^rm");
      expect(isPolicyConfigured()).toBe(true);
    });

    it("returns false for whitespace-only env values", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "   ");
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "");
      expect(isPolicyConfigured()).toBe(false);
    });
  });
});
