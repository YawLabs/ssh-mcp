import { describe, expect, it } from "vitest";
import { checkGitSsh, configLookup, ensureAgent, listSshKeys, testConnection } from "../env.js";

describe("ensureAgent", () => {
  it("returns agent status", () => {
    const result = ensureAgent();
    expect(typeof result.running).toBe("boolean");
    expect(typeof result.reachable).toBe("boolean");
    expect(Array.isArray(result.keys)).toBe(true);
    expect(typeof result.message).toBe("string");
    expect(result.message.length).toBeGreaterThan(0);
  });
});

describe("listSshKeys", () => {
  it("returns an array of key info", () => {
    const keys = listSshKeys();
    expect(Array.isArray(keys)).toBe(true);
    for (const key of keys) {
      expect(key.name).toBeTruthy();
      expect(key.path).toBeTruthy();
      expect(key.type).toBeTruthy();
      expect(typeof key.loadedInAgent).toBe("boolean");
    }
  });
});

describe("configLookup", () => {
  it("returns config for a valid host", () => {
    const result = configLookup("github.com");
    expect("error" in result || "hostname" in result).toBe(true);
    if ("hostname" in result) {
      expect(result.hostname).toBeTruthy();
      expect(result.port).toBeTruthy();
      expect(Array.isArray(result.identityFile)).toBe(true);
    }
  });

  it("rejects invalid hostname", () => {
    const result = configLookup("host; rm -rf /");
    expect("error" in result).toBe(true);
  });

  it("rejects command substitution in hostname", () => {
    const result = configLookup("host$(whoami)");
    expect("error" in result).toBe(true);
  });

  it("rejects backtick injection in hostname", () => {
    const result = configLookup("host`id`");
    expect("error" in result).toBe(true);
  });

  it("rejects pipe injection in hostname", () => {
    const result = configLookup("host | cat /etc/passwd");
    expect("error" in result).toBe(true);
  });

  it("rejects empty hostname", () => {
    const result = configLookup("");
    expect("error" in result).toBe(true);
  });
});

describe("testConnection", () => {
  it("returns status for unreachable host", () => {
    const result = testConnection("definitely-not-real-host-99999.example.com");
    expect(result.status).toBe("error");
    expect(result.message).toBeTruthy();
  });

  it("rejects invalid hostname", () => {
    const result = testConnection("host; rm -rf /");
    expect(result.status).toBe("error");
    expect(result.message).toMatch(/Invalid hostname/);
  });
});

describe("checkGitSsh", () => {
  it("returns a result for github.com", () => {
    const result = checkGitSsh("github.com");
    expect(result.status).toMatch(/^(ok|error)$/);
    expect(result.message).toBeTruthy();
  });

  it("rejects invalid hostname", () => {
    const result = checkGitSsh("host; rm -rf /");
    expect(result.status).toBe("error");
    expect(result.message).toMatch(/Invalid hostname/);
  });
});
