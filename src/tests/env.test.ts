import { describe, expect, it } from "vitest";
import { checkGitSsh, configLookup, testConnection } from "../env.js";

// Only the pure input-validation cases live here: each one returns before any
// subprocess is spawned, so it cannot depend on the machine, its agent, its
// ~/.ssh or the network. Every branch that DOES shell out is covered with a faked
// subprocess in env-diagnose-coverage.test.ts and env-hardening.test.ts.

describe("configLookup", () => {
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
  it("rejects invalid hostname", () => {
    const result = testConnection("host; rm -rf /");
    expect(result.status).toBe("error");
    expect(result.message).toMatch(/Invalid hostname/);
  });
});

describe("checkGitSsh", () => {
  it("rejects invalid hostname", () => {
    const result = checkGitSsh("host; rm -rf /");
    expect(result.status).toBe("error");
    expect(result.message).toMatch(/Invalid hostname/);
  });
});
