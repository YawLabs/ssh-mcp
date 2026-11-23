import { describe, expect, it } from "vitest";
import { checkKnownHosts, diagnose, isValidHostname } from "../diagnose.js";

describe("isValidHostname", () => {
  it("accepts standard hostnames", () => {
    expect(isValidHostname("example.com")).toBe(true);
    expect(isValidHostname("my-server")).toBe(true);
    expect(isValidHostname("host.sub.domain.com")).toBe(true);
    expect(isValidHostname("192.168.1.1")).toBe(true);
  });

  it("accepts hostnames with underscores", () => {
    expect(isValidHostname("my_server")).toBe(true);
  });

  it("accepts bracketed IPv6", () => {
    expect(isValidHostname("[::1]")).toBe(true);
    expect(isValidHostname("[2001:db8::1]")).toBe(true);
    expect(isValidHostname("[fe80:0:0:0:0:0:0:1]")).toBe(true);
  });

  it("rejects malformed IPv6", () => {
    expect(isValidHostname("[::1")).toBe(false); // missing closing bracket
    expect(isValidHostname("::1]")).toBe(false); // missing opening bracket
    expect(isValidHostname("[::1]:22")).toBe(false); // port not part of hostname
  });

  it("rejects shell injection attempts", () => {
    expect(isValidHostname("host; rm -rf /")).toBe(false);
    expect(isValidHostname("host$(whoami)")).toBe(false);
    expect(isValidHostname("host`id`")).toBe(false);
    expect(isValidHostname("host | cat /etc/passwd")).toBe(false);
    expect(isValidHostname("")).toBe(false);
  });

  it("rejects hostnames starting with a dash (flag/option injection)", () => {
    // A leading '-' would otherwise reach ssh / ssh-keygen positionally and be
    // parsed as a flag (e.g. -E logfile, -oProxyCommand=...).
    expect(isValidHostname("-E")).toBe(false);
    expect(isValidHostname("-rf")).toBe(false);
    expect(isValidHostname("-oProxyCommand=evil")).toBe(false);
    // Internal hyphens remain valid.
    expect(isValidHostname("my-server")).toBe(true);
  });

  it("rejects hostnames over 253 chars", () => {
    expect(isValidHostname("a".repeat(254))).toBe(false);
  });

  it("accepts hostnames at 253 chars", () => {
    expect(isValidHostname("a".repeat(253))).toBe(true);
  });

  it("rejects bare colons (no longer valid outside brackets)", () => {
    expect(isValidHostname("::1")).toBe(false);
    expect(isValidHostname("host:22")).toBe(false);
  });
});

// Only pure cases live here -- each returns before any subprocess or filesystem
// read, so none depends on the machine, its agent, its ~/.ssh or the network. The
// checks that do shell out are covered with a faked subprocess and a faked ~/.ssh in
// env-diagnose-coverage.test.ts.

describe("checkKnownHosts", () => {
  it("returns error for invalid hostname", () => {
    const result = checkKnownHosts("host; rm -rf /");
    expect(result.status).toBe("error");
    expect(result.message).toMatch(/Invalid hostname/);
  });
});

describe("diagnose", () => {
  it("rejects invalid hostname early", () => {
    const report = diagnose("host; rm -rf /");
    expect(report.overall).toBe("error");
    expect(report.checks[0].name).toBe("Input Validation");
  });
});
