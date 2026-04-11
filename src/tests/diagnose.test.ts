import { describe, expect, it } from "vitest";
import {
  checkKnownHosts,
  checkSshAgent,
  checkSshConfig,
  checkSshKeys,
  diagnose,
  isValidHostname,
} from "../diagnose.js";

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

describe("checkSshAgent", () => {
  it("returns a diagnostic result", () => {
    const result = checkSshAgent();
    expect(result.status).toMatch(/^(ok|warning|error)$/);
    expect(result.message).toBeTruthy();
  });
});

describe("checkSshKeys", () => {
  it("returns a diagnostic result", () => {
    const result = checkSshKeys();
    expect(result.status).toMatch(/^(ok|warning|error)$/);
    expect(result.message).toBeTruthy();
  });
});

describe("checkKnownHosts", () => {
  it("returns result for known host", () => {
    const result = checkKnownHosts("github.com");
    expect(result.status).toMatch(/^(ok|warning|error)$/);
    expect(result.message).toBeTruthy();
  });

  it("returns warning for unknown host", () => {
    const result = checkKnownHosts("definitely-not-a-real-host-12345.example.com");
    expect(result.status).toBe("warning");
    expect(result.message).toMatch(/not in known_hosts|known_hosts does not exist/);
  });

  it("returns error for invalid hostname", () => {
    const result = checkKnownHosts("host; rm -rf /");
    expect(result.status).toBe("error");
    expect(result.message).toMatch(/Invalid hostname/);
  });
});

describe("checkSshConfig", () => {
  it("returns result for any host", () => {
    const result = checkSshConfig("example.com");
    expect(result.status).toMatch(/^(ok|warning|error)$/);
    expect(result.message).toBeTruthy();
  });
});

describe("diagnose", () => {
  it("returns a complete diagnostic report", () => {
    const report = diagnose("example.com");
    expect(report.overall).toMatch(/^(ok|warning|error)$/);
    expect(report.checks.length).toBeGreaterThanOrEqual(4);
    expect(Array.isArray(report.suggestions)).toBe(true);

    for (const check of report.checks) {
      expect(check.name).toBeTruthy();
      expect(check.status).toMatch(/^(ok|warning|error)$/);
      expect(check.message).toBeTruthy();
    }
  });

  it("includes all check categories", () => {
    const report = diagnose("example.com");
    const names = report.checks.map((c) => c.name);
    expect(names).toContain("SSH Agent");
    expect(names).toContain("SSH Keys");
    expect(names).toContain("SSH Config");
    expect(names).toContain("Known Hosts");
    expect(names).toContain("Connectivity");
  });

  it("rejects invalid hostname early", () => {
    const report = diagnose("host; rm -rf /");
    expect(report.overall).toBe("error");
    expect(report.checks[0].name).toBe("Input Validation");
  });
});
