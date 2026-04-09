import { describe, expect, it } from "vitest";
import { checkKnownHosts, checkSshAgent, checkSshConfig, checkSshKeys, diagnose } from "../diagnose.js";

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
    expect(result.message).toContain("not in known_hosts");
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
});
