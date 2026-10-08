import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";

// The release gate's verdict rules (scripts/check-compliance.mjs). The grader run
// itself happens in release.sh; what is pinned here is that nothing passes silently:
// below A fails, and skipped tests and grader warnings are surfaced, not swallowed.
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
type Verdict = { ok: boolean; lines: string[]; warnings: string[] };
const { evaluateReport } = (await import(pathToFileURL(join(repoRoot, "scripts", "check-compliance.mjs")).href)) as {
  evaluateReport: (report: unknown, minGrade?: string) => Verdict;
};

const report = (over: Record<string, unknown> = {}) => ({
  grade: "A",
  score: 99,
  specVersion: "2025-11-25",
  summary: { total: 3, passed: 3, failed: 0, skipped: 0 },
  tests: [{ id: "lifecycle-init", passed: true, required: true }],
  warnings: [],
  ...over,
});

describe("compliance gate: evaluateReport", () => {
  it("passes grade A with nothing to warn about", () => {
    const v = evaluateReport(report());
    expect(v.ok).toBe(true);
    expect(v.warnings).toEqual([]);
  });

  it.each(["B", "C", "D", "F"])("fails grade %s against the A floor", (grade) => {
    expect(evaluateReport(report({ grade })).ok).toBe(false);
  });

  it("fails a report with no grade instead of treating it as a pass", () => {
    expect(evaluateReport(report({ grade: undefined })).ok).toBe(false);
    expect(evaluateReport({}).ok).toBe(false);
  });

  it("warns once per skipped test, naming it", () => {
    const v = evaluateReport(
      report({
        summary: { total: 2, passed: 1, failed: 0, skipped: 1 },
        tests: [
          { id: "lifecycle-init", passed: true },
          { id: "lifecycle-logging", passed: true, skipped: true, details: "no logging capability" },
        ],
      }),
    );
    expect(v.ok).toBe(true);
    expect(v.warnings).toEqual(["skipped: lifecycle-logging -- no logging capability"]);
  });

  it("still warns when the summary counts skips the test list does not identify", () => {
    const v = evaluateReport(report({ summary: { total: 2, passed: 2, failed: 0, skipped: 2 }, tests: [] }));
    expect(v.warnings).toEqual(["2 test(s) skipped (the report does not say which)"]);
  });

  it("surfaces grader warnings and lists failed tests", () => {
    const v = evaluateReport(
      report({
        warnings: ["Spec version auto-detected"],
        tests: [{ id: "security-x", passed: false, details: "boom" }],
      }),
    );
    expect(v.warnings).toContain("grader warning: Spec version auto-detected");
    expect(v.lines).toContain("failed: security-x -- boom");
  });
});
