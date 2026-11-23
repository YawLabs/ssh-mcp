import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

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

describe("compliance gate runs from a linked checkout", () => {
  // Node realpaths the main module's URL but not argv[1]. The gate's guard was a
  // plain resolve() compare, so through a junction or symlink it skipped main()
  // and exited 0 having graded nothing -- and release.sh gates on that exit code.
  // The fixture is a copy of scripts/ with no node_modules beside it, so a gate
  // that runs at all must refuse with "not installed"; a skipped one exits 0.
  const dirs: string[] = [];
  afterAll(() => {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  it("still runs, and fails closed, when invoked through a junction / symlink to scripts/", () => {
    const root = mkdtempSync(join(tmpdir(), "ssh-mcp-compliance-root-"));
    dirs.push(root);
    mkdirSync(join(root, "scripts"));
    for (const name of ["check-compliance.mjs", "is-main-module.mjs"]) {
      copyFileSync(join(repoRoot, "scripts", name), join(root, "scripts", name));
    }
    const linkParent = mkdtempSync(join(tmpdir(), "ssh-mcp-compliance-link-"));
    dirs.push(linkParent);
    const linked = join(linkParent, "scripts");
    // "junction" needs no privilege on Windows; the type is ignored elsewhere.
    symlinkSync(join(root, "scripts"), linked, "junction");
    const r = spawnSync(process.execPath, [join(linked, "check-compliance.mjs")], {
      encoding: "utf8",
      timeout: 60_000,
    });
    const out = `${r.stdout ?? ""}${r.stderr ?? ""}`;
    expect(r.status, out).toBe(1);
    expect(out).toMatch(/mcp-compliance is not installed/);
  });
});
