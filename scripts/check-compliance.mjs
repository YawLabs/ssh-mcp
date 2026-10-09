#!/usr/bin/env node
/**
 * Release gate: grade the built server with @yawlabs/mcp-compliance and refuse
 * anything below grade A.
 *
 * Why A: Yaw MCP grades every server it fronts with the same tool, and a grade
 * below its YAW_MCP_MIN_COMPLIANCE blocks every way of starting that server. A
 * regression that drops the grade would otherwise ship unnoticed -- this repo has
 * no CI that runs it (see scripts/lint.mjs).
 *
 * The grader is a pinned devDependency, not `npx @latest`, so the version that
 * grades a release here is the version line Yaw MCP grades with. Keep the two in
 * step: package.json's "@yawlabs/mcp-compliance" follows the range in Yaw MCP's own
 * package.json.
 *
 * Nothing passes silently:
 *   - grade below A, or the grader cannot run           -> exit 1
 *   - tests the grader SKIPPED, and grader warnings     -> printed as warnings,
 *     because a skip is a check that did not happen, not a check that passed
 *   - the grader is not installed (`npm ci` not run)    -> exit 1 with the fix;
 *     a gate that quietly no-ops on a broken install is how a bad grade ships
 *
 * The run itself needs no network: the server is spawned from dist/ over stdio.
 *
 * Usage: node scripts/check-compliance.mjs   (after `npm run build`)
 */

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MIN_GRADE = "A";
const GRADES = ["A", "B", "C", "D", "F"];

/**
 * The verdict for one JSON report: `{ ok, lines, warnings }`. Pure, so the
 * pass/warn/fail rules are testable without spawning a server.
 */
export function evaluateReport(report, minGrade = MIN_GRADE) {
  const lines = [];
  const warnings = [];
  const grade = typeof report?.grade === "string" ? report.grade.toUpperCase() : null;
  if (!grade || !GRADES.includes(grade)) {
    return { ok: false, lines: [`no grade in the report (${JSON.stringify(report?.grade)})`], warnings };
  }
  const summary = report.summary ?? {};
  lines.push(
    `grade ${grade} (score ${report.score ?? "?"}), spec ${report.specVersion ?? "?"}, ` +
      `${summary.passed ?? "?"}/${summary.total ?? "?"} passed, ${summary.failed ?? "?"} failed, ${summary.skipped ?? 0} skipped`,
  );
  const tests = Array.isArray(report.tests) ? report.tests : [];
  for (const t of tests) {
    if (t.skipped === true || t.status === "skip" || t.status === "skipped") {
      warnings.push(`skipped: ${t.id}${t.details ? ` -- ${t.details}` : ""}`);
    }
  }
  if ((summary.skipped ?? 0) > 0 && warnings.length === 0) {
    warnings.push(`${summary.skipped} test(s) skipped (the report does not say which)`);
  }
  for (const t of tests) {
    if (t.passed === false && !(t.skipped === true)) {
      lines.push(`failed: ${t.id}${t.required ? " (required)" : ""}${t.details ? ` -- ${t.details}` : ""}`);
    }
  }
  for (const w of Array.isArray(report.warnings) ? report.warnings : []) {
    warnings.push(`grader warning: ${typeof w === "string" ? w : JSON.stringify(w)}`);
  }
  const ok = GRADES.indexOf(grade) <= GRADES.indexOf(minGrade.toUpperCase());
  return { ok, lines, warnings };
}

function main() {
  const pkg = join(REPO_ROOT, "node_modules", "@yawlabs", "mcp-compliance", "package.json");
  if (!existsSync(pkg)) {
    console.error("mcp-compliance is not installed (node_modules/@yawlabs/mcp-compliance is missing).");
    console.error("Run `npm ci` -- it is a pinned devDependency. Refusing to skip the compliance gate.");
    process.exit(1);
  }
  const entry = join(REPO_ROOT, "dist", "index.js");
  if (!existsSync(entry)) {
    console.error("dist/index.js is missing -- run `npm run build` first.");
    process.exit(1);
  }
  const { bin: binField } = JSON.parse(readFileSync(pkg, "utf8"));
  const rel = typeof binField === "string" ? binField : Object.values(binField ?? {})[0];
  const cli = join(dirname(pkg), String(rel));

  const r = spawnSync(
    process.execPath,
    [cli, "test", "--format", "json", "--min-grade", MIN_GRADE, "--", process.execPath, entry],
    { cwd: REPO_ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: 300_000 },
  );
  let report;
  try {
    report = JSON.parse(r.stdout);
  } catch {
    console.error(`mcp-compliance did not produce a JSON report (exit ${r.status}).`);
    if (r.error) console.error(String(r.error));
    if (r.stderr) console.error(r.stderr.trim());
    process.exit(1);
  }
  const { ok, lines, warnings } = evaluateReport(report);
  for (const l of lines) console.log(`  ${l}`);
  for (const w of warnings) console.warn(`  WARNING ${w}`);
  // --min-grade makes the grader exit 1 below the threshold; trust whichever
  // of the two is stricter.
  if (!ok || r.status !== 0) {
    console.error(
      `mcp-compliance: below grade ${MIN_GRADE} (exit ${r.status}). Fix the failures above before releasing.`,
    );
    process.exit(1);
  }
  console.log(`mcp-compliance: grade ${report.grade}, at or above ${MIN_GRADE}.`);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main();
}
