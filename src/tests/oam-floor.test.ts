import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

// Ported from aws-mcp's src/oam-floor.test.ts. The subject lives in scripts/, which
// tsconfig does not include, so it is exercised as a child process -- offline, since
// these cases are about drift and a unit test must not depend on GitHub.
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CHECKER = join(repoRoot, "scripts", "check-oam-floor.mjs");

const dirs: string[] = [];
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

/** A synthetic repo carrying only the files the checker reads. */
function fixture(files: { launcher?: string; readme?: string; launcherTest?: string }): string {
  const root = mkdtempSync(join(tmpdir(), "ssh-mcp-floor-"));
  dirs.push(root);
  mkdirSync(join(root, "bin"), { recursive: true });
  mkdirSync(join(root, "src", "tests"), { recursive: true });
  writeFileSync(join(root, "bin", "ssh-mcp.mjs"), files.launcher ?? "const OAM_MIN = [0, 18, 0];\n");
  if (files.readme !== undefined) writeFileSync(join(root, "README.md"), files.readme);
  writeFileSync(
    join(root, "src", "tests", "launcher.test.ts"),
    files.launcherTest ?? "    expect(floor).toEqual([0, 18, 0]);\n",
  );
  return root;
}

function runChecker(root: string): { code: number | null; out: string } {
  const r = spawnSync(process.execPath, [CHECKER, "--offline", "--root", root], {
    encoding: "utf8",
    timeout: 60_000,
  });
  return { code: r.status, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

describe("the oam floor is consistent across this repo", () => {
  // The no-network half of the staleness check, run on every `npm test`, which is what
  // makes it gate a release: release.sh runs the suite.
  it("the real repo agrees with itself", () => {
    const r = runChecker(repoRoot);
    expect(r.code, `check-oam-floor reported drift in this repo:\n${r.out}`).toBe(0);
    expect(r.out).toMatch(/no drift/);
  });
});

describe("check-oam-floor catches drift", () => {
  // A checker with no test that it FAILS is worse than none.
  it("flags a README still claiming the previous floor", () => {
    const root = fixture({
      readme:
        "This server runs on oam.\n\nThe launcher never serves on an oam older than **0.17.1**, and picks the newest.\n",
    });
    const r = runChecker(root);
    expect(r.code, r.out).toBe(1);
    expect(r.out).toMatch(/DRIFT/);
    expect(r.out, "the message must name the file and line").toMatch(/README\.md:3/);
    expect(r.out, "and the version it found").toMatch(/0\.17\.1/);
  });

  it("flags a launcher test still pinning the previous floor", () => {
    const root = fixture({ launcherTest: "    expect(floor).toEqual([0, 17, 1]);\n" });
    const r = runChecker(root);
    expect(r.code, r.out).toBe(1);
    expect(r.out).toMatch(/pins the floor at 0\.17\.1, but OAM_MIN is 0\.18\.0/);
  });

  it("flags the floor pin being gone", () => {
    const root = fixture({ launcherTest: "    // the floor assertion was deleted\n" });
    const r = runChecker(root);
    expect(r.code, r.out).toBe(1);
    expect(r.out).toMatch(/no longer pins the floor/);
  });

  it("does NOT flag a line naming a host version beside the floor", () => {
    const root = fixture({
      launcherTest:
        "    expect(floor).toEqual([0, 18, 0]);\n" +
        "      /this process is oam 0\\.9\\.0, older than 0\\.18\\.0, and no newer oam was found/,\n",
    });
    expect(runChecker(root).code).toBe(0);
  });

  it("does NOT flag the synthetic 99.0.0 floor the launcher tests raise OAM_MIN to", () => {
    const root = fixture({
      launcherTest:
        "    expect(floor).toEqual([0, 18, 0]);\n" +
        "    expect(r.stderr).toMatch(/is oam \\d+\\.\\d+\\.\\d+, older than 99\\.0\\.0/);\n",
    });
    expect(runChecker(root).code).toBe(0);
  });

  it("flags a stale claim on a line that also names the current floor", () => {
    const root = fixture({
      readme:
        "| `SSH_MCP_RUNTIME` | on oam if that is 0.18.0 or newer. An oam host older than 0.17.1 never serves. |\n",
    });
    const r = runChecker(root);
    expect(r.code, r.out).toBe(1);
    expect(r.out).toMatch(/README\.md:1 +says 0\.17\.1/);
  });

  it("does NOT flag a non-oam version, such as OpenSSH's", () => {
    const root = fixture({ readme: "Probed on OpenSSH 10.2.0 or newer; older than 9.8.0 is untested.\n" });
    expect(runChecker(root).code).toBe(0);
  });

  it("does NOT flag a line that is explicitly about the past", () => {
    const root = fixture({ readme: "Numbers were taken with oam 0.8.2, long before the current 0.18.0 floor.\n" });
    expect(runChecker(root).code).toBe(0);
  });

  it("fails loudly when OAM_MIN cannot be found at all", () => {
    const root = fixture({ launcher: "// somebody renamed the constant\n" });
    const r = runChecker(root);
    expect(r.code, r.out).not.toBe(0);
    expect(r.out).toMatch(/OAM_MIN/);
  });
});
