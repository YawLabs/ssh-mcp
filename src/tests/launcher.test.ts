import { spawn, spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

// bin/ssh-mcp.mjs runs on import -- it is a launcher, not a module with exports --
// so the only honest way to test it is to execute it and observe what it did.
// Each test builds a throwaway layout that mirrors the package:
//
//   <tmp>/bin/ssh-mcp.mjs   a copy of the REAL launcher (optionally with one
//                           constant patched, to reach a branch that would
//                           otherwise need a binary we cannot fabricate)
//   <tmp>/dist/index.js     a stub standing in for the server
//
// The launcher resolves its server as `new URL("../dist/index.js", import.meta.url)`,
// so the copy finds the stub. That keeps these tests independent of whether
// `dist/` has been built, and lets them assert WHICH path ran: the stub prints a
// marker, so its presence means the in-process fallback was taken and its
// absence means oam was spawned instead.

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");
const LAUNCHER_SRC = join(REPO_ROOT, "bin", "ssh-mcp.mjs");

const MARKER = "STUB_SERVER";
// argv1 pins the entry-point fix: the launcher must repoint process.argv[1] at
// the server before importing it, or a server that gates its bootstrap on being
// the process entry point loads and then never serves.
const STUB_SERVER = `console.log(${JSON.stringify(MARKER)} + " " + JSON.stringify({ argv1: process.argv[1], args: process.argv.slice(2) }));\n`;

const layouts: string[] = [];
afterAll(() => {
  for (const dir of layouts) rmSync(dir, { recursive: true, force: true });
});

function makeLayout(opts: { oamMin?: string } = {}): string {
  const dir = mkdtempSync(join(tmpdir(), "ssh-mcp-launcher-"));
  layouts.push(dir);
  mkdirSync(join(dir, "bin"));
  mkdirSync(join(dir, "dist"));
  mkdirSync(join(dir, "home"));

  let src = readFileSync(LAUNCHER_SRC, "utf8");
  if (opts.oamMin) {
    const patched = src.replace(/const OAM_MIN = \[[^\]]*\];/, `const OAM_MIN = ${opts.oamMin};`);
    // Fail loudly rather than silently testing the unpatched launcher if the
    // constant is ever renamed or reformatted.
    expect(patched, "OAM_MIN patch did not apply -- did the constant move?").not.toBe(src);
    src = patched;
  }
  writeFileSync(join(dir, "bin", "ssh-mcp.mjs"), src);
  writeFileSync(join(dir, "dist", "index.js"), STUB_SERVER);
  return dir;
}

/** A directory containing one file, for PATH-discovery tests. */
function dirWith(layout: string, name: string, contents = ""): string {
  const dir = mkdtempSync(join(layout, "pathdir-"));
  writeFileSync(join(dir, name), contents);
  return dir;
}

interface RunOpts {
  mode?: "auto" | "oam" | "node";
  pathDirs?: string[];
  oamBin?: string;
  args?: string[];
}

function run(layout: string, opts: RunOpts = {}) {
  // Build the child env from scratch. A spread of process.env would carry the
  // real PATH (which has a working oam on a developer box) and, on Windows,
  // could leave both `Path` and `PATH` set with different values.
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (typeof v !== "string") continue;
    if (/^(path|oam_bin|ssh_mcp_runtime|userprofile|home|localappdata)$/i.test(k)) continue;
    env[k] = v;
  }
  env.PATH = (opts.pathDirs ?? []).join(delimiter);
  env.SSH_MCP_RUNTIME = opts.mode ?? "auto";
  // Point every "installed oam" location at an empty dir so discovery cannot
  // find the real oam that may be installed on this machine.
  env.USERPROFILE = join(layout, "home");
  env.HOME = join(layout, "home");
  env.LOCALAPPDATA = join(layout, "home");
  if (opts.oamBin) env.OAM_BIN = opts.oamBin;

  const r = spawnSync(process.execPath, [join(layout, "bin", "ssh-mcp.mjs"), ...(opts.args ?? [])], {
    env,
    encoding: "utf8",
  });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

function stubPayload(stdout: string): { argv1: string; args: string[] } {
  const line = stdout.split("\n").find((l) => l.startsWith(MARKER));
  expect(line, `expected the stub server to run; stdout was: ${JSON.stringify(stdout)}`).toBeTruthy();
  return JSON.parse((line as string).slice(MARKER.length + 1));
}

describe("launcher: in-process fallback", () => {
  it("runs the server in this process when SSH_MCP_RUNTIME=node", () => {
    const r = run(makeLayout(), { mode: "node" });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain(MARKER);
    expect(r.stderr).toBe("");
  });

  it("repoints process.argv[1] at the server before importing it", () => {
    const layout = makeLayout();
    const r = run(layout, { mode: "node" });
    expect(stubPayload(r.stdout).argv1).toBe(join(layout, "dist", "index.js"));
  });

  it("passes host-supplied args through to the server", () => {
    const r = run(makeLayout(), { mode: "node", args: ["--version", "extra"] });
    expect(stubPayload(r.stdout).args).toEqual(["--version", "extra"]);
  });

  it("falls back silently in auto mode when no oam is found", () => {
    const r = run(makeLayout(), { mode: "auto" });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain(MARKER);
    // Nothing was skipped, so there is nothing worth saying.
    expect(r.stderr).toBe("");
  });
});

describe("launcher: oam mode is a hard requirement", () => {
  it("exits 1 and does not start a server when no oam is found", () => {
    const r = run(makeLayout(), { mode: "oam" });
    expect(r.status).toBe(1);
    expect(r.stdout).not.toContain(MARKER);
    expect(r.stderr).toMatch(/no runnable oam binary was found/);
  });
});

describe("launcher: version gate distinguishes unreadable from old", () => {
  // An OAM_BIN that exists but cannot be executed: a plain text file. execFileSync
  // rejects it on every platform (EINVAL/UNKNOWN on Windows, EACCES/ENOEXEC on
  // POSIX), so oamVersion returns null -- the "could not be read" case.
  function unexecutable(layout: string): string {
    const p = join(layout, "not-a-binary.txt");
    writeFileSync(p, "definitely not an executable\n");
    return p;
  }

  it("reports an unexecutable oam as unreadable, never as old", () => {
    const layout = makeLayout();
    const r = run(layout, { mode: "auto", oamBin: unexecutable(layout) });
    expect(r.stderr).toMatch(/could not be run, or did not report a version/);
    // The regression this pins: every one of these causes used to be reported as
    // "older than oam 0.9.0", sending the user to `oam self-update`.
    expect(r.stderr).not.toMatch(/older than/);
    expect(r.stderr).not.toMatch(/self-update/);
    // Not fatal in auto mode.
    expect(r.status).toBe(0);
    expect(r.stdout).toContain(MARKER);
  });

  it("gives the unreadable case an executable-binary remedy in oam mode", () => {
    const layout = makeLayout();
    const r = run(layout, { mode: "oam", oamBin: unexecutable(layout) });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/Check that it is an executable oam binary/);
    expect(r.stderr).not.toMatch(/self-update/);
  });

  it("reports a genuinely old oam as old, with the version it detected", () => {
    // node --version prints a semver, so with the floor raised above it the real
    // "too old" branch runs against a real executable.
    const layout = makeLayout({ oamMin: "[99, 0, 0]" });
    const r = run(layout, { mode: "auto", oamBin: process.execPath });
    expect(r.stderr).toMatch(/is oam \d+\.\d+\.\d+, older than 99\.0\.0/);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain(MARKER);
  });

  it("tells the old case to self-update, and exits 1 in oam mode", () => {
    const layout = makeLayout({ oamMin: "[99, 0, 0]" });
    const r = run(layout, { mode: "oam", oamBin: process.execPath });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/self-update/);
    expect(r.stderr).not.toMatch(/could not be run/);
  });
});

describe("launcher: spawning oam", () => {
  it("spawns a usable oam instead of running the server in-process", () => {
    // process.execPath passes the version gate, so the launcher spawns it as
    // `<node> run <server> --`. Node has no script named "run" and exits non-zero;
    // what matters is that the stub never ran, i.e. the spawn path was taken.
    const r = run(makeLayout(), { mode: "auto", oamBin: process.execPath });
    expect(r.stdout).not.toContain(MARKER);
    expect(r.status).not.toBe(0);
  });
});

describe("launcher: Windows PATH discovery", () => {
  const onWindows = process.platform === "win32";

  it.skipIf(!onWindows)("skips a .cmd shim on PATH but names it in oam mode", () => {
    const layout = makeLayout();
    const shimDir = dirWith(layout, "oam.cmd", "@echo off\r\n");
    const r = run(layout, { mode: "oam", pathDirs: [shimDir] });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/oam\.cmd/);
    expect(r.stderr).toMatch(/cannot execute a \.cmd\/\.bat directly/);
  });

  it.skipIf(!onWindows)("names the skipped shim in auto mode, then falls back", () => {
    const layout = makeLayout();
    const shimDir = dirWith(layout, "oam.cmd", "@echo off\r\n");
    const r = run(layout, { mode: "auto", pathDirs: [shimDir] });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain(MARKER);
    // Silence here is how someone never learns their install is unusable.
    expect(r.stderr).toMatch(/oam\.cmd/);
  });

  it.skipIf(!onWindows)("prefers an .exe later on PATH over an earlier .cmd shim", () => {
    const layout = makeLayout();
    const shimDir = dirWith(layout, "oam.cmd", "@echo off\r\n");
    const exeDir = dirWith(layout, "oam.exe", "");
    const r = run(layout, { mode: "oam", pathDirs: [shimDir, exeDir] });
    // The .exe is empty so it cannot actually run, but the message naming it
    // proves discovery chose it over the shim that came first.
    expect(r.stderr).toMatch(/oam\.exe/);
    expect(r.stderr).not.toMatch(/oam\.cmd/);
  });

  it.skipIf(onWindows)("has no shim concept on POSIX -- a bare `oam` is what is looked for", () => {
    const layout = makeLayout();
    const shimDir = dirWith(layout, "oam.cmd", "");
    const r = run(layout, { mode: "oam", pathDirs: [shimDir] });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/no runnable oam binary was found/);
    expect(r.stderr).not.toMatch(/\.cmd/);
  });
});

describe("launcher: signal handling (POSIX only)", () => {
  // These need REAL signal delivery, which does not exist on Windows: there,
  // process.kill() terminates the target instead of delivering something
  // catchable, and child.kill() is TerminateProcess. That is exactly why the
  // launcher forwards nothing on Windows, so there is no Windows behaviour here
  // to assert -- the absence of coverage matches the absence of a mechanism.
  //
  // Verified out-of-band against node 18 under WSL before these were written:
  //   graceful child -> exit 0,   child caught SIGINT,  no SIGKILL
  //   wedged child   -> exit 130, ~2s after ONE signal (the timer, not a second press)
  const posix = process.platform !== "win32";

  const OAM_SH = [
    "#!/bin/sh",
    // The launcher probes `--version` first; answer at the floor so the gate passes.
    'case "$1" in --version) echo "oam 0.9.0"; exit 0;; esac',
    "shift", // drop the leading "run"
    'exec node "$OAM_CHILD"',
    "",
  ].join("\n");

  const CHILD_GRACEFUL = [
    'const fs = require("fs");',
    'for (const s of ["SIGINT", "SIGTERM"]) process.on(s, () => { fs.writeFileSync(process.env.MARK, s); process.exit(0); });',
    'console.log("CHILD_READY");',
    "setInterval(() => {}, 1000);",
    "",
  ].join("\n");

  const CHILD_WEDGED = [
    'for (const s of ["SIGINT", "SIGTERM"]) process.on(s, () => {});',
    'console.log("CHILD_READY");',
    "setInterval(() => {}, 1000);",
    "",
  ].join("\n");

  function signalLayout(childSource: string) {
    const layout = makeLayout();
    const oam = join(layout, "oam");
    writeFileSync(oam, OAM_SH);
    chmodSync(oam, 0o755);
    const child = join(layout, "child.cjs");
    writeFileSync(child, childSource);
    return { layout, oam, child, mark: join(layout, "mark") };
  }

  /** Start the launcher, wait for the child to announce itself, then signal it. */
  function signalOnceAndWait(fixture: ReturnType<typeof signalLayout>) {
    return new Promise<{ code: number | null; caught: string }>((resolveRun) => {
      const env: Record<string, string> = {};
      for (const [k, v] of Object.entries(process.env)) {
        if (typeof v === "string" && !/^(oam_bin|ssh_mcp_runtime|home|mark|oam_child)$/i.test(k)) env[k] = v;
      }
      env.OAM_BIN = fixture.oam;
      env.SSH_MCP_RUNTIME = "oam";
      env.OAM_CHILD = fixture.child;
      env.MARK = fixture.mark;
      env.HOME = join(fixture.layout, "home");

      const proc = spawn(process.execPath, [join(fixture.layout, "bin", "ssh-mcp.mjs")], {
        env,
        stdio: ["ignore", "pipe", "pipe"],
      });
      let out = "";
      let sent = false;
      proc.stdout.on("data", (d) => {
        out += String(d);
        if (out.includes("CHILD_READY") && !sent) {
          sent = true;
          // One signal only. The escape hatch must not need a second press.
          setTimeout(() => process.kill(proc.pid as number, "SIGINT"), 50);
        }
      });
      proc.on("exit", (code) => {
        let caught = "";
        try {
          caught = readFileSync(fixture.mark, "utf8");
        } catch {
          // child never handled a signal
        }
        resolveRun({ code, caught });
      });
    });
  }

  it.skipIf(!posix)("forwards the signal so the child shuts down gracefully", async () => {
    const r = await signalOnceAndWait(signalLayout(CHILD_GRACEFUL));
    expect(r.caught).toBe("SIGINT");
    // Mirrors the child's clean exit rather than a kill status.
    expect(r.code).toBe(0);
  });

  it.skipIf(!posix)(
    "kills a wedged child after the grace window, on a single signal",
    async () => {
      const r = await signalOnceAndWait(signalLayout(CHILD_WEDGED));
      // 128 + SIGINT(2). Reached without a second press: the timer is the hatch.
      expect(r.code).toBe(130);
      expect(r.caught).toBe("");
    },
    15000,
  );
});

describe("launcher: source hygiene", () => {
  it("contains no literal control characters", () => {
    // A stray U+0008 shipped from 0.13.0 until it was caught by a commit hook:
    // invisible in a terminal, and it makes git treat the file as binary so the
    // diff cannot be reviewed. Lint, tsc and the tests all passed either way.
    const src = readFileSync(LAUNCHER_SRC, "utf8");
    const offenders: string[] = [];
    src.split("\n").forEach((line, i) => {
      for (const ch of line) {
        const code = ch.codePointAt(0) ?? 0;
        if (code < 32 && ch !== "\t") {
          offenders.push(`line ${i + 1}: U+${code.toString(16).padStart(4, "0").toUpperCase()}`);
        }
      }
    });
    expect(offenders).toEqual([]);
  });
});
