import { spawn, spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
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
// marker, so its presence means the server ran and its absence means oam was
// spawned instead. The stub also reports its own pid and `process.versions.oam`,
// which is how a test tells "served in the launcher's process" apart from
// "handed off to a Node child that printed the same marker".
//
// Two pure decisions, runtimePlan() and pickNewest(), are ALSO evaluated straight
// from their source text, because their input matrices are too wide to pay a
// process per case. The execution tests next to them are what prove the
// launcher actually wires them.

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");
const LAUNCHER_SRC = join(REPO_ROOT, "bin", "ssh-mcp.mjs");
const isWin = process.platform === "win32";

const MARKER = "STUB_SERVER";
// argv1 pins the entry-point fix: the launcher must repoint process.argv[1] at
// the server before importing it, or a server that gates its bootstrap on being
// the process entry point loads and then never serves.
const STUB_SERVER = `console.log(${JSON.stringify(MARKER)} + " " + JSON.stringify({ argv1: process.argv[1], args: process.argv.slice(2), pid: process.pid, oam: process.versions.oam ?? null }));\n`;

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

/**
 * A PATH directory holding a runnable `node`: a hard link to the Node running
 * this suite, copied when a link cannot be made (another volume, or a
 * hardlink-protected file). A directory of its own rather than
 * dirname(process.execPath), which could also hold an oam this suite must not
 * discover.
 */
function nodeDir(layout: string): string {
  const dir = mkdtempSync(join(layout, "nodedir-"));
  const target = join(dir, isWin ? "node.exe" : "node");
  try {
    linkSync(process.execPath, target);
  } catch {
    copyFileSync(process.execPath, target);
    chmodSync(target, 0o755);
  }
  return dir;
}

interface RunOpts {
  /** SSH_MCP_RUNTIME, passed through verbatim -- case included. */
  mode?: string;
  pathDirs?: string[];
  oamBin?: string;
  args?: string[];
  /**
   * Pose as an oam host by preloading a `process.versions.oam` key before the
   * launcher runs. oam publishes that key and Node does not, and it is the one
   * fact the launcher branches on, so this reaches the "already running on oam"
   * paths without needing a real oam on the box that runs the suite.
   */
  hostOam?: string;
  /** More ESM source to preload, after the `hostOam` pose. */
  preload?: string;
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

  const posing =
    opts.hostOam === undefined
      ? ""
      : `Object.defineProperty(process.versions, "oam", { value: ${JSON.stringify(opts.hostOam)}, enumerable: true });`;
  const source = `${posing}${opts.preload ?? ""}`;
  const preload = source ? ["--import", `data:text/javascript,${encodeURIComponent(source)}`] : [];

  const r = spawnSync(process.execPath, [...preload, join(layout, "bin", "ssh-mcp.mjs"), ...(opts.args ?? [])], {
    env,
    encoding: "utf8",
  });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", pid: r.pid };
}

interface StubPayload {
  argv1: string;
  args: string[];
  pid: number;
  oam: string | null;
}

function stubPayload(stdout: string): StubPayload {
  const line = stdout.split("\n").find((l) => l.startsWith(MARKER));
  expect(line, `expected the stub server to run; stdout was: ${JSON.stringify(stdout)}`).toBeTruthy();
  return JSON.parse((line as string).slice(MARKER.length + 1));
}

/** A path that does not exist, for OAM_BIN. */
function missing(layout: string): string {
  return join(layout, "no-such-dir", isWin ? "oam.exe" : "oam");
}

describe("launcher: in-process fallback", () => {
  it("runs the server in this process when SSH_MCP_RUNTIME=node", () => {
    const r = run(makeLayout(), { mode: "node" });
    expect(r.status).toBe(0);
    expect(stubPayload(r.stdout).pid, "a Node host serves node mode in its own process").toBe(r.pid);
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

  it("reads SSH_MCP_RUNTIME case-insensitively", () => {
    // OAM_BIN is usable, so an `auto` reading would spawn it and the stub would
    // never run. Only a `node` reading of "NODE" serves in-process.
    const r = run(makeLayout(), { mode: "NODE", oamBin: process.execPath });
    expect(r.status, JSON.stringify(r)).toBe(0);
    expect(stubPayload(r.stdout).pid).toBe(r.pid);
  });
});

describe("launcher: oam mode is a hard requirement", () => {
  it("exits 1 and does not start a server when no oam is found", () => {
    const r = run(makeLayout(), { mode: "oam" });
    expect(r.status).toBe(1);
    expect(r.stdout).not.toContain(MARKER);
    expect(r.stderr).toMatch(/no usable oam \(0\.15\.2 or newer\) was found/);
    expect(r.stderr).toMatch(/Install oam from https:\/\/oamjs\.org/);
  });

  it("is case-insensitive too", () => {
    const r = run(makeLayout(), { mode: "OAM" });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/SSH_MCP_RUNTIME=oam but no usable oam/);
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

describe("launcher: a bad OAM_BIN is named, and discovery carries on", () => {
  it("names an OAM_BIN that does not exist instead of falling back silently", () => {
    const layout = makeLayout();
    const r = run(layout, { mode: "auto", oamBin: missing(layout) });
    expect(r.status, JSON.stringify(r)).toBe(0);
    expect(r.stdout).toContain(MARKER);
    expect(r.stderr).toMatch(/^ssh-mcp: OAM_BIN=.*does not exist; using Node instead\.$/m);
  });

  it("gives a missing OAM_BIN its own remedy in oam mode", () => {
    const layout = makeLayout();
    const r = run(layout, { mode: "oam", oamBin: missing(layout) });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/OAM_BIN=.*does not exist/);
    expect(r.stderr).toMatch(/Point OAM_BIN at an existing oam binary/);
  });

  it("still discovers an oam on PATH past an OAM_BIN that does not exist", () => {
    // The discovered oam is an empty file, so it cannot run either (no exec bit
    // on POSIX, not a PE image on Windows) -- but the message naming it proves
    // discovery was reached. The old launcher stopped at OAM_BIN and never looked.
    const layout = makeLayout();
    const name = isWin ? "oam.exe" : "oam";
    const exeDir = dirWith(layout, name, "");
    const r = run(layout, { mode: "oam", oamBin: missing(layout), pathDirs: [exeDir] });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/OAM_BIN=.*does not exist/);
    expect(r.stderr).toContain(`${join(exeDir, name)} could not be run`);
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

type Plan = "in-process" | "discover" | "handoff-node";
type RuntimePlan = (ctx: { mode: string; hostOam: string | undefined }) => Plan;
type Candidate = { path: string; version: number[] | null };
type PickNewest = (candidates: Candidate[]) => Candidate | null;

/**
 * Pull named declarations out of the launcher source and evaluate them, without
 * executing the launcher.
 *
 * Extracting the text exercises the shipped logic rather than a copy that can
 * drift, and a failed extraction is a loud assertion, not a silent skip -- the
 * same contract as the OAM_MIN patch in makeLayout.
 */
function extract(patterns: RegExp[]): string {
  const source = readFileSync(LAUNCHER_SRC, "utf8");
  return patterns
    .map((pattern) => {
      const match = source.match(pattern);
      if (!match) throw new Error(`could not extract ${pattern} from bin/ssh-mcp.mjs -- renamed or reformatted?`);
      return match[0];
    })
    .join("\n");
}

const OAM_MIN_DECL = /const OAM_MIN = \[[^\]]*\];/;
const ATLEAST_DECL = /function atLeast\(v, min\) \{[\s\S]*?\n\}/;

function loadRuntimePlan(): RuntimePlan {
  const pieces = extract([
    OAM_MIN_DECL,
    /function parseVersion\(text\) \{[\s\S]*?\n\}/,
    ATLEAST_DECL,
    /function runtimePlan\(\{ mode, hostOam \}\) \{[\s\S]*?\n\}/,
  ]);
  return new Function(`${pieces}\nreturn runtimePlan;`)() as RuntimePlan;
}

function loadPickNewest(): { pickNewest: PickNewest; floor: number[] } {
  const pieces = extract([OAM_MIN_DECL, ATLEAST_DECL, /function pickNewest\(candidates\) \{[\s\S]*?\n\}/]);
  return new Function(`${pieces}\nreturn { pickNewest, floor: OAM_MIN };`)() as {
    pickNewest: PickNewest;
    floor: number[];
  };
}

describe("launcher: runtimePlan()", () => {
  const runtimePlan = loadRuntimePlan();

  it("serves in-process when already hosted on an oam at or above the floor", () => {
    // The bug this exists for: a host that launches `oam run bin/ssh-mcp.mjs`
    // got a SECOND oam, because the launcher discovered and spawned one without
    // asking what it was already running on. `auto` and `oam` both have to take
    // the shortcut -- `oam` demands oam, and the host already is one.
    //
    // 0.15.2 pins the floor as inclusive (it IS the supported release), and
    // 0.100.0 pins a numeric compare: it sorts BEFORE 0.15.2 as a string, so a
    // compare over the raw text would treat a newer oam as too old.
    for (const mode of ["auto", "oam"]) {
      for (const hostOam of ["0.15.2", "0.16.0", "0.100.0", "1.0.0", "0.16.0-dev"]) {
        expect(runtimePlan({ mode, hostOam }), `mode=${mode} hostOam=${hostOam}`).toBe("in-process");
      }
    }
  });

  it("never serves in-process on a host oam below the floor", () => {
    // Below the floor the host must hand off. Serving there was the bug: an oam
    // older than 0.9.0 runs this server's CLI arguments through a shell, and
    // anything older than the latest release is not what the server is
    // verified on.
    for (const mode of ["auto", "oam"]) {
      for (const hostOam of ["0.15.1", "0.9.0", "0.8.2", "0.0.1"]) {
        expect(runtimePlan({ mode, hostOam }), `mode=${mode} hostOam=${hostOam}`).toBe("discover");
      }
    }
  });

  it("discovers as before on Node, where process.versions has no oam key", () => {
    // An unreadable value must not count as "new enough" either: that would
    // skip discovery on a host that never proved it is a supported oam.
    for (const mode of ["auto", "oam"]) {
      for (const hostOam of [undefined, "", "dev"]) {
        expect(runtimePlan({ mode, hostOam }), `mode=${mode} hostOam=${hostOam}`).toBe("discover");
      }
    }
  });

  it("runs SSH_MCP_RUNTIME=node on Node: in-process on a Node host, handed off from any oam host", () => {
    expect(runtimePlan({ mode: "node", hostOam: undefined })).toBe("in-process");
    for (const hostOam of ["0.8.2", "0.15.2", "1.0.0", "dev"]) {
      expect(runtimePlan({ mode: "node", hostOam }), `hostOam=${hostOam}`).toBe("handoff-node");
    }
  });
});

describe("launcher: pickNewest()", () => {
  const { pickNewest, floor } = loadPickNewest();
  const at = (path: string, version: number[] | null): Candidate => ({ path, version });

  it("pins the floor to the latest oam release", () => {
    expect(floor).toEqual([0, 15, 2]);
  });

  it("takes the newest usable oam, not the first one found", () => {
    // The bug: discovery stopped at the first binary that existed, so an older
    // copy in an earlier location (the installed dir is searched before PATH)
    // hid a newer one later.
    const chosen = pickNewest([at("installed", [0, 15, 2]), at("path-a", [0, 16, 0]), at("path-b", [0, 15, 9])]);
    expect(chosen?.path).toBe("path-a");
  });

  it("compares numerically and keeps search order on a tie", () => {
    expect(pickNewest([at("a", [0, 16, 0]), at("b", [0, 100, 0])])?.path).toBe("b");
    expect(pickNewest([at("first", [0, 15, 2]), at("second", [0, 15, 2])])?.path).toBe("first");
  });

  it("skips binaries below the floor or with no readable version", () => {
    expect(pickNewest([at("old", [0, 9, 0]), at("broken", null), at("good", [0, 15, 2])])?.path).toBe("good");
    expect(pickNewest([at("old", [0, 15, 1]), at("broken", null)])).toBeNull();
    expect(pickNewest([])).toBeNull();
  });
});

describe("launcher: already hosted on oam", () => {
  // The unit tests above prove the decision; these prove the launcher WIRES it
  // -- that the call site actually reads `process.versions.oam` -- which no
  // amount of testing runtimePlan in isolation can.
  //
  // OAM_BIN is pinned to the Node running this suite, exactly as in "spawns a
  // usable oam instead of running the server in-process" above, which is the
  // control for these: same layout, same OAM_BIN, no preload, and the stub must
  // NOT run. With the preload the only thing that changed is the host, so a
  // stub that runs here was served in-process rather than by a nested runtime.
  //
  // Each case boots one or two Node processes, and a bare Node start has been
  // measured in whole seconds on a contended Windows box.
  const TIMEOUT_MS = 45_000;

  for (const mode of ["auto", "oam"] as const) {
    it(
      `serves in-process instead of spawning a nested oam (SSH_MCP_RUNTIME=${mode})`,
      () => {
        const layout = makeLayout();
        const r = run(layout, { mode, hostOam: "0.15.2", oamBin: process.execPath, args: ["--version", "extra"] });
        expect(r.status, JSON.stringify(r)).toBe(0);
        const payload = stubPayload(r.stdout);
        // Same entry-point repoint and argv passthrough as the Node fallback:
        // it is the same runInProcess, not a second copy of it.
        expect(payload.argv1).toBe(join(layout, "dist", "index.js"));
        expect(payload.args).toEqual(["--version", "extra"]);
        expect(payload.pid).toBe(r.pid);
        expect(payload.oam).toBe("0.15.2");
        // No discovery ran, so there is no discovery diagnostic.
        expect(r.stderr).toBe("");
      },
      TIMEOUT_MS,
    );
  }

  it(
    "treats SSH_MCP_RUNTIME=oam as satisfied by the host, with no oam binary to discover",
    () => {
      // PATH, OAM_BIN and every installed location are empty, which on Node is
      // the "no usable oam" hard failure. On an oam host at the floor that
      // requirement is already met.
      const r = run(makeLayout(), { mode: "oam", hostOam: "0.15.2" });
      expect(r.status, JSON.stringify(r)).toBe(0);
      expect(r.stdout).toContain(MARKER);
      expect(r.stderr).not.toMatch(/no usable oam/);
    },
    TIMEOUT_MS,
  );

  it(
    "still discovers and spawns when the host oam is below the floor",
    () => {
      const r = run(makeLayout(), { mode: "auto", hostOam: "0.15.1", oamBin: process.execPath });
      expect(r.stdout, `a below-floor host must not shortcut, got ${JSON.stringify(r)}`).not.toContain(MARKER);
      expect(r.status).not.toBe(0);
      // The spawned child failed, not the launcher: every launcher diagnostic
      // starts with `ssh-mcp: `.
      expect(r.stderr).not.toMatch(/^ssh-mcp: /m);
    },
    TIMEOUT_MS,
  );
});

describe("launcher: an oam host below the floor never serves", () => {
  // Each of these used to serve the server on the old host itself. A handoff to
  // Node is visible in the stub's payload: a different pid from the launcher,
  // and no `process.versions.oam` (the pose is a preload on the launcher only).
  const TIMEOUT_MS = 45_000;

  it(
    "hands off to Node on PATH when no oam is found at all",
    () => {
      const layout = makeLayout();
      const r = run(layout, { mode: "auto", hostOam: "0.9.0", oamBin: missing(layout), pathDirs: [nodeDir(layout)] });
      expect(r.status, JSON.stringify(r)).toBe(0);
      const payload = stubPayload(r.stdout);
      expect(payload.pid, "served by a child, not on the old host").not.toBe(r.pid);
      expect(payload.oam).toBeNull();
      expect(r.stderr).toMatch(
        /this process is oam 0\.9\.0, older than 0\.15\.2, and no newer oam was found; running on .*node(\.exe)? instead/,
      );
    },
    TIMEOUT_MS,
  );

  it(
    "hands off to Node when the only oam found is also too old",
    () => {
      // The floor raised above the Node running the suite makes OAM_BIN a real,
      // runnable, too-old oam -- and makes the posed host too old as well.
      const layout = makeLayout({ oamMin: "[99, 0, 0]" });
      const r = run(layout, {
        mode: "auto",
        hostOam: "1.0.0",
        oamBin: process.execPath,
        pathDirs: [nodeDir(layout)],
      });
      expect(r.status, JSON.stringify(r)).toBe(0);
      expect(stubPayload(r.stdout).pid).not.toBe(r.pid);
      expect(r.stderr).toMatch(/is oam \d+\.\d+\.\d+, older than 99\.0\.0/);
    },
    TIMEOUT_MS,
  );

  it(
    "refuses to serve when there is no Node on PATH either",
    () => {
      const layout = makeLayout();
      const r = run(layout, { mode: "auto", hostOam: "0.9.0", oamBin: missing(layout) });
      expect(r.status, JSON.stringify(r)).toBe(1);
      expect(r.stdout, "nothing may be served").not.toContain(MARKER);
      expect(r.stderr).toMatch(/no Node was found on PATH/);
      expect(r.stderr).toMatch(/oam self-update/);
    },
    TIMEOUT_MS,
  );

  it(
    "exits 1 under SSH_MCP_RUNTIME=oam rather than handing off to Node",
    () => {
      const layout = makeLayout();
      const r = run(layout, { mode: "oam", hostOam: "0.9.0", pathDirs: [nodeDir(layout)] });
      expect(r.status, JSON.stringify(r)).toBe(1);
      expect(r.stdout).not.toContain(MARKER);
      expect(r.stderr).toMatch(/SSH_MCP_RUNTIME=oam but no usable oam/);
    },
    TIMEOUT_MS,
  );

  it(
    "still falls back to Node when the chosen oam fails to spawn",
    () => {
      // The chosen binary passed its --version probe and then could not be
      // spawned (deleted or replaced in between). A failed spawn emits 'error'
      // and then 'close' with the negative errno -- never 'exit' -- and a handoff
      // from an oam host waits for 'close', so an unguarded close handler exited
      // the launcher mid-fallback and nothing served. The preload makes the
      // FIRST spawn target a path that does not exist; the Node fallback, the
      // second spawn, runs for real.
      const failFirstSpawn = [
        'import childProcess from "node:child_process";',
        'import { syncBuiltinESMExports } from "node:module";',
        "const realSpawn = childProcess.spawn;",
        "let failed = false;",
        "childProcess.spawn = function (cmd, args, opts) {",
        "  if (failed) return realSpawn.call(this, cmd, args, opts);",
        "  failed = true;",
        '  return realSpawn.call(this, cmd + ".does-not-exist", args, opts);',
        "};",
        "syncBuiltinESMExports();",
      ].join("\n");
      const layout = makeLayout();
      const r = run(layout, {
        mode: "auto",
        hostOam: "0.9.0",
        oamBin: process.execPath,
        pathDirs: [nodeDir(layout)],
        preload: failFirstSpawn,
      });
      expect(r.status, JSON.stringify(r)).toBe(0);
      expect(r.stderr).toMatch(/^ssh-mcp: failed to launch oam at .*; using Node instead\.$/m);
      // A newer oam WAS found; it just would not start. The handoff note must
      // not then claim that nothing was found.
      expect(r.stderr).toMatch(
        /older than 0\.15\.2, and the newer oam would not start; running on .*node(\.exe)? instead/,
      );
      expect(r.stderr).not.toMatch(/no newer oam was found/);
      const payload = stubPayload(r.stdout);
      expect(payload.pid, "the Node fallback must still serve, in a child").not.toBe(r.pid);
      expect(payload.oam).toBeNull();
    },
    TIMEOUT_MS,
  );
});

describe("launcher: SSH_MCP_RUNTIME=node always means Node", () => {
  const TIMEOUT_MS = 45_000;

  it(
    "hands off to Node even on a supported oam host",
    () => {
      const layout = makeLayout();
      const r = run(layout, { mode: "node", hostOam: "0.15.2", pathDirs: [nodeDir(layout)], args: ["extra"] });
      expect(r.status, JSON.stringify(r)).toBe(0);
      const payload = stubPayload(r.stdout);
      expect(payload.pid).not.toBe(r.pid);
      expect(payload.oam).toBeNull();
      expect(payload.args).toEqual(["extra"]);
      // Asked for outright, so there is nothing to explain.
      expect(r.stderr).toBe("");
    },
    TIMEOUT_MS,
  );

  it(
    "exits 1 with a Node remedy when there is no Node on PATH",
    () => {
      const r = run(makeLayout(), { mode: "node", hostOam: "0.15.2" });
      expect(r.status, JSON.stringify(r)).toBe(1);
      expect(r.stdout).not.toContain(MARKER);
      expect(r.stderr).toMatch(/SSH_MCP_RUNTIME=node on oam 0\.15\.2, and no Node was found on PATH/);
      expect(r.stderr).toMatch(/Put Node on PATH/);
      expect(r.stderr).not.toMatch(/self-update/);
    },
    TIMEOUT_MS,
  );
});

describe("launcher: Windows PATH discovery", () => {
  it.skipIf(!isWin)("skips a .cmd shim on PATH but names it in oam mode", () => {
    const layout = makeLayout();
    const shimDir = dirWith(layout, "oam.cmd", "@echo off\r\n");
    const r = run(layout, { mode: "oam", pathDirs: [shimDir] });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/oam\.cmd/);
    expect(r.stderr).toMatch(/cannot execute a \.cmd\/\.bat directly/);
  });

  it.skipIf(!isWin)("names the skipped shim in auto mode, then falls back", () => {
    const layout = makeLayout();
    const shimDir = dirWith(layout, "oam.cmd", "@echo off\r\n");
    const r = run(layout, { mode: "auto", pathDirs: [shimDir] });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain(MARKER);
    // Silence here is how someone never learns their install is unusable.
    expect(r.stderr).toMatch(/oam\.cmd/);
  });

  it.skipIf(!isWin)("probes an .exe later on PATH and never treats an earlier .cmd shim as a candidate", () => {
    const layout = makeLayout();
    const shimDir = dirWith(layout, "oam.cmd", "@echo off\r\n");
    const exeDir = dirWith(layout, "oam.exe", "");
    const r = run(layout, { mode: "oam", pathDirs: [shimDir, exeDir] });
    expect(r.status).toBe(1);
    // The .exe is empty so it cannot actually run, but the message naming it as
    // a probed candidate proves discovery reached it past the shim that came
    // first. The shim is only ever named as a shape Node cannot execute.
    expect(r.stderr).toContain(`${join(exeDir, "oam.exe")} could not be run`);
    expect(r.stderr).not.toMatch(/oam\.cmd could not be run/);
    expect(r.stderr).toMatch(/oam\.cmd, but Node cannot execute a \.cmd\/\.bat directly/);
  });

  it.skipIf(isWin)("has no shim concept on POSIX -- a bare `oam` is what is looked for", () => {
    const layout = makeLayout();
    const shimDir = dirWith(layout, "oam.cmd", "");
    const r = run(layout, { mode: "oam", pathDirs: [shimDir] });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/no usable oam/);
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
  const posix = !isWin;

  const OAM_SH = [
    "#!/bin/sh",
    // The launcher probes `--version` first; answer at the floor so the gate passes.
    'case "$1" in --version) echo "oam 0.15.2"; exit 0;; esac',
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
