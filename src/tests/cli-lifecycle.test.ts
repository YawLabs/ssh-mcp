import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

// Lifecycle of the two files that are only ever RUN, never imported:
// src/index.ts (the server's process bootstrap) and bin/ssh-mcp.mjs (the
// launcher). launcher.test.ts already executes the launcher for discovery, the
// version gate and POSIX signal forwarding; this file covers what is left, and
// what no unit test can reach by importing a module:
//
//   * the server's --version short-circuit, which must answer BEFORE main()
//     attaches a stdio transport (Homebrew's `brew test` and the SEA smoke test
//     both depend on it, and neither runs on a win32/linux build)
//   * the process.on("exit") backstop, the ONLY thing that reaps a self-spawned
//     ssh-agent when the host closes the pipe -- which fires neither SIGINT nor
//     SIGTERM
//   * the launcher preferring an INSTALLED oam over one on PATH
//   * the exact argv the launcher hands oam, `--` included
//   * the launcher mirroring the child's exit status back to the MCP host
//
// Both harnesses execute a COPY of the real file in a throwaway layout, the
// shape launcher.test.ts established. Copies, not the originals, because each
// needs neighbours it cannot have in the repo: stub sibling modules for the
// server, a fabricated oam install for the launcher.

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");
const INDEX_SRC = join(REPO_ROOT, "src", "index.ts");
const LAUNCHER_SRC = join(REPO_ROOT, "bin", "ssh-mcp.mjs");

const layouts: string[] = [];
afterAll(() => {
  for (const dir of layouts) rmSync(dir, { recursive: true, force: true });
});

function mkLayout(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  layouts.push(dir);
  return dir;
}

// ---------------------------------------------------------------------------
// src/index.ts
// ---------------------------------------------------------------------------

// src/index.ts is pure runtime wiring -- no exports, and every line of it runs
// at import time -- so the only honest test is to execute it. It is also
// type-annotation-free, so the file is already valid ESM: copying it to
// <tmp>/index.mjs and rewriting only its four import specifiers runs the REAL
// source rather than a paraphrase of it.
//
// Three specifiers point at stubs so the test observes the lifecycle instead of
// opening SSH sockets; the fourth (the MCP SDK) becomes an absolute file URL
// because the temp dir has no node_modules to resolve a bare specifier against.
// The SDK itself stays REAL -- StdioServerTransport's own stdin handling is
// precisely the mechanism the EOF test is about.
const SDK_STDIO_URL = (import.meta as unknown as { resolve(s: string): string }).resolve(
  "@modelcontextprotocol/sdk/server/stdio.js",
);

const STUB_VERSION = "9.9.9-stub";

// Every stub records what it was asked to do, in order, to a FILE rather than
// to stdout: a process.on("exit") handler must be synchronous, and an async
// stdout write issued from one is truncated by the exiting process on Windows
// pipes -- the same hazard bin/ssh-mcp.mjs uses errSync for.
const STUB_ENV = [
  'import { appendFileSync } from "node:fs";',
  'export function killStartedAgent() { appendFileSync(process.env.MARK, "kill\\n"); }',
  "",
].join("\n");

const STUB_POOL = [
  'import { appendFileSync } from "node:fs";',
  "export class ConnectionPool {",
  '  drain() { appendFileSync(process.env.MARK, "drain\\n"); }',
  "}",
  "",
].join("\n");

const STUB_SERVER_MODULE = [
  'import { appendFileSync } from "node:fs";',
  "export const version = process.env.STUB_VERSION;",
  "export function createServer() {",
  "  return {",
  "    async connect(transport) {",
  '      appendFileSync(process.env.MARK, "connect\\n");',
  "      // What McpServer.connect does that matters here: it starts the",
  "      // transport, and starting the transport is what attaches to stdin.",
  "      await transport.start();",
  '      appendFileSync(process.env.MARK, "ready\\n");',
  "    },",
  '    async close() { appendFileSync(process.env.MARK, "close\\n"); },',
  "  };",
  "}",
  "",
].join("\n");

interface ServerLayout {
  dir: string;
  entry: string;
  mark: string;
}

function makeServerLayout(): ServerLayout {
  const dir = mkLayout("ssh-mcp-index-");
  let src = readFileSync(INDEX_SRC, "utf8");

  // Rewrite each import, and fail loudly rather than silently testing an
  // unpatched copy if a specifier is ever renamed or reformatted.
  const rewrites: Array<[string, string]> = [
    ['"@modelcontextprotocol/sdk/server/stdio.js"', JSON.stringify(SDK_STDIO_URL)],
    ['"./env.js"', '"./env.mjs"'],
    ['"./pool.js"', '"./pool.mjs"'],
    ['"./server.js"', '"./server.mjs"'],
  ];
  for (const [from, to] of rewrites) {
    expect(src, `import ${from} not found in src/index.ts -- did it move?`).toContain(from);
    src = src.replace(from, to);
  }

  writeFileSync(join(dir, "index.mjs"), src);
  writeFileSync(join(dir, "env.mjs"), STUB_ENV);
  writeFileSync(join(dir, "pool.mjs"), STUB_POOL);
  writeFileSync(join(dir, "server.mjs"), STUB_SERVER_MODULE);
  const mark = join(dir, "mark");
  writeFileSync(mark, "");
  return { dir, entry: join(dir, "index.mjs"), mark };
}

function serverEnv(layout: ServerLayout): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (typeof v === "string") env[k] = v;
  env.MARK = layout.mark;
  env.STUB_VERSION = STUB_VERSION;
  return env;
}

/** The steps the stubs recorded, in order. */
function steps(layout: ServerLayout): string[] {
  return readFileSync(layout.mark, "utf8").split("\n").filter(Boolean);
}

/** Run the server with stdin already at EOF (stdio "ignore" is /dev/null). */
function runServer(layout: ServerLayout, args: string[] = []) {
  const r = spawnSync(process.execPath, [layout.entry, ...args], {
    env: serverEnv(layout),
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

describe("server: --version answers before main() attaches a transport", () => {
  // The contract these pin, from src/index.ts's own header: a BARE version on
  // stdout, exit 0, and no transport. `brew test` greps that stdout, and the
  // SEA smoke test inherits the build shell's stdin -- reaching main() there
  // hangs the build rather than failing it. The smoke test is darwin-only and
  // this repo has no CI, so on win32/linux nothing else catches a break.
  for (const flag of ["--version", "version"]) {
    it(`prints only the version and exits 0 for \`${flag}\``, () => {
      const layout = makeServerLayout();
      const r = runServer(layout, [flag]);
      expect(r.status).toBe(0);
      // Exactly the version and nothing else -- no banner, no trailing noise.
      expect(r.stdout).toBe(`${STUB_VERSION}\n`);
      expect(r.stderr).toBe("");
      // Nothing was constructed and no transport was connected: the exit sits
      // above main(), it is not a fast path through it.
      expect(steps(layout)).toEqual([]);
    });
  }

  it("only examines the FIRST user argument", () => {
    // Observed behaviour, and deliberate per the source note: argv[2] is the
    // first user arg in a SEA binary too. A --version anywhere later is just an
    // argument, so the server starts normally.
    const layout = makeServerLayout();
    const r = runServer(layout, ["serve", "--version"]);
    expect(r.stdout).not.toContain(STUB_VERSION);
    expect(steps(layout)).toContain("connect");
  });
});

describe("server: stdin EOF runs the exit backstop", () => {
  it("stays up while stdin is open, then exits 0 when the host closes it", async () => {
    const layout = makeServerLayout();
    const child = spawn(process.execPath, [layout.entry], {
      env: serverEnv(layout),
      stdio: ["pipe", "pipe", "pipe"],
    });
    let done = false;
    const exited = new Promise<number | null>((res) => {
      child.on("exit", (code) => {
        done = true;
        res(code);
      });
    });

    // Poll for the transport rather than sleeping a fixed window: on a loaded
    // machine the server's own startup can outlast any constant picked here,
    // and a flaky liveness check is worse than a slow one.
    const deadline = Date.now() + 10_000;
    while (!steps(layout).includes("ready") && !done && Date.now() < deadline) {
      await new Promise((res) => setTimeout(res, 25));
    }
    expect(steps(layout)).toEqual(["connect", "ready"]);
    // Still serving a beat later. If the server had exited on its own, the EOF
    // assertions below would prove nothing about EOF.
    await new Promise((res) => setTimeout(res, 250));
    expect(done, "server exited before stdin was closed").toBe(false);

    child.stdin.end();
    expect(await exited).toBe(0);

    // The backstop, and ONLY the backstop: pipe-close fires neither SIGINT nor
    // SIGTERM, so shutdown() never runs and server.close() is never called.
    // pool.drain() and killStartedAgent() happen anyway -- an ssh-agent this
    // process spawned itself gets reaped rather than leaked once per session,
    // silently and cumulatively, if this regresses.
    expect(steps(layout)).toEqual(["connect", "ready", "drain", "kill"]);
  });

  it("reaps the agent even when stdin was never open", () => {
    // The `< /dev/null` shape: EOF before the transport even attaches.
    const layout = makeServerLayout();
    const r = runServer(layout);
    expect(r.status).toBe(0);
    expect(steps(layout)).toEqual(["connect", "ready", "drain", "kill"]);
  });
});

// ---------------------------------------------------------------------------
// bin/ssh-mcp.mjs
// ---------------------------------------------------------------------------

const isWin = process.platform === "win32";
const OAM_EXE = isWin ? "oam.exe" : "oam";
const MARKER = "STUB_SERVER";
const STUB_DIST = `console.log(${JSON.stringify(MARKER)});\n`;

// Intercepts child_process.spawn inside the launcher's own process, recording
// the argv it built and standing in for the child so a test can choose how that
// child dies. A real oam cannot be fabricated here: the launcher refuses a
// .cmd/.bat on Windows by design, and a POSIX shell script cannot report an
// exit signal it never received. process.execPath -- launcher.test.ts's
// stand-in -- exits before it can be asked to exit any particular way.
//
// Patching the builtin from a --require preload is enough: Node builds the ESM
// facade for node:child_process on first import, which happens after preloads
// run, so the launcher's `import { spawn }` sees the replacement. execFileSync
// is deliberately left alone, so the version gate stays the real one.
const SPAWN_SPY = [
  'const cp = require("node:child_process");',
  'const { EventEmitter } = require("node:events");',
  'const { appendFileSync } = require("node:fs");',
  "cp.spawn = (cmd, args, opts) => {",
  // biome-ignore lint/suspicious/noTemplateCurlyInString: SOURCE TEXT for a preload stub, not a string this file evaluates -- the placeholder must reach that file verbatim.
  "  appendFileSync(process.env.SPAWN_LOG, `${JSON.stringify({ cmd, args, stdio: opts && opts.stdio })}\\n`);",
  "  const child = new EventEmitter();",
  "  child.kill = () => true;",
  "  setImmediate(() => {",
  '    child.emit("spawn");',
  "    setImmediate(() => {",
  "      const sig = process.env.FAKE_SIGNAL || null;",
  '      const code = sig ? null : Number(process.env.FAKE_CODE ?? "0");',
  '      child.emit("exit", code, sig);',
  "    });",
  "  });",
  "  return child;",
  "};",
  "",
].join("\n");

interface LauncherLayout {
  dir: string;
  entry: string;
  serverEntry: string;
  home: string;
  localAppData: string;
  spy: string;
  spawnLog: string;
}

function makeLauncherLayout(): LauncherLayout {
  const dir = mkLayout("ssh-mcp-cli-");
  mkdirSync(join(dir, "bin"));
  mkdirSync(join(dir, "dist"));
  mkdirSync(join(dir, "home"));
  mkdirSync(join(dir, "localappdata"));
  writeFileSync(join(dir, "bin", "ssh-mcp.mjs"), readFileSync(LAUNCHER_SRC, "utf8"));
  writeFileSync(join(dir, "dist", "index.js"), STUB_DIST);
  writeFileSync(join(dir, "spy.cjs"), SPAWN_SPY);
  const spawnLog = join(dir, "spawn.log");
  writeFileSync(spawnLog, "");
  return {
    dir,
    entry: join(dir, "bin", "ssh-mcp.mjs"),
    serverEntry: join(dir, "dist", "index.js"),
    home: join(dir, "home"),
    localAppData: join(dir, "localappdata"),
    spy: join(dir, "spy.cjs"),
    spawnLog,
  };
}

/** Plant a fake oam install and return its path. Empty: it only has to EXIST. */
function plantOam(dir: string): string {
  mkdirSync(dir, { recursive: true });
  const p = join(dir, OAM_EXE);
  writeFileSync(p, "");
  return p;
}

interface LauncherOpts {
  mode?: "auto" | "oam" | "node";
  pathDirs?: string[];
  oamBin?: string;
  args?: string[];
  spy?: boolean;
  fakeCode?: string;
  fakeSignal?: string;
}

function runLauncher(layout: LauncherLayout, opts: LauncherOpts = {}) {
  // Built from scratch, not spread: the real PATH has a working oam on a
  // developer box, and on Windows a spread can leave `Path` and `PATH` both set
  // with different values.
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (typeof v !== "string") continue;
    if (/^(path|oam_bin|ssh_mcp_runtime|userprofile|home|localappdata|spawn_log|fake_code|fake_signal)$/i.test(k)) {
      continue;
    }
    env[k] = v;
  }
  env.PATH = (opts.pathDirs ?? []).join(delimiter);
  env.SSH_MCP_RUNTIME = opts.mode ?? "auto";
  // Point every "installed oam" location inside the layout, so discovery cannot
  // reach a real oam installed on this machine.
  env.USERPROFILE = layout.home;
  env.HOME = layout.home;
  env.LOCALAPPDATA = layout.localAppData;
  env.SPAWN_LOG = layout.spawnLog;
  if (opts.oamBin) env.OAM_BIN = opts.oamBin;
  if (opts.fakeCode !== undefined) env.FAKE_CODE = opts.fakeCode;
  if (opts.fakeSignal) env.FAKE_SIGNAL = opts.fakeSignal;

  const nodeArgs = opts.spy ? ["--require", layout.spy] : [];
  const r = spawnSync(process.execPath, [...nodeArgs, layout.entry, ...(opts.args ?? [])], {
    env,
    encoding: "utf8",
  });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

/** The one spawn the launcher made. */
function spawnedWith(layout: LauncherLayout): { cmd: string; args: string[]; stdio: string } {
  const lines = readFileSync(layout.spawnLog, "utf8").split("\n").filter(Boolean);
  expect(lines, "expected the launcher to spawn exactly one child").toHaveLength(1);
  return JSON.parse(lines[0]);
}

describe("launcher: an installed oam beats one on PATH", () => {
  // Deliberate ordering, per the source: someone who develops oam itself has
  // oam/target/release on PATH, and cargo replaces that binary underneath
  // running processes. The installed copy is what a normal user actually has.
  //
  // Every fake oam here is an empty file, so the version gate always fails --
  // and in `oam` mode that failure NAMES the path discovery chose, which is how
  // these tests observe the decision without a runnable binary to fabricate.
  it("takes ~/.oam/bin over a PATH hit", () => {
    const layout = makeLauncherLayout();
    const installed = plantOam(join(layout.home, ".oam", "bin"));
    const onPath = plantOam(join(layout.dir, "pathdir"));

    const r = runLauncher(layout, { mode: "oam", pathDirs: [join(layout.dir, "pathdir")] });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain(installed);
    expect(r.stderr).not.toContain(onPath);
  });

  it("still finds the PATH copy when nothing is installed", () => {
    // The control. Without it, a launcher that had stopped scanning PATH
    // altogether would pass the test above.
    const layout = makeLauncherLayout();
    const onPath = plantOam(join(layout.dir, "pathdir"));

    const r = runLauncher(layout, { mode: "oam", pathDirs: [join(layout.dir, "pathdir")] });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain(onPath);
  });

  it.skipIf(!isWin)("checks %LOCALAPPDATA%\\oam\\bin before ~/.oam/bin on Windows", () => {
    // The Windows installer's default location. Checking only the documented
    // ~/.oam/bin silently misses a real install.
    const layout = makeLauncherLayout();
    const appData = plantOam(join(layout.localAppData, "oam", "bin"));
    const dotOam = plantOam(join(layout.home, ".oam", "bin"));

    const r = runLauncher(layout, { mode: "oam" });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain(appData);
    expect(r.stderr).not.toContain(dotOam);
  });
});

describe("launcher: the argv handed to oam", () => {
  // process.execPath passes the REAL version gate (`node --version` reports a
  // semver well above the 0.9.0 floor); the spy only replaces the spawn.
  it("passes `run <server> --` and forwards host args after the separator", () => {
    const layout = makeLauncherLayout();
    const r = runLauncher(layout, { mode: "oam", oamBin: process.execPath, spy: true, args: ["--version", "extra"] });

    const call = spawnedWith(layout);
    expect(call.cmd).toBe(process.execPath);
    // The `--` is load-bearing: without it oam would read `--version` as one of
    // its own flags and `ssh-mcp --version` would never reach the server on the
    // oam path.
    expect(call.args).toEqual(["run", layout.serverEntry, "--", "--version", "extra"]);
    // inherit keeps the SAME fds, so MCP's newline-delimited JSON framing and
    // the host's stdin-close both survive the hop.
    expect(call.stdio).toBe("inherit");
    // oam was spawned, so the in-process fallback did not also run.
    expect(r.stdout).not.toContain(MARKER);
  });

  it("keeps the separator even with no host args", () => {
    const layout = makeLauncherLayout();
    runLauncher(layout, { mode: "oam", oamBin: process.execPath, spy: true });
    expect(spawnedWith(layout).args).toEqual(["run", layout.serverEntry, "--"]);
  });
});

describe("launcher: the child's exit status is mirrored", () => {
  // An MCP host reads this status to decide whether to restart the server, so
  // collapsing a failure into 0 makes a crash-looping server look healthy.
  it("returns the child's own non-zero code", () => {
    const layout = makeLauncherLayout();
    const r = runLauncher(layout, { mode: "oam", oamBin: process.execPath, spy: true, fakeCode: "3" });
    expect(r.status).toBe(3);
  });

  it("returns 0 when the child exits cleanly", () => {
    const layout = makeLauncherLayout();
    const r = runLauncher(layout, { mode: "oam", oamBin: process.execPath, spy: true, fakeCode: "0" });
    expect(r.status).toBe(0);
  });

  it("turns a signal death into the conventional 128+n", () => {
    const layout = makeLauncherLayout();
    const r = runLauncher(layout, { mode: "oam", oamBin: process.execPath, spy: true, fakeSignal: "SIGTERM" });
    expect(r.status).toBe(143); // 128 + SIGTERM(15)
  });
});
