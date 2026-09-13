#!/usr/bin/env node
/**
 * Runtime launcher for @yawlabs/ssh-mcp.
 *
 * Prefers the newest usable oam runtime (https://oamjs.org) and falls back to
 * Node. It never serves on an oam older than the floor below.
 *
 *
 * WHY THE FALLBACK COSTS NOTHING
 * npm has already started Node to run this launcher, so falling back is a
 * plain `import()` of the server into THIS process: no extra spawn, no extra
 * startup, byte-identical to invoking dist/index.js directly. Finding the
 * candidates is stat-only, so a machine without oam never pays for a
 * subprocess.
 *
 * WHAT THE OAM PATH COSTS
 * Reaching oam through an npm `bin` means Node boots first, every oam binary
 * found is asked for its version, and then oam boots to serve -- so the
 * launcher is slower than pointing a host at oam directly. Measured on
 * npmjs-mcp (windows-arm64, n=12 medians, spawn to first MCP initialize):
 * oam 116ms, node 172ms, launcher 243ms. It exists for `npx` convenience.
 *
 * One `oam --version` probe measured 26ms median (n=12, windows-arm64). It is
 * paid once per oam binary found, on every launch that runs discovery and finds
 * one -- including the launches that go on to fall back to Node.
 *
 * For an MCP host config, point straight at oam and skip this file:
 *   { "command": "oam", "args": ["run", "<abs>/dist/index.js"] }
 *
 * WHICH OAM
 * OAM_BIN, when set and usable, is used as given. Otherwise every oam binary
 * discovery can see -- the installed locations, then PATH -- is asked for its
 * version, and the NEWEST one at or above the floor wins; a tie keeps search
 * order. Taking the first binary found instead let a stale copy early in the
 * search order hide a current one later: with oam 0.9.0 installed in ~/.oam/bin
 * and 0.15.2 on PATH, the launcher bound to 0.9.0 because installed locations
 * are searched first.
 *
 * An OAM_BIN that does not exist, is below the floor, or will not run is always
 * named on stderr, and discovery carries on. It used to stop everything: a typo
 * in OAM_BIN meant Node, with no hint why. The discovered binaries that were
 * passed over, and any .cmd/.bat shim on PATH, are named only when NO usable
 * oam is found -- with 0.9.0 installed and 0.15.2 on PATH, stderr stays empty.
 *
 * ALREADY RUNNING ON OAM
 * A host can resolve this package's `bin` and launch `oam run <this file>`
 * instead of `node <this file>` -- Yaw MCP does, and so does oam's sidecar
 * regression matrix. This launcher used to discover oam and spawn it anyway,
 * so one server cost two runtime boots: measured on Windows, oam.exe with a
 * NESTED oam.exe + conhost.exe underneath it. When `process.versions.oam`
 * clears the floor, the server is imported into THIS process exactly as the
 * Node fallback is -- no discovery, no `oam --version` probe, no second oam.
 * OAM_BIN is a discovery input, so it is not consulted on that path: the host
 * has already chosen which oam runs.
 *
 * Nothing forces a re-spawn on a supported host: the spawn below passes oam no
 * runtime flags -- there is no `--permission` sandbox to apply, see NO SANDBOX
 * HERE -- so serving in-process drops nothing a fresh oam would have applied.
 *
 * A host oam BELOW the floor never serves. It used to, whenever discovery came
 * up empty or found nothing usable. It now hands the server off to the newest
 * usable oam, or to Node found on PATH, or exits with an error when there is
 * neither.
 *
 * That handoff PIPES stdio rather than inheriting it. Before 0.9.0 oam treated
 * `stdio: 'inherit'` as `'pipe'`, so an inherited handoff from such a host
 * connected the child to pipes nobody reads: measured with a real oam 0.8.2
 * host on aws-mcp's launcher, which this one shares, the MCP handshake never
 * answered. Piping the streams explicitly completes it, to both oam and Node. A
 * Node host keeps `inherit`, which hands over the same fds untouched.
 *
 * NO SANDBOX HERE -- DELIBERATELY
 * The purpose of this server is to open outbound SSH to hosts the caller names
 * at run time and run commands there, so the net and child-process grants would
 * both have to be unrestricted, and key material plus known_hosts need the
 * filesystem. Nothing meaningful is left to deny, so `--permission` is not
 * wired up here.
 *
 * MINIMUM OAM VERSION
 * The latest oam release, 0.15.2 -- bump OAM_MIN when oam ships a newer one.
 * Only the current oam is used and verified; an older one is passed over.
 * The floor is not cosmetic: before 0.9.0 `child_process.execFile` ran its
 * arguments through a SHELL, `exec` accepted `timeout` and ignored it,
 * `spawnSync` truncated at `maxBuffer` while reporting success, and
 * `stdio: 'inherit'`/`'ignore'` both behaved as `'pipe'`. This server shells
 * out to a CLI on its main paths, so those were reachable bugs rather than
 * theoretical ones: an argument containing shell metacharacters was re-split
 * and executed.
 *
 * SELECTION
 *   SSH_MCP_RUNTIME=auto   newest usable oam, else Node (default)
 *   SSH_MCP_RUNTIME=oam    newest usable oam, else exit with an error
 *                          (already running on oam at the floor satisfies it)
 *   SSH_MCP_RUNTIME=node   Node: in THIS process on Node, handed off to Node
 *                          on PATH when THIS process is oam
 *   OAM_BIN=/path/to/oam   use this oam when it is usable, before discovery
 * The value is case-insensitive; anything else behaves like `auto`.
 */

import { execFileSync, spawn } from "node:child_process";
import { existsSync, realpathSync } from "node:fs";
import { constants, homedir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";

/** Oldest oam whose `child_process` matches Node. See MINIMUM OAM VERSION above. */
const OAM_MIN = [0, 15, 2];

/**
 * Bound on each `oam --version` probe. A healthy oam answers in milliseconds;
 * the bound only exists so a wedged binary on PATH cannot hang the launch.
 */
const VERSION_PROBE_TIMEOUT_MS = 5_000;

// Two forms, deliberately. `import()` on Windows REJECTS a bare `C:\...` path
// with ERR_UNSUPPORTED_ESM_URL_SCHEME (it reads `c:` as a protocol), so the
// in-process fallback must use the file:// URL. spawn() needs a real path.
const SERVER_URL = new URL("../dist/index.js", import.meta.url);
const SERVER_ENTRY = fileURLToPath(SERVER_URL);
const isWin = process.platform === "win32";
const exe = isWin ? "oam.exe" : "oam";

/** Identity for de-duplicating paths: resolved, and case-folded on Windows. */
function pathKey(p) {
  let key = p;
  try {
    key = realpathSync(p);
  } catch {
    // Unresolvable: fall back to the literal path.
  }
  return isWin ? key.toLowerCase() : key;
}

/**
 * Every oam binary discovery can see, in search order, de-duplicated. Stat-only,
 * never a subprocess -- PATH is resolved manually rather than by spawning
 * `which`/`where`.
 *
 * Installed locations come BEFORE PATH, so when two binaries report the same
 * version the installed copy wins the tie. Someone who develops oam itself
 * usually has oam/target/release on PATH, and cargo replaces that binary
 * underneath running processes; the installed copy is the release the user
 * actually installed. Both forms are checked on Windows: the installer defaults
 * to %LOCALAPPDATA%\oam\bin there, but oam's docs name ~/.oam/bin first and
 * OAM_INSTALL_DIR can pick either.
 *
 * Windows: `.exe` ONLY -- deliberately narrower than PATHEXT. Node refuses to
 * run a .cmd/.bat through execFile/spawn without `shell: true` (EINVAL, and for
 * spawn it throws SYNCHRONOUSLY rather than emitting 'error'), so walking the
 * full PATHEXT list would hand back a path this launcher cannot execute. A
 * skipped shim is still named on stderr when no usable oam is found -- see
 * findOamShim.
 */
function discoverOamPaths() {
  const installed = [join(homedir(), ".oam", "bin", exe)];
  if (isWin) {
    installed.unshift(join(process.env.LOCALAPPDATA ?? join(homedir(), "AppData", "Local"), "oam", "bin", exe));
  }
  const onPath = (process.env.PATH ?? "")
    .split(delimiter)
    .filter(Boolean)
    .map((dir) => join(dir, exe));
  const seen = new Set();
  const found = [];
  for (const candidate of [...installed, ...onPath]) {
    if (!existsSync(candidate)) continue;
    const key = pathKey(candidate);
    if (seen.has(key)) continue;
    seen.add(key);
    found.push(candidate);
  }
  return found;
}

/**
 * Write a diagnostic to stderr synchronously, so a following process.exit
 * cannot truncate it.
 *
 * Not a bare writeSync: that call can short-write (it returns a byte count) and
 * on macOS it can throw EAGAIN, because Node makes a piped stderr non-blocking
 * there rather than blocking the write. Loop over the remaining bytes, and if
 * stderr turns out to be unusable give up quietly -- failing to print a
 * diagnostic is not worth crashing a stdio server over.
 */
async function errSync(message) {
  const { writeSync } = await import("node:fs");
  const buf = Buffer.from(message);
  let off = 0;
  for (let attempts = 0; off < buf.length && attempts < 1000; attempts++) {
    try {
      off += writeSync(2, buf, off, buf.length - off);
    } catch (err) {
      if (err?.code !== "EAGAIN") return;
      // Pipe is full and the reader has not drained yet -- retry.
    }
  }
}

/**
 * Version text -> [major, minor, patch], or null when it holds no version.
 * A pre-release suffix (0.9.0-rc.1) truncates to its base version.
 *
 * Shared by the two places a version is read -- a discovered binary's
 * `oam --version` output ("oam 0.15.1") and the host's own
 * `process.versions.oam` ("0.15.1") -- so they cannot disagree about what a
 * version string means, or which floor it has to clear.
 */
function parseVersion(text) {
  const m = /(\d+)\.(\d+)\.(\d+)/.exec(text);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

/** `oam --version` -> [major, minor, patch], or null when it cannot be read. */
function oamVersion(cmd) {
  try {
    const out = execFileSync(cmd, ["--version"], {
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: VERSION_PROBE_TIMEOUT_MS,
      windowsHide: true,
    });
    return parseVersion(out);
  } catch {
    // Not executable, wrong arch, wedged, or deleted since the stat. Caller degrades.
    return null;
  }
}

/** True when `v` is at least `min`, comparing major/minor/patch in order. */
function atLeast(v, min) {
  if (!v) return false;
  for (let i = 0; i < min.length; i++) {
    if (v[i] > min[i]) return true;
    if (v[i] < min[i]) return false;
  }
  return true;
}

/**
 * The newest candidate at or above the floor, or null. `candidates` is
 * `{ path, version }[]` in search order, `version` null when unreadable.
 * Strictly-greater replaces, so a tie keeps the earlier candidate.
 *
 * Pure on purpose, like runtimePlan: the choice is testable without binaries.
 */
function pickNewest(candidates) {
  let best = null;
  for (const candidate of candidates) {
    if (!atLeast(candidate.version, OAM_MIN)) continue;
    if (!best || !atLeast(best.version, candidate.version)) best = candidate;
  }
  return best;
}

/**
 * Where the server runs, decided BEFORE any discovery:
 *   "in-process"   import it into THIS process
 *   "discover"     choose an oam and spawn it, or fall back to Node
 *   "handoff-node" hand it off to Node on PATH: THIS process is an oam, and
 *                  Node was asked for
 *
 * `hostOam` is `process.versions.oam`: oam's own key, absent on Node. An oam
 * host whose version cannot be read is treated as below the floor -- it never
 * proved it is a supported oam -- and a host below the floor takes the
 * discovery path, whose every outcome on an oam host is a spawn or an error
 * exit, never an in-process serve. The floor is OAM_MIN itself, not a parameter, so a host oam
 * and a discovered one can never be held to different minimums. There is no
 * sandbox input because this launcher has no sandbox; see ALREADY RUNNING ON
 * OAM above for why nothing else forces a spawn.
 *
 * Pure on purpose: every input is passed in, so the whole decision is testable
 * without booting a runtime.
 */
function runtimePlan({ mode, hostOam }) {
  const onOam = hostOam !== undefined;
  if (mode === "node") return onOam ? "handoff-node" : "in-process";
  return atLeast(parseVersion(hostOam ?? ""), OAM_MIN) ? "in-process" : "discover";
}

/**
 * An oam-named .cmd/.bat on PATH: a real install in a shape this launcher
 * cannot spawn. Looked up only when no usable oam was found, and then reported
 * rather than ignored, because "no oam binary was found" reads as "install oam"
 * -- the one thing that will not help. An npm-style install puts `oam.cmd` on
 * PATH, and staying silent about it sends someone to reinstall an oam they
 * already have. With a usable oam.exe chosen, the shim goes unmentioned: nothing
 * degraded. Windows only; there is no such shim concept on POSIX.
 */
function findOamShim() {
  if (!isWin) return null;
  for (const dir of (process.env.PATH ?? "").split(delimiter)) {
    if (!dir) continue;
    for (const ext of [".cmd", ".bat"]) {
      const candidate = join(dir, `oam${ext}`);
      if (existsSync(candidate)) return candidate;
    }
  }
  return null;
}

/** A Node binary on PATH, or null. Stat-only; used only when THIS process is oam. */
function findNodeOnPath() {
  const name = isWin ? "node.exe" : "node";
  for (const dir of (process.env.PATH ?? "").split(delimiter)) {
    if (!dir) continue;
    const candidate = join(dir, name);
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

/**
 * Why a candidate was passed over, for stderr.
 *
 * Two different causes, and they need different remedies. A null `version` is
 * NOT "old": oamVersion returns null when the binary could not be run at all
 * (not executable, wrong arch, wedged, deleted between the stat and the probe)
 * or when its --version output did not parse. Telling that user to
 * `oam self-update` sends them after the one cause it definitely is not, so the
 * wording splits here, and so does the remedy in `remedyFor`.
 */
function unusableReason(path, version, label = path) {
  const min = OAM_MIN.join(".");
  return version
    ? `${label} is oam ${version.join(".")}, older than ${min}`
    : `${label} could not be run, or did not report a version this launcher understands`;
}

/**
 * Choose the oam to spawn: a usable OAM_BIN, else the newest usable discovered
 * binary. Returns the choice (or null) plus what stderr needs:
 *   overrideNote  why OAM_BIN was passed over, or null
 *   skipped       why each discovered binary was passed over, when none was chosen
 *   passedOver    the `version` of every existing binary rejected (OAM_BIN
 *                 included), so a hard failure can name the right remedy
 *   overrideMissing  OAM_BIN was set to a path that does not exist
 */
function chooseOam() {
  const override = process.env.OAM_BIN;
  let overrideNote = null;
  let overrideMissing = false;
  const passedOver = [];
  if (override) {
    if (!existsSync(override)) {
      overrideNote = `OAM_BIN=${override} does not exist`;
      overrideMissing = true;
    } else {
      const version = oamVersion(override);
      if (atLeast(version, OAM_MIN)) {
        return { chosen: { path: override, version }, overrideNote, skipped: [], passedOver, overrideMissing };
      }
      overrideNote = unusableReason(override, version, `OAM_BIN=${override}`);
      passedOver.push(version);
    }
  }
  const overrideKey = override ? pathKey(override) : null;
  const candidates = discoverOamPaths()
    .filter((path) => pathKey(path) !== overrideKey)
    .map((path) => ({ path, version: oamVersion(path) }));
  const chosen = pickNewest(candidates);
  const skipped = chosen ? [] : candidates.map((c) => unusableReason(c.path, c.version));
  if (!chosen) passedOver.push(...candidates.map((c) => c.version));
  return { chosen, overrideNote, skipped, passedOver, overrideMissing };
}

/** What would fix "no usable oam", one line per cause that was actually seen. */
function remedyFor({ passedOver, overrideMissing, shim }) {
  const lines = [];
  if (passedOver.some((v) => v !== null)) {
    lines.push(`Run \`oam self-update\` to get oam ${OAM_MIN.join(".")} or newer.\n`);
  }
  if (passedOver.some((v) => v === null)) {
    lines.push("Check that it is an executable oam binary for this platform.\n");
  }
  if (overrideMissing) lines.push("Point OAM_BIN at an existing oam binary, or unset it.\n");
  if (lines.length === 0 && !shim) lines.push("Install oam from https://oamjs.org, or set OAM_BIN=/path/to/oam.\n");
  lines.push("Or use SSH_MCP_RUNTIME=node to run on Node.\n");
  return lines.join("");
}

/** Run the server in THIS process. The zero-overhead fallback. */
async function runInProcess() {
  // A server may gate its bootstrap on being the process ENTRY POINT --
  // `import.meta.url === pathToFileURL(process.argv[1]).href` -- so that its own
  // test file can import the module for unit tests without connecting a stdio
  // transport. aws-mcp does exactly this. Importing the server here would leave
  // argv[1] pointing at THIS launcher, the guard would read false, and the
  // server would load but never serve: the MCP handshake just hangs.
  //
  // Point argv[1] at the server first, so the in-process path is
  // indistinguishable from having executed the file directly. The spawn path
  // needs no equivalent -- there argv[1] is already the server.
  process.argv[1] = SERVER_ENTRY;
  await import(SERVER_URL.href);
}

// ONE reporter for every failed in-process fallback, so the sync-throw path and
// the 'error'-event path in launchChild cannot drift apart. runInProcess() is a
// bare import() that rejects when dist/index.js is missing or throws at load,
// and at ESM top level an unhandled rejection is an uncaught exception -- it
// kills the process and replaces this launcher's diagnostic with a raw stack
// trace, which is the exact failure this handling exists to prevent.
const fallbackFailed = (e) => {
  process.stderr.write(`ssh-mcp: fallback to Node failed (${e?.message ?? e})\n`);
  process.exitCode = 1;
};

/**
 * Spawn the server in a child runtime and mirror its lifetime.
 *
 * `onLaunchFailed(err)` runs when the child could not be started at all; it is
 * never called once the child is running, which would double-start the server
 * on the same stdio. Every "could not be executed" outcome lands there: the
 * synchronous throw from spawn() and the async 'error' event mean the same
 * thing and must degrade the same way.
 */
async function launchChild(cmd, args, onLaunchFailed) {
  // THIS process being an oam means one below the floor (a supported oam host
  // serves in-process) or any oam under SSH_MCP_RUNTIME=node, and an old oam's
  // `stdio: 'inherit'` does not hand over the fds. Pipe explicitly from every
  // oam host; see ALREADY RUNNING ON OAM.
  const piped = process.versions.oam !== undefined;
  let child = null;
  try {
    child = spawn(cmd, args, {
      // inherit keeps the SAME fds, so MCP's newline-delimited JSON framing on
      // stdin/stdout is untouched and the host's stdin-close still reaches the
      // server's shutdown path. Piping preserves both as well: bytes are copied
      // unchanged, and stdin's end propagates to the child.
      stdio: piped ? ["pipe", "pipe", "pipe"] : "inherit",
      env: process.env,
      windowsHide: true,
    });
  } catch (err) {
    // spawn() THROWS for some failures instead of emitting 'error', and the
    // 'error' listener is registered AFTER this call, so it can never observe
    // one -- an uncaught throw here kills the launcher with a raw stack trace
    // instead of falling back.
    //
    // Belt-and-braces, deliberately: an oam reaching this line already answered
    // a version probe, so the shapes that throw synchronously (a .cmd/.bat Node
    // refuses with EINVAL) were diverted by the version gate -- and a Node
    // handoff only ever names node.exe, never a shim. A deleted binary (ENOENT)
    // or a permission failure (EACCES) is routed to the async 'error' event
    // instead. What is left is a genuine TOCTOU: the binary
    // replaced between the probe and the spawn. Cheap to keep, and the
    // alternative is a stack trace in a stdio server.
    await onLaunchFailed(err).catch(fallbackFailed);
    return;
  }

  // If the runtime cannot be executed at all (deleted between the version probe
  // and the spawn, wrong arch, permission), fall back rather than failing the
  // whole server. `spawned` prevents falling back AFTER the child started.
  //
  // Everything that assumes a live child waits for 'spawn'. A failed spawn
  // still emits 'close' (after 'error', with the negative errno as its code), so
  // an unguarded close handler would process.exit() out from under the fallback
  // onLaunchFailed has just started. Piping and signal forwarding wait as well,
  // so a child that never ran is never handed the host's stdin or its signals:
  // nothing in this file reads process.stdin before 'spawn'.
  let spawned = false;
  child.on("spawn", () => {
    spawned = true;
    if (piped) {
      process.stdin.pipe(child.stdin);
      child.stdout.pipe(process.stdout);
      child.stderr.pipe(process.stderr);
    }
    forwardSignals();
  });
  child.on("error", (err) => {
    if (spawned) return;
    // Handle the rejection instead of discarding the promise: a failing
    // fallback used to escape as an unhandled rejection, replacing this
    // launcher's diagnostic with a raw stack trace.
    onLaunchFailed(err).catch(fallbackFailed);
  });
  // A child that exits before reading everything closes its stdin; the
  // resulting EPIPE is not worth crashing over.
  child.stdin?.on("error", () => {});

  // Forward termination so the server's own shutdown path runs in the child
  // rather than the child being orphaned.
  //
  // Registering ANY handler for these suppresses Node's default
  // terminate-on-signal, so the parent's exit has to be arranged explicitly.
  // `child.killed` only records that kill() was CALLED, never that the child
  // is gone, so gating on it swallows every signal after the first and wedges
  // the launcher with no escape hatch.
  //
  // Escalation is driven by a TIMER, not by counting signals, and not by
  // comparing timestamps. Counting is ambiguous: a supervisor routinely sends
  // SIGINT then SIGTERM milliseconds apart, and a terminal Ctrl-C reaches the
  // whole process group, so the child usually gets its own copy alongside ours
  // -- reading "a second signal" as impatience hard-kills a child that is
  // already shutting down cleanly. A timer makes the count irrelevant: ONE
  // press is enough, and a wedged child dies on schedule without the user
  // having to guess how many times to press. It also sidesteps the wall clock
  // -- setTimeout is monotonic, so a clock step cannot mis-gate the window in
  // either direction.
  //
  // POSIX vs Windows, and why we do not forward on Windows.
  // On POSIX child.kill(sig) delivers a real, catchable signal, so forwarding
  // is what lets the child run its shutdown. On Windows there are no POSIX
  // signals: child.kill IGNORES the name and calls TerminateProcess -- an
  // immediate hard kill (verified: a child with a SIGTERM handler never runs it
  // and dies with code=null). Forwarding there would ABORT the graceful
  // shutdown the console's own Ctrl-C just started, skipping the child's
  // process.on("exit") backstop -- which is what reaps an ssh-agent this server
  // spawned (killStartedAgent, src/env.ts) -- and leak the daemon. The console
  // has already notified the child, so on Windows the timer below is the only
  // kill we issue.
  //
  // The window comfortably exceeds the child's own shutdown budget
  // (server.close -> pool.drain -> killStartedAgent -> ~100ms FIN grace).
  const ESCALATE_AFTER_MS = 2000;
  let escalation = null;
  function forwardSignals() {
    for (const sig of ["SIGINT", "SIGTERM"]) {
      process.on(sig, () => {
        // No try/catch: kill() on an already-exited child returns false, it does
        // not throw. It throws only for a signal the platform does not know,
        // which SIGINT/SIGTERM/SIGKILL never are.
        if (!isWin) child.kill(sig);
        if (escalation) return; // already counting down; further signals are noise
        escalation = setTimeout(() => {
          // Still here after its grace window. Stop waiting on it.
          child.kill("SIGKILL");
          process.exit(128 + (constants.signals[sig] ?? 15));
        }, ESCALATE_AFTER_MS);
      });
    }
  }

  // Piped: wait for 'close', so the child's last stdout bytes are copied out
  // before this process exits. Inherited: 'exit' is enough, the fds were never
  // ours to drain. Either way, only for a child that actually ran -- see the
  // 'spawn' handler above.
  child.on(piped ? "close" : "exit", (code, signal) => {
    if (!spawned) return;
    if (escalation) clearTimeout(escalation);
    // Mirror the child's fate: a signal death becomes 128+n so callers see a
    // conventional shell exit status rather than a bare 0.
    if (signal) {
      process.exit(128 + (constants.signals[signal] ?? 15));
    }
    process.exit(code ?? 0);
  });
}

/**
 * Hand the server to Node on PATH. Only reachable when THIS process is oam --
 * one below the floor, or any oam under SSH_MCP_RUNTIME=node -- so there is no
 * in-process option left.
 */
async function handOffToNode(reason) {
  const node = findNodeOnPath();
  if (!node) {
    // Two ways here, two remedies: an oam below the floor is fixed by updating
    // it, while SSH_MCP_RUNTIME=node on a supported oam asked for Node outright.
    const remedy = reason
      ? `Run \`oam self-update\` to get oam ${OAM_MIN.join(".")} or newer, or launch this command with node.\n`
      : "Put Node on PATH, or unset SSH_MCP_RUNTIME to serve on this oam.\n";
    await errSync(
      `ssh-mcp: ${reason || `SSH_MCP_RUNTIME=node on oam ${process.versions.oam}`}, and no Node was found on PATH to run the server instead.\n${remedy}`,
    );
    process.exit(1);
  }
  if (reason) await errSync(`ssh-mcp: ${reason}; running on ${node} instead.\n`);
  await launchChild(node, [SERVER_ENTRY, ...process.argv.slice(2)], async (err) => {
    await errSync(`ssh-mcp: failed to launch Node at ${node} (${err?.message ?? err})\n`);
    process.exit(1);
  });
}

/**
 * No usable oam, or the chosen one would not start, under a mode that allows
 * Node. `why` finishes the handoff note on an oam host, so a failed spawn --
 * already named on stderr -- is not then reported as nothing being found.
 */
async function fallBackToNode(hostOam, why) {
  if (hostOam === undefined) {
    await runInProcess();
    return;
  }
  await handOffToNode(`this process is oam ${hostOam}, older than ${OAM_MIN.join(".")}, and ${why}`);
}

const mode = (process.env.SSH_MCP_RUNTIME ?? "auto").toLowerCase();
const hostOam = process.versions.oam;
const plan = runtimePlan({ mode, hostOam });

if (plan === "in-process") {
  await runInProcess();
} else if (plan === "handoff-node") {
  const belowFloor = !atLeast(parseVersion(hostOam), OAM_MIN);
  await handOffToNode(belowFloor ? `this process is oam ${hostOam}, older than ${OAM_MIN.join(".")}` : "");
} else {
  const { chosen, overrideNote, skipped, passedOver, overrideMissing } = chooseOam();

  if (chosen) {
    if (overrideNote)
      await errSync(`ssh-mcp: ${overrideNote}; using ${chosen.path} (oam ${chosen.version.join(".")}).\n`);
    // `--` separates oam's own flags from the script's argv, so `ssh-mcp
    // --version` and any host-supplied flags survive the hop unchanged.
    await launchChild(chosen.path, ["run", SERVER_ENTRY, "--", ...process.argv.slice(2)], async (err) => {
      if (mode === "oam") {
        await errSync(`ssh-mcp: failed to launch oam at ${chosen.path} (${err?.message ?? err})\n`);
        process.exit(1);
      }
      await errSync(`ssh-mcp: failed to launch oam at ${chosen.path} (${err?.message ?? err}); using Node instead.\n`);
      await fallBackToNode(hostOam, "the newer oam would not start");
    });
  } else {
    const shim = findOamShim();
    const notes = [
      ...(overrideNote ? [overrideNote] : []),
      ...skipped,
      ...(shim
        ? [
            `found ${shim}, but Node cannot execute a .cmd/.bat directly -- install the native oam binary, or point OAM_BIN at one`,
          ]
        : []),
    ];
    if (mode === "oam") {
      // Explicitly demanded, so this is a real misconfiguration.
      await errSync(
        `ssh-mcp: SSH_MCP_RUNTIME=oam but no usable oam (${OAM_MIN.join(".")} or newer) was found.\n` +
          notes.map((note) => `  ${note}\n`).join("") +
          remedyFor({ passedOver, overrideMissing, shim }),
      );
      process.exit(1);
    }
    // auto: falling back is correct, but silence is how someone never learns
    // their OAM_BIN is wrong, their oam is too old to use, or their install is a
    // shape this launcher skips. Only worth saying when something was skipped.
    //
    // errSync, not process.stderr.write: an exit DOES follow, just indirectly.
    // runInProcess() imports dist/index.js, whose top level answers `--version`
    // with console.log + process.exit(0) (src/index.ts) -- and that exit
    // truncates a pending async stderr write on Windows TTYs and pipes.
    if (notes.length > 0) await errSync(`ssh-mcp: ${notes.join("; ")}; using Node instead.\n`);
    await fallBackToNode(hostOam, "no newer oam was found").catch(fallbackFailed);
  }
}
