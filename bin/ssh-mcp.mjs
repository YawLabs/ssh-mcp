#!/usr/bin/env node
/**
 * Runtime launcher for @yawlabs/ssh-mcp.
 *
 * Prefers the oam runtime (https://oamjs.org) and falls back to the Node
 * process already running this file.
 *
 *
 * WHY THE FALLBACK COSTS NOTHING
 * npm has already started Node to run this launcher, so falling back is a
 * plain `import()` of the server into THIS process: no extra spawn, no extra
 * startup, byte-identical to invoking dist/index.js directly. Discovery is
 * stat-only -- never a subprocess -- so the miss case stays sub-millisecond.
 *
 * WHAT THE OAM PATH COSTS
 * Reaching oam through an npm `bin` means Node boots first and oam boots
 * second, so the launcher is slower than either runtime alone. Measured on
 * npmjs-mcp (windows-arm64, n=12 medians, spawn to first MCP initialize):
 * oam 116ms, node 172ms, launcher 243ms. oam is the fastest runtime and the
 * launcher is the slowest path -- it exists for `npx` convenience.
 *
 * For an MCP host config, point straight at oam and skip this file:
 *   { "command": "oam", "args": ["run", "<abs>/dist/index.js"] }
 *
 * NO SANDBOX HERE -- DELIBERATELY
 * The purpose of this server is to open outbound SSH to hosts the caller names
 * at run time and run commands there, so the net and child-process grants would
 * both have to be unrestricted, and key material plus known_hosts need the
 * filesystem. Nothing meaningful is left to deny, so `--permission` is not
 * wired up here.
 *
 * MINIMUM OAM VERSION
 * 0.9.0. Below it `child_process.execFile` ran its arguments through a SHELL,
 * `exec` accepted `timeout` and ignored it, `spawnSync` truncated at
 * `maxBuffer` while reporting success, and `stdio: 'inherit'`/`'ignore'` both
 * behaved as `'pipe'`. This server shells out to a CLI on its
 * main paths, so those were reachable bugs rather than theoretical ones: an
 * argument containing shell metacharacters was re-split and executed.
 * An older oam is not an error: the launcher falls back to Node and says so on
 * stderr. Pinning the floor here is what makes that fallback automatic.
 *
 * SELECTION
 *   SSH_MCP_RUNTIME=oam    require oam; fail loudly if it is missing
 *   SSH_MCP_RUNTIME=node   never use oam
 *   SSH_MCP_RUNTIME=auto   prefer oam, silently fall back (default)
 *   OAM_BIN=/path/to/oam     explicit binary, checked before any discovery
 */

import { execFileSync, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { constants, homedir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";

/** Oldest oam whose `child_process` matches Node. See MINIMUM OAM VERSION above. */
const OAM_MIN = [0, 9, 0];

// Two forms, deliberately. `import()` on Windows REJECTS a bare `C:\...` path
// with ERR_UNSUPPORTED_ESM_URL_SCHEME (it reads `c:` as a protocol), so the
// in-process fallback must use the file:// URL. spawn() needs a real path.
const SERVER_URL = new URL("../dist/index.js", import.meta.url);
const SERVER_ENTRY = fileURLToPath(SERVER_URL);
const isWin = process.platform === "win32";
const exe = isWin ? "oam.exe" : "oam";

/**
 * Locate an oam binary. Returns `{ path, shim }`:
 *   path -- an oam this launcher can actually execute, or null
 *   shim -- an oam-named `.cmd`/`.bat` seen on PATH and SKIPPED, or null
 *
 * The shim is reported rather than silently dropped: "no oam binary was found"
 * is the wrong thing to tell someone who has one installed in a shape we cannot
 * spawn. Every branch is a stat, never a subprocess.
 */
function findOam() {
  // 1. Explicit override wins and is never second-guessed -- including a .cmd.
  //    If it cannot be executed the version gate reports that specifically,
  //    which is better than second-guessing an explicit instruction here.
  const override = process.env.OAM_BIN;
  if (override) return { path: existsSync(override) ? override : null, shim: null };

  // 2. Installed locations, BEFORE PATH. Someone who develops oam itself
  //    usually has oam/target/release on PATH, and a build directory is the
  //    wrong thing for a user-facing launcher to bind to: cargo replaces the
  //    binary underneath running processes, and the dev build is not the
  //    release the user installed. Preferring the installed copy makes the
  //    default path "what a normal user has", and OAM_BIN remains the way to
  //    point deliberately at a dev build.
  //
  //    Both forms are checked on Windows: the installer defaults to
  //    %LOCALAPPDATA%\oam\bin there, but oam's docs name ~/.oam/bin first and
  //    OAM_INSTALL_DIR can pick either, so checking one silently misses a real
  //    install.
  const installed = [join(homedir(), ".oam", "bin", exe)];
  if (isWin) {
    installed.unshift(join(process.env.LOCALAPPDATA ?? join(homedir(), "AppData", "Local"), "oam", "bin", exe));
  }
  for (const candidate of installed) {
    if (existsSync(candidate)) return { path: candidate, shim: null };
  }

  // 3. PATH, resolved manually rather than by spawning `which`/`where`, which
  //    would cost a subprocess on every launch just to decide whether to spawn.
  //
  //    Windows: only `.exe` is RETURNED -- deliberately narrower than PATHEXT.
  //    Node refuses to run a `.cmd`/`.bat` through execFile/spawn without
  //    `shell: true` (EINVAL, and for spawn it throws SYNCHRONOUSLY rather than
  //    emitting 'error'), so returning one would hand back a path this launcher
  //    cannot execute -- discovery has to agree with execution. `exe` is also
  //    what the installed-location checks above look for, so both discovery
  //    paths accept exactly the same shapes.
  //
  //    A shim is still NOTED, though. An npm-style install puts `oam.cmd` on
  //    PATH, and staying silent about it means auto mode degrades with no
  //    explanation and `SSH_MCP_RUNTIME=oam` claims nothing was found -- both
  //    of which send someone to reinstall an oam they already have.
  let shim = null;
  for (const dir of (process.env.PATH ?? "").split(delimiter)) {
    if (!dir) continue;
    const candidate = join(dir, exe);
    if (existsSync(candidate)) return { path: candidate, shim: null };
    if (isWin && shim === null) {
      for (const ext of [".cmd", ".bat"]) {
        const alt = join(dir, `oam${ext}`);
        if (existsSync(alt)) {
          shim = alt;
          break;
        }
      }
    }
  }

  return { path: null, shim };
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
 * `oam --version` -> [major, minor, patch], or null when it cannot be read.
 * A pre-release suffix (0.9.0-rc.1) truncates to its base version.
 */
function oamVersion(cmd) {
  try {
    const out = execFileSync(cmd, ["--version"], {
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    const m = /(\d+)\.(\d+)\.(\d+)/.exec(out);
    return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
  } catch {
    // Not executable, wrong arch, or deleted since the stat. Caller degrades.
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

const mode = (process.env.SSH_MCP_RUNTIME ?? "auto").toLowerCase();

if (mode === "node") {
  await runInProcess();
} else {
  const { path: oam, shim: oamShim } = findOam();
  // Read the version ONCE, and only when discovery found something: the gate
  // below has to tell "too old" apart from "could not be read at all", and
  // re-probing inside the branch would cost a second subprocess.
  //
  // Discovery itself stays stat-only; this is the first subprocess. It is paid
  // on every launch that finds an oam -- including the ones that go on to fall
  // back to Node -- not only the ones that end up spawning it. Measured 26ms
  // median (n=12, windows-arm64), once per MCP session.
  const found = oam ? oamVersion(oam) : null;

  if (!oam) {
    // An oam-named .cmd/.bat on PATH is a real install in a shape this launcher
    // cannot spawn. Naming it turns "no oam binary was found" -- which reads as
    // "install oam", the one thing that will not help -- into something the user
    // can act on.
    const shimNote = oamShim
      ? `Found ${oamShim}, but Node cannot execute a .cmd/.bat directly.\n` +
        "Install the native oam binary, or point OAM_BIN at one.\n"
      : "";
    if (mode === "oam") {
      // Explicitly demanded, so this is a real misconfiguration.
      await errSync(
        `ssh-mcp: SSH_MCP_RUNTIME=oam but no runnable oam binary was found.\n${shimNote}` +
          "Install from https://oamjs.org, set OAM_BIN=/path/to/oam, or use SSH_MCP_RUNTIME=node.\n",
      );
      process.exit(1);
    }
    // auto: falling back is correct, but silence is how someone never learns
    // their oam install is a shape this launcher skips. Only worth saying when
    // there was actually something to skip.
    if (oamShim) await errSync(`ssh-mcp: ${shimNote}Using Node instead.\n`);
    await runInProcess();
  } else if (!atLeast(found, OAM_MIN)) {
    const min = OAM_MIN.join(".");
    // Two different causes reach this branch and they need different remedies.
    // `found === null` is NOT "old": oamVersion returns null when the binary
    // could not be run at all (not executable, wrong arch, a .cmd/.bat Node
    // refuses, deleted between the stat and the probe) or when its --version
    // output did not parse. Telling that user to `oam self-update` sends them
    // after the one cause it definitely is not, so the wording splits here.
    const detail = found
      ? `${oam} is oam ${found.join(".")}, older than ${min}`
      : `${oam} could not be run, or did not report a version this launcher understands`;
    const remedy = found
      ? "Run `oam self-update`, or use SSH_MCP_RUNTIME=node.\n"
      : "Check that it is an executable oam binary for this platform, or use SSH_MCP_RUNTIME=node.\n";
    if (mode === "oam") {
      await errSync(`ssh-mcp: SSH_MCP_RUNTIME=oam but ${detail}.\n${remedy}`);
      process.exit(1);
    }
    // auto: neither cause is worth failing over -- prefer Node. Say so, because
    // a silent downgrade is how someone keeps running an oam they meant to
    // update, or never learns their oam is unexecutable. stdout carries the MCP
    // frames, so stderr is the only safe channel.
    //
    // errSync, not process.stderr.write: an exit DOES follow, just indirectly.
    // runInProcess() imports dist/index.js, whose top level answers `--version`
    // with console.log + process.exit(0) (src/index.ts) -- and that exit
    // truncates a pending async stderr write on Windows TTYs and pipes.
    await errSync(`ssh-mcp: ${detail}; using Node instead.\n`);
    await runInProcess();
  } else {
    // Every "oam could not be executed" outcome lands here: the synchronous
    // throw from spawn() and the async 'error' event both mean the same thing
    // and must degrade the same way, so the handling lives in one place.
    // errSync rather than process.stderr.write because stderr is async for
    // TTYs and pipes on Windows and the process.exit below truncates pending
    // writes -- the same reason the two branches above use it.
    const launchFailed = async (err) => {
      if (mode === "oam") {
        await errSync(`ssh-mcp: failed to launch oam (${err?.message ?? err})\n`);
        process.exit(1);
      }
      await runInProcess();
    };

    // ONE reporter shared by both launchFailed call sites below, so the
    // sync-throw path and the 'error'-event path cannot drift apart. Either can
    // reject: in auto mode launchFailed awaits runInProcess(), a bare import()
    // that rejects whenever dist/index.js is missing or throws at load. At ESM
    // top level an unhandled rejection is an uncaught exception -- it kills the
    // process and replaces this launcher's diagnostic with a raw stack trace,
    // which is the exact failure this handling exists to prevent.
    const fallbackFailed = (e) => {
      process.stderr.write(`ssh-mcp: fallback to Node failed (${e?.message ?? e})\n`);
      process.exitCode = 1;
    };

    // `--` separates oam's own flags from the script's argv, so `ssh-mcp
    // --version` and any host-supplied flags survive the hop unchanged.
    let child = null;
    try {
      child = spawn(oam, ["run", SERVER_ENTRY, "--", ...process.argv.slice(2)], {
        // inherit keeps the SAME fds, so MCP's newline-delimited JSON framing on
        // stdin/stdout is untouched and the host's stdin-close still reaches the
        // server's shutdown path.
        stdio: "inherit",
        env: process.env,
        windowsHide: true,
      });
    } catch (err) {
      // spawn() THROWS for some failures instead of emitting 'error', and the
      // 'error' listener is registered AFTER this call, so it can never observe
      // one -- an uncaught throw here kills the launcher with a raw stack trace
      // instead of falling back to Node.
      //
      // Belt-and-braces, deliberately: reaching this line already means
      // execFileSync ran this same binary and read a version from it, so the
      // shapes that throw synchronously (a .cmd/.bat Node refuses with EINVAL)
      // have been diverted by the version gate above, and the ones the comments
      // below name -- deleted (ENOENT), permission (EACCES) -- are among the
      // errnos Node routes to the async 'error' event instead. What is left is
      // a genuine TOCTOU: the binary replaced between the probe and the spawn.
      // Cheap to keep, and the alternative is a stack trace in a stdio server.
      await launchFailed(err).catch(fallbackFailed);
    }

    if (child) {
      // If oam cannot be executed at all (deleted between the stat and the spawn,
      // wrong arch, permission), fall back rather than failing the whole server.
      // `spawned` prevents falling back AFTER the child started, which would
      // double-start the server on the same stdio.
      let spawned = false;
      child.on("spawn", () => {
        spawned = true;
      });
      child.on("error", (err) => {
        if (spawned) return;
        // Handle the rejection instead of discarding the promise: a failing
        // runInProcess() used to escape as an unhandled rejection, replacing
        // this launcher's diagnostic with a raw stack trace.
        launchFailed(err).catch(fallbackFailed);
      });

      // Forward termination so the server's own shutdown path runs in the child
      // rather than the child being orphaned.
      //
      // Registering ANY handler for these suppresses Node's default
      // terminate-on-signal, so the parent's exit has to be arranged
      // explicitly. `child.killed` only records that kill() was CALLED, never
      // that the child is gone, so gating on it swallows every signal after the
      // first and wedges the launcher with no escape hatch.
      //
      // Escalation is driven by a TIMER, not by counting signals, and not by
      // comparing timestamps. Counting is ambiguous: a supervisor routinely
      // sends SIGINT then SIGTERM milliseconds apart, and a terminal Ctrl-C
      // reaches the whole process group, so the child usually gets its own copy
      // alongside ours -- reading "a second signal" as impatience hard-kills a
      // child that is already shutting down cleanly. A timer makes the count
      // irrelevant: ONE press is enough, and a wedged child dies on schedule
      // without the user having to guess how many times to press. It also
      // sidesteps the wall clock -- setTimeout is monotonic, so a clock step
      // cannot mis-gate the window in either direction.
      //
      // POSIX vs Windows, and why we do not forward on Windows.
      // On POSIX child.kill(sig) delivers a real, catchable signal, so
      // forwarding is what lets the child run its shutdown. On Windows there
      // are no POSIX signals: child.kill IGNORES the name and calls
      // TerminateProcess -- an immediate hard kill (verified: a child with a
      // SIGTERM handler never runs it and dies with code=null). Forwarding
      // there would ABORT the graceful shutdown the console's own Ctrl-C just
      // started, skipping the child's process.on("exit") backstop -- which is
      // what reaps an ssh-agent this server spawned (killStartedAgent,
      // src/env.ts) -- and leak the daemon. The console has already notified
      // the child, so on Windows the timer below is the only kill we issue.
      //
      // The window comfortably exceeds the child's own shutdown budget
      // (server.close -> pool.drain -> killStartedAgent -> ~100ms FIN grace).
      const ESCALATE_AFTER_MS = 2000;
      let escalation = null;
      for (const sig of ["SIGINT", "SIGTERM"]) {
        process.on(sig, () => {
          // No try/catch: kill() on an already-exited child returns false, it
          // does not throw. It throws only for a signal the platform does not
          // know, which SIGINT/SIGTERM/SIGKILL never are.
          if (!isWin) child.kill(sig);
          if (escalation) return; // already counting down; further signals are noise
          escalation = setTimeout(() => {
            // Still here after its grace window. Stop waiting on it.
            child.kill("SIGKILL");
            process.exit(128 + (constants.signals[sig] ?? 15));
          }, ESCALATE_AFTER_MS);
        });
      }

      child.on("exit", (code, signal) => {
        if (escalation) clearTimeout(escalation);
        // Mirror the child's fate: a signal death becomes 128+n so callers see a
        // conventional shell exit status rather than a bare 0.
        if (signal) {
          process.exit(128 + (constants.signals[signal] ?? 15));
        }
        process.exit(code ?? 0);
      });
    }
  }
}
