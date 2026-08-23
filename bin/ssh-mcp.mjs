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

/** Locate an oam binary, or null. Every branch is a stat, never a subprocess. */
function findOam() {
  // 1. Explicit override wins and is never second-guessed.
  const override = process.env.OAM_BIN;
  if (override) return existsSync(override) ? override : null;

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
    if (existsSync(candidate)) return candidate;
  }

  // 3. PATH, resolved manually rather than by spawning `which`/`where`, which
  //    would cost a subprocess on every launch just to decide whether to spawn.
  //
  //    Windows: `.exe` ONLY -- deliberately narrower than PATHEXT. Node refuses
  //    to run a `.cmd`/`.bat` through execFile/spawn without `shell: true` (it
  //    throws EINVAL, and for spawn it throws SYNCHRONOUSLY rather than emitting
  //    'error'), so walking the full PATHEXT list would hand back a path this
  //    launcher cannot execute -- discovery has to agree with execution. `exe`
  //    is also what the installed-location checks above look for, so the two
  //    discovery paths now accept exactly the same shapes.
  for (const dir of (process.env.PATH ?? "").split(delimiter)) {
    if (!dir) continue;
    const candidate = join(dir, exe);
    if (existsSync(candidate)) return candidate;
  }

  return null;
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
  const oam = findOam();
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
    if (mode === "oam") {
      // Explicitly demanded, so this is a real misconfiguration. writeSync
      // because stderr is async for TTYs/pipes on Windows and process.exit
      // truncates pending writes.
      const { writeSync } = await import("node:fs");
      writeSync(
        2,
        "ssh-mcp: SSH_MCP_RUNTIME=oam but no oam binary was found.\n" +
          "Install from https://oamjs.org, set OAM_BIN=/path/to/oam, or use SSH_MCP_RUNTIME=node.\n",
      );
      process.exit(1);
    }
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
      const { writeSync } = await import("node:fs");
      writeSync(2, `ssh-mcp: SSH_MCP_RUNTIME=oam but ${detail}.\n${remedy}`);
      process.exit(1);
    }
    // auto: neither cause is worth failing over -- prefer Node. Say so, because
    // a silent downgrade is how someone keeps running an oam they meant to
    // update, or never learns their oam is unexecutable. stdout carries the MCP
    // frames, so stderr is the only safe channel.
    //
    // writeSync, not process.stderr.write: an exit DOES follow, just indirectly.
    // runInProcess() imports dist/index.js, whose top level answers `--version`
    // with console.log + process.exit(0) (src/index.ts) -- and that exit
    // truncates a pending async stderr write on Windows TTYs and pipes.
    const { writeSync } = await import("node:fs");
    writeSync(2, `ssh-mcp: ${detail}; using Node instead.\n`);
    await runInProcess();
  } else {
    // Every "oam could not be executed" outcome lands here: the synchronous
    // throw from spawn() and the async 'error' event both mean the same thing
    // and must degrade the same way, so the handling lives in one place.
    // writeSync rather than process.stderr.write because stderr is async for
    // TTYs and pipes on Windows and the process.exit below truncates pending
    // writes -- the same reason the two branches above use it.
    const launchFailed = async (err) => {
      if (mode === "oam") {
        const { writeSync } = await import("node:fs");
        writeSync(2, `ssh-mcp: failed to launch oam (${err?.message ?? err})\n`);
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
      // spawn() THROWS for some unexecutable targets instead of emitting
      // 'error' -- notably a .cmd/.bat on Windows, which Node rejects with a
      // synchronous EINVAL. The 'error' listener is registered AFTER this call
      // and so can never observe it; without this catch the launcher dies with
      // a raw stack trace instead of falling back to Node. findOam no longer
      // returns those shapes, but OAM_BIN can still point straight at one.
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
      // that the child is gone, so gating on it swallowed every signal after
      // the first and wedged the launcher with no escape hatch. Forward once,
      // then let a repeat signal escalate and take the parent down with it --
      // double-Ctrl-C is the conventional way out and has to actually work.
      let forwarded = false;
      for (const sig of ["SIGINT", "SIGTERM"]) {
        process.on(sig, () => {
          const status = 128 + (constants.signals[sig] ?? 15);
          if (forwarded) {
            try {
              child.kill("SIGKILL");
            } catch {
              // already gone
            }
            process.exit(status);
          }
          forwarded = true;
          try {
            child.kill(sig);
          } catch {
            // already gone -- the exit handler below settles the status
          }
        });
      }

      child.on("exit", (code, signal) => {
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
