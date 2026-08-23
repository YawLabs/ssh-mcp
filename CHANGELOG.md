# Changelog

All notable changes to `@yawlabs/ssh-mcp` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Note:** this file starts at the entry below. Releases before it were shipped
> without changelog entries -- see the
> [tag list](https://github.com/YawLabs/ssh-mcp/tags) and the GitHub release notes
> for those versions. `release.sh` sources its release body from the matching
> `## [x.y.z]` heading here, so an absent entry silently falls back to raw
> commit subjects.

## [Unreleased]

### Fixed
- Launcher no longer dies with a raw stack trace when `spawn` fails synchronously. Node throws (rather than emitting `error`) for some unexecutable targets — notably a `.cmd`/`.bat` on Windows, which it rejects with `EINVAL` unless `shell: true` — and the `error` listener is registered *after* the `spawn` call, so it could never observe that throw. The documented fall-back-to-Node contract was broken in exactly the case it exists for. Both failure modes now route through one handler.
- Windows runtime discovery scans `PATH` for `oam.exe` only, instead of walking every `PATHEXT` entry. The installed-location checks already looked for `oam.exe` alone, so the two discovery paths disagreed: `PATH` could hand back an `oam.cmd` this launcher cannot execute, which then surfaced as a misleading "older than 0.9.0 — run `oam self-update`" error. Discovery and execution now accept the same shapes, and a real `oam.exe` further along `PATH` is found instead of being shadowed by a shim.
- A second `SIGINT`/`SIGTERM` now escalates to `SIGKILL` and exits `128+n`. Registering a handler suppresses Node's default terminate-on-signal, and `child.killed` records only that `kill()` was *called* — never that the child is gone — so gating on it swallowed every signal after the first and left the launcher wedged with no escape hatch. Double-Ctrl-C works again.
- The launch-failure message is written with `writeSync` rather than `process.stderr.write`, matching the two sibling branches. On Windows stderr is async for TTYs and pipes, so the immediately-following `process.exit(1)` could truncate it.
- The child `error` handler no longer discards its promise with `void`. A failing in-process fallback surfaced as an unhandled rejection — replacing the launcher's own diagnostic with a raw stack trace — and now reports and sets a non-zero exit code. Both `launchFailed` call sites share one reporter so the synchronous and event-driven paths cannot drift.
- An oam binary that cannot be run is no longer reported as an old one. `oamVersion` returns `null` for several distinct causes — not executable, wrong architecture, a shim Node refuses, deleted since the stat, or a `--version` format this launcher does not parse — and every one of them produced "is older than oam 0.9.0. Run `oam self-update`", pointing the user at the single cause it definitely was not. The two cases now carry separate wording and separate remedies, and the too-old message reports the version actually detected.
- Removed a literal backspace byte (`U+0008`) from the runtime-discovery comment in `bin/ssh-mcp.mjs`, present since 0.13.0 and therefore in the published package. The Windows installer path was written as `%LOCALAPPDATA%\oam\bin` and round-tripped through escape processing, which dropped the first backslash and turned `\b` into a real control character — rendering the line as `%LOCALAPPDATA%oamin` and making git treat the file as binary, so its diff could not be reviewed. Lint, `tsc` and the tests passed either way.

### Changed
- `scripts/build-binary.mjs`: dropped the stale comment claiming the bundle entry is derived from `bin` "regardless of the server's entry filename". It contradicted the pinned `srcEntry` constant directly below it, and this script is copy-pasted across the `@yawlabs/*` servers, so the contradiction travelled with it.

## [0.13.0] — 2026-08-07

### Added
- Runtime launcher at `bin/ssh-mcp.mjs`: the published `ssh-mcp` command now prefers the [oam](https://oamjs.org) runtime and falls back to Node. `SSH_MCP_RUNTIME` selects (`auto` / `oam` / `node`) and `OAM_BIN` overrides discovery. Both paths verified against the MCP surface — handshake plus all 21 tools — and behave identically. The fallback does **not** re-exec Node: npm has already started Node to run the launcher, so it is an in-process `import()` with no extra spawn.

### Changed
- Runtime discovery prefers an **installed** oam (`~/.oam/bin`, `%LOCALAPPDATA%\oam\bin`) over one found on `PATH`. Anyone developing oam itself has `oam/target/release` on PATH, and a build directory is the wrong thing for a user-facing launcher to bind to — cargo replaces the binary underneath running processes. `OAM_BIN` still wins outright and remains the way to point deliberately at a dev build.
- `.gitignore` excludes `bin/*` rather than `bin/`, so the launcher can be re-included with a negation. A negation cannot undo a directory-level exclusion — that trap shipped a broken `bin` in postgres-mcp, where the launcher was untracked and absent from every fresh clone.
- `scripts/build-binary.mjs` pins the CLI source entry instead of deriving it from `bin`'s value, which would have resolved to `bin/ssh-mcp.ts` once `bin` moved to the launcher — the breakage postgres-mcp shipped in its 0.9.0.

### Fixed
- The in-process fallback sets `process.argv[1]` to the server before importing. A server may gate its bootstrap on being the process entry point so its own tests can import the module without opening a transport; without this the MCP handshake loads the module and then hangs forever. Found in aws-mcp, fixed across every server carrying this launcher.

## [0.12.0] — earlier

Released before this changelog existed.
