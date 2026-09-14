# Changelog

All notable changes to `@yawlabs/ssh-mcp` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Note:** this file starts at 0.13.0. Releases before it were shipped without
> changelog entries -- see the
> [tag list](https://github.com/YawLabs/ssh-mcp/tags) and the GitHub release notes
> for those versions. `release.sh` gives every release a `## [x.y.z]` heading
> here -- promoting `[Unreleased]` when it has content, otherwise generating one
> from the commit subjects since the previous tag -- and sources the GitHub
> release notes from that section.

## [Unreleased]

### Added
- Library API: `acquire()` now rejects a full pool with a `PoolFullError` carrying `code: "ERR_SSH_MCP_POOL_FULL"` (`POOL_FULL_ERROR_CODE`, matched by `isPoolFullError()`), and `ConnectionPool.waitForCapacity(timeoutMs, signal?)` parks a caller until a slot may be free, resolving `true` on a wake and `false` on timeout or when `signal` aborts. `acquire()` and `withConnection()` still fail fast by default; pass `{ waitForCapacityMs }` (`AcquireOptions`) and they park on that primitive and retry on every capacity signal until a slot is won or the budget is spent, then reject with a `PoolFullError` whose message says `no slot became available to this call within <n>ms`. `ConnectionPool.maxSize` (read-only) exposes the cap; `multiExec()` runs at most that many hosts at once, and runs unbounded against a pool-like that lacks it. The rejection message's parenthetical changed — `N connections in use or dialing, the SSH_MCP_MAX_POOL_SIZE cap`, was `N active connections` — so match on `code` / `isPoolFullError()`, not the text. Every pool-backed tool uses the wait, as described below.

### Fixed
- **The connection pool no longer opens more connections than its cap under concurrent load.** Connections still being dialed did not count toward `SSH_MCP_MAX_POOL_SIZE` (`maxPoolSize` in the library), so simultaneous calls to distinct hosts could all pass the check: with a cap of 1, three simultaneous acquires opened three connections. In-flight dials now count. Concurrent calls to the same host still share one dial, and a failed dial frees its slot at once. When the cap is reached the pool still closes an idle connection to make room; only when every slot is in use or dialing is a caller refused — at once for a bare library `acquire()`, after a wait for the tools (below).
- **`ssh_multi_exec` respects the pool cap instead of dialing every host at once.** It fired every host in parallel, which the unenforced cap let through. It now runs at most `SSH_MCP_MAX_POOL_SIZE` hosts at a time (default 100) and works through a longer list as slots free up, with results still in input order. `timeout` is per host, so a call over N hosts takes up to about ceil(N / cap) x (`timeout` + connect time) with the pool to itself.
- **A full pool is waited out instead of failing the call.** The pool is shared by every tool, so a slot held elsewhere — a long `ssh_exec`, a concurrent `ssh_multi_exec` — made the next call fail at once with `Connection pool is full`, every host of a fan-out included. Every single-host remote tool (`ssh_exec`, the SFTP tools, `ssh_find`, `ssh_tail`, `ssh_service_status`) now waits up to its `timeout` (30s for the SFTP tools, which have no `timeout` parameter) for a slot and is next in line for the first one that frees, so an `ssh_exec` arriving in the middle of a wide `ssh_multi_exec` runs between two of its hosts; it reports `Connection pool is full` only if it never won a slot in that time. `ssh_multi_exec` treats a full pool as backpressure: a host refused a slot waits and is retried, and the call gives up only when none of its own hosts holds a slot and a full `timeout` has passed with none of them starting or finishing — the hosts waiting at that point (up to one per parallel slot) and every host still queued then report `Connection pool is full`, the queued ones without being attempted. A fan-out that keeps moving never trips it, however long it runs. The message now names `SSH_MCP_MAX_POOL_SIZE` and, after a wait, says what to do (`no slot became available to this call within <n>ms. Retry once the calls holding the slots finish, or raise the cap (SSH_MCP_MAX_POOL_SIZE in the MCP server's environment).`), and the tool descriptions state the wait. Connect and command errors are still reported at once.

### Security
- **`@modelcontextprotocol/sdk` is now `^1.30.0` (was `^1.29.0`), and `npm audit` is clean.** The SDK is a runtime dependency, so the new floor reaches every install of this package, not just this repo's toolchain. The lockfile moves the SDK's transitive packages past their advisories: `fast-uri` 3.1.2 -> 3.1.7, `ip-address` 10.2.0 -> 10.7.0, `qs` 6.15.2 -> 6.16.0, `hono` 4.12.25 -> 4.13.7 and `@hono/node-server` 1.19.14 -> 2.1.1. None of them is bundled into the published `dist/` — the SDK stays external, so a consumer's copies come from their own install — and `fast-uri` (via `ajv`) is the only one the stdio server loads; a fresh install already resolves 3.1.7, while an existing lockfile that pinned 3.1.2, inside the advised range, needs `npm update`.

## [0.16.1] — 2026-09-14

### Changed
- npm and MCP Registry listing metadata: bugs URL, core keywords, and server.json title/repository/websiteUrl
- `release.sh` writes a `## [x.y.z]` changelog entry for every release — promoting `[Unreleased]` when it has content, otherwise generating one from the commit subjects since the previous tag — moves the Keep-a-Changelog link references along when a file has them, and takes the GitHub release notes from that entry instead of from `git log` subjects. Before this the script never touched CHANGELOG.md at all: documented work sat under `[Unreleased]` while the versions that shipped it went out with no entry (0.14.0 through 0.16.0 below are backfilled), and every GitHub release page showed raw commit subjects.

## [0.16.0] — 2026-09-13

Release tooling and README only; no change to the published server.

### Changed
- `release.sh` waits for npm to serve the new version before publishing to the MCP Registry. `npm publish` returns as soon as the registry accepts the tarball, but the version is not yet readable from npm's CDN-backed read path, and the MCP Registry validates a publish by reading it — 0.15.3's registry step failed with `version '0.15.3' was not found (status: 404)` and needed a second run. The wait polls the exact URL the registry's npm validator fetches (scope slash encoded as `%2F`) with `curl` rather than `npm view`, whose metadata cache can outlast the condition; it warns rather than fails on timeout, so `mcp-publisher` still reports its own precise error; `SKIP_NPM_WAIT=1` bypasses it and `NPM_WAIT_TIMEOUT_S` retunes the 300s default (#45).
- README: the X follow badge moved from the top badge row to the bottom of the page (#46).

## [0.15.3] — 2026-09-13

### Fixed
- **The launcher always uses the newest oam, and the minimum is now the latest release, 0.15.2** (raised from 0.9.0). It used to take the FIRST oam binary it found and only then check its version, so a stale copy in an earlier location hid a current one: with oam 0.9.0 in `~/.oam/bin` and 0.15.2 on `PATH`, it ran 0.9.0 — and an unrunnable file in an earlier location meant no oam at all. Every oam binary it can see is now asked for its version, and the newest at or above 0.15.2 wins; on a tie the installed copy still beats `PATH`.
- **An oam host older than the floor no longer serves the server itself.** When a client ran `oam run bin/ssh-mcp.mjs` with an old oam and discovery found nothing usable, the server ran on that old oam. When a newer oam WAS found, the handoff inherited stdio, which an oam older than 0.9.0 does not honor, so the MCP handshake never answered (measured on a real oam 0.8.2 host with aws-mcp's launcher, which this one shares). An old host now hands off with piped stdio to the newest usable oam, or to Node on `PATH`, or exits with an error when there is neither. If the chosen oam then cannot be spawned (deleted or replaced after its version check), the launcher still falls back: a failed spawn emits `close` with the negative errno, so piping, signal forwarding and the exit mirror all wait for the child's `spawn` event rather than exiting the launcher in the middle of the fallback. The in-process path from 0.15.2 for a host at the floor still holds; the floor it names is now 0.15.2.
- **A bad `OAM_BIN` is reported, and discovery carries on.** A path that does not exist, an oam below the floor, or a binary that will not run is named on stderr and the launcher goes on to discovery, instead of treating `OAM_BIN` as the only candidate — where a path that did not exist fell back to Node silently.
- **`SSH_MCP_RUNTIME=node` now always means Node.** Launched under `oam run`, it hands off to Node on `PATH` rather than staying on oam.
- Each `oam --version` probe is bounded at 5s, so a wedged binary on `PATH` cannot hang the launch.

### Changed
- README: the Runtime selection section now covers the launcher being started by oam itself (`oam run bin/ssh-mcp.mjs`, which is how Yaw MCP starts an `npx @yawlabs/ssh-mcp` entry when a recent oam is installed) as well as by Node — the in-process serve on a current oam, the handoff from an older one, and what each `SSH_MCP_RUNTIME` value does on each host — and describes the discovery order, the 0.15.2 floor, and the failed-spawn fallback above (#43, #44).

## [0.15.2] — 2026-09-12

### Fixed
- The launcher no longer spawns a nested oam when it is already running on one. A host that resolves this package's `bin` and launches `oam run bin/ssh-mcp.mjs` — Yaw MCP does, and so does oam's sidecar regression matrix — got a second runtime underneath the first, because the launcher discovered and spawned oam without asking what it was already hosted on: one server, two runtime boots (measured on Windows as `oam.exe` with a nested `oam.exe` + `conhost.exe`). When `process.versions.oam` clears the same 0.9.0 floor a discovered binary must, the server is now imported into the host process — no discovery, no `oam --version` probe — and `SSH_MCP_RUNTIME=oam` counts the host as the oam it demands. A host oam below the floor keeps the discovery path. Nothing is lost by serving in-process: this launcher has no `--permission` sandbox, so the spawn never passed oam any runtime flags.

### Changed
- README documents `SSH_MCP_RUNTIME` and `OAM_BIN` in a new Runtime selection section (closes #37). The launcher's error messages told users to set them, but the README never mentioned either. The section covers the three runtime values and that `auto` is the default, `OAM_BIN` taking priority over discovery and the order discovery searches when it is unset, the oam minimum, when `auto` falls back silently versus with a note on stderr (and that `SSH_MCP_RUNTIME=oam` exits with status 1 in each of those cases), and an example `env` block (#42).
- `biome.json`'s `$schema` synced to the Biome version `package-lock.json` installs, 2.4.15, so editor validation matches the binary that runs (#41).

## [0.15.1] — 2026-09-11

Package metadata, lint tooling and README only; no change to the published server.

### Changed
- npm listing: `homepage` points at https://yaw.sh/mcp-servers/ssh-mcp/, the description leads with what people search for, and the keywords were expanded to 16 terms, every claim checked against the README (#40).
- `npm run lint` is a trustworthy gate on Windows ARM64. Some `@biomejs/cli-win32-arm64` builds crash on every check-shaped run — 2.5.4 exits 139, while 2.4.16 and 2.5.13 run correctly — which turned the release's lint step into a crash with no result. `scripts/lint.mjs` now runs Biome at the version `package-lock.json` installs and, when the native build for this host is unusable, provisions the x64 build of the same version into a gitignored cache and runs that under emulation. The exit code is Biome's own, so a non-zero result is a real finding. The `SKIP_LINT` comment in `release.sh` no longer claims CI catches lint regressions; this repo has no CI (#39).
- README: X follow badge added to the badge row (#36).

## [0.15.0] — 2026-08-31

A full read of every source and test file, then three rounds of adversarial review over the resulting fixes. Tests go from 177 to 858, and `npm run build` works again on a fresh install (#35).

### Security
- **Command injection via environment variable names in `ssh_exec` and `ssh_multi_exec`.** Values were shell-quoted but keys were interpolated raw, so `env: {"A=1; reboot #": "x"}` produced `A=1; reboot #='x' <cmd>` and the remote ran `reboot`; it also slipped past a substring whitelist. Keys are now validated against the POSIX name grammar and rejected before the policy gate or any host is contacted.
- **The command policy failed open.** An all-malformed `SSH_MCP_COMMAND_WHITELIST` compiled to zero patterns, which the guard read as "no policy configured", so a single typo silently allowed everything. It now fails closed with a message naming the bad pattern. An unconfigured server still allows everything, unchanged.
- **Host-key algorithms are ordered from `known_hosts`.** An ecdsa-only entry no longer reads as a MITM when the server offers ed25519. The list is a permutation of ssh2's own defaults, so no reachable host becomes unconnectable, and it resolves in both the ESM dist and the bundled SEA binary.
- `@cert-authority` and `@revoked` marker lines in `known_hosts` are no longer parsed as host keys, which yielded a junk key blob.

### Fixed
- **ProxyJump specs were never parsed.** `ssh -G` emits the value verbatim, so a bastion on a non-default port dialled a hostname containing the port and failed DNS; the bracketed-IPv6 form connected on the wrong port with host-key checking silently degraded to accept-anything. ProxyJump is now covered against real SSH servers (ssh2's own `Server`: full handshakes and `direct-tcpip` channels, no Docker) in the normal suite.
- **The identity walk took the first readable file, not the first usable one**, then stopped: a zero-byte key, or the classic `IdentityFile ~/.ssh/id_ed25519.pub` typo, shadowed the real key behind it and killed identity auth with no fallback.
- `ssh_delete` used `stat`, which follows symlinks: a symlink to a directory dispatched to `rmdir` on the link, and a dangling symlink could not be deleted at all.
- **`ssh_stat`'s advertised `isSymbolicLink` flag was dead** for the same reason, so it could never be true. The type now comes from `lstat`, the metadata from `stat`.
- `ssh_diagnose`'s SSH config check never stripped `#` comments, so `Host bastion # jump box for prod` wrongly matched `prod`; and on a CRLF config the stripper never fired at all.
- `ssh_known_hosts_fix` removed nothing on IPv6 hosts while still appending a new key, leaving the stale key in the file and still trusted. It also claimed removals that never happened (`ssh-keygen -R` exits 0 on a miss) and reported an absent `known_hosts` as a failure.
- `ssh_diagnose` reported an unreachable ssh-agent as healthy for any `ssh-add` failure it did not recognize by wording.
- `npm run build` had been failing at the declaration step on any fresh install since the TypeScript 7 bump; it only appeared to work from a stale `node_modules`. `tsc` now emits the declarations, so `dist/` ships per-file `.d.ts` files instead of one bundled `server.d.ts`; the exports map still resolves for value and type-only imports.
- Biome pinned to 2.4.15 in the lockfile. 2.5.4 segfaults on win32-arm64, which had been masking three real findings — an import that should be `import type`, unsorted imports, and two formatting diffs — now applied.

### Changed
- `ssh_git_check` rejects an explicitly-empty `host` or `user`. Previously `{host: ""}` fell through a truthiness fallback and silently probed `github.com`, bypassing the hostname check every sibling tool routes through.
- `ssh_stat` reports `symlink -> directory` where it previously reported just `directory`, and a dangling symlink now returns a result where it used to error.
- README and CLAUDE.md corrected to what the code does: auth resolution is not a strict first-match chain, host-key handling is trust-always rather than TOFU, the command policy does not cover the SFTP mutation tools, and the server exposes 21 tools, not 18.
- `.gitignore` excludes `.npmrc`, so a project-local automation token — which `npm config set --location=project` writes — cannot be committed by a stray `git add -A`.
- `release.sh` no longer recommends `npm login --auth-type=web` when npm auth fails: web login overwrites the automation token in `~/.npmrc` with a 2FA-bound session, so the advice broke the next release. The prerequisites and the publish-failure message now point at restoring an automation token, and explain that npm answers an unauthorized publish with 404 rather than 401.

## [0.14.1] — 2026-08-23

### Added
- Test coverage for `bin/ssh-mcp.mjs`, which had none — every defect fixed in this release was found by review and verified by hand. The launcher runs on import rather than exporting anything, so the tests execute it against a throwaway layout (a copy of the real launcher plus a stub `dist/index.js`) and assert which path it took: runtime selection and argv passthrough, the entry-point repoint, `oam`-mode failing loudly, unreadable-vs-outdated diagnosis, shim detection and `.exe` preference on Windows, and a guard against control characters in the source. Signal forwarding and grace-window escalation are covered POSIX-only, since Windows has no deliverable signals to assert against.

### Fixed
- Launcher no longer dies with a raw stack trace when `spawn` fails synchronously. Node throws (rather than emitting `error`) for some unexecutable targets — notably a `.cmd`/`.bat` on Windows, which it rejects with `EINVAL` unless `shell: true` — and the `error` listener is registered *after* the `spawn` call, so it could never observe that throw. The documented fall-back-to-Node contract was broken in exactly the case it exists for. Both failure modes now route through one handler.
- Windows runtime discovery scans `PATH` for `oam.exe` only, instead of walking every `PATHEXT` entry. The installed-location checks already looked for `oam.exe` alone, so the two discovery paths disagreed: `PATH` could hand back an `oam.cmd` this launcher cannot execute, which then surfaced as a misleading "older than 0.9.0 — run `oam self-update`" error. Discovery and execution now accept the same shapes, and a real `oam.exe` further along `PATH` is found instead of being shadowed by a shim. A skipped shim is still **reported**: an npm-style install puts `oam.cmd` on `PATH`, and silently ignoring it made auto mode degrade with no explanation and `SSH_MCP_RUNTIME=oam` claim nothing was found — both of which send someone to reinstall an oam they already have. The message now names the shim and says why it cannot be used.
- A wedged child no longer leaves the launcher hanging with no escape hatch. Registering a handler suppresses Node's default terminate-on-signal, and `child.killed` records only that `kill()` was *called* — never that the child is gone — so gating on it swallowed every signal after the first. Escalation is now driven by a **timer** armed on the first signal, not by counting signals: one press is enough, and a child still alive after a 2s grace window is killed on schedule. Counting was ambiguous — a supervisor routinely sends `SIGINT` then `SIGTERM` milliseconds apart, and a terminal Ctrl-C reaches the whole process group, so reading "a second signal" as impatience would `SIGKILL` a child that was already shutting down cleanly, skipping its `process.on("exit")` backstop and leaking any ssh-agent the server spawned. Using a timer rather than timestamp arithmetic also removes a wall-clock dependency, since a clock step could otherwise mis-gate the window in either direction.
- **Windows: the launcher no longer hard-kills the child on the first Ctrl-C.** There are no POSIX signals on Windows — `child.kill(sig)` ignores the name and calls `TerminateProcess`, an immediate hard kill (verified: a child with a `SIGTERM` handler never runs it and dies with `code=null`). Forwarding therefore aborted the graceful shutdown the console's own Ctrl-C had just started, skipping the child's `process.on("exit")` backstop and leaking the spawned ssh-agent. The console already delivers the event to the whole process group, so on Windows the launcher now forwards nothing and lets the grace-window timer be the only kill it issues.
- Diagnostics that precede a `process.exit` are written synchronously rather than with `process.stderr.write`, which the exit could truncate because stderr is async for TTYs and pipes on Windows. They route through one `errSync` helper that also handles the two ways a bare `writeSync` fails: it can short-write (it returns a byte count, so a long message was silently clipped) and on macOS it can throw `EAGAIN`, since Node makes a piped stderr non-blocking there rather than blocking the write. An unusable stderr is now given up on quietly instead of crashing a stdio server over a log line.
- The child `error` handler no longer discards its promise with `void`. A failing in-process fallback surfaced as an unhandled rejection — replacing the launcher's own diagnostic with a raw stack trace — and now reports and sets a non-zero exit code. Both `launchFailed` call sites share one reporter so the synchronous and event-driven paths cannot drift.
- An oam binary that cannot be run is no longer reported as an old one. `oamVersion` returns `null` for several distinct causes — not executable, wrong architecture, a shim Node refuses, deleted since the stat, or a `--version` format this launcher does not parse — and every one of them produced "is older than oam 0.9.0. Run `oam self-update`", pointing the user at the single cause it definitely was not. The two cases now carry separate wording and separate remedies, and the too-old message reports the version actually detected.
- Removed a literal backspace byte (`U+0008`) from the runtime-discovery comment in `bin/ssh-mcp.mjs`, present since 0.13.0 and therefore in the published package. The Windows installer path was written as `%LOCALAPPDATA%\oam\bin` and round-tripped through escape processing, which dropped the first backslash and turned `\b` into a real control character — rendering the line as `%LOCALAPPDATA%oamin` and making git treat the file as binary, so its diff could not be reviewed. Lint, `tsc` and the tests passed either way.

### Changed
- `scripts/build-binary.mjs`: dropped the stale comment claiming the bundle entry is derived from `bin` "regardless of the server's entry filename". It contradicted the pinned `srcEntry` constant directly below it, and this script is copy-pasted across the `@yawlabs/*` servers, so the contradiction travelled with it.

## [0.14.0] — 2026-08-08

### Added
- A release-metadata test asserts that `server.json` and `package.json` agree — the top-level `version`, every `packages[].version`, and `mcpName` against `server.json`'s `name` — so a desynced MCP Registry entry aborts the release at the test step instead of shipping. `server.json` carries the version twice and `release.sh` bumps it separately from `package.json`, so an edit that updates one and not the other is visible to users and invisible to the release; the check earned its keep in tailscale-mcp, where it caught exactly that skew mid-release (#31).

### Changed
- **The launcher requires oam 0.9.0 or newer.** It probes `oam --version`; below the floor, `auto` falls back to Node with a note on stderr and `SSH_MCP_RUNTIME=oam` is a hard error. Older oam ran `child_process.execFile` arguments through a shell, accepted an exec `timeout` and ignored it, truncated `spawnSync` at `maxBuffer` while reporting success, and treated stdio `inherit`/`ignore` as `pipe` — this server shells out, so those were reachable bugs rather than theoretical ones. The launcher header now also says why there is no `--permission` sandbox: the server opens outbound SSH to hosts the caller names and needs key material and `known_hosts`, so nothing meaningful is left to deny.

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
