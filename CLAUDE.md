# ssh-mcp

MCP server that makes SSH work for AI tools. 21 tools across 4 categories: SSH environment management, diagnostics, remote operations, and higher-level ops.

## Architecture

- `src/index.ts` — CLI entry point. Starts MCP server with stdio transport. Drains pool on shutdown.
- `src/server.ts` — Creates McpServer, registers tools, re-exports all public APIs.
- `src/tools.ts` — 21 MCP tools across environment management, diagnostics, remote operations, and higher-level ops.
- `src/ssh.ts` — SSH connection primitives (connect, connectRaw, connectWithProxy, resolveConfig, exec, SFTP ops). resolveConfig uses `ssh -G` for SSH config awareness. Supports ProxyJump for bastion hosts. Auto-diagnoses on connection failure.
- `src/pool.ts` — ConnectionPool class. Reuses SSH connections across tool calls with idle TTL, keepalive, and dead connection detection.
- `src/ops.ts` — Higher-level operations (multiExec, find, tail, serviceStatus). These wrap common ssh_exec patterns agents build manually.
- `src/diagnose.ts` — SSH environment diagnostics (agent, keys, known_hosts, config, connectivity). Handles both Unix and Windows OpenSSH agents. Owns the shared `isValidHostname` / `runArgs` helpers and the `ssh` probe both connectivity checks run.
- `src/env.ts` — SSH environment management (ensureAgent, listSshKeys, loadKey, configLookup, fixKnownHosts, checkGitSsh, testConnection). Handles Windows OpenSSH agent service.
- `src/policy.ts` — Optional command allow/deny policy for the exec tools, configured via `SSH_MCP_COMMAND_WHITELIST` / `SSH_MCP_COMMAND_BLACKLIST`.
- `src/ssh-config.ts` — Pure parser for `ssh -G` output, shared by `resolveConfig` (ssh.ts) and `configLookup` (env.ts).
- `bin/ssh-mcp.mjs` — Runtime launcher. `auto` (the default) prefers the newest usable oam and falls back to Node; `SSH_MCP_RUNTIME=oam` / `=node` demand one. `AUTO_PREFERS_OAM` is `true` again as of oam 0.21.1, which closed all four node:crypto gaps that had forced a Node-only default (YawLabs/oam#489): on 0.20.2 `crypto.verify` threw on an Ed25519 private key — the probe ssh2 uses to decide it supports ed25519 (`eddsaSupported`, ssh2 `lib/protocol/constants.js`) — and signing with a SEC1 EC private key threw, so ed25519/ECDSA key files and ed25519-only servers failed there; `crypto.diffieHellman` and x25519 key pairs were missing too, so curve25519 key exchange was not offered. Measured on 0.21.1 against a local ssh2 server, identical to Node 22: an ed25519 key file, an ECDSA key file, an ed25519-only host key and curve25519-sha256 all complete an exec, and ssh2 reports `eddsaSupported = true` / `curve25519Supported = true`. Setting it back to `false` needs a measured regression on the floor release. `SSH_MCP_RUNTIME=oam` is the hard requirement: the newest `oam` binary at or above `OAM_MIN` (the latest oam release, 0.21.1), or exit 1. An oam host below the floor never serves: it hands off, with piped stdio, to Node or to a newer oam. An oam host AT the floor serves in-process (`auto` and `oam` alike) instead of spawning a second oam, and `OAM_BIN` is not read on that path. A candidate (`OAM_BIN` or discovered) counts only if its `--version` output carries oam's own banner (`oam x.y.z` at the start of a line, `oamBanner`): a bare x.y.z is not enough, or an `OAM_BIN` pointing at node (`v22.x.y`) would clear the floor and be spawned as `node run dist/index.js` with no fallback. `process.versions.oam` keeps the loose parse (only oam sets it). Owns signal forwarding and escalation.

## Build

- **Bundler:** tsup with two entry configs (CLI with shebang, library with types).
- **Linter:** Biome (not ESLint).
- **Tests:** Vitest. Integration tests require Docker (`npm run test:integration`).
- **TypeScript:** Strict mode, ES2022 target, ESM.

## Key patterns

- Auth resolution is NOT a strict first-match chain. An explicit `privateKeyPath` or `password` wins outright and nothing else is offered — that part is first-match-wins. With neither, `resolveConfig` (ssh.ts) sets `connectConfig.agent` AND `connectConfig.privateKey` **together**, offering the agent plus ONE on-disk key on the same connection, which is what the OpenSSH client does. Don't "fix" this back into a fall-through chain.
- The on-disk key in that branch is the first USABLE entry from `ssh -G`'s `identityfile` list — not merely the first readable one. OpenSSH emits that list for every host even with no `IdentityFile` line, so it is the normal path; the hardcoded `id_ed25519`/`id_rsa`/`id_ecdsa` list is reached only when `ssh -G` fails (no ssh client). The walk skips a candidate and continues on two conditions, then stops at the first survivor. If every candidate is skipped, `privateKey` is left unset and the agent (if any) is offered alone.
- Skip condition 1 — NOT a key file (`looksLikePrivateKey`, ssh.ts). A candidate carrying no private-key marker at all is skipped ALWAYS, agent or not: an empty file, a stray text file, or the classic `IdentityFile ~/.ssh/id_ed25519.pub` typo. Before this existed such a file was loaded as the `privateKey` and `break`ed the walk, so it shadowed the real key behind it and killed identity auth with no fallback.
- Skip condition 2 — ENCRYPTED, and only when an agent is configured (`isEncryptedKey`, ssh.ts). ssh2 parses `privateKey` eagerly and throws "no passphrase given", which would break the encrypted-key-on-disk / decrypted-copy-in-agent setup. With no agent an encrypted key is still loaded regardless, so ssh2 surfaces its own error. `agentSock` defaults to the Windows named pipe unconditionally (no service check), so on Windows this skip is always in force. A file wearing OpenSSH armor whose body is not a valid `openssh-key-v1` container counts as encrypted here — deliberately conservative, since it cannot be parsed either way.
- resolveConfig uses `ssh -G <host>` to resolve hostname aliases, user, port, identity files, and ProxyJump from ~/.ssh/config. Falls back gracefully if ssh is not installed.
- ProxyJump support: connectWithProxy recursively connects through jump hosts. Jump host connections close when target connection closes.
- Windows support: the named pipe `\\.\pipe\openssh-ssh-agent` stands in for SSH_AUTH_SOCK when it is not set. Two different behaviors, don't conflate them — the env/diagnostics path (`probeAgent`, env.ts:125) actually PROBES the pipe for liveness, while the connection path (ssh.ts:458) assumes it unconditionally with no check.
- All SSH operations use ssh2 library with connection pooling (ConnectionPool in pool.ts). Connections are reused across tool calls with 60s idle TTL. The pool key folds in a fingerprint of the resolved auth material, so two calls to one host with different credentials never share a connection.
- Connection failures auto-diagnose: when connect/acquire fails, diagnostics run automatically and are included in the error message. Config resolution is inside that wrapper too (`enhanceSshError` in ssh.ts), so a bad `privateKeyPath` gets diagnostics rather than a raw ENOENT.
- Higher-level ops (ops.ts) use shellQuote for safe command construction. A leading-dash path is defused by `./`-prefixing rather than `--`, which is a GNU-find extension and would break against a BSD remote.
- isValidHostname and runArgs are shared between diagnose.ts, env.ts, and ssh.ts (exported from diagnose.ts).

## Security model — read before changing host-key or policy code

- **Host key checking is trust-ALWAYS on an unknown host, not TOFU.** An unknown host is accepted and its key is never persisted, so every connection to it is a "first" use. Only hosts already in known_hosts get MITM protection. `SSH_MCP_STRICT_HOSTKEYS=1` (or the legacy, credential-shaped `SSH_MCP_STRICT_HOST_KEY`; both take trimmed, case-insensitive `1`/`true`, see `isStrictHostKeyMode` in ssh.ts) requires an entry. Do not describe this as TOFU — real TOFU pins the first key it sees, and this deliberately does not.
- **Host-key algorithms are ordered, never restricted.** `hostKeyAlgorithmOrder` (ssh.ts) permutes ssh2's own `DEFAULT_SERVER_HOST_KEY` so algorithms present in known_hosts negotiate first, matching OpenSSH. It is built from ssh2's list via a deep `createRequire` and returns null if that ever fails, so no reachable host can become unconnectable. Never replace it with a hardcoded list — ssh2 throws "Unsupported algorithm" on an entry it does not know.
- **Command policy covers `ssh_exec` and `ssh_multi_exec` ONLY.** The SFTP mutation tools (`ssh_write_file`, `ssh_upload`, `ssh_mkdir`, `ssh_delete`) are NOT gated, so a `^rm` blacklist is not whole-server coverage. See the SCOPE LIMIT block in policy.ts.
- **Policy is enforced against the env-PREFIXED command**, so a `^`-anchored whitelist stops matching once `env` is used. Deliberate and pinned by `src/tests/exec-env-policy.test.ts`; the rejection message explains it when it bites.
- **Policy is a guard rail, not a security boundary.** Denylists are best effort (`/bin/rm`, `\rm`, `r''m` evade `^rm `). While a whitelist is active, a matching command is still refused for shell control syntax or a leading variable assignment (including the `env` prefix, and a leading bare `env ` / `export ` keyword) unless `SSH_MCP_COMMAND_ALLOW_SHELL_SYNTAX=1`. The assignment check anchors on the bare keyword, so `/usr/bin/env` and `command env` spellings pass -- a limit pinned by `src/tests/policy.test.ts`, not protection to rely on. The syntax scan is deliberately quote-blind: the remote shell is unknown and shells disagree about quoting, so do not "improve" it into a quote-aware parser. Any malformed entry in either list fails closed, and the opt-out is validated whenever a policy is configured (not only under a whitelist).
- **`hasLooseQuantifier` consumes a backslash WITH the character it escapes** (`i += 2`). Advancing only past the backslash re-reads the escaped char as syntax: an escaped `\{` looked like a loose quantifier and an escaped `\]` looked like the class end, refusing valid patterns and making the refusal's own "escape the brace as `\{`" advice reproduce the refusal. `splitPatternList`'s `anotherEntryFollows` rule is load-bearing for two pinned rows (`^rm[abc,>],^df`, `^rm[,>|],^df`) whose swallowed comma is followed only by shell punctuation, so the content heuristic misses them; the cost is that the `[,]` idiom is refused in a multi-entry list (README documents `\,` there).

## Commands

```bash
npm run build            # Compile with tsup
npm run dev              # Watch mode
npm test                 # Run vitest (unit tests)
npm run test:integration # Run integration tests (requires Docker)
npm run lint             # Biome check
npm run lint:fix         # Biome auto-fix
npm run typecheck        # tsc --noEmit
npm run test:ci          # Build + test
```
