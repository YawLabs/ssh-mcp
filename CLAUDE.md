# ssh-mcp

MCP server that makes SSH work for AI tools. 18 tools across 4 categories: SSH environment management, diagnostics, remote operations, and higher-level ops.

## Architecture

- `src/index.ts` — CLI entry point. Starts MCP server with stdio transport. Drains pool on shutdown.
- `src/server.ts` — Creates McpServer, registers tools, re-exports all public APIs.
- `src/tools.ts` — 18 MCP tools across environment management, diagnostics, remote operations, and higher-level ops.
- `src/ssh.ts` — SSH connection primitives (connect, connectRaw, connectWithProxy, resolveConfig, exec, SFTP ops). resolveConfig uses `ssh -G` for SSH config awareness. Supports ProxyJump for bastion hosts. Auto-diagnoses on connection failure.
- `src/pool.ts` — ConnectionPool class. Reuses SSH connections across tool calls with idle TTL, keepalive, and dead connection detection.
- `src/ops.ts` — Higher-level operations (multiExec, find, tail, serviceStatus). These wrap common ssh_exec patterns agents build manually.
- `src/diagnose.ts` — SSH environment diagnostics (agent, keys, known_hosts, config, connectivity). Handles both Unix and Windows OpenSSH agents.
- `src/env.ts` — SSH environment management (ensureAgent, listSshKeys, loadKey, configLookup, fixKnownHosts, checkGitSsh, testConnection). Handles Windows OpenSSH agent service.

## Build

- **Bundler:** tsup with two entry configs (CLI with shebang, library with types).
- **Linter:** Biome (not ESLint).
- **Tests:** Vitest. Integration tests require Docker (`npm run test:integration`).
- **TypeScript:** Strict mode, ES2022 target, ESM.

## Key patterns

- Auth resolution: explicit key > explicit password > SSH agent (SSH_AUTH_SOCK or Windows named pipe) > SSH config identity files > default key paths.
- resolveConfig uses `ssh -G <host>` to resolve hostname aliases, user, port, identity files, and ProxyJump from ~/.ssh/config. Falls back gracefully if ssh is not installed.
- ProxyJump support: connectWithProxy recursively connects through jump hosts. Jump host connections close when target connection closes.
- Windows support: detects Windows OpenSSH agent service via named pipe `\\.\pipe\openssh-ssh-agent` when SSH_AUTH_SOCK is not set.
- All SSH operations use ssh2 library with connection pooling (ConnectionPool in pool.ts). Connections are reused across tool calls with 60s idle TTL.
- Connection failures auto-diagnose: when connect/acquire fails, diagnostics run automatically and are included in the error message.
- Higher-level ops (ops.ts) use shellQuote for safe command construction.
- isValidHostname and runArgs are shared between diagnose.ts, env.ts, and ssh.ts (exported from diagnose.ts).

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
