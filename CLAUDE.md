# ssh-mcp

MCP server that makes SSH work for AI tools. 14 tools across 3 categories: SSH environment management, diagnostics, and remote operations.

## Architecture

- `src/index.ts` — CLI entry point. Starts MCP server with stdio transport.
- `src/server.ts` — Creates McpServer, registers tools, re-exports all public APIs.
- `src/tools.ts` — 14 MCP tools across environment management, diagnostics, and remote operations.
- `src/ssh.ts` — SSH connection and operation primitives (connect, connectRaw, resolveConfig, exec, readFile, writeFile, uploadFile, downloadFile, listDir). resolveConfig uses `ssh -G` for SSH config awareness. Auto-diagnoses on connection failure.
- `src/pool.ts` — ConnectionPool class. Reuses SSH connections across tool calls with idle TTL, keepalive, and dead connection detection.
- `src/diagnose.ts` — SSH environment diagnostics (agent, keys, known_hosts, config, connectivity). Parses common SSH error messages into actionable fix suggestions.
- `src/env.ts` — SSH environment management (ensureAgent, listSshKeys, loadKey, configLookup, fixKnownHosts, checkGitSsh, testConnection). These take action to fix SSH, not just diagnose.

## Build

- **Bundler:** tsup with two entry configs (CLI with shebang, library with types).
- **Linter:** Biome (not ESLint).
- **Tests:** Vitest.
- **TypeScript:** Strict mode, ES2022 target, ESM.

## Key patterns

- Auth resolution: explicit key > explicit password > SSH agent (SSH_AUTH_SOCK) > SSH config identity files > default key paths.
- resolveConfig uses `ssh -G <host>` to resolve hostname aliases, user, port, and identity files from ~/.ssh/config. Falls back gracefully if ssh is not installed.
- All SSH operations use ssh2 library with connection pooling (ConnectionPool in pool.ts). Connections are reused across tool calls with 60s idle TTL.
- Connection failures auto-diagnose: when connect/acquire fails, diagnostics run automatically and are included in the error message.
- ssh_diagnose runs 5 checks: agent status, key existence, SSH config, known_hosts, and live connectivity test.
- Environment management tools (env.ts) can take action: start agents, load keys, fix known_hosts, resolve SSH config.
- Diagnostics parse SSH error output to detect: dead agent, no keys, stale host keys, permission denied, connection refused/timeout, DNS failures.
- Each diagnostic failure includes the exact shell command to fix it.
- isValidHostname and runArgs are shared between diagnose.ts and env.ts (exported from diagnose.ts).

## Commands

```bash
npm run build      # Compile with tsup
npm run dev        # Watch mode
npm test           # Run vitest
npm run lint       # Biome check
npm run lint:fix   # Biome auto-fix
npm run typecheck  # tsc --noEmit
npm run test:ci    # Build + test
```
