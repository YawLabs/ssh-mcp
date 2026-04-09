# ssh-mcp

MCP server for SSH operations with built-in diagnostics. 7 tools across 2 categories: core SSH operations and connectivity diagnostics.

## Architecture

- `src/index.ts` — CLI entry point. Starts MCP server with stdio transport.
- `src/server.ts` — Creates McpServer, registers tools, re-exports all public APIs.
- `src/tools.ts` — 7 MCP tools: ssh_exec, ssh_read_file, ssh_write_file, ssh_upload, ssh_download, ssh_ls, ssh_diagnose.
- `src/ssh.ts` — SSH connection and operation primitives (connect, exec, readFile, writeFile, uploadFile, downloadFile, listDir).
- `src/diagnose.ts` — SSH environment diagnostics (agent, keys, known_hosts, config, connectivity). Parses common SSH error messages into actionable fix suggestions.

## Build

- **Bundler:** tsup with two entry configs (CLI with shebang, library with types).
- **Linter:** Biome (not ESLint).
- **Tests:** Vitest.
- **TypeScript:** Strict mode, ES2022 target, ESM.

## Key patterns

- Auth resolution priority: explicit key > explicit password > SSH agent (SSH_AUTH_SOCK) > default key paths (~/.ssh/id_ed25519, id_rsa, id_ecdsa).
- All SSH operations use ssh2 library. Connections are opened per-call and closed in finally blocks.
- ssh_diagnose runs 5 checks: agent status, key existence, SSH config, known_hosts, and live connectivity test.
- Diagnostics parse SSH error output to detect: dead agent, no keys, stale host keys, permission denied, connection refused/timeout, DNS failures.
- Each diagnostic failure includes the exact shell command to fix it.

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
