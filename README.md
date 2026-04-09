# @yawlabs/ssh-mcp

[![npm version](https://img.shields.io/npm/v/@yawlabs/ssh-mcp)](https://www.npmjs.com/package/@yawlabs/ssh-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

**SSH operations for AI agents.** MCP server with remote command execution, file transfer, and built-in SSH diagnostics that tell you exactly what's wrong and how to fix it.

Built and maintained by [Yaw Labs](https://yaw.sh).

## Why this tool?

AI agents that SSH into remote servers hit the same problems over and over: dead ssh-agent, wrong key loaded, stale host keys from recreated instances, permission denied with no useful context. Most SSH MCP servers just wrap `ssh2` and let the agent figure out cryptic errors.

This one includes `ssh_diagnose` — a diagnostic tool that checks your entire SSH environment (agent, keys, config, known_hosts, connectivity) and returns actionable fix commands. Use it before connecting or after a failure.

## Quick start

```bash
npm install -g @yawlabs/ssh-mcp
```

Add to your MCP client config:

```json
{
  "mcpServers": {
    "ssh": {
      "command": "ssh-mcp"
    }
  }
}
```

## Tools

### Core operations

| Tool | Description |
|------|-------------|
| `ssh_exec` | Execute a command on a remote host. Returns stdout, stderr, and exit code. |
| `ssh_read_file` | Read a file from a remote host via SFTP. |
| `ssh_write_file` | Write content to a file on a remote host via SFTP. |
| `ssh_upload` | Upload a local file to a remote host via SFTP. |
| `ssh_download` | Download a file from a remote host to local filesystem. |
| `ssh_ls` | List files in a directory on a remote host. |

### Diagnostics

| Tool | Description |
|------|-------------|
| `ssh_diagnose` | Diagnose SSH connectivity issues. Checks agent, keys, known_hosts, SSH config, and live connectivity. Returns actionable fix commands. |

## Authentication

All tools accept connection parameters:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `host` | SSH hostname or IP (required) | — |
| `port` | SSH port | `22` |
| `username` | SSH username | Current user |
| `privateKeyPath` | Path to SSH private key | Auto-detect |
| `password` | SSH password (prefer keys) | — |

**Auth resolution order:** explicit key > explicit password > ssh-agent (`SSH_AUTH_SOCK`) > default key paths (`~/.ssh/id_ed25519`, `id_rsa`, `id_ecdsa`).

## Diagnostics

`ssh_diagnose` runs 5 checks and returns a structured report:

1. **SSH Agent** — Is `ssh-agent` running? Are keys loaded?
2. **SSH Keys** — Do private keys exist in `~/.ssh/`?
3. **SSH Config** — Is there a config entry for this host? (supports wildcards)
4. **Known Hosts** — Is the host key cached?
5. **Connectivity** — Can we actually connect?

Each failed check includes the exact command to fix it. Example output:

```
SSH Diagnostic Report for dev-server:22
Overall: ERROR

[PASS] SSH Agent
  ssh-agent running with keys:
  256 SHA256:abc... user@host (ED25519)

[PASS] SSH Keys
  Found SSH keys: id_ed25519, gh_woods

[PASS] SSH Config
  SSH config for "dev-server":
  Host dev-server
    HostName 10.0.1.50
    User ec2-user

[FAIL] Known Hosts
  Host "dev-server" is not in known_hosts.

[FAIL] Connectivity
  Host key verification failed for dev-server. The host key changed (instance recreated?).

Suggested fixes:
  - Remove stale host key: ssh-keygen -R "dev-server"
  - Re-add host key: ssh-keyscan -H "dev-server" >> ~/.ssh/known_hosts
```

## Programmatic usage

```typescript
import { connect, exec, diagnose } from '@yawlabs/ssh-mcp';

// Run a command
const client = await connect({ host: 'my-server', username: 'deploy' });
const result = await exec(client, 'uptime');
console.log(result.stdout);
client.end();

// Diagnose connectivity issues
const report = diagnose('my-server');
console.log(report.overall); // "ok" | "warning" | "error"
for (const check of report.checks) {
  console.log(`[${check.status}] ${check.name}: ${check.message}`);
}
```

## Requirements

- Node.js 18+
- SSH client installed (for diagnostics)

## License

MIT
