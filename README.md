# @yawlabs/ssh-mcp

[![npm version](https://img.shields.io/npm/v/@yawlabs/ssh-mcp)](https://www.npmjs.com/package/@yawlabs/ssh-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

**Make SSH work for AI tools.** MCP server that manages your SSH environment, diagnoses what's broken, fixes it, and gives your agent remote access to anything.

Built and maintained by [Yaw Labs](https://yaw.sh).

## The problem

AI CLI tools run in subprocesses where SSH is constantly broken. The agent tries to `git pull` and gets `Permission denied (publickey)`. It tries to SSH into a server and the agent socket is stale. It tries to deploy and the host key changed because the instance was recreated. Every time, the AI has no idea what's wrong and spirals.

This happens across every situation that needs SSH keys:

- **Git** — clone, pull, push, fetch, submodules, LFS
- **Package managers** — `npm install`, `pip install`, `go get`, `cargo`, `composer` from private repos
- **Server access** — SSH, SCP, SFTP, rsync
- **Tunneling** — port forwarding to databases, SOCKS proxies
- **Deployment** — Ansible, Terraform, Capistrano, deploy scripts
- **Cloud** — AWS EC2, GCP, Azure, DigitalOcean, any VPS

**ssh-mcp** fixes this. It manages the SSH agent, loads keys, diagnoses failures with actionable fix commands, and provides remote operations — all as MCP tools your AI agent can call.

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

### SSH environment management

Tools that fix your local SSH setup so everything else — git, deploys, tunnels — stops breaking.

| Tool | Description |
|------|-------------|
| `ssh_agent_ensure` | Ensure ssh-agent is running. Starts one if needed and sets env vars for the session. |
| `ssh_key_list` | List all SSH keys in ~/.ssh/ with type, fingerprint, and agent status. |
| `ssh_key_load` | Load a key into the running agent. Ensures the agent is started first. |
| `ssh_config_lookup` | Resolve the effective SSH config for a host (hostname, user, port, proxy, identity files). |
| `ssh_known_hosts_fix` | Remove a stale host key and re-scan. Fixes "host key verification failed" errors. |
| `ssh_git_check` | Test Git-over-SSH auth to GitHub, GitLab, Bitbucket, etc. |
| `ssh_test` | Quick connectivity test with timing and actionable error details. |

### Diagnostics

| Tool | Description |
|------|-------------|
| `ssh_diagnose` | Full SSH environment diagnostic. Checks agent, keys, config, known_hosts, and connectivity. Returns exact fix commands for every failure. |

### Remote operations

| Tool | Description |
|------|-------------|
| `ssh_exec` | Execute a command on a remote host. Returns stdout, stderr, and exit code. |
| `ssh_read_file` | Read a file from a remote host via SFTP. |
| `ssh_write_file` | Write content to a file on a remote host via SFTP. |
| `ssh_upload` | Upload a local file to a remote host via SFTP. |
| `ssh_download` | Download a file from a remote host to local filesystem. |
| `ssh_ls` | List files in a directory on a remote host. |

### Auto-diagnostics

When any remote operation fails, ssh-mcp automatically runs diagnostics and includes the results in the error response. Your agent doesn't need to call `ssh_diagnose` separately — it gets told what's wrong and how to fix it right in the error message.

### Connection pooling

Remote operations reuse SSH connections automatically. When your agent makes multiple calls to the same host, the first call opens a connection and subsequent calls reuse it. Connections are kept alive for 60 seconds after the last use, then closed automatically.

### SSH config support

All connections respect your `~/.ssh/config`. Host aliases, custom ports, usernames, and identity files from your SSH config are used automatically. If you have `Host myserver` configured in your SSH config, just pass `host: "myserver"` — ssh-mcp resolves the real hostname, user, port, and identity file.

## Authentication

All remote operations accept connection parameters:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `host` | SSH hostname or IP (required) | — |
| `port` | SSH port | From SSH config or `22` |
| `username` | SSH username | From SSH config or current user |
| `privateKeyPath` | Path to SSH private key | Auto-detect |
| `password` | SSH password (prefer keys) | — |

**Auth resolution order:** explicit key > explicit password > ssh-agent (`SSH_AUTH_SOCK`) > SSH config identity files > default key paths (`~/.ssh/id_ed25519`, `id_rsa`, `id_ecdsa`).

## Example workflows

### Agent can't git pull

```
Agent calls ssh_git_check → "Permission denied. Your SSH key is not registered with github.com."
Agent calls ssh_key_list → finds id_ed25519 exists but is not loaded
Agent calls ssh_key_load("~/.ssh/id_ed25519") → "Key loaded"
Agent calls ssh_git_check → "Git SSH authentication to github.com succeeded as username"
Agent runs git pull → works
```

### Host key changed after instance recreation

```
Agent calls ssh_exec on server → error: "Host key verification failed"
  (auto-diagnostics included in error: "Fix with ssh_known_hosts_fix")
Agent calls ssh_known_hosts_fix("my-server") → "Host key refreshed"
Agent calls ssh_exec → works
```

### First-time connection to a new server

```
Agent calls ssh_test("new-server") → "Connection refused at new-server:22"
Agent calls ssh_diagnose("new-server") → full report showing agent running, keys loaded, but host unreachable
Agent reports: "SSH server isn't running on new-server or port 22 is blocked"
```

## Programmatic usage

```typescript
import { connect, exec, diagnose, ensureAgent, listSshKeys, checkGitSsh, ConnectionPool } from '@yawlabs/ssh-mcp';

// Fix SSH environment
const agent = ensureAgent();
console.log(agent.message);

// Check git access
const git = checkGitSsh('github.com');
console.log(git.message);

// List available keys
const keys = listSshKeys();
for (const key of keys) {
  console.log(`${key.name} (${key.type}) - ${key.loadedInAgent ? 'loaded' : 'not loaded'}`);
}

// Run a remote command (one-off)
const client = await connect({ host: 'my-server', username: 'deploy' });
const result = await exec(client, 'uptime');
console.log(result.stdout);
client.end();

// Run multiple commands with connection pooling
const pool = new ConnectionPool();
await pool.withConnection({ host: 'my-server' }, async (client) => {
  const r1 = await exec(client, 'uptime');
  console.log(r1.stdout);
});
// Connection stays open for 60s — next call reuses it
await pool.withConnection({ host: 'my-server' }, async (client) => {
  const r2 = await exec(client, 'df -h');
  console.log(r2.stdout);
});
pool.drain(); // close all connections when done

// Diagnose issues
const report = diagnose('my-server');
console.log(report.overall); // "ok" | "warning" | "error"
for (const check of report.checks) {
  console.log(`[${check.status}] ${check.name}: ${check.message}`);
}
```

## Requirements

- Node.js 18+
- SSH client installed (for diagnostics and environment management)

## License

MIT
