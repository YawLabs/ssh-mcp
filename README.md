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
| `ssh_exec` | Execute a command on a remote host. Returns stdout, stderr, and exit code (or `[signal: NAME]` and `code: -1` when the channel closed signal-only). Optional `env` param sets per-call environment variables (POSIX-safe prefix, works regardless of sshd's `AcceptEnv`). Subject to [command policy](#command-policy) if configured. |
| `ssh_read_file` | Read a file from a remote host via SFTP. |
| `ssh_write_file` | Write content to a file on a remote host via SFTP. |
| `ssh_upload` | Upload a local file to a remote host via SFTP. |
| `ssh_download` | Download a file from a remote host to local filesystem. |
| `ssh_ls` | List files in a directory on a remote host. |
| `ssh_stat` | Get metadata for a file or directory (size, mode in octal, uid/gid, mtime/atime, isFile/isDirectory/isSymbolicLink). Use instead of parsing `ls -la`. |
| `ssh_mkdir` | Create a directory via SFTP. Set `recursive: true` for `mkdir -p` behavior. |
| `ssh_delete` | Delete a file or empty directory via SFTP. Auto-dispatches unlink vs rmdir based on the path's type. Recursive directory delete is intentionally NOT supported -- use `ssh_exec rm -rf` if you need it. |

### Higher-level operations

Tools that wrap common patterns agents build with ssh_exec — faster and less error-prone.

| Tool | Description |
|------|-------------|
| `ssh_multi_exec` | Run a command on multiple hosts in parallel. Returns results per host. Subject to [command policy](#command-policy) if configured (policy is checked once before fan-out). |
| `ssh_find` | Search for files remotely with structured parameters (`name`, `type`, `size`, `depth`, `newer` — match files modified more recently than a reference path). |
| `ssh_tail` | Read the last N lines of a file, optionally filtered by a grep pattern. |
| `ssh_service_status` | Check systemd service status (active, PID, uptime, description). Flags `isError` only when the unit could not be found / queried, not when an existing unit is intentionally stopped. |

### Auto-diagnostics

When any remote operation fails, ssh-mcp automatically runs diagnostics and includes the results in the error response. Your agent doesn't need to call `ssh_diagnose` separately — it gets told what's wrong and how to fix it right in the error message.

### Connection pooling

Remote operations reuse SSH connections automatically. When your agent makes multiple calls to the same host, the first call opens a connection and subsequent calls reuse it. Connections are kept alive for 60 seconds after the last use, then closed automatically.

The pool caps at 100 active connections by default. Set `SSH_MCP_MAX_POOL_SIZE=<n>` to raise it for fan-out workloads against many distinct hosts (e.g. `ssh_multi_exec` across a large fleet). When the cap is reached, the pool evicts an idle entry to make room; if every entry is in use it rejects with `Connection pool is full`.

### SSH config support

All connections respect your `~/.ssh/config`. Host aliases, custom ports, usernames, identity files, and ProxyJump settings are used automatically. If you have `Host myserver` configured in your SSH config, just pass `host: "myserver"` — ssh-mcp resolves everything.

**ProxyJump / bastion hosts** are supported automatically. If your SSH config has `ProxyJump bastion` for a host, ssh-mcp connects through the bastion transparently. Chained proxies work too.

### Host key verification

All remote operations verify the server's host key against `~/.ssh/known_hosts`:

- **Known host, key matches** — accept.
- **Known host, key changed** — reject (MITM protection).
- **Unknown host** — accept on first connection (TOFU). Use `ssh_known_hosts_fix` to pin the key for future mismatch detection.

For stricter environments, set `SSH_MCP_STRICT_HOST_KEY=1` to reject unknown hosts. Add them explicitly with `ssh_known_hosts_fix` first.

The diagnostic tools (`ssh_test`, `ssh_diagnose`) use `StrictHostKeyChecking=no` for their probe commands. Those probes only run `echo SSH_OK` — no credentials or data pass through — so the relaxed setting is safe for connectivity testing. Real operations always go through the `hostVerifier`.

### Command policy

`ssh_exec` and `ssh_multi_exec` accept free-form shell commands from the agent. For security-conscious deployments, you can restrict which commands run via two env vars, each accepting a comma-separated list of regex patterns:

- `SSH_MCP_COMMAND_WHITELIST` — if set, the command **must** match at least one pattern, else it's blocked.
- `SSH_MCP_COMMAND_BLACKLIST` — if set, the command **must not** match any pattern, else it's blocked.

When both are set, the command must pass both checks (whitelist first, then blacklist). When neither is set (the default), all commands are allowed.

Patterns are JavaScript regexes. Use `^` and `$` for anchored matches; otherwise patterns are treated as substring matches. Commas are the delimiter, so a literal comma in a pattern needs to be expressed as `\x2c` or via a character class.

```bash
# Read-only allowlist: only ls / df / cat / find / tail
SSH_MCP_COMMAND_WHITELIST="^ls( .*)?,^df( .*)?,^cat ,^find ,^tail "

# Block destructive ops even if your agent goes off-script
SSH_MCP_COMMAND_BLACKLIST="^rm ,^shutdown,^reboot,^mkfs,^dd if=,>\s*/dev/"
```

Blocked commands surface as a clear error mentioning which pattern (or which env var) rejected the call, so the agent can adapt rather than guess. Policy is enforced before the SSH connection opens — no remote process is started for a blocked command.

The structured higher-level tools (`ssh_find`, `ssh_tail`, `ssh_service_status`, SFTP ops) are exempt from policy. They build commands from typed parameters, so a tight `^ls` whitelist would otherwise force you to allow `^find `, `^tail `, `^systemctl ` just to keep those tools working — defeating the point of a tight whitelist.

#### Policy interaction with `ssh_exec`'s `env` parameter

When `ssh_exec` is called with `env: { KEY: "value" }`, the values are injected as a `KEY='value' ...` shell prefix before the command (see the `ssh_exec` description). **Policy is checked against the full prefixed command**, not the bare `command` argument. That's the safer ordering at the protocol layer — but it means whitelist patterns need to anticipate the prefix and must be **anchored**, not substring matches:

```bash
# WRONG -- blocks any ssh_exec call that uses `env`, because the final command
# starts with `KEY='value' ` and never matches `^ls`.
SSH_MCP_COMMAND_WHITELIST="^ls "

# RIGHT -- allow zero or more `KEY='value' ` prefixes before the real command.
SSH_MCP_COMMAND_WHITELIST="^([A-Za-z_][A-Za-z0-9_]*='[^']*' )*ls( |$)"
```

**Avoid substring-match patterns** like ` ls ` if you're worried about a hostile agent. An agent could pass `env: { ATTACK: " ls " }` to make the final command `ATTACK=' ls ' rm -rf /`, which matches a substring ` ls ` and bypasses the whitelist. Anchored patterns of the form above don't have this weakness because they require the real command name to follow the env-prefix block, not appear inside a quoted env value.

Blacklists need the same care. `^rm ` blocks a bare `rm` call, but doesn't block `FOO='bar' rm`. Use the same env-prefix-tolerant anchor:

```bash
SSH_MCP_COMMAND_BLACKLIST="^([A-Za-z_][A-Za-z0-9_]*='[^']*' )*rm( |$)"
```

If you don't trust the agent's `env` values at all, the simplest mitigation is to leave `env` unused in your client config and pass everything through the `command` string yourself.

### Windows support

On Windows, ssh-mcp detects the OpenSSH Authentication Agent service automatically (via the `\\.\pipe\openssh-ssh-agent` named pipe). No `SSH_AUTH_SOCK` needed — just make sure the OpenSSH agent service is running.

## Authentication

All remote operations accept connection parameters:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `host` | SSH hostname or IP (required) | — |
| `port` | SSH port | From SSH config or `22` |
| `username` | SSH username | From SSH config or current user |
| `privateKeyPath` | Path to SSH private key | Auto-detect |
| `password` | SSH password (prefer keys) | — |

**Auth resolution order:** ssh-mcp picks the first match from this list and does not fall through to later entries — this makes the auth method deterministic and predictable.

1. Explicit `privateKeyPath`
2. Explicit `password`
3. ssh-agent (`SSH_AUTH_SOCK` on Unix, `\\.\pipe\openssh-ssh-agent` on Windows)
4. Identity files from `~/.ssh/config` for the host
5. Default key paths (`~/.ssh/id_ed25519`, `id_rsa`, `id_ecdsa`)

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
