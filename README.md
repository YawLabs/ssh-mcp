# @yawlabs/ssh-mcp

[![npm version](https://img.shields.io/npm/v/@yawlabs/ssh-mcp)](https://www.npmjs.com/package/@yawlabs/ssh-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

**Make SSH work for AI tools.** MCP server that manages your SSH environment, diagnoses what's broken, fixes it, and gives your agent remote access to anything.

Built and maintained by [Yaw Labs](https://yaw.sh).

[![Add to Yaw MCP](https://yaw.sh/yaw-mcp-button.svg)](https://yaw.sh/mcp/install?name=SSH&command=npx&args=-y%2C%40yawlabs%2Fssh-mcp&description=Run%20commands%20on%20remote%20hosts%2C%20transfer%20files%2C%20manage%20SSH%20tunnels%20and%20keys&source=https%3A%2F%2Fgithub.com%2FYawLabs%2Fssh-mcp)

One click adds this to your local Yaw MCP config so it's available in every Yaw Terminal session. Or install manually below.

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

Add to your MCP client config:

```json
{
  "mcpServers": {
    "ssh": {
      "command": "npx",
      "args": ["-y", "@yawlabs/ssh-mcp@latest"]
    }
  }
}
```

On Windows wrap with `cmd /c` since Node 20+ can't spawn `.cmd` files directly:

```json
{
  "mcpServers": {
    "ssh": {
      "command": "cmd",
      "args": ["/c", "npx", "-y", "@yawlabs/ssh-mcp@latest"]
    }
  }
}
```

The `@latest` tag makes `npx` re-resolve against the registry on every spawn, so each MCP session uses the newest published version. Or install globally if you'd rather pin (no auto-update):

```bash
npm install -g @yawlabs/ssh-mcp
# then in client config: "command": "ssh-mcp"
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
| `ssh_mkdir` | Create a directory via SFTP. Set `recursive: true` for `mkdir -p` behavior. Unlike the other SFTP tools, the path may be relative — it resolves against the SFTP working directory (normally the remote user's home). `~` is not expanded; SFTP has no shell. |
| `ssh_delete` | Delete a file or empty directory via SFTP. Auto-dispatches unlink vs rmdir based on the path's *own* type (`lstat`), so a symlink is always unlinked — never followed — including a dangling one or one pointing at a directory. Recursive directory delete is intentionally NOT supported -- use `ssh_exec rm -rf` if you need it. |

### Higher-level operations

Tools that wrap common patterns agents build with ssh_exec — faster and less error-prone.

| Tool | Description |
|------|-------------|
| `ssh_multi_exec` | Run a command on multiple hosts in parallel. Returns results per host. Optional `env` param sets per-call environment variables (same POSIX-safe prefix as `ssh_exec`, applied once and sent to every host). Subject to [command policy](#command-policy) if configured (policy is checked once, against the env-prefixed command, before fan-out). |
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
- **Known host, key changed** — reject (MITM protection). The rejection message distinguishes a genuine key mismatch from "the server offered a key type your `known_hosts` entry doesn't cover", so a missing ed25519 line doesn't read as an attack.
- **Unknown host** — accept, unless `SSH_MCP_STRICT_HOST_KEY=1`.

**That last branch is trust-always, not TOFU.** Real trust-on-first-use pins the key it saw the first time and rejects a change afterwards. The connection path never writes to `known_hosts` — no tool adds an entry as a side effect of connecting — so connecting pins nothing: *every* connection to a host absent from `known_hosts` is a "first" use and is accepted, including one where an attacker swapped the key since your last call. Only hosts put into `known_hosts` out of band get mismatch protection — by you, by `ssh-keyscan`, or by `ssh_known_hosts_fix`, the one tool here that does write the file. Call it explicitly to add an entry so future changes are caught.

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

#### Scope: policy covers `ssh_exec` and `ssh_multi_exec` only

Every other tool runs unchecked. That splits into two very different cases.

The structured **read** tools are all exempt, but for two different reasons — they don't reach the remote the same way.

`ssh_find`, `ssh_tail` and `ssh_service_status` do build a shell command (`find`, `tail`, `systemctl`), but from typed parameters with every interpolated value shell-quoted, never from free-form agent input. They're exempt for ergonomics: a tight `^ls` whitelist would otherwise force you to allow `^find `, `^tail `, `^systemctl ` just to keep those tools working — defeating the point of a tight whitelist.

`ssh_ls`, `ssh_stat`, `ssh_read_file` and `ssh_download` build no command at all. They're pure SFTP (`readdir`, `stat`, `readFile`, `fastGet`), so — exactly like the mutating SFTP tools below — there is no command string for a regex to match, and these env vars could not gate them even if you wanted them to. They're grouped with the reads rather than flagged as a gap because they don't mutate remote state. One caveat: `ssh_download` is non-mutating on the **remote** only — it writes to whatever local path it's handed, and these env vars don't constrain that either.

**The SFTP tools that mutate remote state are also unchecked, and that is a genuine gap — not an ergonomics call.** `ssh_write_file`, `ssh_upload`, `ssh_mkdir`, and `ssh_delete` never build a shell command string, so a command-shaped regex has nothing to match. Concretely: `SSH_MCP_COMMAND_BLACKLIST="^rm "` does **not** stop `ssh_delete`, and `SSH_MCP_COMMAND_WHITELIST="^ls "` does **not** stop `ssh_write_file`. Closing this would need a separate path-policy mechanism, which this server deliberately does not have. If you must prevent remote mutation, drop those four tools from your MCP client's tool allowlist (or run a client that gates them) — these two env vars cannot do it.

#### Policy interaction with the `env` parameter (`ssh_exec`, `ssh_multi_exec`)

When `ssh_exec` or `ssh_multi_exec` is called with `env: { KEY: "value" }`, the values are injected as a `KEY='value' ...` shell prefix before the command (see the tool descriptions). **Policy is checked against the full prefixed command**, not the bare `command` argument — once, before fan-out, in the `ssh_multi_exec` case. That's the safer ordering at the protocol layer — but it means whitelist patterns need to anticipate the prefix and must be **anchored**, not substring matches:

```bash
# WRONG -- blocks any ssh_exec call that uses `env`, because the final command
# starts with `KEY='value' ` and never matches `^ls`.
SSH_MCP_COMMAND_WHITELIST="^ls "

# RIGHT -- allow zero or more `KEY='value' ` prefixes before the real command.
SSH_MCP_COMMAND_WHITELIST="^([A-Za-z_][A-Za-z0-9_]*='[^']*' )*ls( |$)"
```

You don't have to diagnose this from a bare rejection: when a whitelist blocks a call that used `env`, the error appends a note explaining that the prefix is why the `^` anchor stopped matching, and suggests the tolerant pattern above.

**Avoid substring-match patterns** like ` ls ` if you're worried about a hostile agent. An agent could pass `env: { ATTACK: " ls " }` to make the final command `ATTACK=' ls ' rm -rf /`, which matches a substring ` ls ` and bypasses the whitelist. Anchored patterns of the form above don't have this weakness because they require the real command name to follow the env-prefix block, not appear inside a quoted env value.

Blacklists need the same care. `^rm ` blocks a bare `rm` call, but doesn't block `FOO='bar' rm`. Use the same env-prefix-tolerant anchor:

```bash
SSH_MCP_COMMAND_BLACKLIST="^([A-Za-z_][A-Za-z0-9_]*='[^']*' )*rm( |$)"
```

If you don't trust the agent's `env` values at all, the simplest mitigation is to leave `env` unused in your client config and pass everything through the `command` string yourself.

### Windows support

On Windows, ssh-mcp uses the OpenSSH Authentication Agent's `\\.\pipe\openssh-ssh-agent` named pipe automatically when `SSH_AUTH_SOCK` is not set. No `SSH_AUTH_SOCK` needed — just make sure the OpenSSH agent service is running.

`ssh_agent_ensure` and `ssh_diagnose` probe that pipe and tell you if the service is down. Remote operations do *not*: they assume the pipe and let the connection fail on its own if the agent isn't there. That is why a stopped agent service shows up as an auth failure rather than an "agent not running" error until you run the diagnostic tools.

## Authentication

All remote operations accept connection parameters:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `host` | SSH hostname or IP (required) | — |
| `port` | SSH port | From SSH config or `22` |
| `username` | SSH username | From SSH config or current user |
| `privateKeyPath` | Path to SSH private key | Auto-detect |
| `password` | SSH password (prefer keys) | — |

**Auth resolution.** An *explicit* credential wins outright and nothing else is offered. With neither given, ssh-mcp offers the ssh-agent **and** one on-disk key **together** — the way the OpenSSH client does — and lets the server pick during the auth exchange. It is not a strict first-match chain past step 2.

1. **Explicit `privateKeyPath`** — used alone. The agent is not offered and no other key is read.
2. **Explicit `password`** — used alone, same as above.
3. **Neither given** — both of the following are configured on the same connection:
   - **ssh-agent** — `SSH_AUTH_SOCK`, or on Windows the `\\.\pipe\openssh-ssh-agent` named pipe. The Windows pipe is assumed unconditionally; ssh-mcp does not check that the OpenSSH Authentication Agent service is actually running.
   - **One on-disk key** — the first *readable* path in `ssh -G <host>`'s `identityfile` list. OpenSSH emits that list for **every** host, including one with no `IdentityFile` line (it defaults to `~/.ssh/id_rsa`, `id_ecdsa`, `id_ecdsa_sk`, `id_ed25519`, `id_ed25519_sk`), so this is the normal path — not a path reserved for hosts you configured an identity for. ssh-mcp's own built-in list (`~/.ssh/id_ed25519`, `id_rsa`, `id_ecdsa`) is a fallback used only when `ssh -G` cannot run at all, e.g. no SSH client installed.

Two things worth knowing about step 3:

- **Only one on-disk key is ever offered** — the first candidate that exists. ssh-mcp does not walk the whole identity list the way `ssh` does, so if the first readable key is the wrong one, authentication rests on the agent's keys. Pass `privateKeyPath` to force a specific key.
- **When an agent is configured, an *encrypted* on-disk key is skipped** and the scan moves to the next candidate. The underlying ssh2 library parses `privateKey` eagerly and errors with "no passphrase given" on an encrypted key, which would break the common setup of an encrypted key on disk with its decrypted copy loaded in the agent. With no agent configured, the first existing key is loaded regardless of encryption and ssh2 surfaces the passphrase error itself. Because the Windows pipe above is assumed unconditionally, the skip is always in force on Windows.

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
