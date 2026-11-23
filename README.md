# @yawlabs/ssh-mcp

[![Add to Yaw MCP](https://yaw.sh/yaw-mcp-button.svg)](https://yaw.sh/mcp/install?name=SSH&command=npx&args=-y%2C%40yawlabs%2Fssh-mcp&description=Run%20remote%20commands%2C%20transfer%20files%20over%20SFTP%2C%20manage%20ssh-agent%20keys%20and%20known_hosts%2C%20and%20diagnose%20SSH%20failures&source=https%3A%2F%2Fgithub.com%2FYawLabs%2Fssh-mcp)

One click adds this to your local Yaw MCP config so it's available in every Yaw Terminal session. Tested with Yaw MCP 1.1.13 or newer. Or install manually below.

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
| `ssh_exec` | Execute a command on a remote host. Returns up to three content blocks, status first: `[exit code: N]` (plus `[signal: NAME]` with `code: -1` when the channel closed signal-only, and a flag when a stream hit the 10 MB cap), then `[stderr]`, then `[stdout]`. Status leads so a proxy that cuts long results — Yaw MCP keeps about 100 KB by default — never drops the exit code. A non-zero exit or a signal is reported as a normal result, not a tool error (`isError` is not set): read the `[exit code: N]` block. Optional `env` param sets per-call environment variables (POSIX-safe prefix, works regardless of sshd's `AcceptEnv`). Subject to [command policy](#command-policy) if configured. |
| `ssh_read_file` | Read a file from a remote host via SFTP (whole file up to 10 MB). Optional `offset` and `length` (bytes) read one page and return a `[bytes A-B of SIZE; next offset: N]` status block before the text — use them for a large file, or behind a proxy that caps results. |
| `ssh_write_file` | Write content to a file on a remote host via SFTP. |
| `ssh_upload` | Upload a local file to a remote host via SFTP. |
| `ssh_download` | Download a file from a remote host to local filesystem. |
| `ssh_ls` | List files in a directory on a remote host. |
| `ssh_stat` | Get metadata for a file or directory (size, mode in octal, uid/gid, mtime/atime, path type (file / directory / symlink -> target kind)). Use instead of parsing `ls -la`. |
| `ssh_mkdir` | Create a directory via SFTP. Set `recursive: true` for `mkdir -p` behavior. Unlike the other SFTP tools, the path may be relative — it resolves against the SFTP working directory (normally the remote user's home). `~` is not expanded; SFTP has no shell. |
| `ssh_delete` | Delete a file or empty directory via SFTP. Auto-dispatches unlink vs rmdir based on the path's *own* type (`lstat`), so a symlink is always unlinked — never followed — including a dangling one or one pointing at a directory. Recursive directory delete is intentionally NOT supported -- use `ssh_exec rm -rf` if you need it. |

### Higher-level operations

Tools that wrap common patterns agents build with ssh_exec — faster and less error-prone.

| Tool | Description |
|------|-------------|
| `ssh_multi_exec` | Run a command on multiple hosts in parallel. Returns results per host, and flags the whole call `isError` when any host errored or exited non-zero (unlike `ssh_exec`). Optional `env` param sets per-call environment variables (same POSIX-safe prefix as `ssh_exec`, applied once and sent to every host). Subject to [command policy](#command-policy) if configured (policy is checked once, against the env-prefixed command, before fan-out). |
| `ssh_find` | Search for files remotely with structured parameters (`name`, `type`, `size`, `depth`, `newer` — match files modified more recently than a reference path). |
| `ssh_tail` | Read the last N lines of a file, optionally filtered by a grep pattern. |
| `ssh_service_status` | Check systemd service status (active, PID, uptime, description). Flags `isError` only when the unit could not be found / queried, not when an existing unit is intentionally stopped. |

### Auto-diagnostics

When any remote operation fails, ssh-mcp automatically runs diagnostics and includes the results in the error response. Your agent doesn't need to call `ssh_diagnose` separately — it gets told what's wrong and how to fix it right in the error message.

### Connection pooling

Remote operations reuse SSH connections automatically. When your agent makes multiple calls to the same host, the first call opens a connection and subsequent calls reuse it. Connections are kept alive for 60 seconds after the last use, then closed automatically.

The pool caps at 100 connections by default, and a connection still being dialed counts against the cap. When the cap is reached the pool closes an idle connection to make room. If every slot is in use or dialing, a tool call waits for one instead of failing:

- **A single-host remote tool** (`ssh_exec`, the SFTP tools, `ssh_find`, `ssh_tail`, `ssh_service_status`) waits up to its `timeout` (30s for the SFTP tools, which have no `timeout` parameter) and is next in line for the first slot that frees, so an `ssh_exec` arriving in the middle of a wide `ssh_multi_exec` runs between two of its hosts rather than being refused for the whole run. It reports `Connection pool is full` only if it never won a slot in that time.
- **`ssh_multi_exec`** runs at most `SSH_MCP_MAX_POOL_SIZE` hosts at once (default 100) and works through a longer list as slots free up, so raising the cap raises its parallelism; `timeout` is per host, not a bound on the whole call. When the pool is full it waits, and gives up only when none of its own hosts holds a slot and a full `timeout` has passed with none of them starting or finishing. The hosts waiting at that point (up to one per parallel slot) and every host still queued then report `Connection pool is full`; the queued ones are never attempted.

A call reaches `Connection pool is full` only when other calls — a long `ssh_exec`, a concurrent `ssh_multi_exec` — kept every slot from it for a full `timeout`; a fan-out wider than the cap that has the pool to itself never does, however long it runs. If you see it, rerun once those calls finish (for `ssh_multi_exec`, the hosts that reported it), or raise the cap with `SSH_MCP_MAX_POOL_SIZE=<n>` in the server's environment. The error names the variable.

The library's `acquire()` / `withConnection()` do not wait by default: they reject at once with a `PoolFullError` (`code: "ERR_SSH_MCP_POOL_FULL"`, `isPoolFullError()`) unless you pass `{ waitForCapacityMs }` — see [Programmatic usage](#programmatic-usage).

### SSH config support

All connections respect your `~/.ssh/config`. Host aliases, custom ports, usernames, identity files, and ProxyJump settings are used automatically. If you have `Host myserver` configured in your SSH config, just pass `host: "myserver"` — ssh-mcp resolves everything.

**Edits to `~/.ssh/config` need a server restart.** The config resolved for each host (via `ssh -G`) is memoized for the life of the server process, so a running server keeps using what it resolved first; `ssh_config_lookup` is not cached and shows the new values straight away. A lookup that failed (no SSH client, a timed-out `ssh -G`) is not cached and is retried on the next call.

**ProxyJump / bastion hosts** are supported automatically. If your SSH config has `ProxyJump bastion` for a host, ssh-mcp connects through the bastion transparently. Chained proxies work too.

### Host key verification

All remote operations verify the server's host key against `~/.ssh/known_hosts`:

- **Known host, key matches** — accept.
- **Known host, key changed** — reject (MITM protection). The rejection message distinguishes a genuine key mismatch from "the server offered a key type your `known_hosts` entry doesn't cover", so a missing ed25519 line doesn't read as an attack.
- **Unknown host** — accept, unless strict mode is on (`SSH_MCP_STRICT_HOSTKEYS=1`).

**On a port other than 22, only `[host]:port` entries can reject a key.** ssh-mcp also consults the bare-host entry, as OpenSSH does, but only to ACCEPT a key that matches it: a bare entry describes whatever answers on port 22, often a different sshd. So a second sshd on `host:2222` with no `[host]:2222` line is an unknown host (accepted, or refused in strict mode), not a key mismatch. To pin it, add a port-qualified entry (`ssh-keyscan -p 2222 host`, or `ssh_known_hosts_fix` with the port).

**That last branch is trust-always, not TOFU.** Real trust-on-first-use pins the key it saw the first time and rejects a change afterwards. The connection path never writes to `known_hosts` — no tool adds an entry as a side effect of connecting — so connecting pins nothing: *every* connection to a host absent from `known_hosts` is a "first" use and is accepted, including one where an attacker swapped the key since your last call. Only hosts put into `known_hosts` out of band get mismatch protection — by you, by `ssh-keyscan`, or by `ssh_known_hosts_fix`, the one tool here that does write the file. Call it explicitly to add an entry so future changes are caught.

For stricter environments, set `SSH_MCP_STRICT_HOSTKEYS=1` (or `true`, case-insensitive) to reject unknown hosts. Add them explicitly with `ssh_known_hosts_fix` first. The older name `SSH_MCP_STRICT_HOST_KEY` still works and accepts the same values, but prefer the new one: credential scanners such as Yaw MCP's doctor treat any name with a `_KEY` segment as a secret, and flag the old name as a plaintext credential.

The diagnostic tools (`ssh_test`, `ssh_diagnose`) probe with the system `ssh` client, which accepts an unknown host and refuses a changed key, so a changed key shows up there too. Those probes **never write `known_hosts`**: a newly seen key goes to the null device, not to your file, so running a diagnostic pins nothing and cannot satisfy strict mode on your behalf. They only run `echo SSH_OK` — no passwords or data pass through, though an unknown host does see the public keys the client offers. Real operations always go through the `hostVerifier`.

### Command policy

`ssh_exec` and `ssh_multi_exec` accept free-form shell commands from the agent. For security-conscious deployments, you can restrict which commands run via two env vars, each accepting a comma-separated list of regex patterns:

- `SSH_MCP_COMMAND_WHITELIST` — if set, the command **must** match at least one pattern, else it's blocked.
- `SSH_MCP_COMMAND_BLACKLIST` — if set, the command **must not** match any pattern, else it's blocked.

When both are set, the command must pass both checks (whitelist first, then blacklist). When neither is set (the default), all commands are allowed.

**This is a guard rail, not a security boundary.** A regex over a string that a remote shell will interpret can catch an agent going off-script; it cannot contain a hostile one. It covers only `ssh_exec` and `ssh_multi_exec`: the SFTP tools are not gated at all (see [Scope](#scope-policy-covers-ssh_exec-and-ssh_multi_exec-only)). An agent that also has a shell and the credential can bypass any control in this server. If you need a real boundary, enforce it on the remote host: a restricted account, a forced command in `authorized_keys`, sudo rules, or filesystem permissions.

Patterns are JavaScript regexes. Use `^` and `$` for anchored matches; otherwise patterns are treated as substring matches. Commas separate patterns, except a comma inside a character class (`[,]`), an escaped comma (`\,`), or one in a `{m,n}` quantifier, which all stay part of the pattern. Any other literal comma, including one inside a group, must be written `\,`, `[,]` or `\x2c`. **In a list of more than one pattern, write a literal comma as `\,` (`[a\,b]`) rather than `[,]`**: an unescaped comma in a class is refused whenever another entry follows, so `^foo[,]bar$` works alone but must be `^foo[\,]bar$` (or kept as its own single-pattern variable) beside `^df$`.

**A malformed entry blocks everything.** If any entry in either variable fails to compile, every `ssh_exec` and `ssh_multi_exec` call is refused with an error naming the entry, until you fix or unset the variable. The same applies to a character class that may have swallowed a separator: a class holding an unescaped comma is refused when its content suggests a swallowed separator (an unescaped `[` before the comma, or a letter, digit, `_`, `^`, `[` or another comma after it) or when another entry follows the class, because `^rm[,^reboot,^mkfs[.]` and `^rm[abc,>],^df` would otherwise compile as one pattern and stop blocking `reboot` and `rm`. Escape the stray bracket as `\[`, or write a literal comma as `\,` (`[a\,b]`). This catches likely typos and is not a proof: `^rm[,>]` still reads as one class.

```bash
# Allowlist: list directories, check disk space and uptime. Each pattern covers the whole line.
SSH_MCP_COMMAND_WHITELIST='^ls( [A-Za-z0-9_./:=@%+-]+)*$,^df( -[A-Za-z]+)*$,^uptime$'

# Denylist: best effort only. Catches the obvious spellings of these commands, nothing more.
SSH_MCP_COMMAND_BLACKLIST='^rm ,^shutdown,^reboot,^mkfs,^dd if=,>\s*/dev/'
```

**While a whitelist is active, a matching command is still refused if it:**

- contains shell control syntax anywhere, even inside quotes: `;` `&` `|` a backtick `$(` `${` `$[` `@{` `(` `)` `<` `>` or a line break. Quotes are not interpreted because the remote login shell is unknown and shells disagree about them. So `grep 'a|b' file` is refused too, and so is `git show HEAD@{1}`, because `@{` runs code in PowerShell.
- starts with a variable assignment, such as `LD_PRELOAD=/tmp/x.so ls` or `PATH=/tmp ls`. This includes the prefix built from the `env` parameter.

Set `SSH_MCP_COMMAND_ALLOW_SHELL_SYNTAX=1` (or `true`) to turn both checks off and go back to pattern-only matching. Each pattern is then responsible for the entire command, so anchor it at both ends as in the example above. Any value other than `1`, `true`, `0`, `false` or empty is rejected as a misconfiguration.

**Choosing what to allow.** Only allow programs that cannot run other programs or write files with the arguments you permit. These look read-only and are not:

- `find` runs commands and deletes files (`-exec`, `-execdir`, `-ok`, `-delete`, `-fprint`).
- `awk` runs commands (`system()`, `| getline`) and writes files.
- `tar` runs commands (`--checkpoint-action=exec=...`, `--to-command`, `--use-compress-program`).
- `sed` (`e` command, `w`), `xargs`, `env`, `sudo`, `ssh`, `git` (`-c`, aliases, hooks), `less` and `vim` can also launch programs.
- `cat`, `tail` and `head` run nothing, but read any file the account can read, including keys and credentials.

A whitelist only sees the command text, so a broad pattern such as `^find ` allows all of the above.

**Denylists are best effort.** The same command has endless spellings: `^rm ` misses `/bin/rm`, `\rm`, `r''m`, `command rm`, `busybox rm`, and anything run through `sh -c` or a script. Pipes to `curl` and similar exfiltration need no denied word at all. Use a denylist to catch mistakes, never as the control that keeps something from happening.

Blocked commands surface as a clear error mentioning which pattern (or which env var) rejected the call, so the agent can adapt rather than guess. Policy is enforced before the SSH connection opens — no remote process is started for a blocked command.

#### Scope: policy covers `ssh_exec` and `ssh_multi_exec` only

Every other tool runs unchecked. That splits into two very different cases.

The structured **read** tools are all exempt, but for two different reasons — they don't reach the remote the same way.

`ssh_find`, `ssh_tail` and `ssh_service_status` do build a shell command (`find`, `tail`, `systemctl`), but from typed parameters with every interpolated value shell-quoted, never from free-form agent input. They're exempt for ergonomics: a tight `^ls` whitelist would otherwise force you to allow `^find `, `^tail `, `^systemctl ` just to keep those tools working — defeating the point of a tight whitelist.

`ssh_ls`, `ssh_stat`, `ssh_read_file` and `ssh_download` build no command at all. They're pure SFTP (`readdir`, `stat`, `readFile`, `fastGet`), so — exactly like the mutating SFTP tools below — there is no command string for a regex to match, and these env vars could not gate them even if you wanted them to. They're grouped with the reads rather than flagged as a gap because they don't mutate remote state. One caveat: `ssh_download` is non-mutating on the **remote** only — it writes to whatever local path it's handed, and these env vars don't constrain that either.

**The SFTP tools that mutate remote state are also unchecked, and that is a genuine gap — not an ergonomics call.** `ssh_write_file`, `ssh_upload`, `ssh_mkdir`, and `ssh_delete` never build a shell command string, so a command-shaped regex has nothing to match. Concretely: `SSH_MCP_COMMAND_BLACKLIST="^rm "` does **not** stop `ssh_delete`, and `SSH_MCP_COMMAND_WHITELIST="^ls "` does **not** stop `ssh_write_file`. Closing this would need a separate path-policy mechanism, which this server deliberately does not have. If you must prevent remote mutation, drop those four tools from your MCP client's tool allowlist (or run a client that gates them) — these two env vars cannot do it.

#### Policy interaction with the `env` parameter (`ssh_exec`, `ssh_multi_exec`)

When `ssh_exec` or `ssh_multi_exec` is called with `env: { KEY: "value" }`, the values are injected as a `KEY='value' ...` shell prefix before the command (see the tool descriptions). **Policy is checked against the full prefixed command**, not the bare `command` argument — once, before fan-out, in the `ssh_multi_exec` case. That's the safer ordering at the protocol layer, and it has two effects under a whitelist.

**`env` is refused by default while a whitelist is active.** A variable such as `LD_PRELOAD` or `PATH` changes what an allowed command actually runs, so the prefix counts as a leading assignment (see above). Remove `env` from the call. A `^ls` pattern will not match the prefixed string in any case, and the rejection explains why.

If you must allow a specific variable, set `SSH_MCP_COMMAND_ALLOW_SHELL_SYNTAX=1` and write a pattern that names the variable and spells out the whole command. Never use a generic variable-name pattern, which would admit `LD_PRELOAD` and `PATH`:

```bash
SSH_MCP_COMMAND_ALLOW_SHELL_SYNTAX=1
SSH_MCP_COMMAND_WHITELIST="^FOO='(?:[^']|'\\\\'')*' ls( [A-Za-z0-9_./:=@%+-]+)*$"
```

(That is the double-quoted shell form. The regex itself is `^FOO='(?:[^']|'\\'')*' ls( [A-Za-z0-9_./:=@%+-]+)*$`, which is what belongs in a JSON `env` block after JSON escaping.)

**Avoid substring-match patterns** like ` ls `. An agent could pass `env: { ATTACK: " ls " }` to make the final command `ATTACK=' ls ' some-other-command`, which contains ` ls `. The assignment check refuses that by default, but `some-other-command ls` would still match, so anchor every pattern.

Blacklists see the prefix too. `^rm ` blocks a bare `rm` call, but doesn't block `FOO='bar' rm`. An env-tolerant anchor closes that one spelling, and like every denylist it stays best effort:

```bash
SSH_MCP_COMMAND_BLACKLIST="^([A-Za-z_][A-Za-z0-9_]*='(?:[^']|'\\\\'')*' )*rm( |$)"
```

### Windows support

On Windows, ssh-mcp uses the OpenSSH Authentication Agent's `\\.\pipe\openssh-ssh-agent` named pipe automatically when `SSH_AUTH_SOCK` is not set. No `SSH_AUTH_SOCK` needed — just make sure the OpenSSH agent service is running.

On the [oam](https://oamjs.org) runtime, the launcher serves only on oam 0.21.1 or newer. Agent auth needs a `net` that can dial a named pipe or a Unix socket (that is how ssh2 reaches the agent), which older oam releases could not do. On oam 0.20.2 (Windows) the MCP handshake, `ssh_config_lookup`, `ssh_key_list` and `ssh_agent_ensure` were verified through the launcher, and ssh2's own agent client was verified dialing a named pipe and completing an identities request (against a stand-in agent on a pipe). An agent-only `ssh_exec` end to end has so far been verified on Node only. Started from Node, the launcher prefers oam (`auto`); to rule the runtime out when agent auth fails there, set `SSH_MCP_RUNTIME=node`. Started by oam with no Node on `PATH`, it can still serve on oam: see [Runtime selection](#runtime-selection). ed25519 and ECDSA keys and ed25519-only servers used to be broken on oam 0.20.2; that is fixed as of 0.21.1 — see [oam key support](#oam-key-support).

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
   - **One on-disk key** — the first *usable* path in `ssh -G <host>`'s `identityfile` list: it exists, is a private key, and is not encrypted when an agent is configured. OpenSSH emits that list for **every** host, including one with no `IdentityFile` line (it defaults to `~/.ssh/id_rsa`, `id_ecdsa`, `id_ecdsa_sk`, `id_ed25519`, `id_ed25519_sk`), so this is the normal path — not a path reserved for hosts you configured an identity for. ssh-mcp's own built-in list (`~/.ssh/id_ed25519`, `id_rsa`, `id_ecdsa`) is a fallback used only when `ssh -G` cannot run at all, e.g. no SSH client installed.

Two things worth knowing about step 3:

- **Only one on-disk key is ever offered** — the first usable candidate (exists, is a private key, and is not encrypted when an agent is configured). A candidate that is not a private key at all — an empty file, a stray text file, or the classic `IdentityFile ~/.ssh/id_ed25519.pub` typo — is always skipped and the scan moves on. ssh-mcp does not offer every identity the way `ssh` does, so if the first usable key is the wrong one, authentication rests on the agent's keys. Pass `privateKeyPath` to force a specific key.
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
import { connect, exec, diagnose, ensureAgent, listSshKeys, checkGitSsh, ConnectionPool, isPoolFullError } from '@yawlabs/ssh-mcp';

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
// A full pool rejects at once with a PoolFullError; pass a budget to wait for a slot
// instead, the way the tools do, and match the rejection on its code, not its text
try {
  await pool.withConnection(
    { host: 'other-server' },
    async (client) => {
      const r3 = await exec(client, 'uptime');
      console.log(r3.stdout);
    },
    { waitForCapacityMs: 30_000 },
  );
} catch (err) {
  if (!isPoolFullError(err)) throw err;
  console.log('no slot within 30s:', err.message);
}
pool.drain(); // close all connections when done

// Diagnose issues
const report = diagnose('my-server');
console.log(report.overall); // "ok" | "warning" | "error"
for (const check of report.checks) {
  console.log(`[${check.status}] ${check.name}: ${check.message}`);
}
```

## Runtime selection

The `ssh-mcp` command — what `npx @yawlabs/ssh-mcp` runs — is a small launcher. The default runtime, `auto`, prefers the newest usable [oam](https://oamjs.org) and falls back to Node when there is none. The minimum is the **latest oam release, currently 0.21.1**, and the launcher never serves on an older oam.

The default prefers oam again as of **oam 0.21.1**, which closed the `node:crypto` gaps it used to trip over: an ed25519 key file, an ECDSA key file, an ed25519-only server and curve25519 key exchange all work there. It was Node-only for one release line (0.18.4-0.18.6), while oam 0.20.2 was the floor; those four gaps are tracked in [YawLabs/oam#489](https://github.com/YawLabs/oam/issues/489), now closed.

Two environment variables control the choice; set them in your MCP client's `env` block:

- `SSH_MCP_RUNTIME` — which runtime to use. Case-insensitive, surrounding whitespace ignored; any value other than `oam` or `node` behaves as `auto`.
  - `auto` (default) — prefer oam. On a Node host the launcher discovers the newest usable oam and spawns it, falling back to Node in-process when none is found. Started by oam at or above the floor it serves in-process, with no second oam. Started by oam below the floor it hands off to the newest usable oam, else to Node on `PATH`, or exits with status 1 when there is neither; see the list below.
  - `oam` — require oam. Fails loudly: if no usable oam is found, the launcher prints what it found and why each one was passed over to stderr, and exits with status 1 instead of starting the server.
  - `node` — always Node. The launcher does not look for oam, and `OAM_BIN` is ignored.
- `OAM_BIN` — under `auto` or `oam` (whenever the launcher looks for oam), path to an oam binary to use in preference to discovery, when it is 0.21.1 or newer. If it does not exist, is older, will not run, or does not answer `--version` with oam's own `oam x.y.z` banner (another program's version, such as Node's `v22.x.y`, does not count), the launcher says so on stderr and carries on with discovery.

Discovery (under `auto` or `oam`, whenever the launcher looks for oam) looks in `$OAM_INSTALL_DIR` (when set — the oam installer's install target), then `%LOCALAPPDATA%\oam\bin` (Windows only), then `~/.oam/bin`, then every directory on `PATH`; asks every oam binary it finds for its version, counting only an answer that carries oam's own `oam x.y.z` banner; and uses the newest one at 0.21.1 or newer. On a tie the one found first wins, so an installed copy beats one on `PATH`. On Windows only `oam.exe` counts: an `oam.cmd`/`oam.bat` shim on `PATH` is never run, and is named on stderr when no usable oam is found.

With `SSH_MCP_RUNTIME=oam` an unusable oam is an error: the launcher names on stderr each oam (and `OAM_BIN`) it passed over and why — older than 0.21.1, not runnable, or a shim — or the chosen oam that failed to start, and exits with status 1. It does not fall back to Node.

When the launcher is itself started by oam (`oam run <path>/bin/ssh-mcp.mjs`, which is how Yaw MCP starts an `npx @yawlabs/ssh-mcp` entry when a recent oam is installed):

- In `auto` mode an oam 0.21.1 or newer serves the server itself, in the same process, with no note about unusable key types -- the gap that used to earn one is closed. An oam below the floor never serves there: it hands off to the newest usable oam it can find, else to Node on `PATH`, or exits with status 1 when there is neither.
- With `SSH_MCP_RUNTIME=oam` on oam 0.21.1 or newer, it runs the server on that oam, in the same process. Nothing is discovered or spawned, and `OAM_BIN` is not read: that oam is the one required. On an older oam it never runs the server there; it hands off to the newest usable oam it can find, or exits with status 1.
- With `SSH_MCP_RUNTIME=node` it hands the server off to Node on `PATH`, whatever the oam version, and exits with status 1 when there is none.

Whenever an oam host starts a child (the handoffs above), the launcher removes `--permission` and `--allow-*` flags from the child's inherited `NODE_OPTIONS`. oam (since 0.18.0) adds its own permission flags to every child's `NODE_OPTIONS`, and Node refuses some of them there (`--allow-net is not allowed in NODE_OPTIONS`, exit 9); this server is not sandboxed, so there is nothing to pass on. An oam that was itself started with `--permission` re-adds the flags inside `spawn()`, which the launcher cannot undo, so do not start it that way.

### oam key support

oam 0.21.1 supports ed25519 and ECDSA key files, servers whose only host key is ed25519, and curve25519 key exchange in ssh2. Measured through the launcher on oam 0.21.1 (`oam run bin/ssh-mcp.mjs`): MCP `initialize`, `tools/list` (the same 21 tools as on Node) and `tools/call` on `ssh_key_list`, `ssh_config_lookup` and `ssh_agent_ensure`; and against a local ssh2 server, identical to Node 22, an ed25519 key file, an ECDSA key file, an ed25519-only host key and `curve25519-sha256` all complete an exec, with ssh2's probes reporting `eddsaSupported = true` and `curve25519Supported = true`. An ed25519 key held in the agent was not measured end to end; what used to block it was ssh2 failing to parse an ed25519 public key on oam, and the underlying `crypto.verify` gap is closed.

The four `node:crypto` gaps that used to break these on oam 0.20.2 -- a `crypto.verify` that threw on an Ed25519 private key (which is how ssh2 decides it supports ed25519), a missing `crypto.diffieHellman`, x25519 key pairs that could not be generated, and SEC1 (`EC PRIVATE KEY`) signing that threw -- are listed in the launcher's comments and were tracked in [YawLabs/oam#489](https://github.com/YawLabs/oam/issues/489), now closed.

To pin Node regardless of what the default prefers:

```json
{
  "mcpServers": {
    "ssh": {
      "command": "npx",
      "args": ["-y", "@yawlabs/ssh-mcp@latest"],
      "env": { "SSH_MCP_RUNTIME": "node" }
    }
  }
}
```

On Windows, add the same `env` block to the `cmd /c` form from [Quick start](#quick-start).

## Requirements

- Node.js 18+
- SSH client installed (for diagnostics and environment management)
- Optional: [oam](https://oamjs.org) 0.21.1+ (preferred by `auto` when a usable one is installed) — see [Runtime selection](#runtime-selection)

## License

MIT

[![Follow @YawLabs on X](https://img.shields.io/badge/follow-%40YawLabs-000000?logo=x&logoColor=white)](https://x.com/YawLabs)
