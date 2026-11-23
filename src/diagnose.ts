import { execFileSync } from "node:child_process";
import {
  closeSync,
  existsSync,
  constants as fsConstants,
  fstatSync,
  openSync,
  readdirSync,
  readFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export interface DiagnosticResult {
  status: "ok" | "warning" | "error";
  message: string;
}

export interface DiagnosticReport {
  overall: "ok" | "warning" | "error";
  checks: Array<{ name: string } & DiagnosticResult>;
  suggestions: string[];
}

// NOTE on duplicate config parsing: `checkSshConfig` below parses `~/.ssh/config`
// directly (regex) for the read-only diagnostic, while `resolveConfig` in ssh.ts
// delegates to `ssh -G` to get the resolved effective settings. The two paths
// answer different questions (raw text dump vs. resolved values with Match/
// Include/host-pattern expansion), so unifying them is deferred. If a new SSH
// config directive is added, both parsers need updating independently.
//
// checkSshConfig's parse is APPROXIMATE. `ssh -G` (via configLookup in env.ts /
// resolveConfig in ssh.ts) is the authority on what SSH will actually do; the
// diagnostic exists only to show the operator the relevant slice of their config
// file. What it DOES handle: `Host <patterns>` and the `Host=<patterns>`
// separator form; WHITESPACE-separated pattern lists; `*` and `?` wildcards;
// `!` negation (a matching negated pattern disqualifies the whole line, per
// ssh_config(5) PATTERNS); and `#` comments, stripped to end-of-line before any
// parsing, so neither a word in a trailing comment nor a commented-out directive
// is read as config.
//
// Note what is deliberately NOT handled: commas are NOT pattern separators on a
// `Host` line. `Host` takes whitespace-separated patterns, each matched whole;
// comma-separated pattern LISTS are a `Match` criteria construct. Probed on
// OpenSSH_10.2p1 -- with `Host web1,web2` + `User deploy`, both `ssh -G web1`
// and `ssh -G web2` report the DEFAULT user, i.e. the block applies to neither.
// Splitting on commas here would report the block for both, which is the one
// failure mode this diagnostic must not have. Treating the token as a single
// literal pattern reproduces ssh exactly.
//
// Known limitations. All but the last make the report INCOMPLETE (a directive
// that applies is not shown) rather than wrong-way-round (a directive that does
// not apply is shown as if it did):
//   - `Include` directives are not followed. Directives living in an included
//     file are invisible to the diagnostic.
//   - `Match` blocks are not evaluated. A `Match` line ENDS the current Host
//     block and nothing inside it is reported, even when its criteria hold.
//   - Quoted patterns (`Host "my server"`) are not unquoted and will not match.
//   - A `#` inside a quoted value (e.g. a ProxyCommand argument) is treated as a
//     comment start and truncates the line early, where ssh would keep it.
//   - Percent tokens (%h, %p) and CanonicalizeHostname rewriting are not applied.
//   - The one over-reporting case: directives are echoed verbatim, with no
//     keyword/value splitting, no first-value-wins precedence, and no built-in
//     defaults. Every `Host` line that selects the host contributes its body, so
//     two conflicting `User` lines are both printed even though ssh honours only
//     the first. The report is a superset of the effective config here; it never
//     invents a directive the operator did not write, but the operator must
//     apply first-value-wins themselves (or read `ssh -G`) to know which one won.
//
// Files in ~/.ssh that are never private keys. Shared by `checkSshKeys` below and
// `listSshKeys` in env.ts -- they scan the same directory for the same thing, and
// previously kept two hand-maintained copies of this list that had already drifted
// ("environment" was in one and not the other).
export const SSH_NON_KEY_FILES: ReadonlySet<string> = new Set([
  "known_hosts",
  "known_hosts.old",
  "config",
  "authorized_keys",
  "environment",
]);

// Validate a hostname before it reaches ssh / ssh-keygen / ssh-keyscan. No shell is
// involved anywhere (every call is execFileSync with an argv), so the concern is
// OPTION injection -- a host read as a flag -- plus keeping odd bytes out of argv.
// Accepted: letters, digits, dots, underscores and hyphens (not leading), or a
// bracketed IPv6 literal. A port is never part of the host.
export const INVALID_HOSTNAME_SUGGESTION =
  "Provide a valid hostname: letters, digits, dots, underscores and hyphens (not leading), or a bracketed IPv6 literal like [::1]. Pass the port separately, not as host:port.";

export function isValidHostname(host: string): boolean {
  if (host.length === 0 || host.length > 253) return false;
  // IPv6 in brackets: [::1], [2001:db8::1]
  if (host.startsWith("[")) {
    return /^\[[0-9a-fA-F:]+\]$/.test(host);
  }
  // Reject a leading '-' so a host like "-oProxyCommand=evil" or "-E" can't be
  // smuggled in as a flag where it reaches ssh / ssh-keygen positionally (those
  // calls can't all be guarded with `--` -- e.g. `ssh-keygen -F <host>` takes the
  // host as the value of -F). Internal hyphens (my-server) stay valid.
  if (host.startsWith("-")) return false;
  // Standard hostname, IPv4, or SSH config alias (alphanumeric, dots, hyphens, underscores).
  // Underscore is allowed even though DNS labels technically forbid it, because SSH config
  // aliases commonly use it (e.g. "my_server") and rejecting them would surprise users.
  return /^[a-zA-Z0-9._-]+$/.test(host);
}

/** Default kill timeout for every runArgs child. */
export const RUN_ARGS_TIMEOUT_MS = 10000;

export interface RunArgsOptions {
  /**
   * Child-env overrides merged on top of a copy of process.env. A key mapped to
   * `undefined` is DELETED from the copy (so the child does not inherit it). Omit
   * the option entirely and the child inherits process.env unchanged.
   */
  env?: Record<string, string | undefined>;
}

export function runArgs(cmd: string, args: string[], options: RunArgsOptions = {}): { stdout: string; ok: boolean } {
  let env: Record<string, string> | undefined;
  if (options.env) {
    env = {};
    for (const [k, v] of Object.entries(process.env)) {
      if (typeof v === "string") env[k] = v;
    }
    for (const [k, v] of Object.entries(options.env)) {
      if (v === undefined) delete env[k];
      else env[k] = v;
    }
  }
  try {
    // windowsHide: oam 0.19.1 stopped giving every child CREATE_NO_WINDOW, and Node
    // never did, so without it each ssh / ssh-add / ssh-keygen probe can flash a console.
    const stdout = execFileSync(cmd, args, {
      env,
      encoding: "utf8",
      timeout: RUN_ARGS_TIMEOUT_MS,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    return { stdout: stdout.trim(), ok: true };
  } catch (e: unknown) {
    // Capture both stdout and stderr — many SSH commands (ssh -T, ssh-add) output to stderr
    const err = e as { stdout?: Buffer; stderr?: Buffer; message?: string; code?: string };
    const stdout = err.stdout?.toString().trim() || "";
    const stderr = err.stderr?.toString().trim() || "";
    // A child killed by our own timeout throws with code ETIMEDOUT, usually empty
    // streams, and the message "spawnSync <cmd> ETIMEDOUT" -- which carries none of the
    // markers the classifiers look for ("timed out" is not a substring of ETIMEDOUT).
    // ssh's ConnectTimeout=5 is per address, so a host with two dead addresses or slow
    // DNS reaches this. Say "timed out" in words so it classifies as a timeout.
    if (err.code === "ETIMEDOUT") {
      const note = `${cmd} timed out after ${RUN_ARGS_TIMEOUT_MS / 1000}s and was killed`;
      return { stdout: [stdout, stderr, note].filter(Boolean).join("\n"), ok: false };
    }
    const output = [stdout, stderr].filter(Boolean).join("\n") || err.message || "";
    return { stdout: output, ok: false };
  }
}

/** The Windows OpenSSH agent's default named pipe. */
export const WINDOWS_AGENT_PIPE = "\\\\.\\pipe\\openssh-ssh-agent";

/**
 * The child-env override that points ssh-add at `socket`. The DEFAULT Windows pipe
 * is reached by leaving SSH_AUTH_SOCK unset (Windows ssh-add falls back to it), and
 * unsetting rather than omitting keeps a stale inherited value from redirecting it.
 * Every other socket -- a Unix path, or a CUSTOM named pipe (a pageant bridge,
 * gpg-agent, a password manager) -- is passed through as SSH_AUTH_SOCK, so the
 * agent that answers is the one the caller asked about. Pipe names are
 * case-insensitive on Windows.
 */
export function agentChildEnv(socket: string): Record<string, string | undefined> {
  return socket.toLowerCase() === WINDOWS_AGENT_PIPE ? { SSH_AUTH_SOCK: undefined } : { SSH_AUTH_SOCK: socket };
}

/** The platform's own "start an agent" remedy. */
export function agentStartSuggestion(): string {
  return process.platform === "win32"
    ? "Start the Windows OpenSSH agent: Get-Service ssh-agent | Set-Service -StartupType Automatic; Start-Service ssh-agent"
    : 'Start ssh-agent: eval "$(ssh-agent -s)"';
}

// "no identities" is a SUCCESSFUL probe -- the agent answered, it just holds nothing.
// Some builds report it with a non-zero exit and some with a zero one, so it is
// tested before the exit code on every channel. (Covers "The agent has no identities.")
const agentHasNoIdentities = (output: string): boolean => output.includes("no identities");

export function checkSshAgent(): DiagnosticResult {
  const sock = process.env.SSH_AUTH_SOCK;
  const isWindows = process.platform === "win32";

  if (sock) {
    const { stdout, ok } = runArgs("ssh-add", ["-l"]);
    if (agentHasNoIdentities(stdout)) {
      return {
        status: "warning",
        message: "ssh-agent is running but has no keys loaded. Run: ssh-add <key-path>",
      };
    }
    if (ok) return { status: "ok", message: `ssh-agent running with keys:\n${stdout}` };

    // Any other ssh-add failure means the agent did not answer. Do NOT fall through to
    // "ok" on an unrecognised phrasing: that reported a dead agent as healthy.
    // On Windows a set-but-stale SSH_AUTH_SOCK (a leftover WSL / Git Bash path) is
    // common while the OpenSSH service is up, so try the named pipe next -- the same
    // fall-through ensureAgent (env.ts) makes -- instead of blaming a working agent.
    if (!isWindows) {
      return {
        status: "error",
        message: stdout.includes("Could not open a connection")
          ? `SSH_AUTH_SOCK is set to "${sock}" but the agent is not reachable. The agent process may have died. Run: eval "$(ssh-agent -s)"`
          : `SSH_AUTH_SOCK is set to "${sock}" but ssh-add could not query the agent: ${stdout || "no output"}. Run: eval "$(ssh-agent -s)"`,
      };
    }
  } else if (!isWindows) {
    return {
      status: "error",
      message: "SSH_AUTH_SOCK is not set. ssh-agent is not running or not exported to this shell.",
    };
  }

  // win32: the OpenSSH agent service's named pipe, reached with SSH_AUTH_SOCK unset.
  const { stdout, ok } = runArgs("ssh-add", ["-l"], { env: agentChildEnv(WINDOWS_AGENT_PIPE) });
  const reachable = ok || agentHasNoIdentities(stdout);
  if (reachable && sock) {
    // The pipe answers, but SSH_AUTH_SOCK still names a dead socket, and the
    // connection path honours SSH_AUTH_SOCK first -- so connections will not reach
    // this agent until the variable is unset. A warning, not an error: the agent is fine.
    return {
      status: "warning",
      message: `Windows OpenSSH agent is running, but SSH_AUTH_SOCK is set to "${sock}", where no agent answers, and connections use SSH_AUTH_SOCK first. Unset SSH_AUTH_SOCK so every tool reaches the agent through its named pipe.`,
    };
  }
  if (agentHasNoIdentities(stdout)) {
    return {
      status: "warning",
      message: "Windows OpenSSH agent is running but has no keys loaded. Run: ssh-add <key-path>",
    };
  }
  if (ok) return { status: "ok", message: `Windows OpenSSH agent running with keys:\n${stdout}` };
  return {
    status: "error",
    message: sock
      ? `SSH_AUTH_SOCK is set to "${sock}" but no agent answers there, and the Windows OpenSSH Authentication Agent is not running either. Start it: Get-Service ssh-agent | Set-Service -StartupType Automatic; Start-Service ssh-agent`
      : "Windows OpenSSH Authentication Agent is not running. Start it: Get-Service ssh-agent | Set-Service -StartupType Automatic; Start-Service ssh-agent",
  };
}

export interface PrivateKeyCandidate {
  name: string;
  path: string;
  /** The file's content, read through the same descriptor that passed the regular-file check. */
  content: string;
}

/**
 * Reads one ~/.ssh entry as a private-key candidate, or null when it is not one.
 *
 * Open once, then stat and read through the descriptor, so the content checked for a
 * key comes from the file that passed the regular-file check -- a by-path stat
 * followed by a by-path read can be swapped in between. O_NONBLOCK keeps the open
 * from hanging on a FIFO and O_NOCTTY keeps a tty from becoming the controlling
 * terminal; fstat then rejects both as not a regular file. Both flags are POSIX-only,
 * and undefined on Windows.
 */
function readKeyCandidate(sshDir: string, name: string): PrivateKeyCandidate | null {
  const filePath = join(sshDir, name);
  let fd: number | undefined;
  try {
    fd = openSync(filePath, fsConstants.O_RDONLY | (fsConstants.O_NONBLOCK ?? 0) | (fsConstants.O_NOCTTY ?? 0));
    if (!fstatSync(fd).isFile()) return null;
    const content = readFileSync(fd, "utf8");
    return content.includes("PRIVATE KEY") ? { name, path: filePath, content } : null;
  } catch {
    return null; // unreadable: not a usable key
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * The one ~/.ssh private-key scan, shared by `checkSshKeys` below and
 * `listSshKeysDetailed` in env.ts so the two cannot disagree about what is a key.
 * Skips *.pub, dotfiles and SSH_NON_KEY_FILES, then keeps the regular files whose
 * content carries a private-key marker. THROWS when readdir fails, so a caller can
 * tell "unreadable" from "empty".
 */
export function scanPrivateKeyFiles(sshDir: string): PrivateKeyCandidate[] {
  const out: PrivateKeyCandidate[] = [];
  for (const name of readdirSync(sshDir)) {
    if (name.endsWith(".pub") || name.startsWith(".") || SSH_NON_KEY_FILES.has(name)) continue;
    const candidate = readKeyCandidate(sshDir, name);
    if (candidate) out.push(candidate);
  }
  return out;
}

const DEFAULT_KEY_NAMES = ["id_ed25519", "id_rsa", "id_ecdsa"];

export function checkSshKeys(): DiagnosticResult {
  const sshDir = join(homedir(), ".ssh");

  if (!existsSync(sshDir)) {
    return { status: "error", message: "~/.ssh directory does not exist. Run: mkdir -p ~/.ssh && chmod 700 ~/.ssh" };
  }

  let names: string[];
  try {
    names = scanPrivateKeyFiles(sshDir).map((c) => c.name);
  } catch {
    // readdir failed: the default names can still be opened directly.
    names = DEFAULT_KEY_NAMES.filter((n) => readKeyCandidate(sshDir, n) !== null);
  }
  // Default-named keys first, in their conventional order, then the rest as found.
  const found = [
    ...DEFAULT_KEY_NAMES.filter((n) => names.includes(n)),
    ...names.filter((n) => !DEFAULT_KEY_NAMES.includes(n)),
  ];

  if (found.length === 0) {
    return {
      status: "error",
      message: 'No SSH private keys found in ~/.ssh/. Generate one: ssh-keygen -t ed25519 -C "your@email.com"',
    };
  }

  return { status: "ok", message: `Found SSH keys: ${found.join(", ")}` };
}

// Same rules as `unbracketHost` / `knownHostsTargets` in ssh.ts, kept local because
// ssh.ts imports this module (importing back would make a cycle). For a default-port
// entry ssh-keygen stores and matches the address BARE (`-F '::1'` hits a `::1` line,
// `-F '[::1]'` misses it); a non-default port is `[addr]:port`. The bare entry is
// also consulted on a non-default port, exactly as readKnownHostsEntries does, since
// the connection path's verifier accepts it there too.
const unbracket = (host: string): string =>
  host.length > 2 && host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;

function knownHostsLookupTargets(host: string, port: number): string[] {
  const bare = unbracket(host);
  return port !== 22 ? [`[${bare}]:${port}`, bare] : [bare];
}

/** The entry spelling `ssh-keygen -R` must be given for this host and port. */
function knownHostsEntryName(host: string, port: number): string {
  return knownHostsLookupTargets(host, port)[0];
}

/**
 * A runnable `ssh-keyscan` line that pins this host AND port. Callers pass the
 * RESOLVED hostname, never an ssh_config alias: ssh-keyscan does not read
 * ssh_config, and without `-p` it scans port 22. The host goes in bare, because
 * ssh-keyscan and `ssh-keygen -R` share `-F`'s bracket sensitivity.
 */
export function keyscanCommand(host: string, port = 22): string {
  const portFlag = port !== 22 ? ` -p ${port}` : "";
  return `ssh-keyscan -H${portFlag} "${unbracket(host)}" >> ~/.ssh/known_hosts`;
}

// What happens to a host that is not pinned, stated the way this server actually
// behaves: trust-always (accepted unverified, never saved), or refused in strict mode.
// There is no interactive prompt anywhere in this server.
const UNPINNED_BEHAVIOUR =
  "ssh-mcp accepts an unpinned host's key unverified on every connection (it is never saved), or refuses it when SSH_MCP_STRICT_HOSTKEYS=1";

export function checkKnownHosts(host: string, port = 22): DiagnosticResult {
  if (!isValidHostname(host)) {
    return { status: "error", message: `Invalid hostname: "${host}"` };
  }

  const knownHostsPath = join(homedir(), ".ssh", "known_hosts");
  const quoted = port !== 22 ? `"${host}" (port ${port})` : `"${host}"`;

  if (!existsSync(knownHostsPath)) {
    return {
      status: "warning",
      message: `~/.ssh/known_hosts does not exist, so no host is pinned: ${UNPINNED_BEHAVIOUR}.`,
    };
  }

  for (const target of knownHostsLookupTargets(host, port)) {
    const { stdout, ok } = runArgs("ssh-keygen", ["-F", target]);
    if (ok && stdout.trim()) return { status: "ok", message: `Host ${quoted} found in known_hosts` };
  }

  return {
    status: "warning",
    message: `Host ${quoted} is not in known_hosts. ${UNPINNED_BEHAVIOUR}. To pin it: ${keyscanCommand(host, port)}`,
  };
}

// Why a probe outcome is a named union rather than a message string: two callers
// need the SAME classification with DIFFERENT wording -- `checkConnectivity` below
// returns a DiagnosticResult for the diagnose() report, and `testConnection` in
// env.ts returns a {status, message} for the ssh_test tool and adds elapsed-ms
// timing. Splitting "what happened" from "how we phrase it" lets both share the
// probe without either one's operator-facing strings changing.
export type SshProbeOutcome =
  | "ok"
  | "permission-denied"
  | "connection-refused"
  | "timed-out"
  | "host-key-mismatch"
  | "host-key-unknown"
  | "dns-failure"
  | "unknown";

export interface SshProbeResult {
  outcome: SshProbeOutcome;
  /** Combined stdout+stderr from ssh, for the fall-through "unknown" message. */
  output: string;
  /** Wall time of the ssh invocation. Only `testConnection` surfaces this. */
  elapsedMs: number;
}

// Classifies the output of the `echo SSH_OK` probe below (and checkGitSsh's
// failures in env.ts). Ordering is significant: success, then host-key failure,
// then auth failure, refused, timeout, DNS.
//
// Host-key failure comes BEFORE "Permission denied" because OpenSSH can print both:
// when a changed key is tolerated (StrictHostKeyChecking=no) it prints the
// "REMOTE HOST IDENTIFICATION HAS CHANGED" banner and carries on to pubkey auth,
// which then fails -- measured on OpenSSH_10.6p1 with a wrong key pinned for
// github.com. Checked after "Permission denied", a changed key read as an auth
// problem. The probe now refuses a changed key outright (accept-new), which prints
// "Host key verification failed."; the banner test still catches any caller or
// build that tolerates the change.
//
// One deliberate consolidation: `checkConnectivity` used to test for the narrower
// "Could not resolve hostname" while `testConnection` tested for "Could not
// resolve". The broader form is used here. OpenSSH's only client-side spelling is
// `Could not resolve hostname <h>: ...`, so this is the same set in practice and
// the broader form degrades more gracefully if that wording ever changes.
export function classifySshProbe(ok: boolean, output: string): SshProbeOutcome {
  if (ok && output.includes("SSH_OK")) return "ok";
  // Strict mode's refusal of an UNPINNED host prints "No <type> host key is known for
  // <h> and you have requested strict checking." followed by the same "Host key
  // verification failed." line a changed key ends with, so it is told apart first.
  // Not on "requested strict checking" alone: accept-new's refusal of a CHANGED key
  // says "Host key for <h> has changed and you have requested strict checking."
  if (/No \S+ host key is known for /.test(output)) return "host-key-unknown";
  if (output.includes("REMOTE HOST IDENTIFICATION HAS CHANGED") || output.includes("Host key verification failed")) {
    return "host-key-mismatch";
  }
  if (output.includes("Permission denied")) return "permission-denied";
  if (output.includes("Connection refused")) return "connection-refused";
  if (output.includes("timed out")) return "timed-out";
  if (output.includes("Could not resolve")) return "dns-failure";
  return "unknown";
}

/**
 * Strict host-key mode: reject a host with no known_hosts entry instead of trusting it.
 *
 * Two names, one switch. SSH_MCP_STRICT_HOSTKEYS is the documented one.
 * SSH_MCP_STRICT_HOST_KEY is the original name and keeps working, but it is
 * credential-shaped -- `KEY` is a whole underscore segment -- so Yaw MCP's doctor
 * listed `SSH_MCP_STRICT_HOST_KEY=1` as a plaintext secret and suggested moving it
 * into the vault. `HOSTKEYS` is not a credential segment, so the new name is not
 * flagged. Either one turns strict mode on.
 *
 * Both are read the way Yaw MCP reads an opt-in: trimmed, case-insensitive `1` or
 * `true`. Only the exact string "1" used to count, so `=true` silently left strict
 * mode OFF -- the unsafe direction for a security switch.
 */
export function isStrictHostKeyMode(env: NodeJS.ProcessEnv = process.env): boolean {
  const on = (v: string | undefined) => {
    const t = (v ?? "").trim().toLowerCase();
    return t === "1" || t === "true";
  };
  return on(env.SSH_MCP_STRICT_HOSTKEYS) || on(env.SSH_MCP_STRICT_HOST_KEY);
}

// The probe's known_hosts files. A LIST: ssh reads every file in it to verify a key
// but writes a newly accepted key only to the FIRST, which is the null device -- so
// the probe still sees the operator's pins (and so can report a changed key) while
// being unable to add one. `/dev/null`, not `NUL`, on every platform: measured on
// Windows, Git for Windows' OpenSSH_10.6p1 (MSYS) treats `NUL` as a relative file
// name and created a file called NUL in its cwd holding the accepted key, while both
// it and Windows' OpenSSH_for_Windows_9.5p2 map `/dev/null` to the null device (the
// accepted key was discarded, the listed files unchanged). `~` is expanded by ssh
// itself, which sidesteps a home directory containing spaces (the list is
// whitespace-separated). These two files are OpenSSH's own default list.
export const PROBE_USER_KNOWN_HOSTS = "/dev/null ~/.ssh/known_hosts ~/.ssh/known_hosts2";

// Runs the shared SSH reachability probe. Callers own their own wording.
//
// Caller MUST validate `host` with isValidHostname first -- this function passes the
// host to ssh positionally and does not re-check it.
//
// The probe WRITES NOTHING. ssh_diagnose is annotated read-only, and this server
// never persists a host key as a side effect of connecting (only ssh_known_hosts_fix
// writes known_hosts). The old `StrictHostKeyChecking=no` with the default files did
// persist: OpenSSH "Permanently added" an unknown host's key to ~/.ssh/known_hosts,
// pinning whatever answered. Now:
//   - StrictHostKeyChecking=accept-new: an unknown host is accepted, matching the
//     connection path's trust-always behaviour (under SSH_MCP_STRICT_HOSTKEYS it is
//     =yes instead, so ssh_test refuses an unpinned host exactly as ssh_exec does), and a CHANGED key is refused with
//     "Host key verification failed." (=no tolerated it and went on to pubkey auth,
//     so a changed key surfaced as Permission denied, or as ok).
//   - the accepted key goes to /dev/null (see PROBE_USER_KNOWN_HOSTS);
//     GlobalKnownHostsFile=/dev/null because the connection path's verifier reads
//     only the user file; UpdateHostKeys=no stops the hostkeys-update extension from
//     rewriting known_hosts when the server offers extra keys.
// Measured with both ssh builds above against github.com: an empty scratch file
// stayed empty, and a wrong pinned key failed with "Host key verification failed."
// and left the file unchanged.
//
// No passwords or private-key material transit -- BatchMode=yes suppresses password
// prompts and ssh never sends private keys over the wire. But against an unknown
// host the client attempts pubkey auth with whatever answers on this port, so the
// public keys of the identities it offers are observable to it. For real
// connections, hostVerifier in resolveConfig (src/ssh.ts) applies known_hosts.
export function probeSshConnection(host: string, port: number): SshProbeResult {
  const start = Date.now();
  const { ok, stdout } = runArgs("ssh", [
    "-o",
    "ConnectTimeout=5",
    "-o",
    "BatchMode=yes",
    "-o",
    `StrictHostKeyChecking=${isStrictHostKeyMode() ? "yes" : "accept-new"}`,
    "-o",
    `UserKnownHostsFile=${PROBE_USER_KNOWN_HOSTS}`,
    "-o",
    "GlobalKnownHostsFile=/dev/null",
    "-o",
    "UpdateHostKeys=no",
    "-p",
    String(port),
    "--",
    host,
    "echo",
    "SSH_OK",
  ]);
  return { outcome: classifySshProbe(ok, stdout), output: stdout, elapsedMs: Date.now() - start };
}

export function checkConnectivity(host: string, port = 22): DiagnosticResult {
  if (!isValidHostname(host)) {
    return { status: "error", message: `Invalid hostname: "${host}"` };
  }

  const { outcome, output } = probeSshConnection(host, port);

  switch (outcome) {
    case "ok":
      return { status: "ok", message: `SSH connection to ${host}:${port} succeeded` };
    case "permission-denied":
      return {
        status: "error",
        message: `Permission denied connecting to ${host}:${port}. Your key is not authorized on this host. Check: 1) correct key is loaded (ssh-add -l), 2) key is in remote authorized_keys, 3) correct username.`,
      };
    case "connection-refused":
      return {
        status: "error",
        message: `Connection refused at ${host}:${port}. SSH server is not running on this port or host is blocking connections.`,
      };
    case "timed-out":
      return {
        status: "error",
        message: `Connection timed out to ${host}:${port}. Host may be down, port may be blocked by firewall, or DNS resolution failed.`,
      };
    case "host-key-mismatch":
      return {
        status: "error",
        message: `Host key verification failed for ${host}. The host key changed (instance recreated?). Fix: ssh-keygen -R "${knownHostsEntryName(host, port)}" && ${keyscanCommand(host, port)}`,
      };
    case "host-key-unknown":
      return {
        status: "error",
        message: `Host ${host} (port ${port}) is not in known_hosts and SSH_MCP_STRICT_HOSTKEYS is on, so it is refused. To pin it: ${keyscanCommand(host, port)}`,
      };
    case "dns-failure":
      return {
        status: "error",
        message: `Could not resolve hostname "${host}". Check DNS, /etc/hosts, or SSH config aliases.`,
      };
    default:
      return { status: "error", message: `SSH connection failed: ${output}` };
  }
}

// Tests a single (already un-negated) ssh_config host pattern against a hostname.
//
// SSH config supports `*` (any chars) and `?` (single char) as wildcards.
// Escape every regex meta first, then translate the wildcards. Without
// escaping `?`, `[`, `+`, `(`, etc., a literal pattern like `?prod` or
// `srv[12].example.com` would be misinterpreted as regex syntax and
// match unintended hosts.
function matchesHostPattern(pattern: string, host: string): boolean {
  if (pattern === "*") return true;
  if (pattern === host) return true;
  if (pattern.includes("*") || pattern.includes("?")) {
    const escaped = pattern.replace(/[\\^$.|+()[\]{}]/g, "\\$&");
    return new RegExp("^" + escaped.replace(/\*/g, ".*").replace(/\?/g, ".") + "$").test(host);
  }
  return false;
}

// Decides whether a `Host` line's pattern list selects `host`, per ssh_config(5)
// PATTERNS: the list is WHITESPACE-separated (see the file header -- commas are
// not separators on a `Host` line), a leading `!` negates, and "if a negated
// entry is matched, then the Host entry is ignored, regardless of whether any
// other patterns on the line match". So the rule is
// `some positive match AND no negated match` -- NOT `some match`, which is the
// wrong way round for `Host * !prod` (the `*` would otherwise select prod, the
// exact host the operator excluded).
function hostLineSelects(patternList: string, host: string): boolean {
  let positive = false;
  for (const raw of patternList.split(/\s+/)) {
    if (!raw) continue;
    const negated = raw.startsWith("!");
    const pattern = negated ? raw.slice(1) : raw;
    if (!pattern) continue;
    if (!matchesHostPattern(pattern, host)) continue;
    if (negated) return false;
    positive = true;
  }
  return positive;
}

export function checkSshConfig(host: string): DiagnosticResult {
  const configPath = join(homedir(), ".ssh", "config");

  if (!existsSync(configPath)) {
    return { status: "ok", message: "No ~/.ssh/config file (using defaults)" };
  }

  try {
    const content = readFileSync(configPath, "utf8");
    // Split on CRLF or LF. A CRLF config would otherwise leave a trailing `\r` on
    // every line, which defeats the comment strip below (JS `.` excludes `\r`, so
    // `#.*$` cannot reach end-of-line) and trails into every reported directive.
    // Same hazard ssh-config.ts documents for `ssh -G` output on Windows.
    const lines = content.split(/\r?\n/);
    let inHostBlock = false;
    const hostConfig: string[] = [];

    for (const rawLine of lines) {
      // Strip `#`-to-end-of-line BEFORE anything else. ssh does this, and not doing
      // it broke the parser in both directions (probed against OpenSSH_10.2p1):
      //   `Host bastion  # jump box for prod` -- ssh applies the block to `bastion`
      //     only, but tokenising the comment made `prod` a pattern and reported the
      //     whole block as prod's config (a directive ssh does NOT apply).
      //   `Host *  # !prod` -- ssh applies the block to prod, but `!prod` inside the
      //     comment read as a real negation and disqualified the line (omitting a
      //     directive ssh DOES apply).
      // The `#` must START A TOKEN to be a comment -- ssh treats a mid-token `#` as
      // an ordinary pattern character. Probed: with `Host foo#bar`, `ssh -G foo#bar`
      // matches and `ssh -G foo` does not, so cutting at any `#` would truncate the
      // pattern to `foo` and select a host ssh does NOT select -- wrong-way-round,
      // the one failure mode this parser must not have.
      // Known limitation: ssh honours `#` inside a quoted value (e.g. a ProxyCommand
      // argument), and this does not -- such a line is truncated early here. That
      // direction is INCOMPLETE, never wrong-way-round, which is the invariant the
      // note at the top of this file claims.
      const trimmed = rawLine.replace(/(^|\s)#.*/, "$1").trim();
      // `Host foo` and `Host=foo` are both valid separators in ssh_config. The
      // character class also keeps `HostName foo` from being read as a Host line
      // (after "Host" comes "N", which is neither whitespace nor "=").
      if (/^Host[\s=]/i.test(trimmed)) {
        const patternList = trimmed.replace(/^Host[\s=]+/i, "").trim();
        inHostBlock = hostLineSelects(patternList, host);
        if (inHostBlock) hostConfig.push(trimmed);
      } else if (/^Match[\s=]/i.test(trimmed)) {
        // A `Match` line ends the current Host block. Its criteria (exec, user,
        // final, ...) are not evaluated here, so nothing inside it is reported --
        // reporting it unconditionally would attribute conditional directives to
        // this host. `ssh -G` is the authority; see the note at the top of this file.
        inHostBlock = false;
      } else if (inHostBlock && trimmed) {
        hostConfig.push(trimmed);
      }
      // Empty lines within a Host block are valid SSH config syntax and must
      // not end the block. The next `Host` line resets inHostBlock correctly.
    }

    if (hostConfig.length === 0) {
      return { status: "ok", message: `No SSH config entry for "${host}" (using defaults)` };
    }

    return { status: "ok", message: `SSH config for "${host}":\n${hostConfig.join("\n")}` };
  } catch {
    return { status: "warning", message: "Could not read ~/.ssh/config" };
  }
}

export function diagnose(host: string, port = 22): DiagnosticReport {
  const checks: Array<{ name: string } & DiagnosticResult> = [];
  const suggestions: string[] = [];

  if (!isValidHostname(host)) {
    return {
      overall: "error",
      checks: [{ name: "Input Validation", status: "error", message: `Invalid hostname: "${host}"` }],
      suggestions: [INVALID_HOSTNAME_SUGGESTION],
    };
  }

  const agent = checkSshAgent();
  checks.push({ name: "SSH Agent", ...agent });
  if (agent.status === "error") suggestions.push(agentStartSuggestion());
  // A stale SSH_AUTH_SOCK beside a live Windows agent is a warning too, and loading
  // a key is not its fix -- the check's own message names the real one.
  if (agent.status === "warning" && agent.message.includes("no keys loaded")) {
    suggestions.push("Load your key: ssh-add ~/.ssh/id_ed25519");
  }

  const keys = checkSshKeys();
  checks.push({ name: "SSH Keys", ...keys });
  if (keys.status === "error") suggestions.push('Generate a key: ssh-keygen -t ed25519 -C "your@email.com"');

  const config = checkSshConfig(host);
  checks.push({ name: "SSH Config", ...config });

  const known = checkKnownHosts(host, port);
  checks.push({ name: "Known Hosts", ...known });
  if (known.status === "warning") suggestions.push(`Add host key: ${keyscanCommand(host, port)}`);

  const conn = checkConnectivity(host, port);
  checks.push({ name: "Connectivity", ...conn });
  if (conn.status === "error" && conn.message.includes("Host key verification")) {
    suggestions.push(`Remove stale host key: ssh-keygen -R "${knownHostsEntryName(host, port)}"`);
    suggestions.push(`Re-add host key: ${keyscanCommand(host, port)}`);
  }
  if (conn.status === "error" && conn.message.includes("Permission denied")) {
    suggestions.push("Check loaded keys: ssh-add -l");
    suggestions.push("Verify correct username for this host");
  }

  const overall = checks.some((c) => c.status === "error")
    ? "error"
    : checks.some((c) => c.status === "warning")
      ? "warning"
      : "ok";

  return { overall, checks, suggestions };
}
