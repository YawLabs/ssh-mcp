import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
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

// Validate hostname to prevent shell injection — only allow safe characters
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

export function runArgs(cmd: string, args: string[]): { stdout: string; ok: boolean } {
  try {
    const stdout = execFileSync(cmd, args, { encoding: "utf8", timeout: 10000, stdio: ["pipe", "pipe", "pipe"] });
    return { stdout: stdout.trim(), ok: true };
  } catch (e: unknown) {
    // Capture both stdout and stderr — many SSH commands (ssh -T, ssh-add) output to stderr
    const err = e as { stdout?: Buffer; stderr?: Buffer; message?: string };
    const stdout = err.stdout?.toString().trim() || "";
    const stderr = err.stderr?.toString().trim() || "";
    const output = [stdout, stderr].filter(Boolean).join("\n") || err.message || "";
    return { stdout: output, ok: false };
  }
}

export function checkSshAgent(): DiagnosticResult {
  const sock = process.env.SSH_AUTH_SOCK;

  // On Windows without SSH_AUTH_SOCK, try the OpenSSH agent service directly
  if (!sock && process.platform === "win32") {
    const { stdout, ok } = runArgs("ssh-add", ["-l"]);
    if (ok) {
      return { status: "ok", message: `Windows OpenSSH agent running with keys:\n${stdout}` };
    }
    if (stdout.includes("no identities") || stdout.includes("The agent has no identities")) {
      return {
        status: "warning",
        message: "Windows OpenSSH agent is running but has no keys loaded. Run: ssh-add <key-path>",
      };
    }
    // ssh-add failed and no identities message — agent is not reachable
    return {
      status: "error",
      message:
        "Windows OpenSSH Authentication Agent is not running. Start it: Get-Service ssh-agent | Set-Service -StartupType Automatic; Start-Service ssh-agent",
    };
  }

  if (!sock) {
    return {
      status: "error",
      message: "SSH_AUTH_SOCK is not set. ssh-agent is not running or not exported to this shell.",
    };
  }

  const { stdout, ok } = runArgs("ssh-add", ["-l"]);

  // "no identities" is a SUCCESSFUL probe -- the agent answered, it just holds
  // nothing. Some builds report it with a non-zero exit, so it is checked before
  // the failure branch below rather than being treated as unreachable.
  if (stdout.includes("The agent has no identities") || stdout.includes("no identities")) {
    return {
      status: "warning",
      message: "ssh-agent is running but has no keys loaded. Run: ssh-add <key-path>",
    };
  }

  // Any other ssh-add failure means the agent did not answer. Keep the classic
  // wording for the known phrasing, but do NOT fall through to "ok" on an
  // unrecognised one: that reported a dead agent as healthy and pasted the error
  // text in where the key list belongs. Mirrors probeAgent's discriminator in env.ts.
  if (!ok) {
    return {
      status: "error",
      message: stdout.includes("Could not open a connection")
        ? `SSH_AUTH_SOCK is set to "${sock}" but the agent is not reachable. The agent process may have died. Run: eval "$(ssh-agent -s)"`
        : `SSH_AUTH_SOCK is set to "${sock}" but ssh-add could not query the agent: ${stdout || "no output"}. Run: eval "$(ssh-agent -s)"`,
    };
  }

  return { status: "ok", message: `ssh-agent running with keys:\n${stdout}` };
}

export function checkSshKeys(): DiagnosticResult {
  const home = homedir();
  const sshDir = join(home, ".ssh");

  if (!existsSync(sshDir)) {
    return { status: "error", message: "~/.ssh directory does not exist. Run: mkdir -p ~/.ssh && chmod 700 ~/.ssh" };
  }

  const keyTypes = ["id_ed25519", "id_rsa", "id_ecdsa"];
  const found: string[] = [];

  for (const key of keyTypes) {
    const keyPath = join(sshDir, key);
    if (existsSync(keyPath)) {
      found.push(key);
    }
  }

  // Check for any other private key files
  try {
    const allFiles = readdirSync(sshDir).filter((f) => !f.endsWith(".pub") && !SSH_NON_KEY_FILES.has(f));
    for (const f of allFiles) {
      if (!keyTypes.includes(f) && existsSync(join(sshDir, f))) {
        try {
          const content = readFileSync(join(sshDir, f), "utf8");
          if (content.includes("PRIVATE KEY")) {
            found.push(f);
          }
        } catch {
          // Not readable, skip
        }
      }
    }
  } catch {
    // readdir failed, stick with default key check
  }

  if (found.length === 0) {
    return {
      status: "error",
      message: 'No SSH private keys found in ~/.ssh/. Generate one: ssh-keygen -t ed25519 -C "your@email.com"',
    };
  }

  return { status: "ok", message: `Found SSH keys: ${found.join(", ")}` };
}

export function checkKnownHosts(host: string): DiagnosticResult {
  if (!isValidHostname(host)) {
    return { status: "error", message: `Invalid hostname: "${host}"` };
  }

  const knownHostsPath = join(homedir(), ".ssh", "known_hosts");

  if (!existsSync(knownHostsPath)) {
    return {
      status: "warning",
      message: "~/.ssh/known_hosts does not exist. First connection to any host will prompt for verification.",
    };
  }

  const { stdout, ok } = runArgs("ssh-keygen", ["-F", host]);
  if (!ok || !stdout.trim()) {
    return {
      status: "warning",
      message: `Host "${host}" is not in known_hosts. First connection will prompt for host key verification. To add it: ssh-keyscan -H "${host}" >> ~/.ssh/known_hosts`,
    };
  }

  return { status: "ok", message: `Host "${host}" found in known_hosts` };
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
  | "dns-failure"
  | "unknown";

export interface SshProbeResult {
  outcome: SshProbeOutcome;
  /** Combined stdout+stderr from ssh, for the fall-through "unknown" message. */
  output: string;
  /** Wall time of the ssh invocation. Only `testConnection` surfaces this. */
  elapsedMs: number;
}

// Classifies the output of the `echo SSH_OK` probe below. Ordering is significant
// and matches what both callers did before they were unified: auth failure, then
// refused, then timeout, then host-key mismatch, then DNS.
//
// One deliberate consolidation: `checkConnectivity` used to test for the narrower
// "Could not resolve hostname" while `testConnection` tested for "Could not
// resolve". The broader form is used here. OpenSSH's only client-side spelling is
// `Could not resolve hostname <h>: ...`, so this is the same set in practice and
// the broader form degrades more gracefully if that wording ever changes.
export function classifySshProbe(ok: boolean, output: string): SshProbeOutcome {
  if (ok && output.includes("SSH_OK")) return "ok";
  if (output.includes("Permission denied")) return "permission-denied";
  if (output.includes("Connection refused")) return "connection-refused";
  if (output.includes("timed out")) return "timed-out";
  if (output.includes("Host key verification failed")) return "host-key-mismatch";
  if (output.includes("Could not resolve")) return "dns-failure";
  return "unknown";
}

// Runs the shared read-only SSH reachability probe. Callers own their own wording.
//
// Caller MUST validate `host` with isValidHostname first -- this function passes the
// host to ssh positionally and does not re-check it.
//
// StrictHostKeyChecking=no on a read-only "echo SSH_OK" probe. No passwords or
// private-key material transit -- BatchMode=yes suppresses password prompts and ssh
// never sends private keys over the wire. But the SSH client WILL attempt pubkey auth
// against the (possibly-MitM'd) endpoint, so the public-key fingerprints of any
// identities loaded in the agent are observable to whatever answers on this port.
// For real connections, hostVerifier in resolveConfig (src/ssh.ts) enforces
// known_hosts matching and prevents this exposure.
export function probeSshConnection(host: string, port: number): SshProbeResult {
  const start = Date.now();
  const { ok, stdout } = runArgs("ssh", [
    "-o",
    "ConnectTimeout=5",
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=no",
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
        message: `Host key verification failed for ${host}. The host key changed (instance recreated?). Fix: ssh-keygen -R "${host}" && ssh-keyscan -H "${host}" >> ~/.ssh/known_hosts`,
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
      suggestions: ["Provide a valid hostname (alphanumeric, dots, hyphens, colons, brackets only)"],
    };
  }

  const agent = checkSshAgent();
  checks.push({ name: "SSH Agent", ...agent });
  if (agent.status === "error") suggestions.push('Start ssh-agent: eval "$(ssh-agent -s)"');
  if (agent.status === "warning") suggestions.push("Load your key: ssh-add ~/.ssh/id_ed25519");

  const keys = checkSshKeys();
  checks.push({ name: "SSH Keys", ...keys });
  if (keys.status === "error") suggestions.push('Generate a key: ssh-keygen -t ed25519 -C "your@email.com"');

  const config = checkSshConfig(host);
  checks.push({ name: "SSH Config", ...config });

  const known = checkKnownHosts(host);
  checks.push({ name: "Known Hosts", ...known });
  if (known.status === "warning") suggestions.push(`Add host key: ssh-keyscan -H "${host}" >> ~/.ssh/known_hosts`);

  const conn = checkConnectivity(host, port);
  checks.push({ name: "Connectivity", ...conn });
  if (conn.status === "error" && conn.message.includes("Host key verification")) {
    suggestions.push(`Remove stale host key: ssh-keygen -R "${host}"`);
    suggestions.push(`Re-add host key: ssh-keyscan -H "${host}" >> ~/.ssh/known_hosts`);
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
