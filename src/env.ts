import { execFileSync } from "node:child_process";
import { appendFileSync, existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { isValidHostname, probeSshConnection, runArgs, SSH_NON_KEY_FILES } from "./diagnose.js";
import { knownHostsTargets, unbracketHost } from "./ssh.js";
import { parseSshConfigOutput } from "./ssh-config.js";

export interface KeyInfo {
  name: string;
  path: string;
  type: string;
  fingerprint?: string;
  loadedInAgent: boolean;
}

export interface AgentResult {
  running: boolean;
  reachable: boolean;
  socket?: string;
  keys: string[];
  started: boolean;
  env?: { SSH_AUTH_SOCK?: string; SSH_AGENT_PID?: string };
  message: string;
}

// Runs a command with extra env vars merged on top of process.env. Pass `undefined`
// for a key to UNSET it from the child env (delete-from-copy semantics). Mirrors
// runArgs but returns the same {stdout, ok} shape so callers don't branch.
function runArgsWithEnv(
  cmd: string,
  args: string[],
  extraEnv: Record<string, string | undefined>,
): { stdout: string; ok: boolean } {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (typeof v === "string") env[k] = v;
  }
  for (const [k, v] of Object.entries(extraEnv)) {
    if (v === undefined) {
      delete env[k];
    } else {
      env[k] = v;
    }
  }
  try {
    const stdout = execFileSync(cmd, args, {
      env,
      encoding: "utf8",
      timeout: 10000,
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { stdout: stdout.trim(), ok: true };
  } catch (e: unknown) {
    const err = e as { stdout?: Buffer; stderr?: Buffer; message?: string };
    const so = err.stdout?.toString().trim() || "";
    const se = err.stderr?.toString().trim() || "";
    const output = [so, se].filter(Boolean).join("\n") || err.message || "";
    return { stdout: output, ok: false };
  }
}

// Runs `ssh-add -l` against a specific agent channel and shapes the result into
// an AgentResult if the agent was reachable. Returns null if ssh-add couldn't
// talk to any agent on this channel (so the caller can try the next fallback).
//
// Channel selection:
//   - Unix path: pass the socket via SSH_AUTH_SOCK in the child env so ssh-add
//     hits the agent the caller actually asked about (not whatever happens to
//     be in process.env).
//   - Windows named pipe: leave SSH_AUTH_SOCK UNSET in the child env -- Windows
//     ssh-add reaches the OpenSSH agent via the default named pipe when no
//     SSH_AUTH_SOCK is present. Explicitly unsetting (rather than just not
//     passing one) prevents a stale Unix-style SSH_AUTH_SOCK in the parent env
//     from redirecting ssh-add away from the named pipe.
function probeAgent(socket: string, agentLabel: string): AgentResult | null {
  const isWindowsNamedPipe = socket.startsWith("\\\\.\\pipe\\");
  const extraEnv: Record<string, string | undefined> = isWindowsNamedPipe
    ? { SSH_AUTH_SOCK: undefined }
    : { SSH_AUTH_SOCK: socket };
  const { stdout, ok } = runArgsWithEnv("ssh-add", ["-l"], extraEnv);
  const noIdentities = stdout.includes("no identities") || stdout.includes("The agent has no identities");
  if (!ok && !noIdentities) return null;
  const keys = ok && !noIdentities ? stdout.split("\n").filter(Boolean) : [];
  return {
    running: true,
    reachable: true,
    socket,
    keys,
    started: false,
    message:
      keys.length > 0
        ? `${agentLabel} running with ${keys.length} key(s) loaded`
        : `${agentLabel} running but no keys loaded. Use ssh_key_load to add one.`,
  };
}

// PID of an ssh-agent we spawned ourselves, so shutdown can reap it. Without this
// every ssh-mcp run that spawned its own agent would leave a daemon behind.
let startedAgentPid: number | null = null;

export function killStartedAgent(): void {
  if (startedAgentPid === null) return;
  try {
    process.kill(startedAgentPid);
  } catch {
    // Already gone
  }
  startedAgentPid = null;
}

export function ensureAgent(): AgentResult {
  const sock = process.env.SSH_AUTH_SOCK;
  if (sock) {
    const result = probeAgent(sock, "ssh-agent");
    if (result) return result;
  }

  // On Windows, try the OpenSSH agent service (uses named pipe, not SSH_AUTH_SOCK).
  // We attempt this whenever the SSH_AUTH_SOCK path didn't yield a reachable agent --
  // including the case where SSH_AUTH_SOCK is set but stale (e.g. a leftover Unix-style
  // path from WSL or a prior session). Without this fall-through, a Windows user with a
  // stale SSH_AUTH_SOCK never reaches the named-pipe attempt and ensureAgent returns
  // "not running" while the actual OpenSSH agent service is up.
  if (process.platform === "win32") {
    const result = probeAgent("\\\\.\\pipe\\openssh-ssh-agent", "Windows OpenSSH agent");
    if (result) return result;
    // Skip the `ssh-agent -s` spawn below: on win32 it either errors (no Bourne-shell
    // output) or, in Git Bash with a Unix-ish ssh-agent.exe, spawns an agent whose
    // socket the rest of the stack can't reach. Return the Windows-specific error
    // directly so we don't orphan a process.
    return {
      running: false,
      reachable: false,
      keys: [],
      started: false,
      message:
        "Windows OpenSSH agent not running. Start it: Get-Service ssh-agent | Set-Service -StartupType Automatic; Start-Service ssh-agent",
    };
  }

  // Try to start a new agent (Unix)
  const { stdout, ok } = runArgs("ssh-agent", ["-s"]);
  if (ok) {
    const sockMatch = stdout.match(/SSH_AUTH_SOCK=([^;]+)/);
    const pidMatch = stdout.match(/SSH_AGENT_PID=([^;]+)/);
    if (sockMatch) {
      process.env.SSH_AUTH_SOCK = sockMatch[1];
      if (pidMatch) {
        process.env.SSH_AGENT_PID = pidMatch[1];
        startedAgentPid = Number.parseInt(pidMatch[1], 10);
      }
      return {
        running: true,
        reachable: true,
        socket: sockMatch[1],
        keys: [],
        started: true,
        env: { SSH_AUTH_SOCK: sockMatch[1], SSH_AGENT_PID: pidMatch?.[1] },
        message:
          "Started new ssh-agent scoped to the ssh-mcp server process. " +
          "Your shell's environment is NOT modified — this agent is only visible " +
          "to this MCP server and will terminate when the server exits. " +
          "No keys loaded yet — use ssh_key_load to add one.",
      };
    }
  }

  // Unix-only path: Windows returns from the named-pipe block above before reaching here.
  return {
    running: false,
    reachable: false,
    keys: [],
    started: false,
    message: 'Could not start ssh-agent. Run manually: eval "$(ssh-agent -s)"',
  };
}

function detectKeyType(filePath: string, fileName: string): string {
  // Check the .pub file first — most reliable
  const pubPath = `${filePath}.pub`;
  if (existsSync(pubPath)) {
    try {
      const pub = readFileSync(pubPath, "utf8");
      if (pub.includes("ssh-ed25519")) return "ed25519";
      if (pub.includes("ssh-rsa")) return "rsa";
      if (pub.includes("ecdsa")) return "ecdsa";
      if (pub.includes("ssh-dss")) return "dsa";
    } catch {
      // fall through
    }
  }

  // Infer from filename
  if (fileName.includes("ed25519")) return "ed25519";
  if (fileName.includes("rsa")) return "rsa";
  if (fileName.includes("ecdsa")) return "ecdsa";
  if (fileName.includes("dsa")) return "dsa";

  // Check content
  try {
    const content = readFileSync(filePath, "utf8");
    if (content.includes("RSA PRIVATE KEY")) return "rsa";
    if (content.includes("EC PRIVATE KEY")) return "ecdsa";
    if (content.includes("DSA PRIVATE KEY")) return "dsa";

    // Modern OpenSSH wraps every type (including ed25519) in `OPENSSH PRIVATE KEY`,
    // so the type-specific PEM banners above miss ed25519 entirely. Fall back to
    // ssh-keygen -l, which prints `<bits> SHA256:... comment (TYPE)` -- parse the
    // trailing parenthesized type. -l reads only the unencrypted public-key
    // portion of the OpenSSH file, so no passphrase prompt occurs even for
    // passphrased keys; no -P flag needed.
    if (content.includes("OPENSSH PRIVATE KEY")) {
      const { stdout, ok } = runArgs("ssh-keygen", ["-l", "-f", filePath]);
      if (ok) {
        const match = stdout.match(/\(([^)]+)\)\s*$/);
        if (match) return match[1].toLowerCase();
      }
    }
  } catch {
    // fall through
  }

  return "unknown";
}

export function listSshKeys(): KeyInfo[] {
  const sshDir = join(homedir(), ".ssh");
  if (!existsSync(sshDir)) return [];

  // Get fingerprints of keys loaded in agent
  const loadedFingerprints = new Set<string>();
  const { stdout: agentOut, ok: agentOk } = runArgs("ssh-add", ["-l"]);
  if (agentOk && !agentOut.includes("no identities")) {
    for (const line of agentOut.split("\n").filter(Boolean)) {
      const match = line.match(/(\S+:\S+)/);
      if (match) loadedFingerprints.add(match[1]);
    }
  }

  const keys: KeyInfo[] = [];

  let files: string[];
  try {
    files = readdirSync(sshDir);
  } catch {
    return [];
  }

  for (const file of files) {
    if (file.endsWith(".pub") || file.startsWith(".") || SSH_NON_KEY_FILES.has(file)) continue;

    const filePath = join(sshDir, file);
    try {
      const stat = statSync(filePath);
      if (!stat.isFile()) continue;

      const content = readFileSync(filePath, "utf8");
      if (!content.includes("PRIVATE KEY")) continue;

      const type = detectKeyType(filePath, file);

      // Get fingerprint
      let fingerprint: string | undefined;
      const { stdout: fpOut, ok: fpOk } = runArgs("ssh-keygen", ["-lf", filePath]);
      if (fpOk) {
        const match = fpOut.match(/(\S+:\S+)/);
        fingerprint = match?.[1];
      }

      const loadedInAgent = fingerprint ? loadedFingerprints.has(fingerprint) : false;

      keys.push({ name: file, path: filePath, type, fingerprint, loadedInAgent });
    } catch {
      // Skip unreadable files
    }
  }

  return keys;
}

export function loadKey(keyPath: string): { status: "ok" | "error"; message: string } {
  // Ensure agent is running first
  const agent = ensureAgent();
  if (!agent.reachable) {
    return { status: "error", message: agent.message };
  }

  // Resolve ~ to home directory
  const resolved = keyPath.startsWith("~") ? join(homedir(), keyPath.slice(1)) : keyPath;

  if (!existsSync(resolved)) {
    return { status: "error", message: `Key not found: ${resolved}` };
  }

  const { stdout, ok } = runArgs("ssh-add", [resolved]);
  if (ok) {
    return { status: "ok", message: `Key loaded: ${resolved}` };
  }

  // Permissions check first: ssh-add prints "Permissions ... are too open" /
  // "UNPROTECTED PRIVATE KEY" / "This private key will be ignored" -- none of
  // which contain "passphrase". Match on those phrases directly so a too-open
  // key surfaces a chmod hint instead of the generic "Failed to load key".
  if (stdout.includes("UNPROTECTED PRIVATE KEY") || stdout.includes("too open") || stdout.includes("bad permissions")) {
    return { status: "error", message: `Key ${resolved} has too-open permissions. Fix: chmod 600 ${resolved}` };
  }

  if (stdout.includes("passphrase") || stdout.includes("incorrect")) {
    return { status: "error", message: `Key ${resolved} requires a passphrase. Add it manually: ssh-add ${resolved}` };
  }

  return { status: "error", message: `Failed to load key: ${stdout}` };
}

export interface ConfigLookupResult {
  hostname: string;
  user: string;
  port: string;
  identityFile: string[];
  proxyJump?: string;
  proxyCommand?: string;
  all: Record<string, string>;
  raw: string;
}

export function configLookup(host: string): ConfigLookupResult | { error: string } {
  if (!isValidHostname(host)) {
    return { error: `Invalid hostname: "${host}"` };
  }

  const { stdout, ok } = runArgs("ssh", ["-G", host]);
  if (!ok) {
    return { error: `Failed to resolve SSH config for ${host}: ${stdout}` };
  }

  const { all, identityFiles } = parseSshConfigOutput(stdout);

  return {
    hostname: all.hostname || host,
    user: all.user || "",
    port: all.port || "22",
    identityFile: identityFiles,
    proxyJump: all.proxyjump && all.proxyjump !== "none" ? all.proxyjump : undefined,
    proxyCommand: all.proxycommand && all.proxycommand !== "none" ? all.proxycommand : undefined,
    all,
    raw: stdout,
  };
}

type KnownHostRemoval = { result: "removed" | "absent" | "failed"; output: string };

// `ssh-keygen -R <target>` EXITS 0 whether or not the target was in known_hosts,
// so branching on the exit code alone claimed "Removed old host key" on every
// first-time host -- a removal that did not happen. Classify on the output text.
//
// Which stream carries what is load-bearing here. Probed on OpenSSH_10.2p1:
//   hit  -> STDOUT: "# Host <t> found: line N" (one per hit) + "<path> updated."
//   miss -> STDERR: "Host <t> not found in <path>"   (stdout is EMPTY)
// Both exit 0; only a real error (e.g. "Cannot stat <path>: No such file or
// directory") exits non-zero. `runArgs` merges stderr into `stdout` ONLY on its
// failure path -- on a zero exit it returns stdout alone and DISCARDS stderr.
// Since this function returns early on !ok, it classifies exclusively on the
// zero-exit path, which is precisely where stderr is gone. So the miss marker is
// not visible here at all on this OpenSSH, and testing for its ABSENCE would
// report "removed" for every miss -- reinstating the very bug above.
//
// Therefore classify POSITIVELY on the hit markers and FAIL CLOSED: no hit
// marker means "absent" (under-claim), never "removed" (over-claim). That is
// correct whichever stream a given OpenSSH build uses for the miss line.
//
// Both markers are anchored so `target` cannot forge them. isValidHostname
// permits [a-zA-Z0-9._-] only, so a host can contain neither the space+colon of
// "found: line" nor a trailing " updated." at end-of-line.
const KEYGEN_REMOVED = [/(?:^|\s)found: line \d+/m, / updated\.$/m];

// A known_hosts file that does not exist at all is not a failure -- there is simply
// nothing to remove, which is the normal state on a fresh machine. Probed on
// OpenSSH_10.2p1: that case exits 255 with "Cannot stat <path>: No such file or
// directory", so without this it lands in the `!ok` branch below and a first-time
// host reports "Could not remove existing host key ..." even though the overall
// operation succeeded. Matched loosely (any "Cannot stat" + not-found) because the
// path in the message is the user's, and locale may reword the errno string.
const KEYGEN_NO_FILE = /Cannot stat .*No such file or directory/s;

function removeKnownHostEntry(target: string): KnownHostRemoval {
  const { stdout, ok } = runArgs("ssh-keygen", ["-R", target]);
  if (!ok) {
    return KEYGEN_NO_FILE.test(stdout) ? { result: "absent", output: stdout } : { result: "failed", output: stdout };
  }
  if (KEYGEN_REMOVED.some((re) => re.test(stdout))) return { result: "removed", output: stdout };
  return { result: "absent", output: stdout };
}

// Turns a removal outcome into an action line that states what actually happened.
function describeRemoval(target: string, removal: KnownHostRemoval): string {
  switch (removal.result) {
    case "removed":
      return `Removed old host key for ${target}`;
    case "absent":
      return `No existing host key for ${target} (nothing to remove)`;
    default:
      return `Could not remove existing host key for ${target}: ${removal.output || "ssh-keygen failed"}`;
  }
}

export function fixKnownHosts(host: string, port = 22): { status: "ok" | "error"; message: string; actions: string[] } {
  if (!isValidHostname(host)) {
    return { status: "error", message: `Invalid hostname: "${host}"`, actions: [] };
  }

  const actions: string[] = [];

  // Delegate target spelling to knownHostsTargets (ssh.ts) rather than building
  // `[${host}]:${port}` here. That template was wrong for IPv6 in BOTH directions,
  // probed against OpenSSH_10.2p1 with a seeded known_hosts:
  //   `ssh-keygen -R '[::1]'`        -> "not found", exit 0, removes NOTHING
  //   `ssh-keygen -R '[[::1]]:2222'` -> "not found", exit 0, removes NOTHING
  //   `ssh-keygen -R '::1'` / `-R '[::1]:2222'` -> both remove the entry
  // Because the removal silently no-opped while the ssh-keyscan half below still
  // APPENDED a fresh key, ssh_known_hosts_fix left the stale IPv6 key in the file
  // next to the new one -- and buildHostVerifier (ssh.ts) accepts if ANY known key
  // matches, so the key this tool exists to retire stayed trusted.
  for (const target of knownHostsTargets(host, port)) {
    actions.push(describeRemoval(target, removeKnownHostEntry(target)));
  }

  // Re-scan. ssh-keyscan takes the address BARE and writes the canonical spelling
  // itself (`host` at :22, `[host]:port` otherwise) -- which is exactly what the
  // `-R` targets above look for, so the two halves stay in agreement.
  const scanHost = unbracketHost(host);
  const scanArgs = port !== 22 ? ["-H", "-p", String(port), scanHost] : ["-H", scanHost];
  const { stdout: scanOut, ok: scanOk } = runArgs("ssh-keyscan", scanArgs);
  if (scanOk && scanOut.trim()) {
    try {
      const knownHostsPath = join(homedir(), ".ssh", "known_hosts");
      appendFileSync(knownHostsPath, `\n${scanOut.trim()}\n`);
      actions.push(`Added new host key for ${host}`);
      return { status: "ok", message: `Host key refreshed for ${host}`, actions };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      return { status: "error", message: `Scanned key but failed to write known_hosts: ${msg}`, actions };
    }
  }

  return { status: "error", message: `Could not scan host key for ${host}. Host may be unreachable.`, actions };
}

export function checkGitSsh(
  host = "github.com",
  user = "git",
): { status: "ok" | "error"; message: string; authenticatedAs?: string } {
  if (!isValidHostname(host)) {
    return { status: "error", message: `Invalid hostname: "${host}"` };
  }

  // ssh -T git@github.com returns exit code 1 even on success, and output goes to stderr
  // runArgs captures both
  const { stdout } = runArgs("ssh", ["-T", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes", `${user}@${host}`]);

  const text = stdout;

  // GitHub: "Hi username! You've successfully authenticated..."
  // GitLab: "Welcome to GitLab, @username!"
  // Bitbucket: "logged in as username"
  if (
    text.includes("successfully authenticated") ||
    text.includes("Welcome to GitLab") ||
    text.includes("logged in as")
  ) {
    const userMatch = text.match(/Hi (\S+)!/) || text.match(/@(\S+)!/) || text.match(/logged in as (\S+)/);
    return {
      status: "ok",
      message: `Git SSH authentication to ${host} succeeded${userMatch ? ` as ${userMatch[1]}` : ""}`,
      authenticatedAs: userMatch?.[1],
    };
  }

  if (text.includes("Permission denied")) {
    return {
      status: "error",
      message: `Permission denied for ${host}. Either no key is loaded in the agent or your key isn't registered with ${host}. Run ssh_key_list to check, then ssh_key_load if needed.`,
    };
  }

  if (text.includes("Connection refused")) {
    return { status: "error", message: `Connection refused by ${host}. SSH may not be available on this host.` };
  }
  if (text.includes("timed out") || text.includes("Connection timed out")) {
    return { status: "error", message: `Connection to ${host} timed out. Check your network or firewall.` };
  }
  if (text.includes("Could not resolve")) {
    return { status: "error", message: `Could not resolve hostname "${host}". Check DNS or spelling.` };
  }

  return { status: "error", message: `Git SSH check for ${host}: ${text || "no response (agent may not be running)"}` };
}

export function testConnection(host: string, port = 22): { status: "ok" | "warning" | "error"; message: string } {
  if (!isValidHostname(host)) {
    return { status: "error", message: `Invalid hostname: "${host}"` };
  }

  // The probe command and its error classification are shared with
  // checkConnectivity in diagnose.ts -- the two used to carry independent copies of
  // the same ~40 lines. Only the wording and the elapsed-ms timing below are
  // specific to this tool.
  const { outcome, output, elapsedMs } = probeSshConnection(host, port);

  switch (outcome) {
    case "ok":
      return { status: "ok", message: `Connected to ${host}:${port} in ${elapsedMs}ms` };
    case "permission-denied":
      return {
        status: "error",
        message: `Authentication failed to ${host}:${port} (${elapsedMs}ms). Key not authorized. Check: ssh-add -l, verify correct username, verify key is in remote authorized_keys.`,
      };
    case "connection-refused":
      return {
        status: "error",
        message: `Connection refused at ${host}:${port}. SSH server not running or port blocked.`,
      };
    case "timed-out":
      return { status: "error", message: `Connection timed out to ${host}:${port}. Host down or firewall blocking.` };
    case "host-key-mismatch":
      return {
        status: "error",
        message: `Host key mismatch for ${host}. Instance was likely recreated. Fix with ssh_known_hosts_fix.`,
      };
    case "dns-failure":
      return { status: "error", message: `Could not resolve "${host}". Check DNS, /etc/hosts, or SSH config.` };
    default:
      return { status: "error", message: `Connection failed to ${host}:${port}: ${output}` };
  }
}
