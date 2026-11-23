import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  agentChildEnv,
  classifySshProbe,
  isValidHostname,
  type PrivateKeyCandidate,
  portPinnedOnlyAt22Note,
  probeSshConnection,
  runArgs,
  scanPrivateKeyFiles,
  WINDOWS_AGENT_PIPE,
} from "./diagnose.js";
import { expandTilde, knownHostsTargets, unbracketHost } from "./ssh.js";
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

/** Child-env override that reaches one agent channel; see agentChildEnv in diagnose.ts. */
type AgentEnv = Record<string, string | undefined>;

// Runs `ssh-add -l` against a specific agent channel and shapes the result into
// an AgentResult if the agent was reachable. Returns null if ssh-add couldn't
// talk to any agent on this channel (so the caller can try the next fallback).
//
// Channel selection is `agentChildEnv` (diagnose.ts): SSH_AUTH_SOCK is SET to the
// socket the caller asked about -- a Unix path or a custom named pipe -- and UNSET
// only for the default Windows pipe, which Windows ssh-add reaches on its own when
// no SSH_AUTH_SOCK is present. Unsetting (rather than not passing one) keeps a stale
// SSH_AUTH_SOCK in the parent env from redirecting ssh-add away from that pipe.
function probeAgent(socket: string, agentLabel: string, env: AgentEnv): AgentResult | null {
  const { stdout, ok } = runArgs("ssh-add", ["-l"], { env });
  const noIdentities = stdout.includes("no identities");
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

/** A reachable agent plus the child-env override that reached it. */
interface AgentChannel {
  agent: AgentResult;
  /**
   * Pass this to every follow-up ssh-add (load, list) so it talks to the SAME agent
   * the probe found. Undefined means "the inherited process.env already points there".
   */
  env?: AgentEnv;
  /**
   * Set when the agent was reached only through the Windows named pipe while
   * SSH_AUTH_SOCK names a socket where nothing answers. The connection path
   * (resolveConfig, ssh.ts) still tries SSH_AUTH_SOCK first, so a key reported as
   * running/loaded here is not what ssh_exec sees. Same caveat as checkSshAgent.
   */
  caveat?: string;
}

function staleSockCaveat(sock: string): string {
  return `Note: SSH_AUTH_SOCK is set to "${sock}", where no agent answers, and connections use SSH_AUTH_SOCK first, so ssh_exec will not see this agent's keys. Unset SSH_AUTH_SOCK so every tool reaches the agent through its named pipe.`;
}

// Finds an agent that answers, without starting one: SSH_AUTH_SOCK first, then (on
// Windows) the OpenSSH service's named pipe.
//
// The pipe is tried whenever the SSH_AUTH_SOCK path didn't yield a reachable agent --
// including the case where SSH_AUTH_SOCK is set but stale (e.g. a leftover Unix-style
// path from WSL or a prior session). Without this fall-through, a Windows user with a
// stale SSH_AUTH_SOCK never reaches the named-pipe attempt and gets "not running"
// while the actual OpenSSH agent service is up. process.env is NOT changed, which is
// why the channel's env travels with the result: a follow-up ssh-add with the
// inherited stale SSH_AUTH_SOCK fails "Error connecting to agent" (measured with
// Windows' own ssh-add, which honours a stale value).
function findReachableAgent(): AgentChannel | null {
  const sock = process.env.SSH_AUTH_SOCK;
  if (sock) {
    const env = agentChildEnv(sock);
    const agent = probeAgent(sock, "ssh-agent", env);
    if (agent) return { agent, env };
  }
  if (process.platform === "win32") {
    const env = agentChildEnv(WINDOWS_AGENT_PIPE);
    const agent = probeAgent(WINDOWS_AGENT_PIPE, "Windows OpenSSH agent", env);
    if (agent) return sock ? { agent, env, caveat: staleSockCaveat(sock) } : { agent, env };
  }
  return null;
}

export function ensureAgent(): AgentResult {
  const { agent, caveat } = ensureAgentChannel();
  return caveat ? { ...agent, message: `${agent.message} ${caveat}` } : agent;
}

function ensureAgentChannel(): AgentChannel {
  const found = findReachableAgent();
  if (found) return found;

  if (process.platform === "win32") {
    // Skip the `ssh-agent -s` spawn below: on win32 it either errors (no Bourne-shell
    // output) or, in Git Bash with a Unix-ish ssh-agent.exe, spawns an agent whose
    // socket the rest of the stack can't reach. Return the Windows-specific error
    // directly so we don't orphan a process.
    return {
      agent: {
        running: false,
        reachable: false,
        keys: [],
        started: false,
        message:
          "Windows OpenSSH agent not running. Start it: Get-Service ssh-agent | Set-Service -StartupType Automatic; Start-Service ssh-agent",
      },
    };
  }

  return { agent: startAgent() };
}

function startAgent(): AgentResult {
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

// The key type ssh-keygen itself reports: `ssh-keygen -lf` prints
// `<bits> <fingerprint> <comment> (TYPE)`, and the trailing parenthesized type is
// authoritative -- it is parsed from key material, not guessed from a name. (Real
// ssh-keygen reads `<file>.pub` first when one exists, so a mismatched .pub decides
// both the type and the fingerprint.) -l reads only
// the unencrypted public-key portion of an OpenSSH file, so no passphrase prompt
// occurs even for passphrased keys. Anchored at end of output, so a preamble line
// cannot win.
function keyTypeFromFingerprint(fingerprintOutput: string): string | null {
  const match = fingerprintOutput.match(/\(([^)]+)\)\s*$/);
  return match ? match[1].toLowerCase() : null;
}

// Fallback used only when ssh-keygen could not answer. `content` is the private key
// file as the scan already read it through its fd; it is passed in rather than
// re-read here by path, which could see a different file.
function guessKeyType(filePath: string, fileName: string, content: string): string {
  // The .pub file, when present.
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

  // Type-specific PEM banners. Modern OpenSSH wraps every type in the generic
  // `OPENSSH PRIVATE KEY`, which none of these match.
  if (content.includes("RSA PRIVATE KEY")) return "rsa";
  if (content.includes("EC PRIVATE KEY")) return "ecdsa";
  if (content.includes("DSA PRIVATE KEY")) return "dsa";

  // Last resort: the filename, matched on whole tokens -- a substring test read
  // `universal_deploy` as rsa. Token match also keeps `ecdsa` from reading as dsa.
  const tokens = new Set(fileName.toLowerCase().split(/[^a-z0-9]+/));
  for (const type of ["ed25519", "rsa", "ecdsa", "dsa"]) {
    if (tokens.has(type)) return type;
  }

  return "unknown";
}

/**
 * Outcome of a ~/.ssh scan. An empty `keys` array on its own is ambiguous -- it is what
 * "there is no ~/.ssh", "~/.ssh could not be read" and "~/.ssh holds no private keys" all
 * produce -- and only the last of those is remediated by generating a key. `status` is the
 * discriminator that tells them apart:
 *
 *   "ok"          the directory was read; `keys` is what it holds (possibly nothing)
 *   "no-dir"      ~/.ssh does not exist (a fresh machine -- ssh-keygen will create it)
 *   "unreadable"  readdir threw: permission denied, or a non-directory at that path.
 *                 `reason` carries the underlying errno message.
 *
 * `keys` is always present and always empty for the two non-"ok" statuses, so a caller that
 * only wants the keys can read it without narrowing first.
 */
export type SshKeyListing =
  | { status: "ok"; dir: string; keys: KeyInfo[] }
  | { status: "no-dir"; dir: string; keys: KeyInfo[] }
  | { status: "unreadable"; dir: string; keys: KeyInfo[]; reason: string };

/**
 * Thin wrapper kept for every caller that only needs the keys: it discards the reason a
 * scan came back empty. Prefer listSshKeysDetailed when an empty result has to be
 * explained to a human or an agent -- see the type above for why.
 */
export function listSshKeys(): KeyInfo[] {
  return listSshKeysDetailed().keys;
}

export function listSshKeysDetailed(): SshKeyListing {
  const sshDir = join(homedir(), ".ssh");
  if (!existsSync(sshDir)) return { status: "no-dir", dir: sshDir, keys: [] };

  // Fingerprints of the keys loaded in the agent, asked of the SAME channel ensureAgent
  // would pick (findReachableAgent), so a stale SSH_AUTH_SOCK beside a live Windows
  // agent does not mark every key "not loaded". Nothing is started here.
  const loadedFingerprints = new Set<string>();
  for (const line of findReachableAgent()?.agent.keys ?? []) {
    const match = line.match(/(\S+:\S+)/);
    if (match) loadedFingerprints.add(match[1]);
  }

  let candidates: PrivateKeyCandidate[];
  try {
    // The fd-based scan shared with checkSshKeys (diagnose.ts).
    candidates = scanPrivateKeyFiles(sshDir);
  } catch (e) {
    // Distinct from "the directory is empty": EACCES on ~/.ssh, or a plain file sitting
    // where the directory should be (ENOTDIR). Neither is fixed by generating a key, so
    // the reason travels back to the caller instead of being flattened into [].
    return { status: "unreadable", dir: sshDir, keys: [], reason: e instanceof Error ? e.message : String(e) };
  }

  const keys: KeyInfo[] = [];
  for (const { name, path, content } of candidates) {
    // ONE ssh-keygen call yields both the fingerprint and the authoritative type.
    // ssh-keygen takes the path, so a swap after the scan can only skew those two.
    let fingerprint: string | undefined;
    let type: string | null = null;
    const { stdout: fpOut, ok: fpOk } = runArgs("ssh-keygen", ["-lf", path]);
    if (fpOk) {
      fingerprint = fpOut.match(/(\S+:\S+)/)?.[1];
      type = keyTypeFromFingerprint(fpOut);
    }

    const loadedInAgent = fingerprint ? loadedFingerprints.has(fingerprint) : false;
    keys.push({ name, path, type: type ?? guessKeyType(path, name, content), fingerprint, loadedInAgent });
  }

  return { status: "ok", dir: sshDir, keys };
}

export function loadKey(keyPath: string): { status: "ok" | "error"; message: string } {
  // Ensure agent is running first
  const { agent, env: agentEnv, caveat } = ensureAgentChannel();
  if (!agent.reachable) {
    return { status: "error", message: agent.message };
  }

  // Resolve ~ to home directory
  const resolved = expandTilde(keyPath, homedir());

  if (!existsSync(resolved)) {
    return { status: "error", message: `Key not found: ${resolved}` };
  }

  // Through the channel ensureAgent validated, not the inherited env: on Windows with
  // a stale SSH_AUTH_SOCK that is the named pipe, which the inherited value misses.
  const { stdout, ok } = runArgs("ssh-add", [resolved], agentEnv ? { env: agentEnv } : undefined);
  if (ok) {
    return { status: "ok", message: caveat ? `Key loaded: ${resolved}. ${caveat}` : `Key loaded: ${resolved}` };
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

  // SCAN FIRST, remove second. Removing first meant a failed scan (host briefly
  // unreachable, a DNS blip, no ssh-keyscan) returned an error with the old key
  // already deleted -- and since an unknown host is accepted unverified, a host that
  // had MITM protection silently lost it. Nothing in known_hosts changes unless a
  // replacement key is in hand.
  //
  // ssh-keyscan takes the address BARE and writes the canonical spelling itself
  // (`host` at :22, `[host]:port` otherwise) -- which is exactly what the `-R`
  // target below looks for, so the two halves stay in agreement.
  const scanHost = unbracketHost(host);
  const scanArgs = port !== 22 ? ["-H", "-p", String(port), scanHost] : ["-H", scanHost];
  const { stdout: scanOut, ok: scanOk } = runArgs("ssh-keyscan", scanArgs);
  if (!scanOk || !scanOut.trim()) {
    return {
      status: "error",
      message: `Could not scan host key for ${host}. Host may be unreachable. known_hosts was left unchanged.`,
      actions,
    };
  }

  // Delegate target spelling to knownHostsTargets (ssh.ts) rather than building
  // `[${host}]:${port}` here. That template was wrong for IPv6 in BOTH directions,
  // probed against OpenSSH_10.2p1 with a seeded known_hosts:
  //   `ssh-keygen -R '[::1]'`        -> "not found", exit 0, removes NOTHING
  //   `ssh-keygen -R '[[::1]]:2222'` -> "not found", exit 0, removes NOTHING
  //   `ssh-keygen -R '::1'` / `-R '[::1]:2222'` -> both remove the entry
  // Because the removal silently no-opped while the ssh-keyscan half still APPENDED
  // a fresh key, ssh_known_hosts_fix left the stale IPv6 key in the file next to the
  // new one -- and buildHostVerifier (ssh.ts) accepts if ANY known key matches, so
  // the key this tool exists to retire stayed trusted.
  //
  // Only the FIRST target: the entry for this exact port. On a non-default port
  // knownHostsTargets also lists the bare (port-22) spelling for LOOKUP, but that
  // entry belongs to port 22, which this scan did not cover -- removing it would
  // drop port 22's pin with no replacement.
  const [target] = knownHostsTargets(host, port);
  actions.push(describeRemoval(target, removeKnownHostEntry(target)));

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

// A git-host SSH user: letters, digits, dot and underscore, with hyphens after the
// first character. A leading '-' would otherwise be read by ssh as an option.
const VALID_GIT_USER = /^[A-Za-z0-9._][A-Za-z0-9._-]*$/;

// Strips sentence punctuation that a greeting glues onto the name
// ("logged in as jeffy." -> "jeffy").
const trimName = (name: string | undefined): string | undefined => name?.replace(/[.,;:!?]+$/, "") || undefined;

export function checkGitSsh(
  host = "github.com",
  user = "git",
): { status: "ok" | "error"; message: string; authenticatedAs?: string } {
  if (!isValidHostname(host)) {
    return { status: "error", message: `Invalid hostname: "${host}"` };
  }
  if (!VALID_GIT_USER.test(user)) {
    return { status: "error", message: `Invalid user: "${user}"` };
  }

  // ssh -T git@github.com returns exit code 1 even on success, and output goes to stderr
  // runArgs captures both. `--` ends option parsing before the target, as in
  // probeSshConnection.
  const { stdout: text } = runArgs("ssh", [
    "-T",
    "-o",
    "ConnectTimeout=5",
    "-o",
    "BatchMode=yes",
    "--",
    `${user}@${host}`,
  ]);

  // GitHub: "Hi username! You've successfully authenticated..."
  // GitLab: "Welcome to GitLab, @username!"
  // Bitbucket: "logged in as username."
  if (
    text.includes("successfully authenticated") ||
    text.includes("Welcome to GitLab") ||
    text.includes("logged in as")
  ) {
    // "logged in as" is tried before the @-form: the @-form is loose enough that a
    // banner such as "Contact @ops-team!" would otherwise be taken for the user.
    const userMatch = text.match(/Hi (\S+)!/) || text.match(/logged in as (\S+)/) || text.match(/@(\S+)!/);
    const authenticatedAs = trimName(userMatch?.[1]);
    return {
      status: "ok",
      message: `Git SSH authentication to ${host} succeeded${authenticatedAs ? ` as ${authenticatedAs}` : ""}`,
      authenticatedAs,
    };
  }

  // Failures share classifySshProbe (diagnose.ts) with ssh_test / ssh_diagnose, so
  // the three probes cannot drift apart; only the wording here is git-specific.
  switch (classifySshProbe(false, text)) {
    case "host-key-unknown":
    case "host-key-mismatch":
      // Under BatchMode ssh cannot prompt, so this covers BOTH an unknown host and a
      // changed key.
      return {
        status: "error",
        message: `Host key verification failed for ${host}: it is either not in known_hosts (BatchMode cannot prompt to add it) or its key changed. Fix with ssh_known_hosts_fix.`,
      };
    case "permission-denied":
      return {
        status: "error",
        message: `Permission denied for ${host}. Either no key is loaded in the agent or your key isn't registered with ${host}. Run ssh_key_list to check, then ssh_key_load if needed.`,
      };
    case "connection-refused":
      return { status: "error", message: `Connection refused by ${host}. SSH may not be available on this host.` };
    case "timed-out":
      return { status: "error", message: `Connection to ${host} timed out. Check your network or firewall.` };
    case "dns-failure":
      return { status: "error", message: `Could not resolve hostname "${host}". Check DNS or spelling.` };
    default:
      return {
        status: "error",
        message: `Git SSH check for ${host}: ${text || "no response (agent may not be running)"}`,
      };
  }
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
    case "host-key-unknown": {
      // Shared with checkConnectivity: a host pinned only by its bare (port-22) entry
      // is refused here but accepted by ssh_exec when the key matches that entry.
      const note = portPinnedOnlyAt22Note(host, port);
      if (note) return { status: "error", message: note };
      return {
        status: "error",
        message: `${host}:${port} is not in known_hosts and SSH_MCP_STRICT_HOSTKEYS is on, so it is refused. Pin it with ssh_known_hosts_fix.`,
      };
    }
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
