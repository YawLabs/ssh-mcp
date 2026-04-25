import { appendFileSync, existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { isValidHostname, runArgs } from "./diagnose.js";

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

// Runs `ssh-add -l` and shapes the result into an AgentResult if the agent was
// reachable. Returns null if ssh-add couldn't talk to any agent on this channel
// (so the caller can try the next fallback). `socket` is used verbatim in the
// result — the Windows named pipe and a Unix $SSH_AUTH_SOCK path both flow
// through here identically.
function probeAgent(socket: string, agentLabel: string): AgentResult | null {
  const { stdout, ok } = runArgs("ssh-add", ["-l"]);
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

export function ensureAgent(): AgentResult {
  const sock = process.env.SSH_AUTH_SOCK;
  if (sock) {
    const result = probeAgent(sock, "ssh-agent");
    if (result) return result;
  }

  // On Windows, try the OpenSSH agent service (uses named pipe, not SSH_AUTH_SOCK)
  if (!sock && process.platform === "win32") {
    const result = probeAgent("\\\\.\\pipe\\openssh-ssh-agent", "Windows OpenSSH agent");
    if (result) return result;
  }

  // Try to start a new agent (Unix)
  const { stdout, ok } = runArgs("ssh-agent", ["-s"]);
  if (ok) {
    const sockMatch = stdout.match(/SSH_AUTH_SOCK=([^;]+)/);
    const pidMatch = stdout.match(/SSH_AGENT_PID=([^;]+)/);
    if (sockMatch) {
      process.env.SSH_AUTH_SOCK = sockMatch[1];
      if (pidMatch) process.env.SSH_AGENT_PID = pidMatch[1];
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

  return {
    running: false,
    reachable: false,
    keys: [],
    started: false,
    message:
      process.platform === "win32"
        ? "Windows OpenSSH agent not running. Start it: Get-Service ssh-agent | Set-Service -StartupType Automatic; Start-Service ssh-agent"
        : 'Could not start ssh-agent. Run manually: eval "$(ssh-agent -s)"',
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

  const skipFiles = new Set(["known_hosts", "known_hosts.old", "config", "authorized_keys", "environment"]);

  const keys: KeyInfo[] = [];

  let files: string[];
  try {
    files = readdirSync(sshDir);
  } catch {
    return [];
  }

  for (const file of files) {
    if (file.endsWith(".pub") || file.startsWith(".") || skipFiles.has(file)) continue;

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

  if (stdout.includes("passphrase") || stdout.includes("incorrect") || stdout.includes("bad permissions")) {
    if (stdout.includes("UNPROTECTED PRIVATE KEY")) {
      return { status: "error", message: `Key ${resolved} has too-open permissions. Fix: chmod 600 ${resolved}` };
    }
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

  const all: Record<string, string> = {};
  const identityFiles: string[] = [];

  for (const line of stdout.split("\n")) {
    const spaceIdx = line.indexOf(" ");
    if (spaceIdx > 0) {
      const key = line.substring(0, spaceIdx);
      const value = line.substring(spaceIdx + 1);
      if (key === "identityfile") {
        identityFiles.push(value);
      } else {
        all[key] = value;
      }
    }
  }

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

export function fixKnownHosts(host: string, port = 22): { status: "ok" | "error"; message: string; actions: string[] } {
  if (!isValidHostname(host)) {
    return { status: "error", message: `Invalid hostname: "${host}"`, actions: [] };
  }

  const actions: string[] = [];

  // Remove stale entry
  const { ok: removeOk } = runArgs("ssh-keygen", ["-R", host]);
  if (removeOk) {
    actions.push(`Removed old host key for ${host}`);
  }

  // Also remove [host]:port if non-standard port
  if (port !== 22) {
    const { ok } = runArgs("ssh-keygen", ["-R", `[${host}]:${port}`]);
    if (ok) actions.push(`Removed old host key for [${host}]:${port}`);
  }

  // Re-scan
  const scanArgs = port !== 22 ? ["-H", "-p", String(port), host] : ["-H", host];
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

  const start = Date.now();
  // StrictHostKeyChecking=no is safe here: this is a read-only probe that only echoes
  // "SSH_OK". For actual operations, hostVerifier in resolveConfig (src/ssh.ts)
  // enforces known_hosts matching.
  const { ok, stdout } = runArgs("ssh", [
    "-o",
    "ConnectTimeout=5",
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=no",
    "-p",
    String(port),
    host,
    "echo",
    "SSH_OK",
  ]);
  const elapsed = Date.now() - start;

  if (ok && stdout.includes("SSH_OK")) {
    return { status: "ok", message: `Connected to ${host}:${port} in ${elapsed}ms` };
  }

  if (stdout.includes("Permission denied")) {
    return {
      status: "error",
      message: `Authentication failed to ${host}:${port} (${elapsed}ms). Key not authorized. Check: ssh-add -l, verify correct username, verify key is in remote authorized_keys.`,
    };
  }
  if (stdout.includes("Connection refused")) {
    return {
      status: "error",
      message: `Connection refused at ${host}:${port}. SSH server not running or port blocked.`,
    };
  }
  if (stdout.includes("timed out")) {
    return { status: "error", message: `Connection timed out to ${host}:${port}. Host down or firewall blocking.` };
  }
  if (stdout.includes("Host key verification failed")) {
    return {
      status: "error",
      message: `Host key mismatch for ${host}. Instance was likely recreated. Fix with ssh_known_hosts_fix.`,
    };
  }
  if (stdout.includes("Could not resolve")) {
    return { status: "error", message: `Could not resolve "${host}". Check DNS, /etc/hosts, or SSH config.` };
  }

  return { status: "error", message: `Connection failed to ${host}:${port}: ${stdout}` };
}
