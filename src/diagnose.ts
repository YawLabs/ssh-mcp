import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
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

// Validate hostname to prevent shell injection — only allow safe characters
export function isValidHostname(host: string): boolean {
  return /^[a-zA-Z0-9._\-:[\]]+$/.test(host) && host.length <= 253;
}

export function runArgs(cmd: string, args: string[]): { stdout: string; ok: boolean } {
  try {
    const stdout = execFileSync(cmd, args, { encoding: "utf8", timeout: 10000, stdio: ["pipe", "pipe", "pipe"] });
    return { stdout: stdout.trim(), ok: true };
  } catch (e: any) {
    // Capture both stdout and stderr — many SSH commands (ssh -T, ssh-add) output to stderr
    const stdout = e.stdout?.toString().trim() || "";
    const stderr = e.stderr?.toString().trim() || "";
    const output = [stdout, stderr].filter(Boolean).join("\n") || e.message || "";
    return { stdout: output, ok: false };
  }
}

export function checkSshAgent(): DiagnosticResult {
  const sock = process.env.SSH_AUTH_SOCK;
  if (!sock) {
    return {
      status: "error",
      message: "SSH_AUTH_SOCK is not set. ssh-agent is not running or not exported to this shell.",
    };
  }

  const { stdout, ok } = runArgs("ssh-add", ["-l"]);
  if (!ok && stdout.includes("Could not open a connection")) {
    return {
      status: "error",
      message: `SSH_AUTH_SOCK is set to "${sock}" but the agent is not reachable. The agent process may have died. Run: eval "$(ssh-agent -s)"`,
    };
  }

  if (stdout.includes("The agent has no identities")) {
    return {
      status: "warning",
      message: "ssh-agent is running but has no keys loaded. Run: ssh-add <key-path>",
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
    const allFiles = readdirSync(sshDir).filter(
      (f) => !f.endsWith(".pub") && !["known_hosts", "known_hosts.old", "config", "authorized_keys"].includes(f),
    );
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
  const knownHostsPath = join(homedir(), ".ssh", "known_hosts");

  if (!existsSync(knownHostsPath)) {
    return {
      status: "warning",
      message: "~/.ssh/known_hosts does not exist. First connection to any host will prompt for verification.",
    };
  }

  if (!isValidHostname(host)) {
    return { status: "error", message: `Invalid hostname: "${host}"` };
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

export function checkConnectivity(host: string, port = 22): DiagnosticResult {
  if (!isValidHostname(host)) {
    return { status: "error", message: `Invalid hostname: "${host}"` };
  }

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

  if (ok && stdout.includes("SSH_OK")) {
    return { status: "ok", message: `SSH connection to ${host}:${port} succeeded` };
  }

  if (stdout.includes("Permission denied")) {
    return {
      status: "error",
      message: `Permission denied connecting to ${host}:${port}. Your key is not authorized on this host. Check: 1) correct key is loaded (ssh-add -l), 2) key is in remote authorized_keys, 3) correct username.`,
    };
  }
  if (stdout.includes("Connection refused")) {
    return {
      status: "error",
      message: `Connection refused at ${host}:${port}. SSH server is not running on this port or host is blocking connections.`,
    };
  }
  if (stdout.includes("Connection timed out") || stdout.includes("timed out")) {
    return {
      status: "error",
      message: `Connection timed out to ${host}:${port}. Host may be down, port may be blocked by firewall, or DNS resolution failed.`,
    };
  }
  if (stdout.includes("Host key verification failed")) {
    return {
      status: "error",
      message: `Host key verification failed for ${host}. The host key changed (instance recreated?). Fix: ssh-keygen -R "${host}" && ssh-keyscan -H "${host}" >> ~/.ssh/known_hosts`,
    };
  }
  if (stdout.includes("Could not resolve hostname")) {
    return {
      status: "error",
      message: `Could not resolve hostname "${host}". Check DNS, /etc/hosts, or SSH config aliases.`,
    };
  }

  return { status: "error", message: `SSH connection failed: ${stdout}` };
}

export function checkSshConfig(host: string): DiagnosticResult {
  const configPath = join(homedir(), ".ssh", "config");

  if (!existsSync(configPath)) {
    return { status: "ok", message: "No ~/.ssh/config file (using defaults)" };
  }

  try {
    const content = readFileSync(configPath, "utf8");
    const lines = content.split("\n");
    let inHostBlock = false;
    const hostConfig: string[] = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (/^Host\s+/i.test(trimmed)) {
        const patterns = trimmed
          .replace(/^Host\s+/i, "")
          .trim()
          .split(/\s+/);
        inHostBlock = patterns.some((p) => {
          if (p === "*") return true;
          if (p === host) return true;
          // Simple wildcard matching: *.example.com
          if (p.includes("*")) {
            const regex = new RegExp("^" + p.replace(/\./g, "\\.").replace(/\*/g, ".*") + "$");
            return regex.test(host);
          }
          return false;
        });
        if (inHostBlock) hostConfig.push(trimmed);
      } else if (inHostBlock && trimmed) {
        hostConfig.push(trimmed);
      } else if (inHostBlock && !trimmed) {
        inHostBlock = false;
      }
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
