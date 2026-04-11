import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { Client, type ConnectConfig, type SFTPWrapper } from "ssh2";
import { checkKnownHosts, checkSshAgent, checkSshConfig, checkSshKeys, runArgs } from "./diagnose.js";

export interface SSHConfig {
  host: string;
  port?: number;
  username?: string;
  privateKeyPath?: string;
  password?: string;
  agent?: string;
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  code: number;
}

interface SshConfigResult {
  hostname: string;
  user: string;
  port: string;
  identityFiles: string[];
  proxyJump?: string;
}

export interface ResolvedConfig {
  connectConfig: ConnectConfig;
  proxyJump?: string;
}

function resolveFromSshConfig(host: string): SshConfigResult | null {
  try {
    const { stdout, ok } = runArgs("ssh", ["-G", host]);
    if (!ok) return null;

    const config: Record<string, string> = {};
    const identityFiles: string[] = [];

    for (const line of stdout.split("\n")) {
      const spaceIdx = line.indexOf(" ");
      if (spaceIdx > 0) {
        const key = line.substring(0, spaceIdx);
        const value = line.substring(spaceIdx + 1);
        if (key === "identityfile") {
          identityFiles.push(value);
        } else {
          config[key] = value;
        }
      }
    }

    return {
      hostname: config.hostname || host,
      user: config.user || "",
      port: config.port || "22",
      identityFiles,
      proxyJump: config.proxyjump && config.proxyjump !== "none" ? config.proxyjump : undefined,
    };
  } catch {
    return null;
  }
}

export function resolveConfig(config: SSHConfig): ResolvedConfig {
  // Resolve SSH config for the host (hostname aliases, user, port, identity files, proxy)
  const sshConfig = resolveFromSshConfig(config.host);

  const connectConfig: ConnectConfig = {
    host: sshConfig?.hostname || config.host,
    port: config.port || (sshConfig ? Number.parseInt(sshConfig.port, 10) : 22),
    username: config.username || sshConfig?.user || process.env.USER || process.env.USERNAME || "root",
    keepaliveInterval: 15_000,
    keepaliveCountMax: 3,
  };

  // Always set agent if available (including Windows named pipe)
  const agentSock =
    config.agent ||
    process.env.SSH_AUTH_SOCK ||
    (process.platform === "win32" ? "\\\\.\\pipe\\openssh-ssh-agent" : undefined);
  if (agentSock) {
    connectConfig.agent = agentSock;
  }

  // Set password if provided
  if (config.password) {
    connectConfig.password = config.password;
  }

  // Try to load a private key: explicit > SSH config identity files > default paths
  if (config.privateKeyPath) {
    connectConfig.privateKey = readFileSync(config.privateKeyPath);
  } else if (!agentSock) {
    // Only try key files if no agent — agent is the preferred auth method
    const home = homedir();
    const keyPaths =
      sshConfig && sshConfig.identityFiles.length > 0
        ? sshConfig.identityFiles.map((p) => (p.startsWith("~") ? join(home, p.slice(1)) : p))
        : [join(home, ".ssh", "id_ed25519"), join(home, ".ssh", "id_rsa"), join(home, ".ssh", "id_ecdsa")];

    for (const keyPath of keyPaths) {
      try {
        connectConfig.privateKey = readFileSync(keyPath);
        break;
      } catch {
        // Key doesn't exist, try next
      }
    }
  }

  return { connectConfig, proxyJump: sshConfig?.proxyJump };
}

export function formatDiagnostics(host: string): string {
  // Run fast local checks only — skip connectivity re-test to avoid adding seconds of delay
  try {
    const checks = [
      { name: "SSH Agent", ...checkSshAgent() },
      { name: "SSH Keys", ...checkSshKeys() },
      { name: "SSH Config", ...checkSshConfig(host) },
      { name: "Known Hosts", ...checkKnownHosts(host) },
    ];

    const parts: string[] = [];
    const suggestions: string[] = [];

    for (const check of checks) {
      if (check.status !== "ok") {
        parts.push(`[${check.status.toUpperCase()}] ${check.name}: ${check.message}`);
      }
    }

    const agent = checks[0];
    if (agent.status === "error") suggestions.push('Start ssh-agent: eval "$(ssh-agent -s)"');
    if (agent.status === "warning") suggestions.push("Load a key: ssh-add ~/.ssh/id_ed25519");

    const keys = checks[1];
    if (keys.status === "error") suggestions.push('Generate a key: ssh-keygen -t ed25519 -C "your@email.com"');

    const known = checks[3];
    if (known.status === "warning") suggestions.push(`Add host key: ssh-keyscan -H "${host}" >> ~/.ssh/known_hosts`);

    if (suggestions.length > 0) {
      parts.push(`Suggested fixes: ${suggestions.join(" | ")}`);
    }

    return parts.length > 0 ? parts.join("\n") : "";
  } catch {
    return "";
  }
}

export function connectRaw(connectConfig: ConnectConfig): Promise<Client> {
  return new Promise((resolve, reject) => {
    const client = new Client();
    client
      .on("ready", () => resolve(client))
      .on("error", (err) => reject(err))
      .connect(connectConfig);
  });
}

export async function connectWithProxy(resolved: ResolvedConfig): Promise<Client> {
  if (!resolved.proxyJump) {
    return connectRaw(resolved.connectConfig);
  }

  // Connect to the jump host
  const jumpResolved = resolveConfig({ host: resolved.proxyJump });
  const jumpClient = await connectWithProxy(jumpResolved); // recursive for chained proxies

  // Create tunnel from jump host to target
  const targetHost = resolved.connectConfig.host as string;
  const targetPort = resolved.connectConfig.port as number;

  const stream = await new Promise<any>((resolve, reject) => {
    jumpClient.forwardOut("127.0.0.1", 0, targetHost, targetPort, (err, stream) => {
      if (err) {
        jumpClient.end();
        return reject(err);
      }
      resolve(stream);
    });
  });

  // Connect through the tunnel
  return new Promise((resolve, reject) => {
    const client = new Client();
    client
      .on("ready", () => resolve(client))
      .on("error", (err) => {
        jumpClient.end();
        reject(err);
      })
      .on("close", () => {
        jumpClient.end();
      })
      .connect({ ...resolved.connectConfig, sock: stream });
  });
}

export async function connect(config: SSHConfig): Promise<Client> {
  const resolved = resolveConfig(config);
  try {
    return await connectWithProxy(resolved);
  } catch (err: unknown) {
    const diag = formatDiagnostics(config.host);
    if (diag) {
      const message = err instanceof Error ? err.message : String(err);
      const enhanced = new Error(`${message}\n\nSSH Diagnostics:\n${diag}`);
      enhanced.cause = err;
      throw enhanced;
    }
    throw err;
  }
}

export function exec(client: Client, command: string, timeoutMs = 30000): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    let settled = false;

    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };

    const timer = setTimeout(() => {
      settle(() => reject(new Error(`Command timed out after ${timeoutMs}ms`)));
    }, timeoutMs);

    client.exec(command, (err, stream) => {
      if (err) {
        settle(() => reject(err));
        return;
      }

      let stdout = "";
      let stderr = "";

      stream
        .on("close", (code: number) => {
          settle(() => resolve({ stdout, stderr, code: code ?? 0 }));
        })
        .on("data", (data: Buffer) => {
          stdout += data.toString();
        })
        .on("error", (err: Error) => {
          settle(() => reject(err));
        });

      stream.stderr
        .on("data", (data: Buffer) => {
          stderr += data.toString();
        })
        .on("error", (err: Error) => {
          settle(() => reject(err));
        });
    });
  });
}

function getSftp(client: Client): Promise<SFTPWrapper> {
  return new Promise((resolve, reject) => {
    client.sftp((err, sftp) => {
      if (err) return reject(err);
      resolve(sftp);
    });
  });
}

const DEFAULT_MAX_READ_BYTES = 10 * 1024 * 1024; // 10 MB

export async function readFile(client: Client, remotePath: string, maxBytes = DEFAULT_MAX_READ_BYTES): Promise<string> {
  const sftp = await getSftp(client);
  try {
    const stats = await new Promise<{ size: number }>((resolve, reject) => {
      sftp.stat(remotePath, (err, stats) => {
        if (err) return reject(err);
        resolve(stats);
      });
    });
    if (stats.size > maxBytes) {
      throw new Error(
        `File is ${(stats.size / 1024 / 1024).toFixed(1)} MB, exceeds ${(maxBytes / 1024 / 1024).toFixed(0)} MB limit. Use ssh_exec with head/tail to read a portion.`,
      );
    }
    return await new Promise((resolve, reject) => {
      sftp.readFile(remotePath, (err, data) => {
        if (err) return reject(err);
        resolve(data.toString("utf8"));
      });
    });
  } finally {
    sftp.end();
  }
}

export async function writeFile(client: Client, remotePath: string, content: string): Promise<void> {
  const sftp = await getSftp(client);
  try {
    await new Promise<void>((resolve, reject) => {
      sftp.writeFile(remotePath, content, (err) => {
        if (err) return reject(err);
        resolve();
      });
    });
  } finally {
    sftp.end();
  }
}

export async function uploadFile(client: Client, localPath: string, remotePath: string): Promise<void> {
  const sftp = await getSftp(client);
  try {
    await new Promise<void>((resolve, reject) => {
      sftp.fastPut(localPath, remotePath, (err) => {
        if (err) return reject(err);
        resolve();
      });
    });
  } finally {
    sftp.end();
  }
}

export async function downloadFile(client: Client, remotePath: string, localPath: string): Promise<void> {
  const sftp = await getSftp(client);
  try {
    await new Promise<void>((resolve, reject) => {
      sftp.fastGet(remotePath, localPath, (err) => {
        if (err) return reject(err);
        resolve();
      });
    });
  } finally {
    sftp.end();
  }
}

export async function listDir(client: Client, remotePath: string): Promise<string[]> {
  const sftp = await getSftp(client);
  try {
    return await new Promise((resolve, reject) => {
      sftp.readdir(remotePath, (err, list) => {
        if (err) return reject(err);
        resolve(list.map((item) => item.filename));
      });
    });
  } finally {
    sftp.end();
  }
}
