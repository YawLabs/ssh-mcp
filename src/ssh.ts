import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { Client, type ConnectConfig, type SFTPWrapper } from "ssh2";
import {
  checkKnownHosts,
  checkSshAgent,
  checkSshConfig,
  checkSshKeys,
  type DiagnosticResult,
  isValidHostname,
  runArgs,
} from "./diagnose.js";

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

// Looks up entries via `ssh-keygen -F` so hashed known_hosts lines (|1|...) resolve
// transparently without us reimplementing HMAC.
export function readKnownHostsKeys(host: string, port?: number): Buffer[] {
  if (!isValidHostname(host)) return [];
  const targets = port && port !== 22 ? [`[${host}]:${port}`, host] : [host];
  const keys: Buffer[] = [];
  for (const target of targets) {
    const { stdout, ok } = runArgs("ssh-keygen", ["-F", target]);
    if (!ok || !stdout.trim()) continue;
    for (const line of stdout.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      // Format: <host-or-hash> <keytype> <base64> [comment]
      const parts = trimmed.split(/\s+/);
      if (parts.length < 3) continue;
      try {
        keys.push(Buffer.from(parts[2], "base64"));
      } catch {
        // Skip malformed entry
      }
    }
  }
  return keys;
}

// Build a hostVerifier that compares the server's key against ~/.ssh/known_hosts.
// - Known host, key matches: accept.
// - Known host, key mismatch: reject (MITM protection).
// - Unknown host: accept (TOFU) unless SSH_MCP_STRICT_HOST_KEY=1, then reject.
//
// Checks known_hosts under both the user-supplied host (e.g. a ssh_config alias) and
// the resolved hostname, matching OpenSSH's CheckHostIP behavior.
function buildHostVerifier(hosts: ReadonlyArray<string>, port: number | undefined): (key: Buffer) => boolean {
  const strict = process.env.SSH_MCP_STRICT_HOST_KEY === "1";
  return (key: Buffer) => {
    const known = hosts.flatMap((h) => readKnownHostsKeys(h, port));
    if (known.length === 0) {
      return !strict;
    }
    return known.some((k) => k.equals(key));
  };
}

export function resolveConfig(config: SSHConfig): ResolvedConfig {
  // Resolve SSH config for the host (hostname aliases, user, port, identity files, proxy)
  const sshConfig = resolveFromSshConfig(config.host);

  const port = config.port || (sshConfig ? Number.parseInt(sshConfig.port, 10) : 22);
  const verifierHosts = [config.host];
  if (sshConfig?.hostname && sshConfig.hostname !== config.host) {
    verifierHosts.push(sshConfig.hostname);
  }
  const connectConfig: ConnectConfig = {
    host: sshConfig?.hostname || config.host,
    port,
    username: config.username || sshConfig?.user || process.env.USER || process.env.USERNAME || "root",
    keepaliveInterval: 15_000,
    keepaliveCountMax: 3,
    hostVerifier: buildHostVerifier(verifierHosts, port),
  };

  // Auth resolution, in order of precedence — the first match wins and others
  // are not set. This matches what the README promises and gives users a
  // predictable way to force a specific auth method.
  //
  //   explicit key > explicit password > agent > SSH config identity > default key paths
  if (config.privateKeyPath) {
    connectConfig.privateKey = readFileSync(config.privateKeyPath);
  } else if (config.password) {
    connectConfig.password = config.password;
  } else {
    const agentSock =
      config.agent ||
      process.env.SSH_AUTH_SOCK ||
      (process.platform === "win32" ? "\\\\.\\pipe\\openssh-ssh-agent" : undefined);
    if (agentSock) {
      connectConfig.agent = agentSock;
    } else {
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
  }

  return { connectConfig, proxyJump: sshConfig?.proxyJump };
}

// Short TTL cache for the non-host-specific diagnostic checks. Under a burst of
// concurrent failures (say, 20 parallel tool calls when the agent is down) these
// checks spawn processes repeatedly — `ssh-add -l`, filesystem scans — even though
// the answer hasn't changed. Host-specific checks (`checkSshConfig`, `checkKnownHosts`)
// still run every time because they can legitimately differ per host.
const DIAG_CACHE_TTL_MS = 2000;
let diagAgentCache: { at: number; result: DiagnosticResult } | null = null;
let diagKeysCache: { at: number; result: DiagnosticResult } | null = null;

function cachedAgentCheck(): DiagnosticResult {
  const now = Date.now();
  if (diagAgentCache && now - diagAgentCache.at < DIAG_CACHE_TTL_MS) {
    return diagAgentCache.result;
  }
  const result = checkSshAgent();
  diagAgentCache = { at: now, result };
  return result;
}

function cachedKeysCheck(): DiagnosticResult {
  const now = Date.now();
  if (diagKeysCache && now - diagKeysCache.at < DIAG_CACHE_TTL_MS) {
    return diagKeysCache.result;
  }
  const result = checkSshKeys();
  diagKeysCache = { at: now, result };
  return result;
}

export function formatDiagnostics(host: string): string {
  // Run fast local checks only — skip connectivity re-test to avoid adding seconds of delay
  try {
    const checks = [
      { name: "SSH Agent", ...cachedAgentCheck() },
      { name: "SSH Keys", ...cachedKeysCheck() },
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

// Connects with the exact ConnectConfig as given — no hostVerifier is applied unless the
// caller supplied one. Use connect() for known_hosts-verified connections.
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

// ssh2's client.exec() runs the command through the remote user's login shell, so shell
// metacharacters (|, &&, >, globs, etc.) are interpreted. This is intentional — callers
// pass shell command strings. Higher-level helpers in ops.ts use shellQuote() when
// interpolating user-supplied values into command templates.
//
// stdout and stderr are each capped at maxBytes to prevent a chatty or misbehaving
// remote command from exhausting process memory. When the cap is hit, further data is
// dropped and a truncation marker is appended to the captured output.
export const DEFAULT_MAX_EXEC_BYTES = 10 * 1024 * 1024; // 10 MB per stream

export function exec(
  client: Client,
  command: string,
  timeoutMs = 30000,
  maxBytes: number = DEFAULT_MAX_EXEC_BYTES,
): Promise<ExecResult> {
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

      const stdoutChunks: Buffer[] = [];
      const stderrChunks: Buffer[] = [];
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let stdoutTruncated = false;
      let stderrTruncated = false;

      const appendStdout = (data: Buffer) => {
        if (stdoutTruncated) return;
        const remaining = maxBytes - stdoutBytes;
        if (data.length <= remaining) {
          stdoutChunks.push(data);
          stdoutBytes += data.length;
        } else {
          if (remaining > 0) {
            stdoutChunks.push(data.subarray(0, remaining));
            stdoutBytes += remaining;
          }
          stdoutTruncated = true;
        }
      };
      const appendStderr = (data: Buffer) => {
        if (stderrTruncated) return;
        const remaining = maxBytes - stderrBytes;
        if (data.length <= remaining) {
          stderrChunks.push(data);
          stderrBytes += data.length;
        } else {
          if (remaining > 0) {
            stderrChunks.push(data.subarray(0, remaining));
            stderrBytes += remaining;
          }
          stderrTruncated = true;
        }
      };

      stream
        .on("close", (code: number) => {
          let stdout = Buffer.concat(stdoutChunks).toString("utf8");
          let stderr = Buffer.concat(stderrChunks).toString("utf8");
          if (stdoutTruncated) stdout += `\n[output truncated at ${maxBytes} bytes]`;
          if (stderrTruncated) stderr += `\n[stderr truncated at ${maxBytes} bytes]`;
          settle(() => resolve({ stdout, stderr, code: code ?? 0 }));
        })
        .on("data", appendStdout)
        .on("error", (err: Error) => {
          settle(() => reject(err));
        });

      stream.stderr.on("data", appendStderr).on("error", (err: Error) => {
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
