import type { Client } from "ssh2";
import type { ConnectionPool } from "./pool.js";
import { exec } from "./ssh.js";

function shellQuote(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}

// --- Multi-host execution ---

export interface MultiExecResult {
  host: string;
  stdout: string;
  stderr: string;
  code: number;
  error?: string;
}

export interface MultiExecHost {
  host: string;
  port?: number;
  username?: string;
  privateKeyPath?: string;
  password?: string;
}

export async function multiExec(
  pool: ConnectionPool,
  hosts: MultiExecHost[],
  command: string,
  timeoutMs = 30000,
): Promise<MultiExecResult[]> {
  const results = await Promise.allSettled(
    hosts.map(async (hostConfig) => {
      return pool.withConnection(hostConfig, async (client) => {
        const result = await exec(client, command, timeoutMs);
        return { host: hostConfig.host, ...result };
      });
    }),
  );

  return results.map((result, i) => {
    if (result.status === "fulfilled") {
      return result.value;
    }
    return {
      host: hosts[i].host,
      stdout: "",
      stderr: "",
      code: -1,
      error: result.reason instanceof Error ? result.reason.message : String(result.reason),
    };
  });
}

// --- Remote file search ---

export interface FindOptions {
  path: string;
  name?: string;
  type?: "f" | "d" | "l";
  maxdepth?: number;
  minsize?: string;
  maxsize?: string;
  newer?: string;
}

export async function find(client: Client, options: FindOptions, timeoutMs = 30000): Promise<string[]> {
  const args: string[] = [shellQuote(options.path)];

  if (options.maxdepth !== undefined) args.push("-maxdepth", String(options.maxdepth));
  if (options.type) args.push("-type", options.type);
  if (options.name) args.push("-name", shellQuote(options.name));
  if (options.minsize) args.push("-size", `+${options.minsize}`);
  if (options.maxsize) args.push("-size", `-${options.maxsize}`);
  if (options.newer) args.push("-newer", shellQuote(options.newer));

  const command = `find ${args.join(" ")} 2>/dev/null`;
  const result = await exec(client, command, timeoutMs);

  return result.stdout.split("\n").filter(Boolean);
}

// --- Log tailing ---

export async function tail(
  client: Client,
  path: string,
  lines = 100,
  grep?: string,
  timeoutMs = 30000,
): Promise<string> {
  let command = `tail -n ${lines} ${shellQuote(path)}`;
  if (grep) {
    command += ` | grep -i ${shellQuote(grep)}`;
  }

  const result = await exec(client, command, timeoutMs);
  if (result.code !== 0 && result.stderr && !grep) {
    throw new Error(result.stderr.trim());
  }
  return result.stdout;
}

// --- Service status ---

export interface ServiceStatus {
  name: string;
  active: boolean;
  status: string;
  description?: string;
  since?: string;
  pid?: number;
  raw: string;
}

export async function serviceStatus(client: Client, serviceName: string, timeoutMs = 30000): Promise<ServiceStatus> {
  const result = await exec(client, `systemctl status ${shellQuote(serviceName)} 2>&1`, timeoutMs);
  const raw = result.stdout;

  const activeMatch = raw.match(/Active:\s+(\S+)\s+\(([^)]+)\)/);
  const descMatch = raw.match(/^\s+.*?-\s+(.+)$/m);
  const pidMatch = raw.match(/Main PID:\s+(\d+)/);
  const sinceMatch = raw.match(/since\s+(.+?);/);

  return {
    name: serviceName,
    active: activeMatch?.[1] === "active",
    status: activeMatch ? `${activeMatch[1]} (${activeMatch[2]})` : result.code === 0 ? "active" : "unknown",
    description: descMatch?.[1]?.trim(),
    since: sinceMatch?.[1]?.trim(),
    pid: pidMatch ? Number.parseInt(pidMatch[1], 10) : undefined,
    raw,
  };
}
