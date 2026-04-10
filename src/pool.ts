import type { Client } from "ssh2";
import { type SSHConfig, connectWithProxy, formatDiagnostics, resolveConfig } from "./ssh.js";

interface PoolEntry {
  client: Client;
  key: string;
  refCount: number;
  idleTimer: ReturnType<typeof setTimeout> | null;
  dead: boolean;
}

export interface PoolOptions {
  /** Milliseconds before an idle connection is closed. Default: 60000 (60s) */
  idleTtlMs?: number;
}

export class ConnectionPool {
  private entries = new Map<string, PoolEntry>();
  private idleTtlMs: number;

  constructor(options?: PoolOptions) {
    this.idleTtlMs = options?.idleTtlMs ?? 60_000;
  }

  async acquire(config: SSHConfig): Promise<Client> {
    const resolved = resolveConfig(config);
    const cc = resolved.connectConfig;
    const key = `${cc.username}@${cc.host}:${cc.port}`;

    const existing = this.entries.get(key);
    if (existing && !existing.dead) {
      existing.refCount++;
      if (existing.idleTimer) {
        clearTimeout(existing.idleTimer);
        existing.idleTimer = null;
      }
      return existing.client;
    }

    // Remove dead entry if present
    if (existing?.dead) {
      this.entries.delete(key);
    }

    try {
      const client = await connectWithProxy(resolved);

      const entry: PoolEntry = { client, key, refCount: 1, idleTimer: null, dead: false };

      const markDead = () => {
        entry.dead = true;
        if (entry.idleTimer) {
          clearTimeout(entry.idleTimer);
          entry.idleTimer = null;
        }
        if (this.entries.get(key) === entry) {
          this.entries.delete(key);
        }
      };
      client.on("close", markDead);
      client.on("end", markDead);
      client.on("error", markDead);

      this.entries.set(key, entry);
      return client;
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

  release(client: Client): void {
    for (const entry of this.entries.values()) {
      if (entry.client === client) {
        entry.refCount = Math.max(0, entry.refCount - 1);
        if (entry.refCount === 0 && !entry.dead) {
          entry.idleTimer = setTimeout(() => {
            try {
              entry.client.end();
            } catch {
              // already closed
            }
            this.entries.delete(entry.key);
          }, this.idleTtlMs);
          entry.idleTimer.unref();
        }
        return;
      }
    }
    // Not in pool — just close it
    try {
      client.end();
    } catch {
      // already closed
    }
  }

  async withConnection<T>(config: SSHConfig, fn: (client: Client) => Promise<T>): Promise<T> {
    const client = await this.acquire(config);
    try {
      return await fn(client);
    } finally {
      this.release(client);
    }
  }

  drain(): void {
    for (const entry of this.entries.values()) {
      if (entry.idleTimer) {
        clearTimeout(entry.idleTimer);
      }
      try {
        entry.client.end();
      } catch {
        // already closed
      }
    }
    this.entries.clear();
  }

  get size(): number {
    return this.entries.size;
  }

  get stats(): { active: number; idle: number } {
    let active = 0;
    let idle = 0;
    for (const entry of this.entries.values()) {
      if (entry.refCount > 0) active++;
      else idle++;
    }
    return { active, idle };
  }
}
