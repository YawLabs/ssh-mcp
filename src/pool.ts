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
  /** Maximum number of connections in the pool. Default: 100 */
  maxPoolSize?: number;
}

export class ConnectionPool {
  private entries = new Map<string, PoolEntry>();
  // Coalesces concurrent connect attempts for the same key so we don't open N
  // duplicate TCP connections when N tool calls fire simultaneously.
  private pending = new Map<string, Promise<Client>>();
  private idleTtlMs: number;
  private maxPoolSize: number;
  // Total number of successful connects ever made by this pool. Useful for
  // introspection and for tests that want to prove connection reuse.
  private _connectCount = 0;

  constructor(options?: PoolOptions) {
    this.idleTtlMs = options?.idleTtlMs ?? 60_000;
    this.maxPoolSize = options?.maxPoolSize ?? 100;
  }

  async acquire(config: SSHConfig): Promise<Client> {
    const resolved = resolveConfig(config);
    const cc = resolved.connectConfig;
    const key = `${cc.username}@${cc.host}:${cc.port}`;

    // Bound the dead-race retry loop. In practice the loop exits on the first
    // iteration; the retry only fires when a connection dies between the time
    // `connectWithProxy` resolves and the time we bump refCount on its entry.
    // MAX_ACQUIRE_ATTEMPTS caps us against a pathological peer that accepts
    // then immediately closes every new connection.
    const MAX_ACQUIRE_ATTEMPTS = 3;
    let lastErr: unknown;
    for (let attempt = 0; attempt < MAX_ACQUIRE_ATTEMPTS; attempt++) {
      // Fast path: live entry — bump refcount and return.
      const existing = this.entries.get(key);
      if (existing && !existing.dead) {
        existing.refCount++;
        if (existing.idleTimer) {
          clearTimeout(existing.idleTimer);
          existing.idleTimer = null;
        }
        return existing.client;
      }
      if (existing?.dead) {
        this.entries.delete(key);
      }

      // Slow path: share a single in-flight connect across concurrent callers.
      let pending = this.pending.get(key);
      if (!pending) {
        // Eviction is only needed when we're about to create a new entry.
        if (this.entries.size >= this.maxPoolSize) {
          let evicted = false;
          for (const [k, e] of this.entries) {
            if (e.refCount === 0) {
              if (e.idleTimer) clearTimeout(e.idleTimer);
              try {
                e.client.end();
              } catch {
                /* already closed */
              }
              this.entries.delete(k);
              evicted = true;
              break;
            }
          }
          if (!evicted) {
            throw new Error(`Connection pool is full (${this.maxPoolSize} active connections)`);
          }
        }

        pending = (async () => {
          try {
            const client = await connectWithProxy(resolved);
            this._connectCount++;
            const entry: PoolEntry = { client, key, refCount: 0, idleTimer: null, dead: false };

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
          } finally {
            this.pending.delete(key);
          }
        })();
        this.pending.set(key, pending);
      }

      let client: Client;
      try {
        client = await pending;
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

      // NOTE: There is a narrow window between `connectWithProxy` resolving and
      // this refCount bump where the peer could send RST/FIN — `markDead` fires,
      // deletes the entry, and we end up here holding a dead client. In that
      // case fall through to the next loop iteration, which will dial again.
      const entry = this.entries.get(key);
      if (!entry || entry.dead || entry.client !== client) {
        lastErr = new Error("connection died before acquire could take a ref");
        continue;
      }
      entry.refCount++;
      if (entry.idleTimer) {
        clearTimeout(entry.idleTimer);
        entry.idleTimer = null;
      }
      return client;
    }
    throw new Error(
      `Failed to acquire SSH connection for ${key} after ${MAX_ACQUIRE_ATTEMPTS} attempts: ${
        lastErr instanceof Error ? lastErr.message : String(lastErr)
      }`,
    );
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
    // NOTE: The client was never pooled (or already evicted via markDead).
    // Close it directly so callers of `pool.release(client)` can treat release
    // as always safe, regardless of whether the entry is still tracked.
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

  /** Total number of successful SSH connects made by this pool since construction. */
  get connectCount(): number {
    return this._connectCount;
  }
}
