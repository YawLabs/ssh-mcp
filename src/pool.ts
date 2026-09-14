import { createHash } from "node:crypto";
import type { Client, ConnectConfig } from "ssh2";
import { connectWithProxy, enhanceSshError, type ResolvedConfig, resolveConfig, type SSHConfig } from "./ssh.js";

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
  /**
   * Maximum number of connections in the pool, counting dials still in flight.
   * Default: 100, overridable via the
   * `SSH_MCP_MAX_POOL_SIZE` env var. When at capacity, the pool first tries to evict
   * an idle entry; if no idle entry can be evicted (every slot is in use or dialing),
   * `acquire()` rejects with a {@link PoolFullError} ("Connection pool is full") -- at once
   * by default, or after `waitForCapacityMs` (see {@link AcquireOptions}) with no slot freed.
   * Bump this for fan-out workloads against many distinct hosts (e.g. `ssh_multi_exec`
   * across a large fleet, which runs at most this many hosts at once).
   */
  maxPoolSize?: number;
}

export interface AcquireOptions {
  /**
   * How long `acquire()` / `withConnection()` may wait for a slot when the pool is full,
   * in milliseconds. Default 0: reject at once with a {@link PoolFullError}. With a budget,
   * the caller parks (see `waitForCapacity`) and retries on every capacity signal until a
   * slot is won or the budget is spent, then rejects with a {@link PoolFullError} whose
   * message ends in "no slot freed up within <budget>ms". Only a capacity rejection is
   * waited out; connect failures and a drained pool reject at once as before.
   */
  waitForCapacityMs?: number;
}

/** `code` of the error `acquire()` throws when no slot is free. Match on this, not on the message. */
export const POOL_FULL_ERROR_CODE = "ERR_SSH_MCP_POOL_FULL";

/**
 * Thrown by `acquire()` when a new connection is needed and no slot is free: every slot is
 * held by an in-use entry or an in-flight dial, and no idle entry can be evicted. Distinct
 * from connect and exec failures so a caller that can wait (see `waitForCapacity`) retries
 * only on this. `waitedMs` is set when the caller asked to wait and the budget ran out; the
 * message then carries the "no slot freed up within <n>ms" suffix -- appended here, once, so
 * no caller has to add it.
 */
export class PoolFullError extends Error {
  readonly code = POOL_FULL_ERROR_CODE;
  readonly maxPoolSize: number;
  readonly waitedMs?: number;
  constructor(maxPoolSize: number, waitedMs?: number) {
    const base = `Connection pool is full (${maxPoolSize} connections in use or dialing)`;
    super(waitedMs === undefined ? base : `${base}; no slot freed up within ${Math.round(waitedMs)}ms`);
    this.name = "PoolFullError";
    this.maxPoolSize = maxPoolSize;
    if (waitedMs !== undefined) this.waitedMs = waitedMs;
  }
}

/**
 * True for the pool's capacity rejection. Checks `code` rather than `instanceof`, so it still
 * holds when two copies of this module are loaded (the CLI and library bundles are separate).
 */
export function isPoolFullError(err: unknown): err is PoolFullError {
  return typeof err === "object" && err !== null && (err as { code?: unknown }).code === POOL_FULL_ERROR_CODE;
}

// setTimeout clamps anything above a signed 32-bit millisecond count to 1ms.
const MAX_TIMER_MS = 2_147_483_647;

function defaultMaxPoolSize(): number {
  const raw = process.env.SSH_MCP_MAX_POOL_SIZE;
  if (!raw) return 100;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 100;
}

// Distinct credentials must not collide on one pooled connection. The pool keys on
// username@host:port, but two calls to the same target that differ only in auth
// (different key, password vs key, different password) would otherwise reuse the
// first caller's authenticated connection and silently ignore the second's
// credential. Fold a short fingerprint of the resolved auth material into the key
// so they get distinct entries. Same effective credential -> same fingerprint ->
// reuse still works.
function authFingerprint(cc: ConnectConfig): string {
  const h = createHash("sha256");
  if (cc.privateKey) {
    h.update("k");
    h.update(cc.privateKey as Buffer | string);
  }
  if (cc.password !== undefined) {
    h.update("p");
    h.update(cc.password);
  }
  // ssh2 types `agent` as string | BaseAgent; resolveConfig only ever sets a string
  // socket path, so fingerprint that and ignore the (unused) object form.
  if (typeof cc.agent === "string") {
    h.update("a");
    h.update(cc.agent);
  }
  return h.digest("hex").slice(0, 16);
}

// resolveConfig() does real I/O (readFileSync on privateKeyPath, `ssh -G`) and can
// throw. It used to sit OUTSIDE acquire()'s diagnostic wrapper, so a bad
// privateKeyPath escaped as a raw readFileSync ENOENT with none of the
// auto-diagnostics this server advertises. Routed through the same
// `enhanceSshError` helper the connect path uses -- one shape, not two.
function resolveOrDiagnose(config: SSHConfig): ResolvedConfig {
  try {
    return resolveConfig(config);
  } catch (err: unknown) {
    throw enhanceSshError(err, config.host);
  }
}

export class ConnectionPool {
  private entries = new Map<string, PoolEntry>();
  // Coalesces concurrent connect attempts for the same key so we don't open N
  // duplicate TCP connections when N tool calls fire simultaneously.
  //
  // The ResolvedConfig is stored alongside the promise because the coalesced dial
  // runs with the FIRST caller's resolved: only that one's `hostVerifier` is ever
  // invoked, so only that one's `hostKeyRejection` side channel records why the
  // server's key was turned down. Waiters must report the failure from THAT resolved
  // rather than their own (whose verifier never ran and whose rejection is still
  // null), or one caller gets "the server offered an ed25519 key but known_hosts
  // has only ecdsa" while the other N-1 get generic environment diagnostics for the
  // very same failure.
  private pending = new Map<string, { promise: Promise<Client>; resolved: ResolvedConfig }>();
  private idleTtlMs: number;
  private maxPoolSize: number;
  // Total number of successful connects ever made by this pool. Useful for
  // introspection and for tests that want to prove connection reuse.
  private _connectCount = 0;
  // Once drained, the pool stays drained — new acquires reject and any in-flight
  // factory closes the freshly-connected client instead of registering it.
  // Consumers must construct a new pool to use again.
  private drained = false;
  // Callers parked in waitForCapacity(). Every site that can free a slot for a NEW key calls
  // notifyCapacity(), which wakes all of them: an entry dropping to refCount 0 (it becomes
  // evictable), an entry leaving the map (markDead, idle expiry), a dial failing without
  // registering, and drain(). Waking all rather than one means a woken caller that does not
  // take the slot (its retry fails for another reason, or joins a same-key dial) cannot
  // strand the rest; the losers of a wake just find the pool full again and re-park.
  private capacityWaiters = new Set<() => void>();

  constructor(options?: PoolOptions) {
    this.idleTtlMs = options?.idleTtlMs ?? 60_000;
    this.maxPoolSize = options?.maxPoolSize ?? defaultMaxPoolSize();
  }

  /**
   * Checks out a connection for `config`, dialing one if needed. Fails fast on a full pool
   * unless `options.waitForCapacityMs` is set, in which case the caller parks and retries on
   * every capacity signal until it wins a slot or the budget is spent. The wait is bounded,
   * never a reservation: a woken caller can lose the slot to another and simply parks again
   * for whatever budget is left. The final rejection carries the budget in its message.
   */
  async acquire(config: SSHConfig, options?: AcquireOptions): Promise<Client> {
    const budgetMs = options?.waitForCapacityMs ?? 0;
    if (!(budgetMs > 0)) return this.acquireNow(config);
    const deadline = performance.now() + budgetMs;
    for (;;) {
      try {
        return await this.acquireNow(config);
      } catch (err: unknown) {
        if (!isPoolFullError(err)) throw err;
        const remaining = deadline - performance.now();
        if (remaining <= 0) throw new PoolFullError(this.maxPoolSize, budgetMs);
        // Resolves at once when the slot freed before we parked, on any capacity signal, or
        // when `remaining` runs out -- in which case the retry above is the one final attempt
        // (a slot can free right at the boundary) before the budget is declared spent.
        await this.waitForCapacity(remaining);
      }
    }
  }

  // The fail-fast acquire: one admission check, one dial (or a join on an in-flight one).
  private async acquireNow(config: SSHConfig): Promise<Client> {
    const resolved = resolveOrDiagnose(config);
    const cc = resolved.connectConfig;
    const key = `${cc.username}@${cc.host}:${cc.port}#${authFingerprint(cc)}`;

    // Bound the dead-race retry loop. In practice the loop exits on the first
    // iteration; the retry only fires when a connection dies between the time
    // `connectWithProxy` resolves and the time we bump refCount on its entry.
    // MAX_ACQUIRE_ATTEMPTS caps us against a pathological peer that accepts
    // then immediately closes every new connection.
    const MAX_ACQUIRE_ATTEMPTS = 3;
    let lastErr: unknown;
    for (let attempt = 0; attempt < MAX_ACQUIRE_ATTEMPTS; attempt++) {
      // Drain wins over any in-flight or queued acquire — pool is one-way.
      if (this.drained) {
        throw new Error("ConnectionPool was drained");
      }
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
      let inflight = this.pending.get(key);
      if (!inflight) {
        // Eviction is only needed when we're about to create a new entry.
        //
        // In-flight dials count against the cap: `entries.set` only runs after
        // `connectWithProxy` resolves, so checking `entries.size` alone let N concurrent
        // acquires to N distinct hosts all pass and open N connections past the limit.
        // Same-key callers never reach this check (they join `pending` above), so a
        // shared dial does not reject its own waiters. No slot is counted twice: the
        // factory's `entries.set` and its `finally` `pending.delete` run in one
        // synchronous segment, and a failed dial runs only the delete, freeing its slot.
        if (this.entries.size + this.pending.size >= this.maxPoolSize) {
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
          // No notifyCapacity() on eviction: this acquire takes the freed slot in the same
          // synchronous segment (pending.set below), so nothing opened up for anyone else.
          if (!evicted) {
            throw new PoolFullError(this.maxPoolSize);
          }
        }

        const promise = (async () => {
          let registered = false;
          try {
            const client = await connectWithProxy(resolved);
            // If drain() ran while we were dialing, do not register this client
            // into the just-cleared map — close it and propagate a rejection so
            // the awaiting acquire() bails out instead of holding a phantom ref.
            // Invariant: the block from `if (this.drained)` through `this.entries.set(key, entry)`
            // MUST remain synchronous. Inserting an `await` between the drained check and the
            // entries.set would re-open the drain race this guard closes.
            if (this.drained) {
              try {
                client.end();
              } catch {
                // already closed
              }
              throw new Error("ConnectionPool was drained while connecting");
            }
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
                this.notifyCapacity();
              }
            };
            client.on("close", markDead);
            client.on("end", markDead);
            client.on("error", markDead);

            this.entries.set(key, entry);
            registered = true;
            return client;
          } finally {
            this.pending.delete(key);
            // A failed dial frees its slot outright. A successful one only moves it from
            // `pending` to `entries`, so waking waiters there would free nothing -- and would
            // send them into the window before this acquire takes its ref, where the new
            // refCount-0 entry still looks evictable.
            if (!registered) this.notifyCapacity();
          }
        })();
        // `resolved` here is this caller's, and it is the one the factory above dials
        // with -- so it is also the one whose hostVerifier writes the rejection.
        inflight = { promise, resolved };
        this.pending.set(key, inflight);
      }

      let client: Client;
      try {
        client = await inflight.promise;
      } catch (err: unknown) {
        // Deliberately `inflight.resolved`, not this caller's `resolved`: see the
        // comment on `pending`. Every waiter on one coalesced dial reports the same
        // reason, because there was only ever one dial to have a reason.
        throw enhanceSshError(err, config.host, inflight.resolved);
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
            // Redundant under today's admission rule -- the entry was already evictable, so
            // the notify below (and waitForCapacity's re-check) covered anyone who could be
            // parked -- and kept so that every site removing an entry notifies, which is the
            // invariant a changed eviction rule would rely on.
            this.notifyCapacity();
          }, this.idleTtlMs);
          entry.idleTimer.unref();
          // An idle entry is evictable, so a new host fits from this point on.
          this.notifyCapacity();
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

  /** `acquire()` + `fn` + `release()`, with the same optional bounded wait for a slot. */
  async withConnection<T>(config: SSHConfig, fn: (client: Client) => Promise<T>, options?: AcquireOptions): Promise<T> {
    const client = await this.acquire(config, options);
    try {
      return await fn(client);
    } finally {
      this.release(client);
    }
  }

  drain(): void {
    // Set drained first so any in-flight factory checks it AFTER its connect
    // resolves and discards the client instead of registering into the cleared map.
    this.drained = true;
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
    this.pending.clear();
    // Parked callers must not sit out their timeout against a pool that will never free a
    // slot: wake them, and their retry sees the drained pool and rejects.
    this.notifyCapacity();
  }

  /**
   * Parks until the pool's capacity may have changed, for a caller whose `acquire()` just
   * rejected with a {@link PoolFullError} and that would rather wait than fail. This is the
   * primitive behind `acquire()`'s `waitForCapacityMs` option; a bare `acquire()` never waits.
   *
   * Resolves `true` when a slot may be free (woken by a release, an entry closing or expiring,
   * a failed dial, or `drain()`), or at once if a new host would fit right now or the pool is
   * already drained. Resolves `false` after `timeoutMs` with nothing having changed. Never
   * rejects. A `true` is a hint, not a reservation: another caller can take the slot first,
   * so retry `acquire()` and wait again on another `PoolFullError`. The timer is cleared on
   * wake and unref'd, so a parked caller never holds the process open.
   */
  waitForCapacity(timeoutMs: number): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const wake = () => {
        if (timer !== undefined) clearTimeout(timer);
        this.capacityWaiters.delete(wake);
        resolve(true);
      };
      this.capacityWaiters.add(wake);
      if (this.drained) {
        wake();
        return;
      }
      // Re-check AFTER registering. The caller's acquire() rejected some microtasks before
      // this call, and a slot freed in between notified nobody; without this check the
      // caller would sleep through capacity that is already there.
      if (this.hasCapacity()) {
        wake();
        return;
      }
      if (!(timeoutMs > 0)) {
        this.capacityWaiters.delete(wake);
        resolve(false);
        return;
      }
      timer = setTimeout(
        () => {
          this.capacityWaiters.delete(wake);
          resolve(false);
        },
        Math.min(timeoutMs, MAX_TIMER_MS),
      );
      timer.unref();
    });
  }

  // Mirrors acquire()'s admission test for a new key: below the cap, or an idle entry to evict.
  private hasCapacity(): boolean {
    if (this.entries.size + this.pending.size < this.maxPoolSize) return true;
    for (const e of this.entries.values()) {
      if (e.refCount === 0) return true;
    }
    return false;
  }

  private notifyCapacity(): void {
    if (this.capacityWaiters.size === 0) return;
    const waiters = [...this.capacityWaiters];
    this.capacityWaiters.clear();
    for (const wake of waiters) wake();
  }

  get size(): number {
    return this.entries.size;
  }

  /** The connection cap (`maxPoolSize`), counting pooled entries plus in-flight dials. */
  get maxSize(): number {
    return this.maxPoolSize;
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
