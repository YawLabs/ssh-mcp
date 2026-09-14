import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock only connectWithProxy — everything else in ssh.js (resolveConfig,
// hostVerifier, readKnownHostsKeys, etc.) keeps its real implementation so the
// pool's surrounding logic still exercises real code paths.
vi.mock("../ssh.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../ssh.js")>();
  return {
    ...actual,
    connectWithProxy: vi.fn(),
  };
});

import { ConnectionPool, isPoolFullError, POOL_FULL_ERROR_CODE, PoolFullError } from "../pool.js";
import { connectWithProxy } from "../ssh.js";

const mockedConnect = vi.mocked(connectWithProxy);

function makeFakeClient() {
  const client = new EventEmitter() as any;
  client.endCalls = 0;
  // end() triggers a deferred 'close' so the pool can mark dead correctly.
  client.end = () => {
    client.endCalls++;
    queueMicrotask(() => client.emit("close"));
  };
  return client;
}

describe("ConnectionPool — concurrent acquire dedup", () => {
  beforeEach(() => {
    mockedConnect.mockReset();
    // Each call returns a fresh fake Client. If the pool ever calls this more
    // than once per host, the resulting clients are distinct objects and we
    // can detect it both by call count and by client identity.
    mockedConnect.mockImplementation(async () => makeFakeClient());
  });

  it("makes exactly one connection for N concurrent acquires of the same host", async () => {
    const pool = new ConnectionPool();
    try {
      const tasks = Array.from({ length: 50 }, () => pool.acquire({ host: "dedup-test.example.com" }));
      const clients = await Promise.all(tasks);

      expect(mockedConnect).toHaveBeenCalledTimes(1);
      // All 50 callers must receive the same Client instance, proving no
      // orphaned connections were created and handed out.
      expect(new Set(clients).size).toBe(1);
      expect(pool.size).toBe(1);
      expect(pool.connectCount).toBe(1);
      // stats.active counts entries with refCount > 0, not the refCount value
      // itself. 50 shared refs on one entry still reports as one active entry.
      expect(pool.stats.active).toBe(1);
      expect(pool.stats.idle).toBe(0);

      // All 50 callers must release before the entry goes idle — this proves
      // the refCount was actually bumped 50 times, not 1.
      for (let i = 0; i < clients.length - 1; i++) {
        pool.release(clients[i]);
        expect(pool.stats.active).toBe(1); // still held by remaining refs
        expect(pool.stats.idle).toBe(0);
      }
      pool.release(clients[clients.length - 1]);
      expect(pool.stats.active).toBe(0);
      expect(pool.stats.idle).toBe(1);
    } finally {
      pool.drain();
    }
  });

  it("still opens distinct connections for distinct hosts concurrently", async () => {
    const pool = new ConnectionPool();
    try {
      const tasks = Array.from({ length: 20 }, (_, i) => pool.acquire({ host: `dedup-host-${i}.example.com` }));
      const clients = await Promise.all(tasks);

      expect(mockedConnect).toHaveBeenCalledTimes(20);
      expect(new Set(clients).size).toBe(20);
      expect(pool.size).toBe(20);
      expect(pool.connectCount).toBe(20);

      for (const c of clients) pool.release(c);
    } finally {
      pool.drain();
    }
  });

  it("reuses a warm idle connection without dialing again", async () => {
    const pool = new ConnectionPool();
    try {
      const c1 = await pool.acquire({ host: "warm-test.example.com" });
      pool.release(c1); // goes idle, stays in the pool
      const c2 = await pool.acquire({ host: "warm-test.example.com" });

      expect(c1).toBe(c2);
      expect(mockedConnect).toHaveBeenCalledTimes(1);
      expect(pool.connectCount).toBe(1);

      pool.release(c2);
    } finally {
      pool.drain();
    }
  });

  it("surfaces connect errors to all concurrent waiters", async () => {
    mockedConnect.mockReset();
    mockedConnect.mockRejectedValue(new Error("connect boom"));

    const pool = new ConnectionPool();
    try {
      const tasks = Array.from({ length: 10 }, () =>
        pool.acquire({ host: "fail-test.example.com" }).catch((e: Error) => e.message),
      );
      const outcomes = await Promise.all(tasks);

      expect(mockedConnect).toHaveBeenCalledTimes(1);
      // Every waiter sees the same underlying error (message may be wrapped
      // with diagnostics, so we just check the core substring).
      for (const o of outcomes) {
        expect(typeof o).toBe("string");
        expect(o as string).toContain("connect boom");
      }
      expect(pool.size).toBe(0);
      expect(pool.connectCount).toBe(0);
    } finally {
      pool.drain();
    }
  });

  it("does NOT share a pooled connection across differing credentials", async () => {
    // Same host:user:port, different password -> distinct auth fingerprint -> distinct
    // pool key. Without the auth fingerprint in the key the second caller would silently
    // reuse the first's authenticated connection and ignore its own credential.
    const pool = new ConnectionPool();
    try {
      const a = await pool.acquire({ host: "auth-diff.example.com", password: "pw-a" });
      const b = await pool.acquire({ host: "auth-diff.example.com", password: "pw-b" });
      expect(a).not.toBe(b);
      expect(mockedConnect).toHaveBeenCalledTimes(2);
      expect(pool.size).toBe(2);
      pool.release(a);
      pool.release(b);
    } finally {
      pool.drain();
    }
  });

  it("DOES reuse a pooled connection for identical credentials", async () => {
    const pool = new ConnectionPool();
    try {
      const a = await pool.acquire({ host: "auth-same.example.com", password: "pw" });
      pool.release(a); // goes idle, stays in the pool
      const b = await pool.acquire({ host: "auth-same.example.com", password: "pw" });
      expect(a).toBe(b);
      expect(mockedConnect).toHaveBeenCalledTimes(1);
      pool.release(b);
    } finally {
      pool.drain();
    }
  });

  it("retries a fresh connect after a prior connection dies", async () => {
    const pool = new ConnectionPool();
    try {
      const c1 = await pool.acquire({ host: "respawn-test.example.com" });
      pool.release(c1);
      // Simulate the server kicking us off while idle.
      c1.emit("close");

      const c2 = await pool.acquire({ host: "respawn-test.example.com" });
      expect(c2).not.toBe(c1);
      expect(mockedConnect).toHaveBeenCalledTimes(2);
      expect(pool.connectCount).toBe(2);

      pool.release(c2);
    } finally {
      pool.drain();
    }
  });
});

describe("ConnectionPool — drain race", () => {
  beforeEach(() => {
    mockedConnect.mockReset();
  });

  it("rejects in-flight acquire and closes the connecting client when drain() runs mid-connect", async () => {
    const fakeClient = makeFakeClient();
    let resolveConnect!: (c: any) => void;
    const deferred = new Promise<any>((resolve) => {
      resolveConnect = resolve;
    });
    mockedConnect.mockImplementation(() => deferred);

    const pool = new ConnectionPool();
    const acquirePromise = pool.acquire({ host: "drain-race.example.com" });
    // Yield once so the factory has actually started awaiting connectWithProxy.
    await Promise.resolve();

    pool.drain();
    // Now let the connect resolve; the factory should see drained=true and
    // close the client instead of registering it.
    resolveConnect(fakeClient);

    await expect(acquirePromise).rejects.toThrow(/drained/);
    expect(fakeClient.endCalls).toBeGreaterThanOrEqual(1);
    expect(pool.size).toBe(0);
  });

  it("rejects new acquires after drain() with /drained/", async () => {
    mockedConnect.mockImplementation(async () => makeFakeClient());
    const pool = new ConnectionPool();
    pool.drain();
    await expect(pool.acquire({ host: "post-drain.example.com" })).rejects.toThrow(/drained/);
    expect(mockedConnect).not.toHaveBeenCalled();
  });
});

describe("ConnectionPool — maxPoolSize eviction", () => {
  beforeEach(() => {
    mockedConnect.mockReset();
    mockedConnect.mockImplementation(async () => makeFakeClient());
  });
  // Runs even when an assertion throws mid-test, so a stubbed SSH_MCP_MAX_POOL_SIZE
  // can never leak into a later test.
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("evicts an idle entry to make room for a new host when at capacity", async () => {
    const pool = new ConnectionPool({ maxPoolSize: 2 });
    try {
      const c1 = await pool.acquire({ host: "evict-1.example.com" });
      const c2 = await pool.acquire({ host: "evict-2.example.com" });
      // Release both so they're idle and eligible for eviction.
      pool.release(c1);
      pool.release(c2);
      expect(pool.size).toBe(2);

      const c3 = await pool.acquire({ host: "evict-3.example.com" });
      expect(c3).toBeDefined();
      expect(pool.size).toBe(2);
      // Exactly one of c1 / c2 should have been evicted (end() called on it).
      const evictedCount = ((c1 as any).endCalls > 0 ? 1 : 0) + ((c2 as any).endCalls > 0 ? 1 : 0);
      expect(evictedCount).toBe(1);

      pool.release(c3);
    } finally {
      pool.drain();
    }
  });

  it("rejects with /Connection pool is full/ when all entries are active", async () => {
    const pool = new ConnectionPool({ maxPoolSize: 2 });
    try {
      const c1 = await pool.acquire({ host: "full-1.example.com" });
      const c2 = await pool.acquire({ host: "full-2.example.com" });
      // Hold both refs — no eviction candidate available.
      await expect(pool.acquire({ host: "full-3.example.com" })).rejects.toThrow(/Connection pool is full/);

      pool.release(c1);
      pool.release(c2);
    } finally {
      pool.drain();
    }
  });

  /**
   * connectWithProxy stand-in whose dials stay in flight until the test settles them,
   * so several acquires can reach the capacity check while a dial has not yet
   * registered its entry.
   */
  function deferredConnects() {
    const dials: { host: string; resolve: (c: any) => void; reject: (e: Error) => void }[] = [];
    mockedConnect.mockImplementation(
      (resolved) =>
        new Promise((resolve, reject) => {
          dials.push({ host: String(resolved.connectConfig.host), resolve, reject });
        }),
    );
    return dials;
  }

  it("counts in-flight dials against the cap: concurrent distinct-host acquires cannot overshoot", async () => {
    const dials = deferredConnects();
    const pool = new ConnectionPool({ maxPoolSize: 1 });
    try {
      const settled = Promise.allSettled(
        ["inflight-1.example.com", "inflight-2.example.com", "inflight-3.example.com"].map((host) =>
          pool.acquire({ host }),
        ),
      );
      // Only the first acquire may dial; the other two hit the cap while it is in flight.
      expect(mockedConnect).toHaveBeenCalledTimes(1);
      for (const d of dials) d.resolve(makeFakeClient());

      const outcomes = await settled;
      const fulfilled = outcomes.filter((o) => o.status === "fulfilled");
      const rejected = outcomes.filter((o): o is PromiseRejectedResult => o.status === "rejected");
      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(2);
      for (const r of rejected) expect(String(r.reason)).toMatch(/Connection pool is full/);
      expect(pool.connectCount).toBe(1);
      expect(pool.size).toBe(1);

      pool.release((fulfilled[0] as PromiseFulfilledResult<any>).value);
    } finally {
      pool.drain();
    }
  });

  it("still dedupes concurrent SAME-host acquires at the cap -- a shared dial never rejects its own waiters", async () => {
    const dials = deferredConnects();
    const pool = new ConnectionPool({ maxPoolSize: 1 });
    try {
      const tasks = Array.from({ length: 5 }, () => pool.acquire({ host: "shared-dial.example.com" }));
      expect(mockedConnect).toHaveBeenCalledTimes(1);
      dials[0].resolve(makeFakeClient());

      const clients = await Promise.all(tasks);
      expect(new Set(clients).size).toBe(1);
      expect(pool.connectCount).toBe(1);
      expect(pool.size).toBe(1);

      for (const c of clients) pool.release(c);
    } finally {
      pool.drain();
    }
  });

  it("frees the slot of an in-flight dial that fails", async () => {
    const dials = deferredConnects();
    const pool = new ConnectionPool({ maxPoolSize: 1 });
    try {
      const doomed = pool.acquire({ host: "dial-fails.example.com" });
      // While the failing dial is in flight it holds the only slot.
      await expect(pool.acquire({ host: "after-fail.example.com" })).rejects.toThrow(/Connection pool is full/);

      dials[0].reject(new Error("connect ECONNREFUSED"));
      await expect(doomed).rejects.toThrow(/ECONNREFUSED/);
      expect(pool.size).toBe(0);

      // The failed dial registered nothing and released its slot, so a new host fits.
      const next = pool.acquire({ host: "after-fail.example.com" });
      expect(mockedConnect).toHaveBeenCalledTimes(2);
      dials[1].resolve(makeFakeClient());
      const client = await next;
      expect(pool.size).toBe(1);
      expect(pool.connectCount).toBe(1);

      pool.release(client);
    } finally {
      pool.drain();
    }
  });

  it("evicts an idle entry when in-flight dials fill the rest of the cap", async () => {
    const dials = deferredConnects();
    const pool = new ConnectionPool({ maxPoolSize: 2 });
    try {
      const idleTask = pool.acquire({ host: "cap-idle.example.com" });
      const idle = makeFakeClient();
      dials[0].resolve(idle);
      pool.release(await idleTask); // one idle entry

      const dialing = pool.acquire({ host: "cap-dialing.example.com" }); // one in-flight dial
      // entries (1) + pending (1) is at the cap, so this one must evict the idle entry.
      const newcomer = pool.acquire({ host: "cap-newcomer.example.com" });
      expect(mockedConnect).toHaveBeenCalledTimes(3);
      expect(idle.endCalls).toBe(1);

      dials[1].resolve(makeFakeClient());
      dials[2].resolve(makeFakeClient());
      const [a, b] = await Promise.all([dialing, newcomer]);
      expect(pool.size).toBe(2);
      expect(pool.stats).toEqual({ active: 2, idle: 0 });

      pool.release(a);
      pool.release(b);
    } finally {
      pool.drain();
    }
  });

  // --- waitForCapacity: opt-in backpressure on top of the fail-fast acquire() ---
  //
  // Every wait below uses a SHORT timeout and asserts the resolved value: `true` means the
  // pool woke the waiter, `false` means it slept to the timeout. A missing notify therefore
  // shows up as `false`, not as a hang.

  it("rejects a full pool with a PoolFullError identified by its code, and a failed dial with neither", async () => {
    const pool = new ConnectionPool({ maxPoolSize: 1 });
    try {
      const held = await pool.acquire({ host: "code-held.example.com" });
      const full = await pool.acquire({ host: "code-full.example.com" }).catch((e: unknown) => e);
      expect(full).toBeInstanceOf(PoolFullError);
      expect((full as PoolFullError).code).toBe(POOL_FULL_ERROR_CODE);
      expect(isPoolFullError(full)).toBe(true);
      // Matched by code, not by class or message: a look-alike from another module copy counts,
      expect(isPoolFullError(Object.assign(new Error("anything"), { code: POOL_FULL_ERROR_CODE }))).toBe(true);
      // ...and a message that merely mentions it does not.
      expect(isPoolFullError(new Error("Connection pool is full"))).toBe(false);
      pool.release(held);

      mockedConnect.mockRejectedValueOnce(new Error("connect ECONNREFUSED"));
      const dialErr = await pool.acquire({ host: "code-refused.example.com" }).catch((e: unknown) => e);
      expect(String(dialErr)).toMatch(/ECONNREFUSED/);
      expect(isPoolFullError(dialErr)).toBe(false);
    } finally {
      pool.drain();
    }
  });

  it("waitForCapacity wakes a parked caller when a held entry is released, and its retry fits", async () => {
    const pool = new ConnectionPool({ maxPoolSize: 1 });
    try {
      const held = await pool.acquire({ host: "wake-held.example.com" });
      await expect(pool.acquire({ host: "wake-next.example.com" })).rejects.toThrow(PoolFullError);

      let woke: boolean | undefined;
      const wait = pool.waitForCapacity(200).then((v) => {
        woke = v;
        return v;
      });
      await Promise.resolve();
      expect(woke).toBeUndefined(); // parked: nothing has freed yet

      pool.release(held); // refCount 0 -> evictable -> notify
      expect(await wait).toBe(true);
      const next = await pool.acquire({ host: "wake-next.example.com" });
      expect((held as any).endCalls).toBe(1); // the idle entry was evicted to make the room
      pool.release(next);
    } finally {
      pool.drain();
    }
  });

  it("waitForCapacity wakes when a held entry dies, and when an in-flight dial fails", async () => {
    const dials = deferredConnects();
    const pool = new ConnectionPool({ maxPoolSize: 1 });
    try {
      // markDead: the only slot's connection drops while still checked out.
      const t1 = pool.acquire({ host: "dies-held.example.com" });
      const c1 = makeFakeClient();
      dials[0].resolve(c1);
      await t1;
      const onDeath = pool.waitForCapacity(200);
      c1.emit("close");
      expect(await onDeath).toBe(true);
      expect(pool.size).toBe(0);

      // Failed dial: the slot is held by a dial, not an entry.
      const doomed = pool.acquire({ host: "dial-doomed.example.com" }).catch(() => undefined);
      const onFailure = pool.waitForCapacity(200);
      dials[1].reject(new Error("connect ETIMEDOUT"));
      expect(await onFailure).toBe(true);
      await doomed;
    } finally {
      pool.drain();
    }
  });

  it("waitForCapacity resolves at once when the slot freed BEFORE the caller parked", async () => {
    // The lost-wakeup shape: acquire() rejects, the holder releases (notifying nobody, since
    // nobody is parked yet), and only then does the caller call waitForCapacity. Only the
    // re-check at registration can see that capacity already exists.
    const pool = new ConnectionPool({ maxPoolSize: 1 });
    try {
      const held = await pool.acquire({ host: "early-held.example.com" });
      await expect(pool.acquire({ host: "early-next.example.com" })).rejects.toThrow(PoolFullError);
      pool.release(held);

      expect(await pool.waitForCapacity(50)).toBe(true);
    } finally {
      pool.drain();
    }
  });

  it("waitForCapacity times out to false, and its timer is unref'd", async () => {
    const pool = new ConnectionPool({ maxPoolSize: 1 });
    const timeoutSpy = vi.spyOn(globalThis, "setTimeout");
    try {
      const held = await pool.acquire({ host: "timeout-held.example.com" });
      const wait = pool.waitForCapacity(20);
      const timer = timeoutSpy.mock.results.at(-1)?.value as NodeJS.Timeout;
      expect(timer.hasRef()).toBe(false); // a parked caller never holds the process open
      expect(await wait).toBe(false);
      pool.release(held);
    } finally {
      timeoutSpy.mockRestore();
      pool.drain();
    }
  });

  it("waitForCapacity clears its timer on wake, and drain() wakes a parked caller", async () => {
    vi.useFakeTimers();
    const pool = new ConnectionPool({ maxPoolSize: 1 });
    try {
      const held = await pool.acquire({ host: "clear-held.example.com" });
      const wait = pool.waitForCapacity(60_000);
      expect(vi.getTimerCount()).toBe(1);
      pool.release(held); // arms the entry's idle timer, wakes the waiter
      expect(await wait).toBe(true);
      expect(vi.getTimerCount()).toBe(1); // only the idle timer: the wait timer was cleared

      const again = await pool.acquire({ host: "clear-held.example.com" });
      const parked = pool.waitForCapacity(60_000);
      pool.drain();
      expect(await parked).toBe(true); // woken, not left to sit out 60s
      expect(vi.getTimerCount()).toBe(0);
      await expect(pool.acquire({ host: "clear-after.example.com" })).rejects.toThrow(/drained/);
      // Already drained: resolves at once rather than arming a timer.
      expect(await pool.waitForCapacity(60_000)).toBe(true);
      expect(vi.getTimerCount()).toBe(0);
      pool.release(again);
    } finally {
      pool.drain();
      vi.useRealTimers();
    }
  });

  it("acquire({ waitForCapacityMs }) parks for a slot; a spent budget names itself; a connect failure is not waited out", async () => {
    const pool = new ConnectionPool({ maxPoolSize: 1 });
    try {
      const held = await pool.acquire({ host: "budget-held.example.com" });

      // Budget spent: still a PoolFullError (same code), now carrying the budget in its message.
      const spent = await pool
        .acquire({ host: "budget-next.example.com" }, { waitForCapacityMs: 20 })
        .catch((e: unknown) => e);
      expect(spent).toBeInstanceOf(PoolFullError);
      expect(isPoolFullError(spent)).toBe(true);
      expect((spent as PoolFullError).waitedMs).toBe(20);
      expect((spent as Error).message).toBe(
        "Connection pool is full (1 connections in use or dialing); no slot freed up within 20ms",
      );
      expect(mockedConnect).toHaveBeenCalledTimes(1); // never dialed
      // A bare acquire() is unchanged: fail-fast, no suffix.
      const bare = await pool.acquire({ host: "budget-next.example.com" }).catch((e: unknown) => e);
      expect((bare as Error).message).toBe("Connection pool is full (1 connections in use or dialing)");
      expect((bare as PoolFullError).waitedMs).toBeUndefined();

      // Parked, then woken by the release; its retry evicts the idle entry and wins the slot.
      let settled = false;
      const parked = pool.acquire({ host: "budget-next.example.com" }, { waitForCapacityMs: 1_000 }).then((c) => {
        settled = true;
        return c;
      });
      await new Promise((r) => setTimeout(r, 5));
      expect(settled).toBe(false);
      pool.release(held);
      const next = await parked;
      expect(mockedConnect).toHaveBeenCalledTimes(2);
      expect((held as any).endCalls).toBe(1);
      pool.release(next);

      // A connect failure is not a capacity signal: rejected at once, no retry on the budget.
      mockedConnect.mockRejectedValueOnce(new Error("connect ECONNREFUSED"));
      await expect(pool.acquire({ host: "budget-refused.example.com" }, { waitForCapacityMs: 5_000 })).rejects.toThrow(
        /ECONNREFUSED/,
      );
      expect(mockedConnect).toHaveBeenCalledTimes(3);
    } finally {
      pool.drain();
    }
  });

  // defaultMaxPoolSize() reads process.env on every ConnectionPool construction, so a
  // stubbed env plus the file-level (already mocked) ConnectionPool is enough -- no
  // module reset or re-import needed.
  it("uses SSH_MCP_MAX_POOL_SIZE as the default cap when no maxPoolSize option is passed", async () => {
    vi.stubEnv("SSH_MCP_MAX_POOL_SIZE", "2");
    const pool = new ConnectionPool(); // no explicit maxPoolSize -- should pick up env
    try {
      const c1 = await pool.acquire({ host: "env-cap-1.example.com" });
      const c2 = await pool.acquire({ host: "env-cap-2.example.com" });
      await expect(pool.acquire({ host: "env-cap-3.example.com" })).rejects.toThrow(/Connection pool is full \(2 /);
      pool.release(c1);
      pool.release(c2);
    } finally {
      pool.drain();
    }
  });

  // Pins the fallback to EXACTLY 100: 100 held connections succeed and the 101st is
  // refused. "" takes the early `!raw` return that an unset var shares, and is the only
  // row that pins that return's constant (the other rows reach the final fallback). "-1"
  // catches a sign flip (Math.abs would yield cap 1); the 400-digit value makes
  // Number.parseInt return Infinity, which only the Number.isFinite guard rejects.
  // Distinct ports on one host give 100 distinct pool keys while paying for a single
  // memoized `ssh -G` spawn instead of 101. The regexes pin the number but not the
  // words after it, so a rewording of the pool-full message does not break them.
  it.each([
    { label: '"" (empty/unset)', value: "" },
    { label: "0", value: "0" },
    { label: "-1", value: "-1" },
    { label: "not-a-number", value: "not-a-number" },
    { label: '"9" x 400 (parseInt -> Infinity)', value: "9".repeat(400) },
  ])("falls back to the default pool cap of exactly 100 when SSH_MCP_MAX_POOL_SIZE=$label", async ({ value }) => {
    vi.stubEnv("SSH_MCP_MAX_POOL_SIZE", value);
    const pool = new ConnectionPool();
    try {
      const clients = [];
      // Sequential so each dial registers before the next; keeps the 100th/101st
      // boundary deterministic (in-flight dials count against the cap too).
      for (let i = 0; i < 100; i++) {
        clients.push(await pool.acquire({ host: "fallback-cap.example.com", port: 10_000 + i }));
      }
      expect(pool.size).toBe(100);
      expect(mockedConnect).toHaveBeenCalledTimes(100);
      await expect(pool.acquire({ host: "fallback-cap.example.com", port: 10_100 })).rejects.toThrow(
        /Connection pool is full \(100 /,
      );
      for (const c of clients) pool.release(c);
    } finally {
      pool.drain();
    }
  });
});
