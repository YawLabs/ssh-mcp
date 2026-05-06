import { EventEmitter } from "node:events";
import { beforeEach, describe, expect, it, vi } from "vitest";

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

import { ConnectionPool } from "../pool.js";
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
});
