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
  // end() triggers a deferred 'close' so the pool can mark dead correctly.
  client.end = () => {
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
