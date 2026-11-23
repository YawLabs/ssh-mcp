import { describe, expect, it } from "vitest";
import { ConnectionPool } from "../pool.js";

// ConnectionPool construction and the never-dialed paths. Dialing, eviction, TTL and cap
// behaviour live in pool-concurrency.test.ts and pool-ops-lifecycle.test.ts; the
// resolveConfig / hostVerifier tests that used to sit here are in pool-ssh-config.test.ts.

describe("ConnectionPool", () => {
  it("creates a pool with default options", () => {
    const pool = new ConnectionPool();
    expect(pool.size).toBe(0);
    expect(pool.stats).toEqual({ active: 0, idle: 0 });
    pool.drain();
  });

  it("takes a custom maxPoolSize", () => {
    const pool = new ConnectionPool({ maxPoolSize: 50 });
    expect(pool.maxSize).toBe(50);
    pool.drain();
  });

  it("drain on empty pool is safe", () => {
    const pool = new ConnectionPool();
    pool.drain();
    pool.drain(); // double drain is safe
    expect(pool.size).toBe(0);
  });

  it("release of unknown client closes it", () => {
    const pool = new ConnectionPool();
    // Create a mock client-like object
    let endCalled = false;
    const fakeClient = {
      end: () => {
        endCalled = true;
      },
    } as any;
    pool.release(fakeClient);
    expect(endCalled).toBe(true);
    pool.drain();
  });

  it("release of already-closed unknown client is safe", () => {
    const pool = new ConnectionPool();
    const fakeClient = {
      end: () => {
        throw new Error("already closed");
      },
    } as any;
    // Should not throw
    expect(() => pool.release(fakeClient)).not.toThrow();
    pool.drain();
  });
});
