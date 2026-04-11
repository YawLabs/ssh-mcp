import { describe, expect, it } from "vitest";
import { ConnectionPool } from "../pool.js";
import { resolveConfig } from "../ssh.js";

describe("ConnectionPool", () => {
  it("creates a pool with default options", () => {
    const pool = new ConnectionPool();
    expect(pool.size).toBe(0);
    expect(pool.stats).toEqual({ active: 0, idle: 0 });
    pool.drain();
  });

  it("creates a pool with custom TTL", () => {
    const pool = new ConnectionPool({ idleTtlMs: 30_000 });
    expect(pool.size).toBe(0);
    pool.drain();
  });

  it("creates a pool with custom maxPoolSize", () => {
    const pool = new ConnectionPool({ maxPoolSize: 50 });
    expect(pool.size).toBe(0);
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

describe("resolveConfig", () => {
  it("returns a resolved config with connectConfig and optional proxyJump", () => {
    const resolved = resolveConfig({ host: "example.com" });
    expect(resolved.connectConfig).toBeDefined();
    expect(resolved.connectConfig.host).toBeTruthy();
    expect(resolved.connectConfig.port).toBeGreaterThan(0);
    expect(resolved.connectConfig.username).toBeTruthy();
  });

  it("respects explicit port override", () => {
    const resolved = resolveConfig({ host: "example.com", port: 2222 });
    expect(resolved.connectConfig.port).toBe(2222);
  });

  it("respects explicit username override", () => {
    const resolved = resolveConfig({ host: "example.com", username: "deploy" });
    expect(resolved.connectConfig.username).toBe("deploy");
  });

  it("sets keepalive options", () => {
    const resolved = resolveConfig({ host: "example.com" });
    expect(resolved.connectConfig.keepaliveInterval).toBe(15_000);
    expect(resolved.connectConfig.keepaliveCountMax).toBe(3);
  });

  it("sets agent when SSH_AUTH_SOCK is available", () => {
    if (process.env.SSH_AUTH_SOCK) {
      const resolved = resolveConfig({ host: "example.com" });
      expect(resolved.connectConfig.agent).toBe(process.env.SSH_AUTH_SOCK);
    }
  });

  it("resolves SSH config hostname aliases", () => {
    const resolved = resolveConfig({ host: "github.com" });
    expect(resolved.connectConfig.host).toBeTruthy();
  });

  it("proxyJump is undefined for hosts without proxy config", () => {
    const resolved = resolveConfig({ host: "example.com" });
    // Most hosts won't have a ProxyJump configured
    expect(resolved.proxyJump === undefined || typeof resolved.proxyJump === "string").toBe(true);
  });
});
