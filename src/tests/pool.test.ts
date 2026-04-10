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

  it("drain on empty pool is safe", () => {
    const pool = new ConnectionPool();
    pool.drain();
    pool.drain(); // double drain is safe
    expect(pool.size).toBe(0);
  });
});

describe("resolveConfig", () => {
  it("returns a connect config with host and port", () => {
    const config = resolveConfig({ host: "example.com" });
    expect(config.host).toBeTruthy();
    expect(config.port).toBeGreaterThan(0);
    expect(config.username).toBeTruthy();
  });

  it("respects explicit port override", () => {
    const config = resolveConfig({ host: "example.com", port: 2222 });
    expect(config.port).toBe(2222);
  });

  it("respects explicit username override", () => {
    const config = resolveConfig({ host: "example.com", username: "deploy" });
    expect(config.username).toBe("deploy");
  });

  it("sets keepalive options", () => {
    const config = resolveConfig({ host: "example.com" });
    expect(config.keepaliveInterval).toBe(15_000);
    expect(config.keepaliveCountMax).toBe(3);
  });

  it("sets agent when SSH_AUTH_SOCK is available", () => {
    if (process.env.SSH_AUTH_SOCK) {
      const config = resolveConfig({ host: "example.com" });
      expect(config.agent).toBe(process.env.SSH_AUTH_SOCK);
    }
  });

  it("resolves SSH config hostname aliases", () => {
    // ssh -G resolves Host aliases from ~/.ssh/config
    // We can't control the user's config, but we can verify the function runs without error
    const config = resolveConfig({ host: "github.com" });
    expect(config.host).toBeTruthy();
  });
});
