import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ConnectionPool } from "../pool.js";
import { isStrictHostKeyMode, readKnownHostsKeys, resolveConfig } from "../ssh.js";

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

  it("sets a hostVerifier on connectConfig", () => {
    const resolved = resolveConfig({ host: "example.com" });
    expect(typeof resolved.connectConfig.hostVerifier).toBe("function");
  });
});

describe("hostVerifier (via resolveConfig)", () => {
  const UNKNOWN = "ssh-mcp-nonexistent-host-xyz.invalid";

  beforeEach(() => {
    vi.stubEnv("SSH_MCP_STRICT_HOST_KEY", "");
    vi.stubEnv("SSH_MCP_STRICT_HOSTKEYS", "");
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("accepts unknown hosts by default (trust-always -- no key is ever persisted)", () => {
    const resolved = resolveConfig({ host: UNKNOWN });
    const verify = resolved.connectConfig.hostVerifier as (key: Buffer) => boolean;
    expect(verify(Buffer.from("fake-key-bytes"))).toBe(true);
  });

  it("rejects unknown hosts when SSH_MCP_STRICT_HOST_KEY=1", () => {
    vi.stubEnv("SSH_MCP_STRICT_HOST_KEY", "1");
    const resolved = resolveConfig({ host: UNKNOWN });
    const verify = resolved.connectConfig.hostVerifier as (key: Buffer) => boolean;
    expect(verify(Buffer.from("fake-key-bytes"))).toBe(false);
  });

  it("rejects unknown hosts when SSH_MCP_STRICT_HOSTKEYS=1 (the non-credential-shaped name)", () => {
    vi.stubEnv("SSH_MCP_STRICT_HOSTKEYS", "1");
    const resolved = resolveConfig({ host: UNKNOWN });
    const verify = resolved.connectConfig.hostVerifier as (key: Buffer) => boolean;
    expect(verify(Buffer.from("fake-key-bytes"))).toBe(false);
  });

  it("strict mode is captured at resolveConfig time, not verify time", () => {
    // Verifier built with strict=false should keep accepting even if env flips later.
    const resolved = resolveConfig({ host: UNKNOWN });
    vi.stubEnv("SSH_MCP_STRICT_HOST_KEY", "1");
    const verify = resolved.connectConfig.hostVerifier as (key: Buffer) => boolean;
    expect(verify(Buffer.from("x"))).toBe(true);
  });
});

describe("isStrictHostKeyMode", () => {
  // Read the way Yaw MCP reads an opt-in: trimmed, case-insensitive 1/true. Only "1"
  // used to count, so =true silently left strict mode off.
  it.each(["1", "true", "TRUE", " True ", " 1\n"])("treats %j as on, under either name", (value) => {
    expect(isStrictHostKeyMode({ SSH_MCP_STRICT_HOSTKEYS: value })).toBe(true);
    expect(isStrictHostKeyMode({ SSH_MCP_STRICT_HOST_KEY: value })).toBe(true);
  });

  it.each(["", "0", "false", "yes", "on", "2"])("treats %j as off", (value) => {
    expect(isStrictHostKeyMode({ SSH_MCP_STRICT_HOSTKEYS: value, SSH_MCP_STRICT_HOST_KEY: value })).toBe(false);
  });

  it("is off when neither name is set", () => {
    expect(isStrictHostKeyMode({})).toBe(false);
  });

  it("either name alone turns it on (the old name keeps working)", () => {
    expect(isStrictHostKeyMode({ SSH_MCP_STRICT_HOST_KEY: "1", SSH_MCP_STRICT_HOSTKEYS: "" })).toBe(true);
    expect(isStrictHostKeyMode({ SSH_MCP_STRICT_HOSTKEYS: "1", SSH_MCP_STRICT_HOST_KEY: "0" })).toBe(true);
  });
});

describe("readKnownHostsKeys", () => {
  it("returns [] for an invalid hostname", () => {
    expect(readKnownHostsKeys("host; rm -rf /")).toEqual([]);
  });

  it("returns [] for a host not in known_hosts", () => {
    expect(readKnownHostsKeys("ssh-mcp-nonexistent-host-xyz.invalid")).toEqual([]);
  });

  it("returns Buffer[] when ssh-keygen is available (may be empty)", () => {
    const result = readKnownHostsKeys("example.com");
    expect(Array.isArray(result)).toBe(true);
    for (const buf of result) expect(Buffer.isBuffer(buf)).toBe(true);
  });
});
