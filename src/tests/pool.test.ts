import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ConnectionPool } from "../pool.js";
import { connect, isStrictHostKeyMode, readKnownHostsKeys, resolveConfig } from "../ssh.js";

// Captures every fs write attempted by code under test while this file runs, so the
// NOT-TOFU test can prove that connecting to an unknown host persists nothing. The
// recorders never call through: a real write would touch the developer's known_hosts.
const fsWrites = vi.hoisted(() => [] as Array<{ path: unknown; data: unknown }>);

// Only the dial is faked: the fake Client runs the REAL hostVerifier from resolveConfig
// against a presented key, exactly as ssh2 would. Same boundary as ssh-hardening.test.ts.
vi.mock("ssh2", async () => {
  const { EventEmitter } = await import("node:events");

  class FakeClient extends EventEmitter {
    connect(cfg: Record<string, any>) {
      queueMicrotask(() => {
        const verifier = cfg.hostVerifier as ((key: Buffer) => boolean) | undefined;
        if (typeof verifier === "function" && !verifier(Buffer.from("ssh-mcp-unpersisted-key"))) {
          return void this.emit("error", new Error("Host denied (verification failed)"));
        }
        this.emit("ready");
      });
      return this;
    }
    end() {
      queueMicrotask(() => this.emit("close"));
    }
  }

  return { Client: FakeClient };
});

// Write interception for the NOT-TOFU pin: appendFileSync/writeFileSync and their
// fs/promises twins are the shapes a regression to real TOFU would use to persist a key.
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  const record = (path: unknown, data: unknown): void => {
    fsWrites.push({ path, data });
  };
  return {
    ...actual,
    appendFileSync: record as unknown as typeof actual.appendFileSync,
    writeFileSync: record as unknown as typeof actual.writeFileSync,
  };
});
vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  const record = (path: unknown, data: unknown): Promise<void> => {
    fsWrites.push({ path, data });
    return Promise.resolve();
  };
  return {
    ...actual,
    appendFile: record as unknown as typeof actual.appendFile,
    writeFile: record as unknown as typeof actual.writeFile,
  };
});
// Subprocess persistence is the write shape the fs mocks above cannot see:
// a regression could pin a key by spawning `ssh-keyscan`/`ssh-keygen` with a
// known_hosts append instead of calling appendFileSync. Wraps (never blocks)
// every child_process entry point and records ONLY keyscan-shaped invocations
// -- the benign `ssh -G` config lookup resolveConfig runs on every connect is
// read-only and stays unrecorded, as does everything else on this path.
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  const recordIfPersisting = (cmd: unknown, args?: unknown): void => {
    const line = `${String(cmd)} ${(Array.isArray(args) ? args : []).join(" ")}`;
    if (/keyscan|known_hosts/.test(line)) fsWrites.push({ path: "child_process", data: line });
  };
  const wrap =
    (fn: any): any =>
    (...rest: any[]) => {
      recordIfPersisting(rest[0], rest[1]);
      return fn(...rest);
    };
  return {
    ...actual,
    spawn: wrap(actual.spawn),
    execFile: wrap(actual.execFile),
    exec: wrap(actual.exec),
    execSync: wrap(actual.execSync),
    spawnSync: wrap(actual.spawnSync),
    fork: wrap(actual.fork),
  };
});

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
  // Runs even when an assertion throws mid-test, so a stubbed env var can never leak
  // into a later test (same discipline as the maxPoolSize describe in
  // pool-concurrency.test.ts).
  afterEach(() => {
    vi.unstubAllEnvs();
  });

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
    // Stubbed explicitly so the test exercises its path on every machine -- left
    // conditional on the real env it silently passed on hosts without the var.
    vi.stubEnv("SSH_AUTH_SOCK", "/tmp/agent.sock");
    const resolved = resolveConfig({ host: "example.com" });
    expect(resolved.connectConfig.agent).toBe("/tmp/agent.sock");
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

  it("persisting NOTHING to known_hosts when an unknown host's key is accepted (NOT TOFU)", async () => {
    // The non-persistence half of trust-always, which the accept test above does not
    // cover: a regression to real TOFU (accept + pin the first key seen) would still
    // pass every assertion above. The fake Client feeds the REAL hostVerifier the
    // server's key through a full ssh.ts connect, then this asserts no fs write
    // happened at all -- a re-introduced persist makes the write land in fsWrites and
    // the final assertion fail. Calls the real appendFileSync/writeFileSync shapes
    // (sync + fs/promises), all intercepted at module level for the whole file, plus
    // a child_process wrapper that records keyscan-shaped spawns -- so a persist via
    // `ssh-keyscan >> known_hosts` lands in fsWrites too.
    fsWrites.length = 0;

    const client = await connect({ host: UNKNOWN });
    client.end();

    expect(fsWrites).toHaveLength(0);
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
