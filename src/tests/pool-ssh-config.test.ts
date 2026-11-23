import * as fs from "node:fs";
import * as fsPromises from "node:fs/promises";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { connect, isStrictHostKeyMode, readKnownHostsKeys, resolveConfig } from "../ssh.js";

// resolveConfig / hostVerifier / known_hosts tests, moved out of pool.test.ts (they never
// touched the pool). `ssh -G` is answered from a fixture table here rather than by the real
// client, so results no longer depend on the developer's own ~/.ssh/config.

// Captures every fs write attempted by code under test while this file runs, so the
// NOT-TOFU test can prove that connecting to an unknown host persists nothing. The
// recorders never call through: a real write would touch the developer's known_hosts.
const fsWrites = vi.hoisted(() => [] as Array<{ path: unknown; data: unknown }>);

// Canned `ssh -G <host>` answers. A host not listed gets a minimal config naming itself,
// which is what OpenSSH prints for a host with no matching block.
const SSH_G = vi.hoisted(
  () =>
    ({
      "alias-db": ["hostname 10.20.30.40", "user deploy", "port 2200", "proxyjump bastion.internal"],
      "plain-host": ["hostname plain-host.example.net", "user tester", "port 22", "proxyjump none"],
    }) as Record<string, string[]>,
);

// One canned `ssh-keygen -F` answer, so the known_hosts parse is pinned against a fixture.
// The blob is SSH-wire shaped (uint32 length + "ssh-ed25519" + key bytes): readKnownHostsTarget
// keeps an entry only when the blob's own algorithm name matches the type column.
const { KEYGEN_HOST, KEYGEN_BLOB } = vi.hoisted(() => {
  const type = Buffer.from("ssh-ed25519");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(type.length);
  return { KEYGEN_HOST: "kh-fixture.test", KEYGEN_BLOB: Buffer.concat([len, type, Buffer.alloc(36, 7)]) };
});

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

// Write interception for the NOT-TOFU pin. Every shape a regression to real TOFU could use
// to persist a key is recorded and never called through: the sync and callback
// appendFile/writeFile, the `promises` object reached through `node:fs` itself, a write
// stream, and openSync-for-write + writeSync. A read-only openSync still calls through.
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  const SENTINEL_FD = 2 ** 30;
  const record = (path: unknown, data: unknown): void => {
    fsWrites.push({ path, data });
  };
  const recordCb = (path: unknown, data: unknown, ...rest: unknown[]): void => {
    record(path, data);
    const cb = rest.at(-1);
    if (typeof cb === "function") queueMicrotask(() => cb(null));
  };
  const recordAsync = (path: unknown, data: unknown): Promise<void> => {
    record(path, data);
    return Promise.resolve();
  };
  const isReadOnly = (flags: unknown) =>
    flags === undefined || flags === "r" || flags === "rs" || flags === "sr" || flags === actual.constants.O_RDONLY;
  const { Writable } = await import("node:stream");
  return {
    ...actual,
    appendFileSync: record as unknown as typeof actual.appendFileSync,
    writeFileSync: record as unknown as typeof actual.writeFileSync,
    appendFile: recordCb as unknown as typeof actual.appendFile,
    writeFile: recordCb as unknown as typeof actual.writeFile,
    promises: { ...actual.promises, appendFile: recordAsync, writeFile: recordAsync },
    createWriteStream: ((path: unknown) => {
      record(path, "createWriteStream");
      return new Writable({
        write(chunk, _enc, cb) {
          record(path, chunk);
          cb();
        },
      });
    }) as unknown as typeof actual.createWriteStream,
    openSync: ((path: fs.PathLike, flags?: unknown, mode?: unknown) => {
      if (isReadOnly(flags)) return actual.openSync(path, flags as fs.OpenMode, mode as fs.Mode);
      record(path, `openSync:${String(flags)}`);
      return SENTINEL_FD;
    }) as typeof actual.openSync,
    writeSync: ((fd: number, data: unknown, ...rest: unknown[]) => {
      // stdout/stderr pass through; any other fd is a file write and is recorded instead.
      if (fd <= 2) return (actual.writeSync as (...a: unknown[]) => number)(fd, data, ...rest);
      record(fd, data);
      return typeof data === "string" ? Buffer.byteLength(data) : ((data as Buffer)?.length ?? 0);
    }) as typeof actual.writeSync,
    closeSync: ((fd: number) => {
      if (fd !== SENTINEL_FD) actual.closeSync(fd);
    }) as typeof actual.closeSync,
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
// Subprocess persistence is the write shape the fs mocks above cannot see: a regression could
// pin a key by spawning `ssh-keyscan`/`ssh-keygen` with a known_hosts append instead of calling
// appendFileSync. Every child_process entry point is wrapped and keyscan-shaped invocations
// recorded. execFileSync (what runArgs uses) also answers `ssh -G` from the SSH_G table and
// `ssh-keygen -F` for KEYGEN_HOST from its fixture; everything else calls through.
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
  const execFileSync = (cmd: string, args?: string[], opts?: unknown) => {
    recordIfPersisting(cmd, args);
    if (cmd === "ssh" && args?.[0] === "-G") {
      const host = String(args.at(-1)); // `ssh -G [--] <host>`: the host is always last
      return `${(SSH_G[host] ?? [`hostname ${host}`, "user tester", "port 22"]).join("\n")}\n`;
    }
    if (cmd === "ssh-keygen" && args?.[0] === "-F" && args.at(-1) === KEYGEN_HOST) {
      return [
        `# Host ${KEYGEN_HOST} found: line 3`,
        `${KEYGEN_HOST} ssh-ed25519 ${KEYGEN_BLOB.toString("base64")}`,
        "",
      ].join("\n");
    }
    return (actual.execFileSync as (...a: unknown[]) => unknown)(cmd, args, opts);
  };
  return {
    ...actual,
    spawn: wrap(actual.spawn),
    execFile: wrap(actual.execFile),
    exec: wrap(actual.exec),
    execSync: wrap(actual.execSync),
    execFileSync,
    spawnSync: wrap(actual.spawnSync),
    fork: wrap(actual.fork),
  };
});

describe("resolveConfig", () => {
  // Runs even when an assertion throws mid-test, so a stubbed env var can never leak
  // into a later test (same discipline as the maxPoolSize describe in
  // pool-concurrency.test.ts).
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("returns a resolved config with connectConfig", () => {
    const resolved = resolveConfig({ host: "example.com" });
    expect(resolved.connectConfig.host).toBe("example.com");
    expect(resolved.connectConfig.port).toBe(22);
    expect(resolved.connectConfig.username).toBe("tester");
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

  it("resolves an ssh_config alias to its HostName, User, Port and ProxyJump", () => {
    const resolved = resolveConfig({ host: "alias-db" });
    expect(resolved.connectConfig.host).toBe("10.20.30.40");
    expect(resolved.connectConfig.username).toBe("deploy");
    expect(resolved.connectConfig.port).toBe(2200);
    expect(resolved.proxyJump).toBe("bastion.internal");
  });

  it("leaves proxyJump undefined when ssh -G reports `proxyjump none`", () => {
    const resolved = resolveConfig({ host: "plain-host" });
    expect(resolved.connectConfig.host).toBe("plain-host.example.net");
    expect(resolved.proxyJump).toBeUndefined();
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

  it("the write recorder sees every persistence shape it claims to (so an empty record means something)", async () => {
    fsWrites.length = 0;
    const target = "/ssh-mcp-never-written/known_hosts";
    fs.appendFileSync(target, "a");
    fs.writeFileSync(target, "b");
    await new Promise<void>((r) => fs.appendFile(target, "c", () => r()));
    await new Promise<void>((r) => fs.writeFile(target, "d", () => r()));
    await fs.promises.appendFile(target, "e");
    await fs.promises.writeFile(target, "f");
    await fsPromises.appendFile(target, "g");
    await fsPromises.writeFile(target, "h");
    const ws = fs.createWriteStream(target);
    await new Promise<void>((r) => ws.end("i", () => r()));
    const fd = fs.openSync(target, "a");
    fs.writeSync(fd, "j");
    fs.closeSync(fd);
    const paths = fsWrites.map((w) => w.path);
    expect(paths.filter((p) => p === target)).toHaveLength(11); // writeSync records its fd
    expect(fsWrites.map((w) => String(w.data))).toEqual(
      expect.arrayContaining(["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]),
    );
    fsWrites.length = 0;
  });

  it("persisting NOTHING to known_hosts when an unknown host's key is accepted (NOT TOFU)", async () => {
    // The non-persistence half of trust-always, which the accept test above does not
    // cover: a regression to real TOFU (accept + pin the first key seen) would still
    // pass every assertion above. The fake Client feeds the REAL hostVerifier the
    // server's key through a full ssh.ts connect, then this asserts no fs write
    // happened at all -- a re-introduced persist makes the write land in fsWrites and
    // the final assertion fail. Every fs write shape the module-level mock records
    // (proven by the test above), plus a child_process wrapper that records
    // keyscan-shaped spawns -- so a persist via `ssh-keyscan >> known_hosts` lands too.
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

  it("decodes the key blob of each `ssh-keygen -F` line, skipping its comment header", () => {
    expect(readKnownHostsKeys(KEYGEN_HOST)).toEqual([KEYGEN_BLOB]);
  });
});
