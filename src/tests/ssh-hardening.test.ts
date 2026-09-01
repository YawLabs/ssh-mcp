import { EventEmitter } from "node:events";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { beforeEach, describe, expect, it, vi } from "vitest";

// `runArgs` and the four diagnostic checks are the only impure edges ssh.ts touches
// for host resolution, so mocking them here makes `ssh -G`, `ssh-keygen -F`, and
// `formatDiagnostics` fully deterministic -- no real ssh binary, no real known_hosts,
// no dependence on the developer's SSH environment.
const stubs = vi.hoisted(() => ({
  runArgsCalls: [] as Array<{ cmd: string; args: string[] }>,
  runArgs: { fn: (_cmd: string, _args: string[]) => ({ stdout: "", ok: false }) },
  // Drives formatDiagnostics(). checkKnownHosts is deliberately the knob: unlike
  // checkSshAgent / checkSshKeys it is NOT memoized inside ssh.ts, so flipping it
  // takes effect immediately instead of waiting out a 2s TTL.
  knownHostsCheck: { status: "ok" as "ok" | "warning" | "error", message: "ok" },
  // --- fake ssh2 Client (see the vi.mock below) ---
  /** Every ConnectConfig handed to Client.connect(), in order. THE dial counter. */
  dials: [] as Array<Record<string, any>>,
  /**
   * Per-host dial script. `hostKey` is the blob the fake server presents, which the
   * real hostVerifier from resolveConfig then judges; `error` fails the dial outright.
   * Absent -> the connection just goes ready.
   */
  dialScript: new Map<string, { hostKey?: Buffer; error?: Error }>(),
}));

// A fake ssh2 Client. ssh2 is imported for its runtime `Client` by ssh.ts alone
// (pool.ts and ops.ts take types only), so faking it here buys the REAL connect
// path -- connectRaw, connectWithProxy, the hostVerifier, ConnectionPool.acquire --
// with no socket and no network. Everything else in these suites hands its own fake
// client object straight to exec()/SFTP helpers and never touches this.
vi.mock("ssh2", async () => {
  const { EventEmitter } = await import("node:events");

  class FakeClient extends EventEmitter {
    connect(cfg: Record<string, any>) {
      stubs.dials.push(cfg);
      queueMicrotask(() => {
        const script = stubs.dialScript.get(String(cfg.host)) ?? {};
        if (script.error) return void this.emit("error", script.error);
        // Exercise the caller's real hostVerifier with the key the server "offered".
        if (script.hostKey && typeof cfg.hostVerifier === "function" && !cfg.hostVerifier(script.hostKey)) {
          // Verbatim what ssh2 reports for every rejection (lib/protocol/kex.js) --
          // the opaque string the hostKeyRejection side channel exists to enrich.
          return void this.emit("error", new Error("Host denied (verification failed)"));
        }
        this.emit("ready");
      });
      return this;
    }
    end() {
      queueMicrotask(() => this.emit("close"));
    }
    forwardOut(_srcIp: string, _srcPort: number, _dstHost: string, _dstPort: number, cb: (e: any, s?: any) => void) {
      queueMicrotask(() => cb(null, new EventEmitter()));
    }
  }

  return { Client: FakeClient };
});

vi.mock("../diagnose.js", async () => {
  const actual = await vi.importActual<typeof import("../diagnose.js")>("../diagnose.js");
  return {
    ...actual,
    runArgs: (cmd: string, args: string[]) => {
      stubs.runArgsCalls.push({ cmd, args });
      return stubs.runArgs.fn(cmd, args);
    },
    checkSshAgent: () => ({ status: "ok", message: "ok" }),
    checkSshKeys: () => ({ status: "ok", message: "ok" }),
    checkSshConfig: () => ({ status: "ok", message: "ok" }),
    checkKnownHosts: () => ({ ...stubs.knownHostsCheck }),
  };
});

const {
  clearKnownHostTypeCache,
  clearSshConfigCache,
  connect,
  deleteFile,
  enhanceSshError,
  exec,
  formatJumpHop,
  hostKeyAlgorithmOrder,
  hostKeyBlobType,
  knownHostsTargets,
  makeDir,
  parseJumpSpec,
  readKnownHostsEntries,
  readKnownHostsKeys,
  resolveConfig,
  unbracketHost,
} = await import("../ssh.js");
const { ConnectionPool } = await import("../pool.js");

// ---------------------------------------------------------------- helpers

/** An SSH public-key blob: uint32 length + algorithm name + opaque body. */
function keyBlob(type: string, body: string): Buffer {
  const name = Buffer.from(type, "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(name.length, 0);
  return Buffer.concat([len, name, Buffer.from(body, "utf8")]);
}

/** One `ssh-keygen -F` stdout blob, comment header included as the real tool emits it. */
function keygenOutput(host: string, entries: Array<{ type: string; blob: Buffer }>): string {
  return [`# Host ${host} found: line 1`, ...entries.map((e) => `${host} ${e.type} ${e.blob.toString("base64")}`)].join(
    "\n",
  );
}

function sshConfigOutput(fields: Record<string, string>): string {
  return Object.entries(fields)
    .map(([k, v]) => `${k} ${v}`)
    .join("\n");
}

interface SftpProbe {
  lstat: string[];
  stat: string[];
  unlink: string[];
  rmdir: string[];
  mkdir: string[];
  ended: number;
}

type StatLike = { isDirectory(): boolean; isSymbolicLink(): boolean };

function statOf(kind: "file" | "dir" | "symlink"): StatLike {
  return {
    isDirectory: () => kind === "dir",
    isSymbolicLink: () => kind === "symlink",
  };
}

/**
 * A fake SFTPWrapper plus the client that hands it out. `lstat` / `stat` are supplied
 * independently so a test can model a symlink whose lstat succeeds while stat fails
 * (dangling) or reports the TARGET's type (symlink to a directory).
 */
function fakeSftpClient(opts: {
  lstat?: (path: string) => StatLike | Error;
  stat?: (path: string) => StatLike | Error;
  mkdir?: (path: string) => Error | null;
}): { client: any; probe: SftpProbe } {
  const probe: SftpProbe = { lstat: [], stat: [], unlink: [], rmdir: [], mkdir: [], ended: 0 };
  const settle = (result: StatLike | Error, cb: (err: any, stats?: StatLike) => void) => {
    queueMicrotask(() => (result instanceof Error ? cb(result) : cb(undefined, result)));
  };
  const sftp = {
    lstat: (path: string, cb: (err: any, stats?: StatLike) => void) => {
      probe.lstat.push(path);
      settle(opts.lstat?.(path) ?? new Error("lstat not stubbed"), cb);
    },
    stat: (path: string, cb: (err: any, stats?: StatLike) => void) => {
      probe.stat.push(path);
      settle(opts.stat?.(path) ?? new Error("stat not stubbed"), cb);
    },
    unlink: (path: string, cb: (err: any) => void) => {
      probe.unlink.push(path);
      queueMicrotask(() => cb(undefined));
    },
    rmdir: (path: string, cb: (err: any) => void) => {
      probe.rmdir.push(path);
      queueMicrotask(() => cb(undefined));
    },
    mkdir: (path: string, cb: (err: any) => void) => {
      probe.mkdir.push(path);
      queueMicrotask(() => cb(opts.mkdir?.(path) ?? null));
    },
    end: () => {
      probe.ended++;
    },
  };
  return { client: { sftp: (cb: (err: any, s: any) => void) => cb(null, sftp) } as any, probe };
}

beforeEach(() => {
  stubs.runArgsCalls.length = 0;
  stubs.runArgs.fn = () => ({ stdout: "", ok: false });
  stubs.knownHostsCheck = { status: "ok", message: "ok" };
  stubs.dials.length = 0;
  stubs.dialScript.clear();
  clearSshConfigCache();
  clearKnownHostTypeCache();
  vi.unstubAllEnvs();
  vi.stubEnv("SSH_MCP_STRICT_HOST_KEY", "");
});

/** `ssh-keygen -F <host>` answers with these entries; everything else misses. */
function stubKnownHostsFor(host: string, entries: Array<{ type: string; blob: Buffer }>) {
  const prev = stubs.runArgs.fn;
  stubs.runArgs.fn = (cmd, args) =>
    cmd === "ssh-keygen" && args[1] === host ? { stdout: keygenOutput(host, entries), ok: true } : prev(cmd, args);
}

function keygenSpawns(): string[] {
  return stubs.runArgsCalls.filter((c) => c.cmd === "ssh-keygen").map((c) => c.args[1]);
}

// ---------------------------------------------------------------- finding 1

describe("deleteFile symlink handling", () => {
  it("unlinks a symlink that points at a directory instead of calling rmdir on it", async () => {
    // The bug: stat() FOLLOWS the link, so the symlink reported isDirectory() and
    // got dispatched to rmdir(<symlink path>), which is not a directory.
    const { client, probe } = fakeSftpClient({
      lstat: () => statOf("symlink"),
      stat: () => statOf("dir"),
    });
    await deleteFile(client, "/srv/link-to-dir");
    expect(probe.unlink).toEqual(["/srv/link-to-dir"]);
    expect(probe.rmdir).toEqual([]);
    // Must not consult stat at all -- that is what followed the link.
    expect(probe.stat).toEqual([]);
    expect(probe.lstat).toEqual(["/srv/link-to-dir"]);
  });

  it("deletes a dangling symlink (stat would reject ENOENT before unlink was reached)", async () => {
    const enoent = Object.assign(new Error("No such file"), { code: 2 });
    const { client, probe } = fakeSftpClient({
      lstat: () => statOf("symlink"),
      stat: () => enoent,
    });
    await expect(deleteFile(client, "/srv/dangling")).resolves.toBeUndefined();
    expect(probe.unlink).toEqual(["/srv/dangling"]);
    expect(probe.rmdir).toEqual([]);
  });

  it("still rmdirs a real directory and unlinks a real file", async () => {
    const dir = fakeSftpClient({ lstat: () => statOf("dir") });
    await deleteFile(dir.client, "/srv/realdir");
    expect(dir.probe.rmdir).toEqual(["/srv/realdir"]);
    expect(dir.probe.unlink).toEqual([]);

    const file = fakeSftpClient({ lstat: () => statOf("file") });
    await deleteFile(file.client, "/srv/realfile");
    expect(file.probe.unlink).toEqual(["/srv/realfile"]);
    expect(file.probe.rmdir).toEqual([]);
  });

  it("propagates a genuine lstat failure and still closes the sftp session", async () => {
    const { client, probe } = fakeSftpClient({ lstat: () => new Error("Permission denied") });
    await expect(deleteFile(client, "/root/secret")).rejects.toThrow(/Permission denied/);
    expect(probe.ended).toBe(1);
  });
});

// ---------------------------------------------------------------- finding 4

describe("makeDir recursive path construction", () => {
  it("builds absolute segments as /a, /a/b, /a/b/c", async () => {
    const { client, probe } = fakeSftpClient({ mkdir: () => null });
    await makeDir(client, "/a/b/c", true);
    expect(probe.mkdir).toEqual(["/a", "/a/b", "/a/b/c"]);
  });

  it("builds relative segments as ./a, ./a/b", async () => {
    const { client, probe } = fakeSftpClient({ mkdir: () => null });
    await makeDir(client, "a/b", true);
    expect(probe.mkdir).toEqual(["./a", "./a/b"]);
  });

  it("tolerates existing intermediate segments but surfaces a leaf failure", async () => {
    const { client, probe } = fakeSftpClient({
      mkdir: (p) => (p === "/a/b/c" ? new Error("Failure") : new Error("Failure")),
    });
    await expect(makeDir(client, "/a/b/c", true)).rejects.toThrow(/Failure/);
    // Every segment was still attempted in order; only the leaf threw.
    expect(probe.mkdir).toEqual(["/a", "/a/b", "/a/b/c"]);
  });

  it("non-recursive mode creates exactly the given path", async () => {
    const { client, probe } = fakeSftpClient({ mkdir: () => null });
    await makeDir(client, "/a/b/c");
    expect(probe.mkdir).toEqual(["/a/b/c"]);
  });
});

// ---------------------------------------------------------------- finding 17

describe("knownHostsTargets", () => {
  it("looks a default-port IPv6 host up BARE, the only spelling ssh-keygen -F matches", () => {
    // Probed against OpenSSH: `ssh-keygen -F '::1'` hits a `::1` known_hosts line,
    // `ssh-keygen -F '[::1]'` misses it.
    expect(knownHostsTargets("[::1]", 22)).toEqual(["::1"]);
    expect(knownHostsTargets("::1", 22)).toEqual(["::1"]);
    expect(knownHostsTargets("::1")).toEqual(["::1"]);
  });

  it("brackets an IPv6 host exactly once for a non-default port", () => {
    expect(knownHostsTargets("[::1]", 2222)).toEqual(["[::1]:2222", "::1"]);
    expect(knownHostsTargets("::1", 2222)).toEqual(["[::1]:2222", "::1"]);
    // Regression: the old `[${host}]:${port}` template double-bracketed an
    // already-bracketed host into a target that can never match.
    for (const target of knownHostsTargets("[2001:db8::1]", 2222)) {
      expect(target.startsWith("[[")).toBe(false);
    }
    expect(knownHostsTargets("[2001:db8::1]", 2222)).toEqual(["[2001:db8::1]:2222", "2001:db8::1"]);
  });

  it("leaves plain hostnames exactly as before", () => {
    expect(knownHostsTargets("example.com", 22)).toEqual(["example.com"]);
    expect(knownHostsTargets("example.com")).toEqual(["example.com"]);
    expect(knownHostsTargets("example.com", 2222)).toEqual(["[example.com]:2222", "example.com"]);
  });

  it("rejects injection-shaped hosts in both bracketed and bare form", () => {
    expect(knownHostsTargets("host; rm -rf /")).toEqual([]);
    expect(knownHostsTargets("[::1; rm -rf /]")).toEqual([]);
    expect(knownHostsTargets("-oProxyCommand=evil")).toEqual([]);
    expect(knownHostsTargets("")).toEqual([]);
  });

  it("unbracketHost only strips a genuine bracket pair", () => {
    expect(unbracketHost("[::1]")).toBe("::1");
    expect(unbracketHost("::1")).toBe("::1");
    expect(unbracketHost("example.com")).toBe("example.com");
    expect(unbracketHost("[]")).toBe("[]");
  });
});

describe("readKnownHostsKeys with a bare IPv6 host", () => {
  it("finds entries for '::1' -- the exact string `ssh -G '[::1]'` hands back", () => {
    // Before the fix this returned [] without ever spawning ssh-keygen, because
    // isValidHostname's plain-host regex has no ':' and only accepts IPv6 bracketed.
    const blob = keyBlob("ssh-ed25519", "ipv6-key");
    stubs.runArgs.fn = (cmd, args) =>
      cmd === "ssh-keygen" && args[1] === "::1"
        ? { stdout: keygenOutput("::1", [{ type: "ssh-ed25519", blob }]), ok: true }
        : { stdout: "", ok: false };

    const keys = readKnownHostsKeys("::1");
    expect(keys).toHaveLength(1);
    expect(keys[0].equals(blob)).toBe(true);
    expect(stubs.runArgsCalls.some((c) => c.cmd === "ssh-keygen")).toBe(true);
  });
});

describe("resolveConfig with a bracketed IPv6 host", () => {
  function stubIpv6SshConfig() {
    stubs.runArgs.fn = (cmd, args) => {
      if (cmd === "ssh") {
        // Matches the real probe: `ssh -G '[::1]'` answers `hostname ::1`.
        return { stdout: sshConfigOutput({ user: "tester", hostname: "::1", port: "22" }), ok: true };
      }
      if (cmd === "ssh-keygen" && args[1] === "::1") {
        return {
          stdout: keygenOutput("::1", [{ type: "ssh-ed25519", blob: keyBlob("ssh-ed25519", "k") }]),
          ok: true,
        };
      }
      return { stdout: "", ok: false };
    };
  }

  it("resolves to the bare host and never builds a double-bracketed known_hosts target", () => {
    stubIpv6SshConfig();
    const resolved = resolveConfig({ host: "[::1]" });
    expect(resolved.connectConfig.host).toBe("::1");
    expect(typeof resolved.connectConfig.hostVerifier).toBe("function");

    // known_hosts is read on the dial path now, not during resolveConfig -- run the
    // thunk connectWithProxy would run so there are lookups to inspect.
    resolved.applyHostKeyAlgorithms?.();
    const keygenTargets = stubs.runArgsCalls.filter((c) => c.cmd === "ssh-keygen").map((c) => c.args[1]);
    expect(keygenTargets.length).toBeGreaterThan(0);
    for (const t of keygenTargets) expect(t).toBe("::1");
  });

  it("dedupes '[::1]' against the '::1' ssh -G resolves it to, so lookups do not double", () => {
    stubIpv6SshConfig();
    const resolved = resolveConfig({ host: "[::1]" });
    const verify = resolved.connectConfig.hostVerifier as (key: Buffer) => boolean;
    stubs.runArgsCalls.length = 0;
    verify(keyBlob("ssh-ed25519", "k"));
    // One canonical host -> exactly one ssh-keygen lookup, not one per spelling.
    expect(stubs.runArgsCalls.filter((c) => c.cmd === "ssh-keygen")).toHaveLength(1);
  });

  it("matches the known_hosts entry recorded under the bare IPv6 form", () => {
    stubIpv6SshConfig();
    const resolved = resolveConfig({ host: "[::1]" });
    const verify = resolved.connectConfig.hostVerifier as (key: Buffer) => boolean;
    expect(verify(keyBlob("ssh-ed25519", "k"))).toBe(true);
    expect(resolved.hostKeyRejection?.current).toBeNull();
  });
});

// ---------------------------------------------------------------- finding 7

describe("hostKeyBlobType", () => {
  it("reads the algorithm name out of a well-formed blob", () => {
    expect(hostKeyBlobType(keyBlob("ssh-ed25519", "body"))).toBe("ssh-ed25519");
    expect(hostKeyBlobType(keyBlob("ecdsa-sha2-nistp256", "body"))).toBe("ecdsa-sha2-nistp256");
    expect(hostKeyBlobType(keyBlob("rsa-sha2-512@example.com", "body"))).toBe("rsa-sha2-512@example.com");
  });

  it("returns null rather than garbage for blobs that are not key-shaped", () => {
    expect(hostKeyBlobType(Buffer.alloc(0))).toBeNull();
    expect(hostKeyBlobType(Buffer.from("ab"))).toBeNull();
    // Length field larger than the buffer.
    const truncated = Buffer.alloc(8);
    truncated.writeUInt32BE(99, 0);
    expect(hostKeyBlobType(truncated)).toBeNull();
    // Zero-length name.
    expect(hostKeyBlobType(Buffer.alloc(8))).toBeNull();
    // Name with bytes outside the algorithm-name charset.
    expect(hostKeyBlobType(keyBlob("bad name!", "x"))).toBeNull();
  });
});

describe("hostKeyAlgorithmOrder", () => {
  it("puts the algorithm we hold a known_hosts entry for first", () => {
    const order = hostKeyAlgorithmOrder(["ecdsa-sha2-nistp256"]);
    expect(order).not.toBeNull();
    expect((order as string[])[0]).toBe("ecdsa-sha2-nistp256");
  });

  it("is a PERMUTATION of the defaults -- it never removes a negotiable algorithm", () => {
    const ecdsaFirst = hostKeyAlgorithmOrder(["ecdsa-sha2-nistp256"]) as string[];
    const ed25519First = hostKeyAlgorithmOrder(["ssh-ed25519"]) as string[];
    expect(ecdsaFirst).not.toBeNull();
    expect(ed25519First).not.toBeNull();
    // Same multiset, different order -- which is exactly "prefer, never restrict".
    expect([...ecdsaFirst].sort()).toEqual([...ed25519First].sort());
    expect(new Set(ecdsaFirst).size).toBe(ecdsaFirst.length);
    expect(ecdsaFirst[0]).not.toBe(ed25519First[0]);
    // ed25519 is still offered even when known_hosts only knows ecdsa -- the whole
    // point: ordering must not turn a valid host into an unconnectable one.
    expect(ecdsaFirst).toContain("ssh-ed25519");
  });

  it("expands an ssh-rsa known_hosts entry to the RFC 8332 signature algorithms", () => {
    const order = hostKeyAlgorithmOrder(["ssh-rsa"]) as string[];
    expect(order).not.toBeNull();
    expect(order.slice(0, 3)).toEqual(["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]);
  });

  it("never introduces ssh-dss, which ssh2 disables by default", () => {
    for (const types of [["ssh-ed25519"], ["ssh-rsa"], ["ecdsa-sha2-nistp521"], ["ssh-dss"]]) {
      const order = hostKeyAlgorithmOrder(types);
      if (order) expect(order).not.toContain("ssh-dss");
    }
  });

  it("returns null when there is nothing to reorder", () => {
    expect(hostKeyAlgorithmOrder([])).toBeNull();
    // A type outside ssh2's default list moves nothing to the front.
    expect(hostKeyAlgorithmOrder(["ssh-dss"])).toBeNull();
    expect(hostKeyAlgorithmOrder(["some-future-algo"])).toBeNull();
  });

  it("orders multiple known types together, ahead of everything else", () => {
    const order = hostKeyAlgorithmOrder(["ecdsa-sha2-nistp256", "ssh-rsa"]) as string[];
    expect(order).not.toBeNull();
    const front = new Set(["ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]);
    for (let i = 0; i < front.size; i++) expect(front.has(order[i])).toBe(true);
    expect(front.has(order[front.size])).toBe(false);
  });
});

describe("host-key algorithm preference is computed on the DIAL path only", () => {
  const HOST = "prefers-ecdsa.test";
  const ECDSA = { type: "ecdsa-sha2-nistp256", blob: keyBlob("ecdsa-sha2-nistp256", "k") };

  function serverHostKeyOf(cc: any): string[] | undefined {
    return cc.algorithms?.serverHostKey as string[] | undefined;
  }

  it("resolveConfig spawns no ssh-keygen and leaves algorithms unset", () => {
    // The regression this guards: computing the order eagerly here charged EVERY
    // pool acquire 1-4 `ssh-keygen -F` spawns (~235ms each) for a value only a real
    // dial ever reads -- and a warm pooled connection never dials.
    stubKnownHostsFor(HOST, [ECDSA]);
    const resolved = resolveConfig({ host: HOST });
    expect(keygenSpawns()).toEqual([]);
    expect(resolved.connectConfig.algorithms).toBeUndefined();
  });

  it("prefers the ecdsa algorithm once the dial materializes the order", () => {
    stubKnownHostsFor(HOST, [ECDSA]);
    const resolved = resolveConfig({ host: HOST });
    resolved.applyHostKeyAlgorithms?.();

    const serverHostKey = serverHostKeyOf(resolved.connectConfig);
    expect(serverHostKey).toBeDefined();
    expect((serverHostKey as string[])[0]).toBe("ecdsa-sha2-nistp256");
    expect(serverHostKey).toContain("ssh-ed25519");
    expect(keygenSpawns()).toContain(HOST);
  });

  it("is idempotent, so a pool retry on one resolved does not re-read known_hosts", () => {
    stubKnownHostsFor(HOST, [ECDSA]);
    const resolved = resolveConfig({ host: HOST });
    resolved.applyHostKeyAlgorithms?.();
    const first = keygenSpawns().length;
    expect(first).toBeGreaterThan(0);

    clearKnownHostTypeCache(); // even with the TTL memo gone, the thunk is one-shot
    resolved.applyHostKeyAlgorithms?.();
    expect(keygenSpawns()).toHaveLength(first);
  });

  it("connectWithProxy applies it, so the socket still gets the preferred order", async () => {
    stubKnownHostsFor(HOST, [ECDSA]);
    const client = await connect({ host: HOST });
    client.end();

    expect(stubs.dials).toHaveLength(1);
    expect(serverHostKeyOf(stubs.dials[0])?.[0]).toBe("ecdsa-sha2-nistp256");
  });

  it("leaves algorithms unset when the host is not in known_hosts", () => {
    const resolved = resolveConfig({ host: "not-in-known-hosts.test" });
    resolved.applyHostKeyAlgorithms?.();
    expect(resolved.connectConfig.algorithms).toBeUndefined();
  });
});

describe("a warm-pool acquire does no work the connection cannot use", () => {
  const HOST = "warm-acquire.test";

  it("spawns ZERO subprocesses when acquire() hits an already-pooled connection", async () => {
    stubKnownHostsFor(HOST, [{ type: "ecdsa-sha2-nistp256", blob: keyBlob("ecdsa-sha2-nistp256", "k") }]);
    const pool = new ConnectionPool();
    try {
      const c1 = await pool.acquire({ host: HOST });
      // The cold acquire dialed, and that dial DID carry the preference order.
      expect(stubs.dials).toHaveLength(1);
      expect(stubs.dials[0].algorithms?.serverHostKey?.[0]).toBe("ecdsa-sha2-nistp256");
      pool.release(c1); // idle, still pooled

      // Drop BOTH memos' worth of protection: the point is that the warm path never
      // asks the question, not that a cache happened to be holding the answer. (The
      // known-host TTL is 5s, so any tool-call cadence slower than that re-paid it.)
      clearKnownHostTypeCache();
      stubs.runArgsCalls.length = 0;

      const c2 = await pool.acquire({ host: HOST });
      expect(c2).toBe(c1);
      expect(stubs.dials).toHaveLength(1); // reused, not redialed
      expect(stubs.runArgsCalls).toEqual([]); // no ssh-keygen, no `ssh -G`, nothing
      pool.release(c2);
    } finally {
      pool.drain();
    }
  });
});

describe("hostVerifier rejection reasons", () => {
  const HOST = "verifier-host.test";

  function stubKnownHosts(entries: Array<{ type: string; blob: Buffer }>) {
    stubs.runArgs.fn = (cmd, args) =>
      cmd === "ssh-keygen" && args[1] === HOST
        ? { stdout: keygenOutput(HOST, entries), ok: true }
        : { stdout: "", ok: false };
  }

  function verifierFor(host = HOST) {
    const resolved = resolveConfig({ host });
    return {
      resolved,
      verify: resolved.connectConfig.hostVerifier as (key: Buffer) => boolean,
    };
  }

  it("distinguishes 'no entry for the offered algorithm' from a MITM", () => {
    // known_hosts has ONLY ecdsa; the server offers ed25519. OpenSSH would have
    // negotiated ecdsa; ssh2 may not, and the old code called this a mismatch.
    stubKnownHosts([{ type: "ecdsa-sha2-nistp256", blob: keyBlob("ecdsa-sha2-nistp256", "known") }]);
    const { resolved, verify } = verifierFor();
    expect(verify(keyBlob("ssh-ed25519", "offered"))).toBe(false);

    const rejection = resolved.hostKeyRejection?.current;
    expect(rejection?.reason).toBe("algorithm-not-in-known-hosts");
    expect(rejection?.message).toContain("ssh-ed25519");
    expect(rejection?.message).toContain("ecdsa-sha2-nistp256");
    expect(rejection?.message).toContain("NOT a key mismatch");
    expect(rejection?.message).not.toContain("man-in-the-middle");
  });

  it("reports a genuine same-algorithm mismatch as a possible MITM", () => {
    stubKnownHosts([{ type: "ssh-ed25519", blob: keyBlob("ssh-ed25519", "the-real-key") }]);
    const { resolved, verify } = verifierFor();
    expect(verify(keyBlob("ssh-ed25519", "an-imposter-key"))).toBe(false);

    const rejection = resolved.hostKeyRejection?.current;
    expect(rejection?.reason).toBe("key-mismatch");
    expect(rejection?.message).toContain("man-in-the-middle");
    expect(rejection?.message).toContain("ssh-keygen -R");
  });

  it("accepts a matching key and records no rejection", () => {
    const blob = keyBlob("ssh-ed25519", "the-real-key");
    stubKnownHosts([{ type: "ssh-ed25519", blob }]);
    const { resolved, verify } = verifierFor();
    expect(verify(blob)).toBe(true);
    expect(resolved.hostKeyRejection?.current).toBeNull();
  });

  it("matches when known_hosts holds several types and one of them is the offered key", () => {
    const ed = keyBlob("ssh-ed25519", "ed-key");
    stubKnownHosts([
      { type: "ecdsa-sha2-nistp256", blob: keyBlob("ecdsa-sha2-nistp256", "ecdsa-key") },
      { type: "ssh-ed25519", blob: ed },
    ]);
    const { resolved, verify } = verifierFor();
    expect(verify(ed)).toBe(true);
    expect(resolved.hostKeyRejection?.current).toBeNull();
  });

  it("clears a previous rejection when a later key verifies", () => {
    const blob = keyBlob("ssh-ed25519", "the-real-key");
    stubKnownHosts([{ type: "ssh-ed25519", blob }]);
    const { resolved, verify } = verifierFor();
    expect(verify(keyBlob("ssh-ed25519", "wrong"))).toBe(false);
    expect(resolved.hostKeyRejection?.current?.reason).toBe("key-mismatch");
    expect(verify(blob)).toBe(true);
    expect(resolved.hostKeyRejection?.current).toBeNull();
  });

  it("records a reason for an unknown host only under SSH_MCP_STRICT_HOST_KEY=1", () => {
    const lenient = verifierFor("unknown-host.test");
    expect(lenient.verify(keyBlob("ssh-ed25519", "x"))).toBe(true);
    expect(lenient.resolved.hostKeyRejection?.current).toBeNull();

    vi.stubEnv("SSH_MCP_STRICT_HOST_KEY", "1");
    clearSshConfigCache();
    clearKnownHostTypeCache();
    const strict = verifierFor("unknown-host.test");
    expect(strict.verify(keyBlob("ssh-ed25519", "x"))).toBe(false);
    expect(strict.resolved.hostKeyRejection?.current?.reason).toBe("unknown-host-strict");
    expect(strict.resolved.hostKeyRejection?.current?.message).toContain("ssh-keyscan");
  });
});

describe("rejection remediation commands are pasteable for an IPv6 host", () => {
  // ssh-keyscan and `ssh-keygen -R` have the same bracket sensitivity as `-F`:
  // probed on OpenSSH 10.2p1, `ssh-keygen -R '[::1]'` prints "Host [::1] not found"
  // and removes NOTHING, while `-R '::1'` removes the entry. The verifier's hosts
  // keep the caller's own spelling, so a caller who passed `[::1]` was handed a
  // command that silently no-ops -- worse than no advice, since it looks like it ran.
  function ipv6Verifier() {
    stubs.runArgs.fn = (cmd, args) => {
      if (cmd === "ssh") return { stdout: sshConfigOutput({ user: "t", hostname: "::1", port: "22" }), ok: true };
      if (cmd === "ssh-keygen" && args[1] === "::1") {
        return {
          stdout: keygenOutput("::1", [{ type: "ecdsa-sha2-nistp256", blob: keyBlob("ecdsa-sha2-nistp256", "known") }]),
          ok: true,
        };
      }
      return { stdout: "", ok: false };
    };
    const resolved = resolveConfig({ host: "[::1]" });
    return { resolved, verify: resolved.connectConfig.hostVerifier as (key: Buffer) => boolean };
  }

  it("unbrackets the host in the ssh-keyscan refresh command", () => {
    const { resolved, verify } = ipv6Verifier();
    expect(verify(keyBlob("ssh-ed25519", "offered"))).toBe(false);

    const message = resolved.hostKeyRejection?.current?.message ?? "";
    expect(resolved.hostKeyRejection?.current?.reason).toBe("algorithm-not-in-known-hosts");
    expect(message).toContain('ssh-keyscan -H "::1"');
    expect(message).not.toContain('ssh-keyscan -H "[::1]"');
  });

  it("unbrackets the host in the ssh-keygen -R removal command", () => {
    const { resolved, verify } = ipv6Verifier();
    expect(verify(keyBlob("ecdsa-sha2-nistp256", "imposter"))).toBe(false);

    const message = resolved.hostKeyRejection?.current?.message ?? "";
    expect(resolved.hostKeyRejection?.current?.reason).toBe("key-mismatch");
    expect(message).toContain('ssh-keygen -R "::1"');
    expect(message).not.toContain('ssh-keygen -R "[::1]"');
  });

  it("unbrackets the host in the strict-mode 'add an entry' command", () => {
    vi.stubEnv("SSH_MCP_STRICT_HOST_KEY", "1");
    stubs.runArgs.fn = (cmd) =>
      cmd === "ssh"
        ? { stdout: sshConfigOutput({ hostname: "::1", port: "22" }), ok: true }
        : { stdout: "", ok: false };

    const resolved = resolveConfig({ host: "[::1]" });
    const verify = resolved.connectConfig.hostVerifier as (key: Buffer) => boolean;
    expect(verify(keyBlob("ssh-ed25519", "x"))).toBe(false);

    const message = resolved.hostKeyRejection?.current?.message ?? "";
    expect(message).toContain('ssh-keyscan -H "::1"');
    expect(message).not.toContain('ssh-keyscan -H "[::1]"');
  });

  it("leaves a plain hostname exactly as the caller spelled it", () => {
    stubs.runArgs.fn = (cmd, args) =>
      cmd === "ssh-keygen" && args[1] === "plain.test"
        ? {
            stdout: keygenOutput("plain.test", [
              { type: "ecdsa-sha2-nistp256", blob: keyBlob("ecdsa-sha2-nistp256", "known") },
            ]),
            ok: true,
          }
        : { stdout: "", ok: false };

    const resolved = resolveConfig({ host: "plain.test" });
    const verify = resolved.connectConfig.hostVerifier as (key: Buffer) => boolean;
    expect(verify(keyBlob("ssh-ed25519", "offered"))).toBe(false);
    expect(resolved.hostKeyRejection?.current?.message).toContain('ssh-keyscan -H "plain.test"');
  });
});

// ---------------------------------------------------------------- finding 3

describe("diagnostics cover config resolution, not just the connect", () => {
  const BAD_KEY = "/definitely/not/a/real/key/path/id_ed25519";

  beforeEach(() => {
    // Make formatDiagnostics() produce output deterministically.
    stubs.knownHostsCheck = { status: "warning", message: "TEST-DIAG-MARKER" };
  });

  it("connect() attaches diagnostics when resolveConfig throws on a bad privateKeyPath", async () => {
    // Regression: resolveConfig ran OUTSIDE the try, so this surfaced as a bare
    // readFileSync ENOENT with none of the auto-diagnostics this server advertises.
    await expect(connect({ host: "diag-connect.test", privateKeyPath: BAD_KEY })).rejects.toThrow(/TEST-DIAG-MARKER/);
    await expect(connect({ host: "diag-connect.test", privateKeyPath: BAD_KEY })).rejects.toThrow(/ENOENT/);
  });

  it("pool.acquire() attaches diagnostics on the same failure", async () => {
    const pool = new ConnectionPool();
    try {
      await expect(pool.acquire({ host: "diag-pool.test", privateKeyPath: BAD_KEY })).rejects.toThrow(
        /TEST-DIAG-MARKER/,
      );
    } finally {
      pool.drain();
    }
  });

  it("keeps the original error as `cause` so the raw failure is not lost", async () => {
    const err = await connect({ host: "diag-cause.test", privateKeyPath: BAD_KEY }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).cause).toBeInstanceOf(Error);
    expect(((err as Error).cause as Error).message).toMatch(/ENOENT/);
  });
});

describe("enhanceSshError", () => {
  it("returns the original error untouched when there is nothing to add", () => {
    stubs.knownHostsCheck = { status: "ok", message: "ok" };
    const original = new Error("boom");
    expect(enhanceSshError(original, "quiet.test")).toBe(original);
  });

  it("folds the host-key rejection reason in ahead of the diagnostics", () => {
    stubs.knownHostsCheck = { status: "warning", message: "TEST-DIAG-MARKER" };
    const resolved = {
      connectConfig: {},
      hostKeyRejection: {
        current: { reason: "key-mismatch" as const, message: "TEST-REJECTION-DETAIL" },
      },
    };
    const enhanced = enhanceSshError(new Error("Host denied (verification failed)"), "x.test", resolved);
    expect(enhanced).toBeInstanceOf(Error);
    const message = (enhanced as Error).message;
    expect(message).toContain("Host denied (verification failed)");
    expect(message).toContain("TEST-REJECTION-DETAIL");
    expect(message).toContain("TEST-DIAG-MARKER");
    expect(message.indexOf("TEST-REJECTION-DETAIL")).toBeLessThan(message.indexOf("TEST-DIAG-MARKER"));
  });

  it("handles a non-Error rejection value", () => {
    stubs.knownHostsCheck = { status: "warning", message: "TEST-DIAG-MARKER" };
    const enhanced = enhanceSshError("plain string failure", "x.test");
    expect((enhanced as Error).message).toContain("plain string failure");
  });
});

describe("a host-key rejection on the JUMP host is not swallowed", () => {
  const TARGET = "behind-bastion.test";
  const BASTION = "bastion.test";

  beforeEach(() => {
    // ssh_config sends TARGET through BASTION; known_hosts holds an ecdsa line for
    // the bastion, and the bastion offers ed25519 -- the algorithm-not-in-known_hosts
    // case, which is precisely the one ssh2 reports as an opaque "Host denied".
    stubs.runArgs.fn = (cmd, args) => {
      if (cmd === "ssh") {
        if (args[1] === TARGET) {
          return { stdout: sshConfigOutput({ hostname: TARGET, user: "t", port: "22", proxyjump: BASTION }), ok: true };
        }
        if (args[1] === BASTION) {
          return { stdout: sshConfigOutput({ hostname: BASTION, user: "t", port: "22" }), ok: true };
        }
      }
      if (cmd === "ssh-keygen" && args[1] === BASTION) {
        return {
          stdout: keygenOutput(BASTION, [
            { type: "ecdsa-sha2-nistp256", blob: keyBlob("ecdsa-sha2-nistp256", "bastion-known") },
          ]),
          ok: true,
        };
      }
      return { stdout: "", ok: false };
    };
    stubs.dialScript.set(BASTION, { hostKey: keyBlob("ssh-ed25519", "bastion-offered") });
  });

  it("connect() reports WHY the bastion turned us down, not just 'Host denied'", async () => {
    // The bug: connectWithProxy resolved the jump host into a local ResolvedConfig,
    // so the reason its verifier recorded died with that object -- connect() hands
    // enhanceSshError the TARGET's resolved, whose verifier never ran.
    const err = await connect({ host: TARGET }).catch((e: unknown) => e);
    const message = (err as Error).message;

    expect(message).toContain("Host denied (verification failed)"); // ssh2's own text, kept
    expect(message).toContain(`on jump host ${BASTION}`);
    expect(message).toContain("ssh-ed25519");
    expect(message).toContain("ecdsa-sha2-nistp256");
    expect(message).toContain("NOT a key mismatch");
    // Only the bastion was ever dialed; the target is never reached.
    expect(stubs.dials.map((d) => d.host)).toEqual([BASTION]);
  });

  it("pool.acquire() surfaces the same jump-host reason", async () => {
    const pool = new ConnectionPool();
    try {
      const err = await pool.acquire({ host: TARGET }).catch((e: unknown) => e);
      expect((err as Error).message).toContain(`on jump host ${BASTION}`);
      expect((err as Error).message).toContain("NOT a key mismatch");
    } finally {
      pool.drain();
    }
  });

  it("says nothing about a jump host when the bastion fails for an unrelated reason", async () => {
    stubs.dialScript.set(BASTION, { error: new Error("ECONNREFUSED 10.0.0.9:22") });
    const err = await connect({ host: TARGET }).catch((e: unknown) => e);
    expect((err as Error).message).toContain("ECONNREFUSED");
    expect((err as Error).message).not.toContain("on jump host");
  });
});

describe("concurrent acquires on one coalesced dial report one reason", () => {
  const HOST = "coalesced-reject.test";

  it("gives every waiter the specific host-key reason, not just the first caller", async () => {
    // The bug: each acquire built its own ResolvedConfig, but only the FIRST one's
    // hostVerifier ever ran (the others awaited its promise). Waiters then asked
    // enhanceSshError to read THEIR rejection side channel, which was still null, so
    // N-1 callers got generic environment diagnostics for a rejection the pool had
    // already diagnosed precisely -- same failure, different story per caller.
    stubKnownHostsFor(HOST, [{ type: "ecdsa-sha2-nistp256", blob: keyBlob("ecdsa-sha2-nistp256", "known") }]);
    stubs.dialScript.set(HOST, { hostKey: keyBlob("ssh-ed25519", "offered") });

    const pool = new ConnectionPool();
    try {
      const messages = await Promise.all(
        Array.from({ length: 10 }, () =>
          pool.acquire({ host: HOST }).then(
            () => "unexpectedly connected",
            (e: Error) => e.message,
          ),
        ),
      );

      expect(stubs.dials).toHaveLength(1); // one dial, so there is only one reason to tell
      for (const message of messages) {
        expect(message).toContain("Host key check failed");
        expect(message).toContain("NOT a key mismatch");
        expect(message).toContain("ssh-ed25519");
      }
      expect(new Set(messages).size).toBe(1); // and every waiter gets it verbatim
    } finally {
      pool.drain();
    }
  });
});

// ---------------------------------------------------------------- finding 12

/** A fake exec stream that never closes on its own, so the timeout path is exercised. */
function hangingStream(): any {
  const stream: any = new EventEmitter();
  stream.stderr = new EventEmitter();
  stream.closed = 0;
  stream.signalled = [] as string[];
  stream.signal = (sig: string) => stream.signalled.push(sig);
  stream.close = () => {
    stream.closed++;
  };
  return stream;
}

describe("exec timeout releases the capture", () => {
  it("detaches both data listeners when the timeout fires", async () => {
    const stream = hangingStream();
    const client: any = { exec: (_cmd: string, cb: any) => cb(null, stream) };

    stream.emit("data", Buffer.from("some output before the timeout"));
    await expect(exec(client, "sleep 100", 15)).rejects.toThrow(/timed out after 15ms/);

    expect(stream.listenerCount("data")).toBe(0);
    expect(stream.stderr.listenerCount("data")).toBe(0);
    // The channel was still torn down -- the timeout path's other job.
    expect(stream.closed).toBe(1);
    expect(stream.signalled).toEqual(["TERM"]);
  });

  it("keeps the error listeners attached so a late stream error cannot throw", async () => {
    const stream = hangingStream();
    const client: any = { exec: (_cmd: string, cb: any) => cb(null, stream) };
    await expect(exec(client, "sleep 100", 15)).rejects.toThrow(/timed out/);

    expect(stream.listenerCount("error")).toBeGreaterThan(0);
    expect(stream.stderr.listenerCount("error")).toBeGreaterThan(0);
    // An unhandled "error" on an EventEmitter with no listener would throw here.
    expect(() => stream.emit("error", new Error("late failure"))).not.toThrow();
    expect(() => stream.stderr.emit("error", new Error("late failure"))).not.toThrow();
  });

  it("ignores data that arrives after the timeout instead of buffering it", async () => {
    const stream = hangingStream();
    const client: any = { exec: (_cmd: string, cb: any) => cb(null, stream) };
    await expect(exec(client, "chatty", 15)).rejects.toThrow(/timed out/);

    // A chatty command draining in the background must not be able to keep appending.
    expect(() => {
      stream.emit("data", Buffer.alloc(1024, 0x61));
      stream.stderr.emit("data", Buffer.alloc(1024, 0x62));
    }).not.toThrow();
    expect(stream.listenerCount("data")).toBe(0);
    expect(stream.stderr.listenerCount("data")).toBe(0);
  });

  it("releases and tears down even when exec calls back AFTER the timeout fired", async () => {
    const stream = hangingStream();
    const client: any = {
      exec: (_cmd: string, cb: any) => {
        setTimeout(() => cb(null, stream), 40);
      },
    };
    await expect(exec(client, "slow-to-open", 10)).rejects.toThrow(/timed out after 10ms/);
    // Give the late callback time to land.
    await new Promise((r) => setTimeout(r, 60));
    expect(stream.listenerCount("data")).toBe(0);
    expect(stream.stderr.listenerCount("data")).toBe(0);
    expect(stream.closed).toBe(1);
  });

  it("leaves the resolve path's exit-code and signal semantics untouched", async () => {
    const streamFor = (code: number | null, signal?: string) => ({
      exec: (_cmd: string, cb: any) => {
        const stream: any = new EventEmitter();
        stream.stderr = new EventEmitter();
        stream.signal = () => {};
        stream.close = () => {};
        cb(null, stream);
        queueMicrotask(() => {
          stream.emit("data", Buffer.from("out"));
          stream.stderr.emit("data", Buffer.from("err"));
          stream.emit("close", code, signal);
        });
      },
    });

    const ok = await exec(streamFor(0) as any, "true", 5000);
    expect(ok).toMatchObject({ stdout: "out", stderr: "err", code: 0 });
    expect(ok.signal).toBeUndefined();

    const signaled = await exec(streamFor(null, "TERM") as any, "killed", 5000);
    expect(signaled.code).toBe(-1);
    expect(signaled.signal).toBe("TERM");
    expect(signaled.stdout).toBe("out");
  });
});

// ---------------------------------------------------------------- ProxyJump parsing

describe("parseJumpSpec", () => {
  // `ssh -G` prints the ProxyJump value VERBATIM -- probed on OpenSSH 10.2p1, a
  // config line `ProxyJump jeff@bastion.example.com:2222` comes back as exactly that
  // string. Every form below therefore has to be split apart here; re-resolving the
  // raw string as a hostname (what this replaced) mangled all but the first.
  it("parses a plain host", () => {
    expect(parseJumpSpec("bastion.example.com")).toEqual([{ host: "bastion.example.com" }]);
  });

  it("splits a trailing :port instead of swallowing it into the hostname", () => {
    expect(parseJumpSpec("bastion.example.com:2222")).toEqual([{ host: "bastion.example.com", port: 2222 }]);
  });

  it("splits the login at the LAST @", () => {
    expect(parseJumpSpec("jeff@bastion.example.com")).toEqual([{ host: "bastion.example.com", username: "jeff" }]);
    // A user part that itself contains an @ keeps the trailing host.
    expect(parseJumpSpec("jeff@corp@bastion.example.com")).toEqual([
      { host: "bastion.example.com", username: "jeff@corp" },
    ]);
  });

  it("parses user@host:port -- form (a)", () => {
    expect(parseJumpSpec("jeff@bastion.example.com:2222")).toEqual([
      { host: "bastion.example.com", port: 2222, username: "jeff" },
    ]);
  });

  it("splits a multi-hop comma list in visit order -- form (b)", () => {
    expect(parseJumpSpec("first.example.com:2201,second.example.com:2202")).toEqual([
      { host: "first.example.com", port: 2201 },
      { host: "second.example.com", port: 2202 },
    ]);
  });

  it("strips IPv6 brackets BEFORE looking for a port -- form (c)", () => {
    // The worst of the three: this used to yield host "2001:db8::1" and port 22, i.e.
    // a silent connection to the WRONG PORT rather than a visible failure.
    expect(parseJumpSpec("[2001:db8::1]:2222")).toEqual([{ host: "2001:db8::1", port: 2222 }]);
    expect(parseJumpSpec("[2001:db8::1]")).toEqual([{ host: "2001:db8::1" }]);
    expect(parseJumpSpec("jeff@[2001:db8::1]:2222")).toEqual([{ host: "2001:db8::1", port: 2222, username: "jeff" }]);
  });

  it("never splits a port out of a BARE IPv6 literal", () => {
    // Unbracketed, every colon belongs to the address -- a port there requires brackets.
    expect(parseJumpSpec("2001:db8::1")).toEqual([{ host: "2001:db8::1" }]);
    expect(parseJumpSpec("::1")).toEqual([{ host: "::1" }]);
  });

  it("leaves a :suffix that is not a valid port as part of the host, so a typo fails loudly", () => {
    expect(parseJumpSpec("bastion.example.com:notaport")).toEqual([{ host: "bastion.example.com:notaport" }]);
    expect(parseJumpSpec("bastion.example.com:99999")).toEqual([{ host: "bastion.example.com:99999" }]);
    expect(parseJumpSpec("bastion.example.com:0")).toEqual([{ host: "bastion.example.com:0" }]);
    // Bracketed form: the address is unambiguous, so only the bad port is dropped.
    expect(parseJumpSpec("[::1]:abc")).toEqual([{ host: "::1" }]);
  });

  it("accepts the ssh:// URI spelling ssh_config also allows", () => {
    expect(parseJumpSpec("ssh://jeff@bastion.example.com:2222")).toEqual([
      { host: "bastion.example.com", port: 2222, username: "jeff" },
    ]);
  });

  it("ignores whitespace and empty pieces, and yields nothing for an empty spec", () => {
    expect(parseJumpSpec(" first.example.com , second.example.com ")).toEqual([
      { host: "first.example.com" },
      { host: "second.example.com" },
    ]);
    expect(parseJumpSpec("")).toEqual([]);
    expect(parseJumpSpec("  ")).toEqual([]);
    expect(parseJumpSpec(",,")).toEqual([]);
  });

  it("round-trips through formatJumpHop, which is what lets a chain be re-parsed", () => {
    for (const spec of [
      "bastion.example.com",
      "bastion.example.com:2222",
      "jeff@bastion.example.com",
      "jeff@bastion.example.com:2222",
      "[2001:db8::1]",
      "[2001:db8::1]:2222",
      "jeff@[2001:db8::1]:2222",
    ]) {
      const hops = parseJumpSpec(spec);
      expect(hops).toHaveLength(1);
      expect(formatJumpHop(hops[0])).toBe(spec);
    }
    // A bare IPv6 literal comes back bracketed -- a different spelling of the same hop,
    // and the one that keeps a port unambiguous. It must still parse back identically.
    const bare = parseJumpSpec("2001:db8::1")[0];
    expect(formatJumpHop(bare)).toBe("[2001:db8::1]");
    expect(parseJumpSpec(formatJumpHop(bare))).toEqual([bare]);
  });
});

/** Script `ssh -G <host>` and `ssh-keygen -F <target>` per host for a whole topology. */
function stubSshEnvironment(opts: {
  sshConfig: Record<string, Record<string, string>>;
  knownHosts?: Record<string, Array<{ type: string; blob: Buffer }>>;
}) {
  stubs.runArgs.fn = (cmd, args) => {
    const target = args[1];
    if (cmd === "ssh") {
      const fields = opts.sshConfig[target];
      return fields ? { stdout: sshConfigOutput(fields), ok: true } : { stdout: "", ok: false };
    }
    if (cmd === "ssh-keygen") {
      const entries = opts.knownHosts?.[target];
      return entries ? { stdout: keygenOutput(target, entries), ok: true } : { stdout: "", ok: false };
    }
    return { stdout: "", ok: false };
  };
}

describe("connectWithProxy parses the ProxyJump spec instead of re-resolving it as a host", () => {
  const TARGET = "behind-jump.test";

  it("dials user@host:port on the parsed host, port and login", async () => {
    stubSshEnvironment({
      sshConfig: {
        [TARGET]: { hostname: TARGET, user: "target-user", port: "22", proxyjump: "jeff@bastion.example.com:2222" },
        "bastion.example.com": { hostname: "bastion.example.com", user: "config-user", port: "22" },
      },
    });

    const client = await connect({ host: TARGET });
    client.end();

    expect(stubs.dials).toHaveLength(2);
    const [jump, target] = stubs.dials;
    // Was: host "bastion.example.com:2222" on port 22, so DNS failed before a byte
    // was sent. The port and the login only survive as SEPARATE resolveConfig fields.
    expect(jump.host).toBe("bastion.example.com");
    expect(jump.port).toBe(2222);
    expect(jump.username).toBe("jeff"); // spec login beats ssh_config's User
    expect(jump.sock).toBeUndefined(); // dialed directly
    expect(target.host).toBe(TARGET);
    expect(target.sock).toBeDefined(); // reached through the jump host
  });

  it("falls back to the hop's own ssh_config for a field the spec omits", async () => {
    stubSshEnvironment({
      sshConfig: {
        [TARGET]: { hostname: TARGET, port: "22", proxyjump: "bastion.example.com" },
        "bastion.example.com": { hostname: "real-bastion.internal", user: "config-user", port: "2022" },
      },
    });

    const client = await connect({ host: TARGET });
    client.end();

    expect(stubs.dials[0].host).toBe("real-bastion.internal");
    expect(stubs.dials[0].port).toBe(2022);
    expect(stubs.dials[0].username).toBe("config-user");
  });

  it("strips IPv6 brackets before the port instead of dialing port 22 silently", async () => {
    stubSshEnvironment({
      sshConfig: {
        [TARGET]: { hostname: TARGET, port: "22", proxyjump: "[2001:db8::1]:2222" },
        "2001:db8::1": { hostname: "2001:db8::1", port: "22" },
      },
    });

    const client = await connect({ host: TARGET });
    client.end();

    expect(stubs.dials[0].host).toBe("2001:db8::1");
    expect(stubs.dials[0].port).toBe(2222); // was 22 -- connected, with no error, to the wrong port
  });

  it("chains a comma list left to right: first hop dialed directly, last one reaches the target", async () => {
    stubSshEnvironment({
      sshConfig: {
        [TARGET]: { hostname: TARGET, port: "22", proxyjump: "first.example.com:2201,second.example.com:2202" },
        "first.example.com": { hostname: "first.example.com", port: "22" },
        "second.example.com": { hostname: "second.example.com", port: "22" },
      },
    });

    const client = await connect({ host: TARGET });
    client.end();

    expect(stubs.dials.map((d) => `${d.host}:${d.port}`)).toEqual([
      "first.example.com:2201",
      "second.example.com:2202",
      `${TARGET}:22`,
    ]);
    expect(stubs.dials[0].sock).toBeUndefined(); // direct
    expect(stubs.dials[1].sock).toBeDefined(); // through the first hop
    expect(stubs.dials[2].sock).toBeDefined(); // through the last hop
  });

  it("puts the jump hop back under REAL known_hosts checking", async () => {
    // The security regression this guards: knownHostsTargets("jeff@bastion.example.com:2222")
    // failed hostname validation and returned [], so buildHostVerifier saw ZERO known
    // entries and returned !strict -- i.e. the bastion's key was accepted sight unseen
    // and the dial SUCCEEDED. Correct parsing restores the lookup, so a bastion offering
    // a key we cannot match is now turned down.
    const spec = "jeff@bastion.example.com:2222";
    stubSshEnvironment({
      sshConfig: {
        [TARGET]: { hostname: TARGET, port: "22", proxyjump: spec },
        "bastion.example.com": { hostname: "bastion.example.com", port: "22" },
      },
      knownHosts: {
        "[bastion.example.com]:2222": [{ type: "ecdsa-sha2-nistp256", blob: keyBlob("ecdsa-sha2-nistp256", "known") }],
      },
    });
    stubs.dialScript.set("bastion.example.com", { hostKey: keyBlob("ssh-ed25519", "offered") });

    const err = await connect({ host: TARGET }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(Error);
    const message = (err as Error).message;
    expect(message).toContain(`on jump host ${spec}`);
    expect(message).toContain("NOT a key mismatch");
    // The port-qualified spelling is the one `ssh-keygen -F` actually matches.
    expect(keygenSpawns()).toContain("[bastion.example.com]:2222");
    expect(stubs.dials.map((d) => d.host)).toEqual(["bastion.example.com"]); // target never reached
  });

  it("accepts the bastion when the port-qualified known_hosts entry matches", async () => {
    const blob = keyBlob("ssh-ed25519", "bastion-key");
    stubSshEnvironment({
      sshConfig: {
        [TARGET]: { hostname: TARGET, port: "22", proxyjump: "bastion.example.com:2222" },
        "bastion.example.com": { hostname: "bastion.example.com", port: "22" },
      },
      knownHosts: { "[bastion.example.com]:2222": [{ type: "ssh-ed25519", blob }] },
    });
    stubs.dialScript.set("bastion.example.com", { hostKey: blob });

    const client = await connect({ host: TARGET });
    client.end();
    expect(stubs.dials).toHaveLength(2);
  });
});

// ---------------------------------------------------------------- known_hosts markers

describe("readKnownHostsEntries skips known_hosts marker lines", () => {
  const HOST = "corp.example.com";
  const REAL = keyBlob("ssh-ed25519", "the-real-host-key");
  const CA = keyBlob("ssh-ed25519", "the-ca-key");
  const REVOKED = keyBlob("ssh-rsa", "a-revoked-key");

  /**
   * Realistic mixed `ssh-keygen -F` output. Marker lines come back VERBATIM, with the
   * marker as an extra LEADING field -- so every index shifts by one and the
   * "<host> <type> <base64>" assumption reads the host PATTERN as the key type.
   */
  function stubMixedKnownHosts() {
    stubs.runArgs.fn = (cmd, args) =>
      cmd === "ssh-keygen" && args[1] === HOST
        ? {
            stdout: [
              `# Host ${HOST} found: line 12`,
              `@cert-authority *.corp.example.com ssh-ed25519 ${CA.toString("base64")}`,
              `@revoked ${HOST} ssh-rsa ${REVOKED.toString("base64")}`,
              `${HOST} ssh-ed25519 ${REAL.toString("base64")}`,
            ].join("\n"),
            ok: true,
          }
        : { stdout: "", ok: false };
  }

  it("returns only the plain host-key line", () => {
    stubMixedKnownHosts();
    const entries = readKnownHostsEntries(HOST);
    expect(entries).toHaveLength(1);
    expect(entries[0].type).toBe("ssh-ed25519");
    expect(entries[0].key.equals(REAL)).toBe(true);
  });

  it("never stores a host PATTERN as a key type", () => {
    stubMixedKnownHosts();
    expect(readKnownHostsEntries(HOST).map((e) => e.type)).toEqual(["ssh-ed25519"]);
  });

  it("the malformed entry decoded silently, which is why the try/catch never fired", () => {
    // Pins the premise: parts[2] on the @cert-authority line is the literal string
    // "ssh-ed25519", and Node accepts "-" as base64url, so this yields 8 junk bytes
    // instead of throwing -- the junk went straight into the comparison set.
    expect(() => Buffer.from("ssh-ed25519", "base64")).not.toThrow();
    expect(Buffer.from("ssh-ed25519", "base64")).toHaveLength(8);
  });

  it("accepts the real host key and rejects both the CA key and the revoked key", () => {
    stubMixedKnownHosts();
    const resolved = resolveConfig({ host: HOST });
    const verify = resolved.connectConfig.hostVerifier as (key: Buffer) => boolean;
    expect(verify(REAL)).toBe(true);
    // A @cert-authority line holds a CA's key, not this host's; a @revoked key must
    // never be treated as valid.
    expect(verify(CA)).toBe(false);
    expect(verify(REVOKED)).toBe(false);
  });

  it("keeps the rejection message naming key TYPES, not a host pattern", () => {
    stubMixedKnownHosts();
    const resolved = resolveConfig({ host: HOST });
    const verify = resolved.connectConfig.hostVerifier as (key: Buffer) => boolean;
    expect(verify(keyBlob("ecdsa-sha2-nistp256", "offered"))).toBe(false);

    const message = resolved.hostKeyRejection?.current?.message ?? "";
    expect(message).toContain("known_hosts has only ssh-ed25519");
    // The bug's visible symptom: a message naming a host pattern where a key type
    // belongs, denying the existence of an entry it had just read.
    expect(message).not.toContain("*.corp.example.com");
  });

  it("does not let a marker-only result look like a known host", () => {
    stubs.runArgs.fn = (cmd, args) =>
      cmd === "ssh-keygen" && args[1] === "ca-only.test"
        ? { stdout: `@cert-authority *.test ssh-ed25519 ${CA.toString("base64")}`, ok: true }
        : { stdout: "", ok: false };
    expect(readKnownHostsKeys("ca-only.test")).toEqual([]);
  });
});

// ---------------------------------------------------------------- bundled algorithm list

describe("ssh2's default host-key list stays reachable from a BUNDLED build", () => {
  it("resolves ssh2's real DEFAULT_SERVER_HOST_KEY, whichever route answered", () => {
    const { DEFAULT_SERVER_HOST_KEY } = createRequire(import.meta.url)("ssh2/lib/protocol/constants.js") as {
      DEFAULT_SERVER_HOST_KEY: string[];
    };
    const order = hostKeyAlgorithmOrder(["ssh-ed25519"]);
    expect(order).not.toBeNull();
    // A permutation of ssh2's own list -- never a hardcoded copy that could drift out
    // of sync with the installed ssh2 and make connect() throw "Unsupported algorithm".
    expect([...(order as string[])].sort()).toEqual([...DEFAULT_SERVER_HOST_KEY].sort());
  });

  it("keeps a LITERAL require() specifier a bundler can follow", () => {
    // esbuild resolves a literal require() at BUILD time and inlines the constants
    // module into the SEA single-file binary; createRequire(import.meta.url) is opaque
    // to it and throws there (a SEA has no node_modules), which silently no-opped the
    // whole reorder in every Homebrew/Scoop binary. No runtime test can catch that
    // regression -- the ESM dist takes the createRequire route and works -- so pin the
    // literal itself. Verified by bundling this file's shape with esbuild in both
    // configurations: CJS/bundled inlines the module, ESM/external falls through.
    const source = readFileSync(new URL("../ssh.ts", import.meta.url), "utf8");
    expect(source).toContain('require("ssh2/lib/protocol/constants.js")');
    // ...and the literal must not be hiding behind a require the bundler cannot see.
    expect(source).not.toContain('createRequire(import.meta.url)("ssh2/lib/protocol/constants.js")');
    expect(source).not.toMatch(/(const|let|var)\s+require\s*=/);
  });
});
