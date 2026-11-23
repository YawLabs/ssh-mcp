import { execFileSync } from "node:child_process";
import { chmodSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { find, multiExec, tail } from "../ops.js";
import { ConnectionPool } from "../pool.js";
import { connect, connectWithProxy, exec, listDir, type ResolvedConfig, readFile, writeFile } from "../ssh.js";

const INTEGRATION = process.env.SSH_MCP_INTEGRATION === "1";
const TEST_HOST = "127.0.0.1";
const TEST_PORT = 2222;
const TEST_USER = "root";
// ESM-safe __dirname replacement — `__dirname` is not defined in ESM modules.
const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_KEY = join(__dirname, "../../test/docker/test_key");

const connConfig = {
  host: TEST_HOST,
  port: TEST_PORT,
  username: TEST_USER,
  privateKeyPath: TEST_KEY,
};

describe.skipIf(!INTEGRATION)("integration: SSH operations", () => {
  it("connects and runs a command", async () => {
    const client = await connect(connConfig);
    try {
      const result = await exec(client, "echo hello");
      expect(result.stdout.trim()).toBe("hello");
      expect(result.code).toBe(0);
    } finally {
      client.end();
    }
  });

  it("reads and writes files via SFTP", async () => {
    const client = await connect(connConfig);
    try {
      await writeFile(client, "/tmp/test-write.txt", "ssh-mcp test content");
      const content = await readFile(client, "/tmp/test-write.txt");
      expect(content).toBe("ssh-mcp test content");
    } finally {
      client.end();
    }
  });

  it("lists directory contents", async () => {
    const client = await connect(connConfig);
    try {
      const files = await listDir(client, "/tmp/testdir");
      expect(files).toContain("file1.txt");
      expect(files).toContain("file2.log");
      expect(files).toContain("file3.txt");
    } finally {
      client.end();
    }
  });

  it("handles command exit codes", async () => {
    const client = await connect(connConfig);
    try {
      const result = await exec(client, "exit 42");
      expect(result.code).toBe(42);
    } finally {
      client.end();
    }
  });

  it("handles command timeout", async () => {
    const client = await connect(connConfig);
    try {
      await expect(exec(client, "sleep 10", 1000)).rejects.toThrow("timed out");
    } finally {
      client.end();
    }
  });
});

describe.skipIf(!INTEGRATION)("integration: connection pool", () => {
  it("reuses connections", async () => {
    const pool = new ConnectionPool();
    try {
      const r1 = await pool.withConnection(connConfig, (client) => exec(client, "echo first"));
      expect(r1.stdout.trim()).toBe("first");
      expect(pool.size).toBe(1);

      const r2 = await pool.withConnection(connConfig, (client) => exec(client, "echo second"));
      expect(r2.stdout.trim()).toBe("second");
      expect(pool.size).toBe(1); // same connection reused
    } finally {
      pool.drain();
    }
  });

  it("reports correct stats", async () => {
    const pool = new ConnectionPool();
    try {
      await pool.withConnection(connConfig, async () => {
        expect(pool.stats.active).toBe(1);
        expect(pool.stats.idle).toBe(0);
      });
      expect(pool.stats.active).toBe(0);
      expect(pool.stats.idle).toBe(1);
    } finally {
      pool.drain();
    }
  });
});

describe.skipIf(!INTEGRATION)("integration: higher-level ops", () => {
  it("finds files remotely", async () => {
    const pool = new ConnectionPool();
    try {
      await pool.withConnection(connConfig, async (client) => {
        const files = await find(client, { path: "/tmp/testdir", name: "*.txt" });
        expect(files.length).toBe(2);
        expect(files.some((f) => f.includes("file1.txt"))).toBe(true);
        expect(files.some((f) => f.includes("file3.txt"))).toBe(true);
      });
    } finally {
      pool.drain();
    }
  });

  it("tails log files", async () => {
    const pool = new ConnectionPool();
    try {
      await pool.withConnection(connConfig, async (client) => {
        const output = await tail(client, "/var/log/test.log", 10);
        expect(output).toContain("test log line");
      });
    } finally {
      pool.drain();
    }
  });

  it("runs multi-host exec", async () => {
    const pool = new ConnectionPool();
    try {
      // Use the same host twice to simulate multi-host
      const results = await multiExec(pool, [connConfig, connConfig], "hostname");
      expect(results.length).toBe(2);
      for (const r of results) {
        expect(r.code).toBe(0);
        expect(r.stdout.trim()).toBeTruthy();
      }
    } finally {
      pool.drain();
    }
  });
});

describe.skipIf(!INTEGRATION)("integration: pool under concurrency", () => {
  it("reuses a single connection under a 50-way concurrent burst", async () => {
    const pool = new ConnectionPool();
    try {
      const tasks = Array.from({ length: 50 }, (_, i) =>
        pool.withConnection(connConfig, async (client) => {
          const r = await exec(client, `echo ${i}`);
          return r.stdout.trim();
        }),
      );
      const results = await Promise.all(tasks);
      expect(results).toHaveLength(50);
      expect(new Set(results).size).toBe(50);
      // Single host/user/port → single pool entry even under concurrency.
      expect(pool.size).toBe(1);
      expect(pool.stats.active).toBe(0);
      expect(pool.stats.idle).toBe(1);
      // Critically, exactly ONE actual connect happened — no leaked orphans
      // from racing acquires. pool.size only counts entries in the map, so
      // this assertion is what guards against the concurrency bug.
      expect(pool.connectCount).toBe(1);
    } finally {
      pool.drain();
    }
  });

  it("release decrements refcount to zero after concurrent work completes", async () => {
    const pool = new ConnectionPool();
    try {
      await Promise.all(Array.from({ length: 10 }, () => pool.withConnection(connConfig, async () => "done")));
      expect(pool.stats.active).toBe(0);
      expect(pool.stats.idle).toBe(1);
    } finally {
      pool.drain();
    }
  });
});

// ---------------------------------------------------------------------------
// ProxyJump against a REAL bastion.
//
// Every other ProxyJump assertion in the suite runs against a hand-written fake
// whose forwardOut hands back a bare EventEmitter, so `sock: stream` had never
// been given to a real ssh2 Client and no real sshd had ever accepted a channel
// from this code. The compose fixture now runs two extra hosts for this: a
// `bastion` published on 2223, and a `target` with NO ports mapping at all.
//
// The target being unpublished is the evidence. A direct dial from the runner
// must FAIL, and the same dial through the bastion must SUCCEED -- that pair can
// only pass if a real direct-tcpip channel was opened and handed to ssh2.
//
// Extra gate beyond SSH_MCP_INTEGRATION: connectWithProxy resolves the JUMP host
// itself (resolveConfig on the parsed spec), so the jump's credential comes from
// the agent or the default key paths -- it cannot be injected per-call. The test
// therefore starts its own ssh-agent holding test_key and points SSH_AUTH_SOCK at
// it, which is POSIX-only (on Windows ssh-agent is a service, not a socket we can
// spawn). Skipped rather than faked where that is not available.
const canRunJump = INTEGRATION && process.platform !== "win32";

describe.skipIf(!canRunJump)("integration: ProxyJump through a real bastion", () => {
  const BASTION_PORT = 2223;
  let agentSock: string | undefined;
  let agentPid: string | undefined;
  let priorSock: string | undefined;

  beforeAll(() => {
    priorSock = process.env.SSH_AUTH_SOCK;
    const out = execFileSync("ssh-agent", ["-s"], { encoding: "utf8" });
    agentSock = out.match(/SSH_AUTH_SOCK=([^;]+)/)?.[1];
    agentPid = out.match(/SSH_AGENT_PID=([^;]+)/)?.[1];
    if (!agentSock) throw new Error("could not start an ssh-agent for the ProxyJump test");
    process.env.SSH_AUTH_SOCK = agentSock;
    // ssh-add refuses a group/world-readable key; the repo copy may be 0644.
    chmodSync(TEST_KEY, 0o600);
    execFileSync("ssh-add", [TEST_KEY], { env: { ...process.env, SSH_AUTH_SOCK: agentSock } });
  });

  afterAll(() => {
    if (priorSock === undefined) delete process.env.SSH_AUTH_SOCK;
    else process.env.SSH_AUTH_SOCK = priorSock;
    if (agentPid) {
      try {
        process.kill(Number.parseInt(agentPid, 10));
      } catch {
        // already gone
      }
    }
  });

  it("cannot reach the target directly -- the premise of the whole test", async () => {
    // Two halves, because neither alone proves the target is jump-only. (1) The fixture
    // publishes no port for `target`: publishing it on ANY host port would let a direct
    // dial succeed, so the compose service block itself must carry no `ports:` key.
    const compose = readFileSync(join(__dirname, "../../test/docker/docker-compose.yml"), "utf8");
    // The service's body: every following line indented deeper than the service name.
    const targetBlock = compose.match(/^ {2}target:\r?\n((?:(?: {3,}.*)?(?:\r?\n|$))*)/m)?.[1];
    expect(targetBlock, "docker-compose.yml has no `target` service").toBeDefined();
    expect(targetBlock).not.toMatch(/^\s+ports:/m);
    // (2) Dial exactly what the jump dials -- `target:22` -- from the runner. The name
    // resolves only inside the compose network, so this must fail at DNS (or, if a stray
    // `target` resolves locally, at connect), not on some unrelated error such as a bad key.
    // Match the ORIGINAL error (enhanceSshError keeps it as `cause`), not the enhanced
    // message: the appended diagnostics probe `target` too and print their own DNS/TCP
    // failure, so a key error would otherwise pass this check on the report's text alone.
    const err = await connect({ host: "target", port: 22, username: TEST_USER, privateKeyPath: TEST_KEY }).then(
      (c) => {
        c.end();
        return undefined;
      },
      (e: unknown) => e,
    );
    expect(err, "a direct dial to target:22 succeeded -- the target is reachable without the jump").toBeInstanceOf(
      Error,
    );
    const original = ((err as Error).cause ?? err) as Error;
    expect(original.message).toMatch(/ENOTFOUND|EAI_AGAIN|getaddrinfo|ECONNREFUSED|EHOSTUNREACH|ETIMEDOUT/);
  });

  it("reaches the target THROUGH the bastion and runs a command there", async () => {
    // `root@127.0.0.1:2223` also exercises parseJumpSpec end to end: `ssh -G`
    // emits a ProxyJump value verbatim, and the user@host:port form used to be
    // handed to resolveConfig as one hostname (dialling "127.0.0.1:2223" on
    // port 22, which fails DNS before a byte is sent).
    const resolved: ResolvedConfig = {
      connectConfig: { host: "target", port: 22, username: TEST_USER, privateKey: readFileSync(TEST_KEY) },
      proxyJump: `${TEST_USER}@127.0.0.1:${BASTION_PORT}`,
    };
    const client = await connectWithProxy(resolved);
    try {
      const result = await exec(client, "hostname");
      // The compose fixture pins `hostname: target` (and `bastion`), so this equality
      // is what proves the command ran on the TARGET rather than on the bastion we
      // tunnelled through -- any non-empty hostname would not.
      expect(result.code).toBe(0);
      expect(result.stdout.trim()).toBe("target");
    } finally {
      client.end();
    }
  });

  it("closes the jump connection when the target connection closes", async () => {
    // The documented promise: jump connections close with the target. A leak here
    // is invisible until a fan-out exhausts the bastion's MaxSessions, and one
    // leaked client never gets there -- so count the bastion's TCP connections on
    // port 22 directly instead. A jump adds two (our inbound hop, the bastion's
    // forwarded dial to target:22); both must be gone once the target closes.
    // /proc/net/tcp state 01 = ESTABLISHED, port 22 = 0x0016.
    const countSsh22 =
      "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk '$4==\"01\" && ($2 ~ /:0016$/ || $3 ~ /:0016$/)' | wc -l";
    const observer = await connect({
      host: TEST_HOST,
      port: BASTION_PORT,
      username: TEST_USER,
      privateKeyPath: TEST_KEY,
    });
    const established = async () => Number.parseInt((await exec(observer, countSsh22)).stdout.trim(), 10);
    try {
      const baseline = await established(); // includes the observer's own connection
      const resolved: ResolvedConfig = {
        connectConfig: { host: "target", port: 22, username: TEST_USER, privateKey: readFileSync(TEST_KEY) },
        proxyJump: `${TEST_USER}@127.0.0.1:${BASTION_PORT}`,
      };
      const client = await connectWithProxy(resolved);
      // Sanity: the measurement can see the jump at all, or the "after" check proves nothing.
      expect(await established()).toBeGreaterThan(baseline);
      const closed = new Promise<void>((resolve) => client.once("close", () => resolve()));
      client.end();
      await closed;
      // Teardown is asynchronous on the bastion side; poll briefly for it.
      let after = await established();
      for (let i = 0; i < 25 && after > baseline; i++) {
        await new Promise((r) => setTimeout(r, 200));
        after = await established();
      }
      expect(after).toBe(baseline);
    } finally {
      observer.end();
    }
  });
});

describe.skipIf(!INTEGRATION)("integration: ProxyJump failure", () => {
  it("rejects when the jump host is unreachable", async () => {
    // Construct a ResolvedConfig that points at a definitely-unreachable jump host.
    // connectWithProxy should recurse into the jump and fail rather than hang. Only the
    // rejection is asserted; jump teardown is covered by the bastion-session count above.
    const resolved: ResolvedConfig = {
      connectConfig: { host: TEST_HOST, port: TEST_PORT, username: TEST_USER },
      proxyJump: "ssh-mcp-nonexistent-jump.invalid",
    };
    await expect(connectWithProxy(resolved)).rejects.toThrow();
  });
});

describe.skipIf(!INTEGRATION)("integration: SFTP error paths", () => {
  it("rejects reading a path that does not exist", async () => {
    const client = await connect(connConfig);
    try {
      await expect(readFile(client, "/nonexistent/path/xyz.txt")).rejects.toThrow();
    } finally {
      client.end();
    }
  });

  it("rejects writing to a directory without permission", async () => {
    const client = await connect(connConfig);
    try {
      // /proc is read-only on Linux; writing under it should fail.
      await expect(writeFile(client, "/proc/ssh-mcp-denied.txt", "x")).rejects.toThrow();
    } finally {
      client.end();
    }
  });

  it("rejects listing a directory that does not exist", async () => {
    const client = await connect(connConfig);
    try {
      await expect(listDir(client, "/nonexistent/dir/xyz")).rejects.toThrow();
    } finally {
      client.end();
    }
  });
});

// NOTE: maxPoolSize eviction is not exercised end-to-end here yet, though the fixture
// can now support it: the compose file publishes two endpoints (sshd on 2222, bastion
// on 2223), and the pool key folds an auth fingerprint into user@host:port (pool.ts),
// so two entries are reachable either via the two ports or via two credentials on one
// endpoint. The test to add: acquire N+1 entries with maxPoolSize=N and verify the
// oldest idle entry is evicted and the new acquire succeeds.
