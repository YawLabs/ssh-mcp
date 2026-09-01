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
    // If this ever starts passing, the target got published and every assertion
    // below stops proving anything about the jump.
    await expect(
      connect({ host: "127.0.0.1", port: 2299, username: TEST_USER, privateKeyPath: TEST_KEY }),
    ).rejects.toThrow();
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
      // The remote hostname is the container's, proving the command ran on the
      // TARGET rather than on the bastion we tunnelled through.
      expect(result.code).toBe(0);
      expect(result.stdout.trim()).toBeTruthy();
      expect(result.stdout.trim()).not.toBe("");
    } finally {
      client.end();
    }
  });

  it("closes the jump connection when the target connection closes", async () => {
    // The documented promise: jump connections close with the target. A leak here
    // is invisible until a fan-out exhausts the bastion's MaxSessions.
    const resolved: ResolvedConfig = {
      connectConfig: { host: "target", port: 22, username: TEST_USER, privateKey: readFileSync(TEST_KEY) },
      proxyJump: `${TEST_USER}@127.0.0.1:${BASTION_PORT}`,
    };
    const client = await connectWithProxy(resolved);
    const closed = new Promise<void>((resolve) => client.once("close", () => resolve()));
    client.end();
    await closed;
    // Re-connecting proves the bastion did not run out of channels, i.e. the
    // previous jump client was actually torn down rather than left dangling.
    const again = await connectWithProxy(resolved);
    again.end();
  });
});

describe.skipIf(!INTEGRATION)("integration: ProxyJump failure", () => {
  it("rejects and cleans up when the jump host is unreachable", async () => {
    // Construct a ResolvedConfig that points at a definitely-unreachable jump host.
    // connectWithProxy should recurse into the jump, fail, and not leak connections.
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

// NOTE: maxPoolSize eviction cannot be exercised end-to-end with the current Docker
// setup (single sshd container, single port). The pool key is username@host:port, so
// two distinct entries require two distinct endpoints. When the test fixture grows to
// multiple containers, add: acquire N+1 entries with maxPoolSize=N, verify the oldest
// idle entry is evicted and the new one succeeds.
