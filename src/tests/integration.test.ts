import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { find, multiExec, tail } from "../ops.js";
import { ConnectionPool } from "../pool.js";
import { type ResolvedConfig, connect, connectWithProxy, exec, listDir, readFile, writeFile } from "../ssh.js";

const INTEGRATION = process.env.SSH_MCP_INTEGRATION === "1";
const TEST_HOST = "127.0.0.1";
const TEST_PORT = 2222;
const TEST_USER = "root";
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
