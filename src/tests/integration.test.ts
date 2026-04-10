import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { find, multiExec, tail } from "../ops.js";
import { ConnectionPool } from "../pool.js";
import { connect, exec, listDir, readFile, writeFile } from "../ssh.js";

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
