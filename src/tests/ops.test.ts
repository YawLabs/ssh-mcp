import { EventEmitter } from "node:events";
import { describe, expect, it } from "vitest";
import { find, tail } from "../ops.js";

// Build a fake ssh2 Client whose exec() emits a configurable stdout/stderr/exit.
// This lets us test ops.ts error-surfacing without a real SSH connection.
function fakeClient(opts: { stdout?: string; stderr?: string; code?: number }): any {
  return {
    exec: (_command: string, cb: (err: Error | null, stream: any) => void) => {
      const stream: any = new EventEmitter();
      stream.stderr = new EventEmitter();
      cb(null, stream);
      // Emit data and close asynchronously so listeners attach first.
      queueMicrotask(() => {
        if (opts.stdout) stream.emit("data", Buffer.from(opts.stdout));
        if (opts.stderr) stream.stderr.emit("data", Buffer.from(opts.stderr));
        stream.emit("close", opts.code ?? 0);
      });
    },
  };
}

describe("find input validation", () => {
  // These tests verify validation without needing a real SSH connection.
  // find() validates inputs before executing any SSH command.

  it("rejects invalid minsize format", async () => {
    const fakeClient = {} as any;
    await expect(find(fakeClient, { path: "/tmp", minsize: "1M; rm -rf /" })).rejects.toThrow("Invalid minsize format");
  });

  it("rejects invalid maxsize format", async () => {
    const fakeClient = {} as any;
    await expect(find(fakeClient, { path: "/tmp", maxsize: "abc" })).rejects.toThrow("Invalid maxsize format");
  });

  it("rejects maxsize with shell metacharacters", async () => {
    const fakeClient = {} as any;
    await expect(find(fakeClient, { path: "/tmp", maxsize: "10M$(whoami)" })).rejects.toThrow("Invalid maxsize format");
  });

  it("accepts valid size formats", async () => {
    // These would fail at the SSH exec step (no real client), but should pass validation.
    // We just verify they don't throw the validation error.
    const fakeClient = {
      exec: (_cmd: string, cb: (err: Error) => void) => cb(new Error("not connected")),
    } as any;

    const validSizes = ["1k", "100M", "5G", "2T", "10P", "1024"];
    for (const size of validSizes) {
      // Should reject with SSH error, not validation error
      await expect(find(fakeClient, { path: "/tmp", minsize: size })).rejects.not.toThrow("Invalid minsize format");
    }
  });
});

describe("find error surfacing", () => {
  it("surfaces stderr when find produced no stdout", async () => {
    const client = fakeClient({ stderr: "find: '/nope': No such file or directory", code: 1 });
    await expect(find(client, { path: "/nope" })).rejects.toThrow("No such file or directory");
  });

  it("returns results and silently drops stderr on partial errors", async () => {
    // Classic case: most of the tree is readable, a few subdirs are denied.
    const client = fakeClient({
      stdout: "/var/log/a.log\n/var/log/b.log\n",
      stderr: "find: '/var/log/private': Permission denied",
      code: 1,
    });
    const results = await find(client, { path: "/var/log" });
    expect(results).toEqual(["/var/log/a.log", "/var/log/b.log"]);
  });

  it("returns empty list when find truly found nothing (no stderr)", async () => {
    const client = fakeClient({ stdout: "", stderr: "", code: 0 });
    const results = await find(client, { path: "/empty" });
    expect(results).toEqual([]);
  });
});

describe("tail error surfacing", () => {
  it("throws when tail fails with stderr", async () => {
    const client = fakeClient({ stderr: "tail: cannot open '/nope' for reading: No such file or directory", code: 1 });
    await expect(tail(client, "/nope")).rejects.toThrow("No such file");
  });

  it("throws when tail fails even if grep is set (regression: no longer suppressed)", async () => {
    // grep is set, tail fails — stderr must still surface.
    const client = fakeClient({ stderr: "tail: cannot open '/nope' for reading: No such file or directory", code: 1 });
    await expect(tail(client, "/nope", 100, "error")).rejects.toThrow("No such file");
  });

  it("returns empty string when grep finds no matches (not an error)", async () => {
    // grep exit code 1 with no stderr means "no match" — that's fine.
    const client = fakeClient({ stdout: "", stderr: "", code: 1 });
    const out = await tail(client, "/var/log/app.log", 100, "nonexistent-pattern");
    expect(out).toBe("");
  });

  it("returns output when tail succeeds", async () => {
    const client = fakeClient({ stdout: "line1\nline2\n", code: 0 });
    const out = await tail(client, "/var/log/app.log");
    expect(out).toContain("line1");
  });
});
