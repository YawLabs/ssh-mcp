import { EventEmitter } from "node:events";
import { describe, expect, it } from "vitest";
import { exec } from "../ssh.js";

// Build a fake ssh2 Client whose exec() streams a configurable number of
// stdout/stderr bytes, then closes. This lets us exercise the output cap
// without needing a real SSH connection.
function fakeClient(opts: { stdoutChunks?: Buffer[]; stderrChunks?: Buffer[]; code?: number; execError?: Error }): any {
  return {
    exec: (_command: string, cb: (err: Error | null, stream: any) => void) => {
      if (opts.execError) {
        cb(opts.execError, null);
        return;
      }
      const stream: any = new EventEmitter();
      stream.stderr = new EventEmitter();
      cb(null, stream);
      queueMicrotask(() => {
        for (const c of opts.stdoutChunks ?? []) stream.emit("data", c);
        for (const c of opts.stderrChunks ?? []) stream.stderr.emit("data", c);
        stream.emit("close", opts.code ?? 0);
      });
    },
  };
}

describe("exec output cap", () => {
  it("passes through output under the cap unchanged", async () => {
    const client = fakeClient({
      stdoutChunks: [Buffer.from("hello world")],
      code: 0,
    });
    const result = await exec(client, "echo", 30000, 1024);
    expect(result.stdout).toBe("hello world");
    expect(result.stderr).toBe("");
    expect(result.code).toBe(0);
  });

  it("truncates stdout when it exceeds the cap and appends a marker", async () => {
    // 1 KB chunks, total 3 KB; cap at 1 KB.
    const chunk = Buffer.alloc(1024, 0x61); // "aaaa..."
    const client = fakeClient({
      stdoutChunks: [chunk, chunk, chunk],
      code: 0,
    });
    const result = await exec(client, "bigcmd", 30000, 1024);
    // 1024 "a"s plus the truncation marker.
    expect(result.stdout.startsWith("a".repeat(1024))).toBe(true);
    expect(result.stdout).toContain("[output truncated at 1024 bytes]");
    // Ensure we did not buffer significantly past the cap.
    expect(result.stdout.length).toBeLessThan(1024 + 100);
  });

  it("truncates stderr independently of stdout", async () => {
    const stdoutChunk = Buffer.from("ok");
    const stderrChunk = Buffer.alloc(2048, 0x65); // "eeee..."
    const client = fakeClient({
      stdoutChunks: [stdoutChunk],
      stderrChunks: [stderrChunk],
      code: 0,
    });
    const result = await exec(client, "cmd", 30000, 512);
    expect(result.stdout).toBe("ok");
    expect(result.stderr.startsWith("e".repeat(512))).toBe(true);
    expect(result.stderr).toContain("[stderr truncated at 512 bytes]");
  });

  it("truncates exactly at cap when one chunk spans the boundary", async () => {
    // A single 4 KB chunk against a 1 KB cap — boundary case.
    const client = fakeClient({
      stdoutChunks: [Buffer.alloc(4096, 0x62)],
      code: 0,
    });
    const result = await exec(client, "cmd", 30000, 1024);
    // The first 1024 bytes are the raw capped output, followed by a `\n` and
    // then the truncation marker — so the marker `[` lands at byte 1025.
    expect(result.stdout.slice(0, 1024)).toBe("b".repeat(1024));
    expect(result.stdout[1024]).toBe("\n");
    expect(result.stdout.slice(1025)).toBe("[output truncated at 1024 bytes]");
  });

  it("propagates exec errors", async () => {
    const client = fakeClient({ execError: new Error("exec failed") });
    await expect(exec(client, "cmd")).rejects.toThrow("exec failed");
  });

  it("exposes stdoutTruncated when the cap is hit", async () => {
    const chunk = Buffer.alloc(2048, 0x61);
    const client = fakeClient({ stdoutChunks: [chunk], code: 0 });
    const result = await exec(client, "cmd", 30000, 1024);
    expect(result.stdoutTruncated).toBe(true);
    expect(result.stderrTruncated).toBeUndefined();
  });

  it("exposes stderrTruncated independently of stdout", async () => {
    const client = fakeClient({
      stdoutChunks: [Buffer.from("ok")],
      stderrChunks: [Buffer.alloc(2048, 0x65)],
      code: 0,
    });
    const result = await exec(client, "cmd", 30000, 512);
    expect(result.stdoutTruncated).toBeUndefined();
    expect(result.stderrTruncated).toBe(true);
  });

  it("does not set truncated flags when output fits", async () => {
    const client = fakeClient({ stdoutChunks: [Buffer.from("hi")], code: 0 });
    const result = await exec(client, "cmd", 30000, 1024);
    expect(result.stdoutTruncated).toBeUndefined();
    expect(result.stderrTruncated).toBeUndefined();
  });

  it("captures signal name and returns code=-1 when the channel closes signal-only", async () => {
    const client: any = {
      exec: (_command: string, cb: (err: Error | null, stream: any) => void) => {
        const stream: any = new EventEmitter();
        stream.stderr = new EventEmitter();
        cb(null, stream);
        queueMicrotask(() => {
          // ssh2 emits close(code, signal). Signal-only close has code=null.
          stream.emit("close", null, "TERM");
        });
      },
    };
    const result = await exec(client, "killed-cmd");
    expect(result.code).toBe(-1);
    expect(result.signal).toBe("TERM");
  });

  it("uses code=0 (not -1) when the channel closes with a real zero exit", async () => {
    // Regression guard: previously `code ?? 0` masked signal-only closes as success.
    // The new logic only falls to -1 when `code` is non-numeric.
    const client = fakeClient({ stdoutChunks: [Buffer.from("ok")], code: 0 });
    const result = await exec(client, "cmd");
    expect(result.code).toBe(0);
    expect(result.signal).toBeUndefined();
  });

  it("tears down the remote channel on timeout", async () => {
    let signalCalledWith: string | undefined;
    let closeCalled = false;
    const stream: any = new EventEmitter();
    stream.stderr = new EventEmitter();
    stream.signal = (sig: string) => {
      signalCalledWith = sig;
    };
    stream.close = () => {
      closeCalled = true;
    };

    const client = {
      exec: (_command: string, cb: (err: Error | null, stream: any) => void) => {
        cb(null, stream);
        // Never emit close — the command is "still running" on the remote side.
      },
    } as any;

    await expect(exec(client, "sleep 60", 50)).rejects.toThrow(/timed out/);
    expect(signalCalledWith).toBe("TERM");
    expect(closeCalled).toBe(true);
  });
});
