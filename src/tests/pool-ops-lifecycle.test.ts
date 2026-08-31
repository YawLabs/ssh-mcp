import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock ONLY connectWithProxy. resolveConfig, exec, hostVerifier, etc. keep their real
// implementations, so both the pool's lifecycle logic and multiExec's use of the real
// exec() channel state machine run for real. Same boundary as pool-concurrency.test.ts.
vi.mock("../ssh.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../ssh.js")>();
  return {
    ...actual,
    connectWithProxy: vi.fn(),
  };
});

import { type MultiExecHost, multiExec } from "../ops.js";
import { ConnectionPool } from "../pool.js";
import { connectWithProxy } from "../ssh.js";

const mockedConnect = vi.mocked(connectWithProxy);

// ---------------------------------------------------------------------------
// GAP 3 — multiExec mixed success/failure fan-out
// ---------------------------------------------------------------------------

interface HostScript {
  /** Milliseconds before the host settles. Deliberately out of input order so the
   *  index-based result mapping is tested against real completion order. */
  delayMs?: number;
  /** When present, withConnection rejects with this value instead of running the command. */
  reject?: unknown;
  stdout?: string;
  stderr?: string;
  code?: number;
}

/**
 * ssh2-Client-like object whose exec() emits scripted stdout/stderr and exit code.
 * Drives the REAL exec() from ssh.ts (same shape as ops.test.ts's fakeClient), so a
 * "success" result in these tests is a genuine ExecResult, not a hand-built literal.
 */
function scriptedClient(script: HostScript): unknown {
  return {
    exec: (_command: string, cb: (err: Error | null, stream: unknown) => void) => {
      const stream = new EventEmitter() as EventEmitter & { stderr: EventEmitter };
      stream.stderr = new EventEmitter();
      cb(null, stream);
      queueMicrotask(() => {
        if (script.stdout) stream.emit("data", Buffer.from(script.stdout));
        if (script.stderr) stream.stderr.emit("data", Buffer.from(script.stderr));
        stream.emit("close", script.code ?? 0);
      });
    },
  };
}

/**
 * ConnectionPool subclass that never touches the network: withConnection either rejects
 * with the scripted reason or hands the callback a scripted client. Same pattern as
 * tools-hardening.test.ts's RecordingPool, extended with per-host scripting.
 */
class ScriptedPool extends ConnectionPool {
  constructor(private readonly scripts: Record<string, HostScript>) {
    super();
  }

  override async withConnection<T>(config: { host: string }, fn: (client: never) => Promise<T>): Promise<T> {
    const script = this.scripts[config.host];
    if (!script) throw new Error(`test bug: no script for ${config.host}`);
    if (script.delayMs) await new Promise((r) => setTimeout(r, script.delayMs));
    if ("reject" in script) throw script.reject;
    return fn(scriptedClient(script) as never);
  }
}

describe("multiExec — mixed success/failure fan-out", () => {
  beforeEach(() => {
    // The pool suites below use fake timers; the scripted delays here need real ones.
    vi.useRealTimers();
  });

  it("returns one result per host, in INPUT order, each carrying its own host name", async () => {
    // Hosts 2 and 4 fail, 1 and 3 succeed. Completion order (0ms, 5ms, 20ms, 30ms) is
    // deliberately the REVERSE of input order, so a mapping that followed settlement
    // order rather than index would scramble the host names.
    const scripts: Record<string, HostScript> = {
      "alpha.test": { delayMs: 30, stdout: "alpha-uptime\n", code: 0 },
      "bravo.test": { delayMs: 20, reject: new Error("connect ECONNREFUSED 10.0.0.2:22") },
      "charlie.test": { delayMs: 5, stdout: "charlie-uptime\n", code: 0 },
      // A non-Error rejection: exercises the String(reason) fallback in the map.
      "delta.test": { delayMs: 0, reject: "pool exhausted: no slot for delta" },
    };
    const hosts: MultiExecHost[] = [
      { host: "alpha.test" },
      { host: "bravo.test" },
      { host: "charlie.test" },
      { host: "delta.test" },
    ];

    const results = await multiExec(new ScriptedPool(scripts), hosts, "uptime");

    expect(results).toHaveLength(4);
    // The load-bearing assertion: index i of the output is host i of the input.
    expect(results.map((r) => r.host)).toEqual(["alpha.test", "bravo.test", "charlie.test", "delta.test"]);

    // Successes carry their OWN output and no `error` key at all.
    expect(results[0]).toMatchObject({ host: "alpha.test", stdout: "alpha-uptime\n", stderr: "", code: 0 });
    expect(results[0]).not.toHaveProperty("error");
    expect(results[2]).toMatchObject({ host: "charlie.test", stdout: "charlie-uptime\n", stderr: "", code: 0 });
    expect(results[2]).not.toHaveProperty("error");

    // Failures: code -1 sentinel, empty streams, the rejection message in `error`.
    expect(results[1]).toEqual({
      host: "bravo.test",
      stdout: "",
      stderr: "",
      code: -1,
      error: "connect ECONNREFUSED 10.0.0.2:22",
    });
    // Non-Error rejection falls back to String(reason) — no "[object Object]", no undefined.
    expect(results[3]).toEqual({
      host: "delta.test",
      stdout: "",
      stderr: "",
      code: -1,
      error: "pool exhausted: no slot for delta",
    });
  });

  it("attributes each failure to its OWN host, not to a fixed index", async () => {
    // Three hosts, failures at index 0 AND index 2 with a success between them. Two
    // hosts with the failure at index 0 is not enough: there `hosts[0].host` and
    // `hosts[i].host` are the same string, so a mapping pinned to a fixed index still
    // reads as correct. Mutation-verified -- this fixture dies to `hosts[0]`, to
    // `hosts[i + 1]`, and to a last-index pin alike; the two-host version survived the
    // first of those.
    const scripts: Record<string, HostScript> = {
      "down-first.test": { reject: new Error("Error: All configured authentication methods failed") },
      "up-middle.test": { stdout: "ok\n", code: 0 },
      "down-last.test": { reject: new Error("connect ECONNREFUSED") },
    };
    const results = await multiExec(
      new ScriptedPool(scripts),
      [{ host: "down-first.test" }, { host: "up-middle.test" }, { host: "down-last.test" }],
      "id",
    );

    expect(results.map((r) => r.host)).toEqual(["down-first.test", "up-middle.test", "down-last.test"]);
    // Each error text must land on the host that actually produced it -- the whole point.
    expect(results[0].error).toContain("authentication methods failed");
    expect(results[0].code).toBe(-1);
    expect(results[1].error).toBeUndefined();
    expect(results[1].stdout).toBe("ok\n");
    expect(results[2].error).toContain("ECONNREFUSED");
    expect(results[2].code).toBe(-1);
  });

  it("does NOT report a non-zero EXIT as an `error` — a command that ran and failed is a success", async () => {
    // The distinction the caller acts on: "I could not reach the box" (error, code -1)
    // vs "the box ran my command and it exited 3" (no error, real code + stderr).
    const scripts: Record<string, HostScript> = {
      "ran-and-failed.test": { stdout: "", stderr: "cat: /nope: No such file or directory\n", code: 3 },
      "unreachable.test": { reject: new Error("connect ETIMEDOUT") },
    };
    const results = await multiExec(
      new ScriptedPool(scripts),
      [{ host: "ran-and-failed.test" }, { host: "unreachable.test" }],
      "cat /nope",
    );

    expect(results[0].code).toBe(3);
    expect(results[0].stderr).toBe("cat: /nope: No such file or directory\n");
    expect(results[0]).not.toHaveProperty("error");
    expect(results[0].host).toBe("ran-and-failed.test");

    // Only the unreachable host gets the -1 sentinel + error.
    expect(results[1].code).toBe(-1);
    expect(results[1].error).toBe("connect ETIMEDOUT");
  });

  it("reports every host when the whole fleet is down", async () => {
    const scripts: Record<string, HostScript> = {
      "a.test": { reject: new Error("boom a") },
      "b.test": { reject: new Error("boom b") },
      "c.test": { reject: new Error("boom c") },
    };
    const results = await multiExec(
      new ScriptedPool(scripts),
      [{ host: "a.test" }, { host: "b.test" }, { host: "c.test" }],
      "true",
    );

    expect(results.map((r) => r.host)).toEqual(["a.test", "b.test", "c.test"]);
    expect(results.map((r) => r.error)).toEqual(["boom a", "boom b", "boom c"]);
    expect(results.every((r) => r.code === -1)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// GAP 4 — ConnectionPool idle-timer release path
// ---------------------------------------------------------------------------

const TTL = 5_000;

/**
 * A client whose end() records the call but emits NOTHING. Real ssh2 clients emit "close"
 * some time after end(), which would fire the pool's markDead handler and delete the entry
 * as a side effect — masking whether the idle callback itself deleted it. This models the
 * window before that close lands, so the idle callback's own two actions (end + delete) are
 * each independently observable.
 */
function makeQuietClient(): EventEmitter & { endCalls: number; end: () => void } {
  const client = new EventEmitter() as EventEmitter & { endCalls: number; end: () => void };
  client.endCalls = 0;
  client.end = () => {
    client.endCalls++;
  };
  return client;
}

describe("ConnectionPool — idle timer release path", () => {
  beforeEach(() => {
    // NOTE ON unref(): release() calls .unref() on the timer so a pending idle close can
    // never hold the process open. Vitest's fake clock still tracks unref'd timers and
    // advanceTimersByTime() still fires them, so the production unref() needs no special
    // handling here — these assertions prove the callback runs under fake timers.
    vi.useFakeTimers();
    mockedConnect.mockReset();
    mockedConnect.mockImplementation(async () => makeQuietClient() as never);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("does not close a connection while it is still referenced", async () => {
    const pool = new ConnectionPool({ idleTtlMs: TTL });
    try {
      const c1 = (await pool.acquire({ host: "held.example.com" })) as unknown as { endCalls: number };
      // No release: refCount stays 1, so no timer is ever armed.
      expect(vi.getTimerCount()).toBe(0);
      vi.advanceTimersByTime(TTL * 10);
      expect(c1.endCalls).toBe(0);
      expect(pool.size).toBe(1);
      expect(pool.stats).toEqual({ active: 1, idle: 0 });
      pool.release(c1 as never);
    } finally {
      pool.drain();
    }
  });

  it("release() arms the idle timer at idleTtlMs, then ends the client AND deletes the entry", async () => {
    const pool = new ConnectionPool({ idleTtlMs: TTL });
    try {
      const c1 = (await pool.acquire({ host: "idle-expiry.example.com" })) as unknown as { endCalls: number };
      pool.release(c1 as never);

      // Armed but not fired: the connection stays warm and reusable.
      expect(vi.getTimerCount()).toBe(1);
      expect(c1.endCalls).toBe(0);
      expect(pool.size).toBe(1);
      expect(pool.stats).toEqual({ active: 0, idle: 1 });

      // One tick short of the TTL, nothing has happened yet.
      vi.advanceTimersByTime(TTL - 1);
      expect(c1.endCalls).toBe(0);
      expect(pool.size).toBe(1);

      // The tick that crosses idleTtlMs does BOTH halves of the release path.
      vi.advanceTimersByTime(1);
      expect(c1.endCalls).toBe(1);
      expect(pool.size).toBe(0);
      expect(pool.stats).toEqual({ active: 0, idle: 0 });
    } finally {
      pool.drain();
    }
  });

  it("dials a FRESH connection on the next acquire after the idle timer has expired", async () => {
    // The regression this guards: end()ing without deleting the entry leaves the fast
    // path handing out a closed client forever. Reuse would keep connectCount at 1.
    const pool = new ConnectionPool({ idleTtlMs: TTL });
    try {
      const c1 = await pool.acquire({ host: "redial.example.com" });
      pool.release(c1);
      vi.advanceTimersByTime(TTL);
      expect(pool.size).toBe(0);

      const c2 = await pool.acquire({ host: "redial.example.com" });
      expect(c2).not.toBe(c1);
      expect(mockedConnect).toHaveBeenCalledTimes(2);
      expect(pool.connectCount).toBe(2);
      expect(pool.size).toBe(1);
      expect((c1 as unknown as { endCalls: number }).endCalls).toBe(1);
      expect((c2 as unknown as { endCalls: number }).endCalls).toBe(0);

      pool.release(c2);
    } finally {
      pool.drain();
    }
  });

  it("re-acquiring BEFORE expiry cancels the pending timer so a live caller is never closed underneath", async () => {
    const pool = new ConnectionPool({ idleTtlMs: TTL });
    try {
      const c1 = (await pool.acquire({ host: "reacquire.example.com" })) as unknown as { endCalls: number };
      pool.release(c1 as never);
      expect(vi.getTimerCount()).toBe(1);

      vi.advanceTimersByTime(TTL - 1); // right up to the edge, still warm
      const c2 = await pool.acquire({ host: "reacquire.example.com" });
      expect(c2).toBe(c1 as unknown as typeof c2);
      expect(mockedConnect).toHaveBeenCalledTimes(1);

      // The pending close must be cancelled, not merely rescheduled.
      expect(vi.getTimerCount()).toBe(0);
      expect(pool.stats).toEqual({ active: 1, idle: 0 });

      // Long past the original deadline the caller still holds a live connection.
      vi.advanceTimersByTime(TTL * 10);
      expect(c1.endCalls).toBe(0);
      expect(pool.size).toBe(1);

      // ...and the timer machinery still works after the cancel: releasing again
      // re-arms it and the entry closes normally.
      pool.release(c2);
      expect(vi.getTimerCount()).toBe(1);
      vi.advanceTimersByTime(TTL);
      expect(c1.endCalls).toBe(1);
      expect(pool.size).toBe(0);
    } finally {
      pool.drain();
    }
  });

  it("each acquire needs its own release before the idle timer is armed", async () => {
    const pool = new ConnectionPool({ idleTtlMs: TTL });
    try {
      const a = (await pool.acquire({ host: "refcount.example.com" })) as unknown as { endCalls: number };
      const b = await pool.acquire({ host: "refcount.example.com" });
      expect(b).toBe(a as unknown as typeof b);

      pool.release(a as never);
      // One ref outstanding: no timer, and time passing changes nothing.
      expect(vi.getTimerCount()).toBe(0);
      vi.advanceTimersByTime(TTL * 3);
      expect(a.endCalls).toBe(0);
      expect(pool.size).toBe(1);

      pool.release(b);
      expect(vi.getTimerCount()).toBe(1);
      vi.advanceTimersByTime(TTL);
      expect(a.endCalls).toBe(1);
      expect(pool.size).toBe(0);
    } finally {
      pool.drain();
    }
  });

  it("drain() cancels a pending idle timer so the client is not end()ed twice", async () => {
    const pool = new ConnectionPool({ idleTtlMs: TTL });
    const c1 = (await pool.acquire({ host: "drain-idle.example.com" })) as unknown as { endCalls: number };
    pool.release(c1 as never);
    expect(vi.getTimerCount()).toBe(1);

    pool.drain();
    expect(c1.endCalls).toBe(1);
    expect(pool.size).toBe(0);
    expect(vi.getTimerCount()).toBe(0);

    // The cancelled timer must not fire later against an already-closed client.
    vi.advanceTimersByTime(TTL * 10);
    expect(c1.endCalls).toBe(1);
  });

  it("a dead connection's markDead cancels the pending idle timer", async () => {
    // A client that emits "close" when the peer hangs up: markDead should clear the
    // armed idle timer and drop the entry, so nothing fires against it afterwards.
    const pool = new ConnectionPool({ idleTtlMs: TTL });
    try {
      const c1 = (await pool.acquire({ host: "dies-while-idle.example.com" })) as unknown as EventEmitter & {
        endCalls: number;
      };
      pool.release(c1 as never);
      expect(vi.getTimerCount()).toBe(1);

      c1.emit("close"); // peer kicked us off while the connection sat idle
      expect(pool.size).toBe(0);
      expect(vi.getTimerCount()).toBe(0);

      vi.advanceTimersByTime(TTL * 10);
      expect(c1.endCalls).toBe(0); // the pool never got to end() it; the peer already did
    } finally {
      pool.drain();
    }
  });

  it("PINS A BUG: an unbalanced double release orphans a timer that later closes a live connection", async () => {
    // release() re-arms unconditionally whenever refCount is 0, overwriting entry.idleTimer
    // without clearing the previous one. The orphaned timer is unreachable by the
    // clearTimeout on re-acquire, so it fires on its own deadline and end()s + evicts a
    // connection the caller is actively holding. Pinned as ACTUAL behavior, not endorsed.
    const pool = new ConnectionPool({ idleTtlMs: TTL });
    try {
      const c1 = (await pool.acquire({ host: "double-release.example.com" })) as unknown as { endCalls: number };
      pool.release(c1 as never); // arms T1
      vi.advanceTimersByTime(1_000);
      pool.release(c1 as never); // refCount already 0 -> arms T2, T1 is orphaned
      expect(vi.getTimerCount()).toBe(2);

      // A new caller takes the connection; only T2 is cancelled.
      const c2 = await pool.acquire({ host: "double-release.example.com" });
      expect(c2).toBe(c1 as unknown as typeof c2);
      expect(vi.getTimerCount()).toBe(1); // T1 survives

      // T1's original deadline arrives and closes the connection out from under c2.
      vi.advanceTimersByTime(TTL - 1_000);
      expect(c1.endCalls).toBe(1);
      expect(pool.size).toBe(0);
      expect(pool.stats).toEqual({ active: 0, idle: 0 });
    } finally {
      pool.drain();
    }
  });
});
