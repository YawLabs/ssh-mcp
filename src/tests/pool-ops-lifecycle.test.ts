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

import { find, type MultiExecHost, multiExec, serviceStatus } from "../ops.js";
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

// ---------------------------------------------------------------------------
// GAP 5 — eviction at capacity with a MIX of held and idle entries
// ---------------------------------------------------------------------------

describe("ConnectionPool — eviction with held and idle entries mixed", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    mockedConnect.mockReset();
    mockedConnect.mockImplementation(async () => makeQuietClient() as never);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("picks an entry with refCount 0 and leaves the in-use one alone", async () => {
    // The normal shape of a fan-out at capacity: one host is still mid-exec while
    // another has finished and gone idle. Insertion order matters here -- the HELD
    // entry is created first, so it is the first candidate the eviction loop sees.
    // Without the `refCount === 0` guard the loop would end() the connection the
    // live caller is holding, and that caller's next channel open would fail with an
    // unrelated "Not connected" instead of a clean pool-full rejection.
    const pool = new ConnectionPool({ idleTtlMs: TTL, maxPoolSize: 2 });
    try {
      const held = (await pool.acquire({ host: "mid-exec.example.com" })) as unknown as { endCalls: number };
      const idle = (await pool.acquire({ host: "finished.example.com" })) as unknown as { endCalls: number };
      pool.release(idle as never); // refCount 0, idle timer armed -> the eviction candidate

      expect(pool.size).toBe(2); // at capacity
      expect(pool.stats).toEqual({ active: 1, idle: 1 });
      expect(vi.getTimerCount()).toBe(1);

      // A third distinct host arrives. Room must come from the idle entry.
      const newcomer = await pool.acquire({ host: "newcomer.example.com" });
      expect(newcomer).toBeDefined();

      expect(held.endCalls).toBe(0); // the load-bearing assertion
      expect(idle.endCalls).toBe(1);
      expect(pool.size).toBe(2);
      expect(pool.stats).toEqual({ active: 2, idle: 0 });
      // The evicted entry's armed idle timer is cleared as part of eviction, so it
      // cannot fire later against a client the pool no longer tracks.
      expect(vi.getTimerCount()).toBe(0);

      // The held entry is still the pool's: re-acquiring hits the fast path, no redial.
      const again = await pool.acquire({ host: "mid-exec.example.com" });
      expect(again).toBe(held as unknown as typeof again);
      expect(pool.connectCount).toBe(3);
      expect(mockedConnect).toHaveBeenCalledTimes(3);

      // Nothing fires against the already-ended client once its deadline passes.
      vi.advanceTimersByTime(TTL * 10);
      expect(idle.endCalls).toBe(1);
      expect(held.endCalls).toBe(0);

      pool.release(again);
      pool.release(held as never);
      pool.release(newcomer);
    } finally {
      pool.drain();
    }
  });

  it("evicts exactly ONE idle entry — the first in insertion order — and skips over the held one", async () => {
    // Order: idle, held, idle. The first idle is the only casualty: the held entry is
    // skipped by the refCount guard and the SECOND idle survives because the loop
    // breaks after one eviction. Dropping that break would close a second warm
    // connection nobody asked to close.
    const pool = new ConnectionPool({ idleTtlMs: TTL, maxPoolSize: 3 });
    try {
      const idleFirst = (await pool.acquire({ host: "idle-first.example.com" })) as unknown as { endCalls: number };
      pool.release(idleFirst as never);
      const held = (await pool.acquire({ host: "held-middle.example.com" })) as unknown as { endCalls: number };
      const idleLast = (await pool.acquire({ host: "idle-last.example.com" })) as unknown as { endCalls: number };
      pool.release(idleLast as never);

      expect(pool.size).toBe(3);
      expect(pool.stats).toEqual({ active: 1, idle: 2 });
      expect(vi.getTimerCount()).toBe(2);

      const newcomer = await pool.acquire({ host: "newcomer-2.example.com" });

      expect(idleFirst.endCalls).toBe(1); // first refCount-0 entry in iteration order
      expect(held.endCalls).toBe(0);
      expect(idleLast.endCalls).toBe(0); // the break stopped the loop
      expect(pool.size).toBe(3);
      expect(pool.stats).toEqual({ active: 2, idle: 1 });
      expect(vi.getTimerCount()).toBe(1); // only idleLast's timer remains armed

      // idleLast is still warm and reusable -- no fourth dial.
      const reused = await pool.acquire({ host: "idle-last.example.com" });
      expect(reused).toBe(idleLast as unknown as typeof reused);
      expect(pool.connectCount).toBe(4);

      pool.release(reused);
      pool.release(held as never);
      pool.release(newcomer);
    } finally {
      pool.drain();
    }
  });
});

// ---------------------------------------------------------------------------
// GAP 6 — drain() while a connection is checked out
// ---------------------------------------------------------------------------

describe("ConnectionPool — drain() while a connection is checked out", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    mockedConnect.mockReset();
    mockedConnect.mockImplementation(async () => makeQuietClient() as never);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("ends the held client, clears the map, and the later release() falls through WITHOUT throwing", async () => {
    // index.ts drains on SIGTERM and on process exit, so a shutdown during a
    // long-running remote command produces exactly this interleaving: drain() clears
    // the entry out from under a caller who has not released yet.
    const pool = new ConnectionPool({ idleTtlMs: TTL });
    const c = (await pool.acquire({ host: "drain-midflight.example.com" })) as unknown as { endCalls: number };
    expect(pool.stats).toEqual({ active: 1, idle: 0 });

    pool.drain();
    expect(c.endCalls).toBe(1); // drain ends a held connection too, refCount notwithstanding
    expect(pool.size).toBe(0);

    // The late release: the entry is gone, so the loop finds nothing and the
    // unknown-client branch runs. It must not throw -- this call sits in
    // withConnection's `finally`, where a throw would replace the caller's real error.
    expect(() => pool.release(c as never)).not.toThrow();
    expect(c.endCalls).toBe(2); // end() again (idempotent on a real ssh2 client)
    expect(pool.size).toBe(0);
    // A drained pool must not arm anything: the unknown-client branch has no timer.
    expect(vi.getTimerCount()).toBe(0);
    vi.advanceTimersByTime(TTL * 10);
    expect(c.endCalls).toBe(2);
  });

  it("withConnection surfaces the callback's OWN error when drain() runs mid-flight", async () => {
    const pool = new ConnectionPool({ idleTtlMs: TTL });
    const boom = new Error("remote command interrupted by shutdown");
    let seen: { endCalls: number } | undefined;

    await expect(
      pool.withConnection({ host: "sigterm.example.com" }, async (client) => {
        seen = client as unknown as { endCalls: number };
        pool.drain(); // the SIGTERM handler fires while the command is still running
        throw boom; // ...and the command dies because its transport went away
      }),
    ).rejects.toBe(boom); // NOT an error thrown out of release() in the finally

    expect(seen?.endCalls).toBe(2); // once by drain, once by the fall-through release
    expect(pool.size).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// GAP 7 — markDead is registered on "end" and "error", not only "close"
// ---------------------------------------------------------------------------

describe("ConnectionPool — markDead handler registration", () => {
  // HONEST FRAMING: ssh2 follows both "end" and "error" with "close", and the "close"
  // handler is already covered above ("a dead connection's markDead cancels the pending
  // idle timer"). So these two tests do not pin a distinct real-world outcome -- they
  // pin that all THREE registrations stay attached, so the entry is dropped on the first
  // of the three signals rather than only on the trailing "close".
  beforeEach(() => {
    vi.useFakeTimers();
    mockedConnect.mockReset();
    mockedConnect.mockImplementation(async () => makeQuietClient() as never);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("'end' drops the entry and cancels the armed idle timer", async () => {
    const pool = new ConnectionPool({ idleTtlMs: TTL });
    try {
      const c = (await pool.acquire({ host: "emits-end.example.com" })) as unknown as EventEmitter & {
        endCalls: number;
      };
      pool.release(c as never);
      expect(vi.getTimerCount()).toBe(1);

      c.emit("end");
      expect(pool.size).toBe(0);
      expect(vi.getTimerCount()).toBe(0);

      vi.advanceTimersByTime(TTL * 10);
      expect(c.endCalls).toBe(0); // the peer hung up; the pool never had to end() it
    } finally {
      pool.drain();
    }
  });

  it("'error' drops a still-held entry so the next acquire dials fresh", async () => {
    const pool = new ConnectionPool({ idleTtlMs: TTL });
    try {
      const c1 = (await pool.acquire({ host: "emits-error.example.com" })) as unknown as EventEmitter & {
        endCalls: number;
      };
      // Still held (refCount 1, never released) -- the transport dying mid-exec.
      // Note the emit only survives because the pool itself attached an "error"
      // listener; an EventEmitter with none throws the emitted error.
      c1.emit("error", new Error("read ECONNRESET"));
      expect(pool.size).toBe(0);

      const c2 = await pool.acquire({ host: "emits-error.example.com" });
      expect(c2).not.toBe(c1 as unknown as typeof c2);
      expect(pool.connectCount).toBe(2);
      expect(pool.size).toBe(1);

      // Releasing the dead client afterwards is still safe.
      expect(() => pool.release(c1 as never)).not.toThrow();
      expect(c1.endCalls).toBe(1);

      pool.release(c2);
    } finally {
      pool.drain();
    }
  });
});

// ---------------------------------------------------------------------------
// GAP 8 — find size predicates reach the command string
// ---------------------------------------------------------------------------

/**
 * Records the command string handed to client.exec so the assembled `find` line can be
 * asserted verbatim. Same shape as scriptedClient above, plus the capture.
 */
function commandCapturingClient(script: { stdout?: string; stderr?: string; code?: number }): {
  client: never;
  lastCommand: () => string | undefined;
} {
  let last: string | undefined;
  const client = {
    exec: (command: string, cb: (err: Error | null, stream: unknown) => void) => {
      last = command;
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
  return { client: client as never, lastCommand: () => last };
}

describe("find — size predicates reach the command string", () => {
  beforeEach(() => {
    vi.useRealTimers();
  });

  it("emits `-size +N` for minsize (files BIGGER than N)", async () => {
    // The disk-pressure call operators actually make. `+` and `-` are opposite
    // predicates to find, and swapping them returns the exact complement of the
    // intended set with no error anywhere -- nothing downstream can notice.
    const cap = commandCapturingClient({ stdout: "/var/log/huge.log\n/var/log/old.gz\n", code: 0 });
    const results = await find(cap.client, { path: "/var/log", minsize: "100M" });

    expect(cap.lastCommand()).toBe("find '/var/log' -size +100M");
    expect(results).toEqual(["/var/log/huge.log", "/var/log/old.gz"]);
  });

  it("emits `-size -N` for maxsize (files SMALLER than N)", async () => {
    const cap = commandCapturingClient({ stdout: "", code: 0 });
    await find(cap.client, { path: "/tmp", maxsize: "10M" });
    expect(cap.lastCommand()).toBe("find '/tmp' -size -10M");
  });

  it("emits both bounds, minsize first, in fixed order with the other predicates", async () => {
    const cap = commandCapturingClient({ stdout: "", code: 0 });
    await find(cap.client, {
      path: "/srv",
      maxdepth: 3,
      type: "f",
      name: "*.log",
      minsize: "1M",
      maxsize: "500M",
      newer: "/etc/passwd",
    });
    expect(cap.lastCommand()).toBe(
      "find '/srv' -maxdepth 3 -type f -name '*.log' -size +1M -size -500M -newer '/etc/passwd'",
    );
  });

  it("passes the unit-suffixed and bare-number forms through unchanged", async () => {
    for (const [size, expected] of [
      ["512c", "find '/data' -size +512c"],
      ["1024", "find '/data' -size +1024"],
      ["5G", "find '/data' -size +5G"],
    ] as const) {
      const cap = commandCapturingClient({ stdout: "", code: 0 });
      await find(cap.client, { path: "/data", minsize: size });
      expect(cap.lastCommand()).toBe(expected);
    }
  });
});

// ---------------------------------------------------------------------------
// GAP 9 — serviceStatus on crashed and masked units
// ---------------------------------------------------------------------------

describe("serviceStatus — crashed and masked units", () => {
  beforeEach(() => {
    vi.useRealTimers();
  });

  it("reports a FAILED unit as active=false with unknown=false", async () => {
    // `unknown` means "systemctl could not answer at all". A crashed unit answered
    // perfectly well -- it has a parseable `Active:` line -- it just answered
    // "failed". Reporting it as unknown would send an operator hunting for a typo'd
    // unit name instead of reading the exit status that is right there.
    // The fixture omits `Main PID:`, the shape systemd prints when ExecStart never
    // became the main process (status=203/EXEC).
    const cap = commandCapturingClient({
      stdout: [
        "* myapp.service - My Application",
        "     Loaded: loaded (/etc/systemd/system/myapp.service; enabled; preset: enabled)",
        "     Active: failed (Result: exit-code) since Wed 2025-06-04 08:12:03 UTC; 2min ago",
        "    Process: 8123 ExecStart=/usr/local/bin/myapp --serve (code=exited, status=203/EXEC)",
        "        CPU: 3ms",
      ].join("\n"),
      code: 3,
    });

    const status = await serviceStatus(cap.client, "myapp");

    expect(cap.lastCommand()).toBe("systemctl status -- 'myapp' 2>&1");
    expect(status.unknown).toBe(false); // systemctl DID answer
    expect(status.active).toBe(false);
    expect(status.status).toBe("failed (Result: exit-code)");
    expect(status.description).toBe("My Application");
    // `since` stops at the first `;`, so the trailing "2min ago" is not swept in.
    expect(status.since).toBe("Wed 2025-06-04 08:12:03 UTC");
    expect(status.pid).toBeUndefined(); // no `Main PID:` line in this shape
    expect(status.name).toBe("myapp");
    expect(status.raw).toContain("status=203/EXEC");
  });

  it("leaves description undefined for a MASKED unit whose header has no ' - '", async () => {
    // A masked unit's header line is just the unit name -- no " - <description>".
    // The description regex must not fall back to scraping the `Loaded: masked` line
    // (which would report "masked (Reason: ...)" as the service's description).
    const cap = commandCapturingClient({
      stdout: [
        "* postfix.service",
        "     Loaded: masked (Reason: Unit postfix.service is masked.)",
        "     Active: inactive (dead)",
      ].join("\n"),
      code: 3,
    });

    const status = await serviceStatus(cap.client, "postfix");

    expect(status.description).toBeUndefined();
    expect(status.unknown).toBe(false); // the `Active:` line parsed
    expect(status.active).toBe(false);
    expect(status.status).toBe("inactive (dead)");
    expect(status.since).toBeUndefined(); // no "since ...;" in a masked unit's output
    expect(status.pid).toBeUndefined();
    expect(status.raw).toContain("Loaded: masked");
  });
});
