import { EventEmitter } from "node:events";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock ONLY connectWithProxy. resolveConfig, exec, hostVerifier, etc. keep their real
// implementations, so both the pool's lifecycle logic and multiExec's use of the real
// exec() channel state machine run for real. Same boundary as pool-concurrency.test.ts.
// resolveConfig is wrapped in a pass-through spy (the real function still runs) so a test can
// count which hosts the pool resolved.
vi.mock("../ssh.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../ssh.js")>();
  return {
    ...actual,
    connectWithProxy: vi.fn(),
    resolveConfig: vi.fn(actual.resolveConfig),
  };
});

import { find, type MultiExecHost, multiExec, serviceStatus } from "../ops.js";
import { ConnectionPool, PoolFullError } from "../pool.js";
import { connectWithProxy, exec, resolveConfig } from "../ssh.js";

const mockedConnect = vi.mocked(connectWithProxy);
const resolveSpy = vi.mocked(resolveConfig);

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

describe("multiExec — fan-out wider than the pool cap", () => {
  beforeEach(() => {
    vi.useRealTimers();
    mockedConnect.mockReset();
  });

  it("completes every host as slots free up on a REAL pool, never opening more than maxSize connections, in input order", async () => {
    // The pool counts in-flight dials against maxPoolSize, so firing all six hosts at
    // once would fail four of them with "Connection pool is full". multiExec must pace
    // the fan-out to the cap and let each released (idle) entry be evicted for the next.
    const CAP = 2;
    const hosts: MultiExecHost[] = Array.from({ length: 6 }, (_, i) => ({ host: `wave-${i}.test` }));
    let open = 0;
    let peak = 0;
    mockedConnect.mockImplementation(async (resolved) => {
      const host = String(resolved.connectConfig.host);
      const idx = hosts.findIndex((h) => h.host === host);
      if (idx < 0) throw new Error(`test bug: unexpected host ${host}`);
      open++;
      peak = Math.max(peak, open);
      const client = makeQuietClient() as EventEmitter & { endCalls: number; end: () => void; exec: unknown };
      client.end = () => {
        if (client.endCalls++ === 0) open--;
      };
      client.exec = (_command: string, cb: (err: Error | null, stream: unknown) => void) => {
        const stream = new EventEmitter() as EventEmitter & { stderr: EventEmitter };
        stream.stderr = new EventEmitter();
        cb(null, stream);
        // Later hosts finish sooner, so completion order is NOT input order.
        setTimeout(
          () => {
            stream.emit("data", Buffer.from(`out:${host}\n`));
            stream.emit("close", 0);
          },
          (hosts.length - idx) * 5,
        );
      };
      return client as never;
    });

    const pool = new ConnectionPool({ maxPoolSize: CAP });
    try {
      const results = await multiExec(pool, hosts, "hostname");

      expect(results.map((r) => r.error)).toEqual(hosts.map(() => undefined));
      expect(results.map((r) => r.host)).toEqual(hosts.map((h) => h.host));
      // Each host's OWN output sits at its own index.
      expect(results.map((r) => r.stdout)).toEqual(hosts.map((h) => `out:${h.host}\n`));
      expect(mockedConnect).toHaveBeenCalledTimes(hosts.length);
      // Parallel up to the cap, and never past it.
      expect(peak).toBe(CAP);
    } finally {
      pool.drain();
    }
  });

  it("runs every host concurrently when the pool exposes no usable maxSize", async () => {
    let inFlight = 0;
    let peak = 0;
    const barePool = {
      async withConnection<T>(_config: unknown, fn: (client: never) => Promise<T>): Promise<T> {
        inFlight++;
        peak = Math.max(peak, inFlight);
        await new Promise((r) => setTimeout(r, 5));
        inFlight--;
        return fn(scriptedClient({ stdout: "ok\n" }) as never);
      },
    } as unknown as ConnectionPool;

    const results = await multiExec(barePool, [{ host: "x.test" }, { host: "y.test" }, { host: "z.test" }], "true");

    expect(results.map((r) => r.host)).toEqual(["x.test", "y.test", "z.test"]);
    expect(peak).toBe(3);
  });
});

describe("multiExec — waits for pool capacity held by OTHER callers", () => {
  // The pool is shared by every tool. multiExec pacing its own workers to the cap does not
  // stop a slot held elsewhere from rejecting its acquires; those rejections must be waited
  // out and retried, not recorded as the host's result -- recording them used to fail the
  // rest of the queue within microtasks, one rejected host after another.
  const DIAL_MS = 10;
  const EXEC_MS = 20;

  /** Dials take DIAL_MS, every command takes `execMs` and prints `out:<host>`. Tracks open/peak. */
  function timedConnects(execMs = EXEC_MS) {
    const stats = { open: 0, peak: 0 };
    mockedConnect.mockImplementation(async (resolved) => {
      const host = String(resolved.connectConfig.host);
      await new Promise((r) => setTimeout(r, DIAL_MS));
      stats.open++;
      stats.peak = Math.max(stats.peak, stats.open);
      const client = makeQuietClient() as EventEmitter & { endCalls: number; end: () => void; exec: unknown };
      client.end = () => {
        if (client.endCalls++ === 0) stats.open--;
      };
      client.exec = (_command: string, cb: (err: Error | null, stream: unknown) => void) => {
        const stream = new EventEmitter() as EventEmitter & { stderr: EventEmitter };
        stream.stderr = new EventEmitter();
        cb(null, stream);
        setTimeout(() => {
          stream.emit("data", Buffer.from(`out:${host}\n`));
          stream.emit("close", 0);
        }, execMs);
      };
      return client as never;
    });
    return stats;
  }

  const fleet = (prefix: string, n: number): MultiExecHost[] =>
    Array.from({ length: n }, (_, i) => ({ host: `${prefix}-${i}.test` }));

  beforeEach(() => {
    vi.useRealTimers();
    mockedConnect.mockReset();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("completes every host while one slot is held outside the fan-out", async () => {
    const stats = timedConnects();
    const pool = new ConnectionPool({ maxPoolSize: 3 });
    try {
      // e.g. a long-running ssh_exec holding one of the three slots for the whole fan-out.
      const held = await pool.acquire({ host: "held-outside.test" });
      const hosts = fleet("outside", 9);

      const results = await multiExec(pool, hosts, "hostname");

      expect(results.map((r) => r.error)).toEqual(hosts.map(() => undefined));
      expect(results.map((r) => r.stdout)).toEqual(hosts.map((h) => `out:${h.host}\n`));
      expect(stats.peak).toBeLessThanOrEqual(3);
      pool.release(held);
    } finally {
      pool.drain();
    }
  });

  it("completes both of two concurrent fan-outs that together need twice the cap", async () => {
    timedConnects();
    const pool = new ConnectionPool({ maxPoolSize: 4 });
    try {
      const first = fleet("first", 8);
      const second = fleet("second", 8);

      const [a, b] = await Promise.all([multiExec(pool, first, "hostname"), multiExec(pool, second, "hostname")]);

      expect(a.map((r) => r.error)).toEqual(first.map(() => undefined));
      expect(b.map((r) => r.error)).toEqual(second.map(() => undefined));
      expect(b.map((r) => r.stdout)).toEqual(second.map((h) => `out:${h.host}\n`));
    } finally {
      pool.drain();
    }
  });

  it("still records 'Connection pool is full' once the call has gone timeoutMs without a slot", async () => {
    // multiExec and the pool's wait loop measure the bound with performance.now(). Vitest's
    // fake clock covers it (the default toFake is everything but nextTick / queueMicrotask),
    // so advancing the clock moves the deadline too; a narrower toFake would leave the retry
    // loop re-parking on real time and this test would hang instead of settling at the bound.
    vi.useFakeTimers();
    mockedConnect.mockImplementation(async () => makeQuietClient() as never);
    const pool = new ConnectionPool({ maxPoolSize: 1 });
    try {
      const held = await pool.acquire({ host: "hog.test" }); // never released during the wait
      const BOUND = 1_000;
      let settled = false;
      const run = multiExec(pool, [{ host: "starved.test" }], "true", BOUND).then((r) => {
        settled = true;
        return r;
      });

      await vi.advanceTimersByTimeAsync(BOUND - 1);
      expect(settled).toBe(false); // still waiting inside the bound

      await vi.advanceTimersByTimeAsync(1);
      // Settled at the bound, checked BEFORE awaiting: a wait that overruns it must fail here,
      // not hang to the test timeout with the fake clock never advanced again.
      expect(settled).toBe(true);
      const [result] = await run;
      expect(result).toMatchObject({ host: "starved.test", code: -1 });
      expect(result.error).toMatch(/Connection pool is full/);
      expect(result.error).toContain(`no slot became available to this call within ${BOUND}ms`);
      expect(mockedConnect).toHaveBeenCalledTimes(1); // the starved host never dialed
      // The wait timer is gone -- nothing left armed behind the recorded result.
      expect(vi.getTimerCount()).toBe(0);
      pool.release(held);
    } finally {
      pool.drain();
    }
  });

  it("does not hang when the pool is drained while hosts are waiting for a slot", async () => {
    // Asserted on TIME, not only on the error text: a parked worker whose wait merely ran out
    // retries against the drained pool and records /drained/ just the same, so only settling
    // right at drain() -- with the clock nowhere near the bound -- proves drain() woke it.
    vi.useFakeTimers();
    mockedConnect.mockImplementation(async () => makeQuietClient() as never);
    const pool = new ConnectionPool({ maxPoolSize: 1 });
    try {
      await pool.acquire({ host: "hog-until-shutdown.test" });
      const BOUND = 60_000;
      let settled = false;
      const run = multiExec(pool, [{ host: "queued-1.test" }, { host: "queued-2.test" }], "true", BOUND).then((r) => {
        settled = true;
        return r;
      });
      await vi.advanceTimersByTimeAsync(5); // let the worker hit the full pool and park
      expect(settled).toBe(false);
      expect(vi.getTimerCount()).toBe(1); // parked: its wait timer is the only one armed

      pool.drain();
      await vi.advanceTimersByTimeAsync(1);
      expect(settled).toBe(true); // 1ms after drain(), 59,994ms short of the bound
      const results = await run;
      expect(results.map((r) => r.host)).toEqual(["queued-1.test", "queued-2.test"]);
      for (const r of results) expect(r.error).toBe("ConnectionPool was drained");
    } finally {
      pool.drain();
    }
  });

  it("stops resolving the queued hosts once drain() lands mid-fan-out", async () => {
    // resolveConfig can run a synchronous `ssh -G` spawn per host. drain() wakes the parked
    // workers, and each then runs through every queued host in one microtask chain; a drained
    // check that sat below the resolve paid one spawn per queued host there, stalling the
    // process's shutdown timer behind it. Only the first host of each worker may be resolved.
    vi.useFakeTimers();
    mockedConnect.mockImplementation(async () => makeQuietClient() as never);
    const pool = new ConnectionPool({ maxPoolSize: 2 });
    try {
      await Promise.all(fleet("hog", 2).map((h) => pool.acquire(h))); // held until shutdown
      const hosts = fleet("drained-queue", 6);
      resolveSpy.mockClear();
      let settled = false;
      const run = multiExec(pool, hosts, "true", 60_000).then((r) => {
        settled = true;
        return r;
      });
      await vi.advanceTimersByTimeAsync(5); // both workers hit the full pool and park
      const resolvedHosts = () => resolveSpy.mock.calls.map(([config]) => config.host);
      expect(resolvedHosts()).toEqual([hosts[0].host, hosts[1].host]);

      pool.drain();
      await vi.advanceTimersByTimeAsync(1);
      expect(settled).toBe(true);
      const results = await run;
      expect(results.map((r) => r.error)).toEqual(hosts.map(() => "ConnectionPool was drained"));
      // Neither the woken retries nor the four queued hosts were resolved again.
      expect(resolvedHosts()).toEqual([hosts[0].host, hosts[1].host]);
    } finally {
      pool.drain();
    }
  });

  it("a single-host call arriving mid-fan-out takes the next freed slot instead of being refused for the whole run", async () => {
    // The shared pool's other tenants: a fan-out's workers release and re-acquire within one
    // microtask drain, so a fail-fast caller landing from a macrotask found the pool full at
    // every probe of a 9-host / cap-3 run (measured: rejected at t=5..125ms of ~135ms). With a
    // wait budget it is next in line: notifyCapacity() resolves it synchronously inside
    // release(), so its continuation is queued BEFORE the releasing worker's own, and its
    // retry takes the slot before that worker reaches its next host.
    const stats = timedConnects();
    const pool = new ConnectionPool({ maxPoolSize: 3 });
    try {
      const hosts = fleet("fanout", 9);
      let fanOutSettled = false;
      const fanOut = multiExec(pool, hosts, "hostname").then((r) => {
        fanOutSettled = true;
        return r;
      });

      // Arrive from a macrotask while the first wave is mid-command: every slot is held.
      await new Promise((r) => setTimeout(r, DIAL_MS + EXEC_MS / 2));
      // The default is still fail-fast (the precondition: the pool really is full right now).
      await expect(pool.withConnection({ host: "single.test" }, async () => "never")).rejects.toThrow(PoolFullError);

      const single = await pool.withConnection({ host: "single.test" }, (client) => exec(client, "hostname", 1_000), {
        waitForCapacityMs: 30_000,
      });
      expect(single.stdout).toBe("out:single.test\n");
      expect(fanOutSettled).toBe(false); // it ran INSIDE the fan-out, not after it

      const results = await fanOut;
      expect(results.map((r) => r.error)).toEqual(hosts.map(() => undefined));
      expect(stats.peak).toBeLessThanOrEqual(3);
    } finally {
      pool.drain();
    }
  });

  it("a starved call settles after ONE timeout, not one per host, and reports every host without attempting it", async () => {
    // The budget is call-level: a per-host budget on a serial worker queue made a call whose
    // pool freed nothing settle only after ceil(hosts / cap) timeouts, every host reporting
    // pool-full in turn (measured: cap 4, 4 slots held elsewhere, 40 hosts, 1000ms -> 10000ms).
    vi.useFakeTimers();
    mockedConnect.mockImplementation(async () => makeQuietClient() as never);
    const pool = new ConnectionPool({ maxPoolSize: 4 });
    try {
      const held = await Promise.all(fleet("hog", 4).map((h) => pool.acquire(h))); // held elsewhere
      const hosts = fleet("starved", 40);
      const BOUND = 1_000;
      const attempts = vi.spyOn(pool, "withConnection");
      const start = performance.now();
      let settledAt: number | undefined;
      const run = multiExec(pool, hosts, "true", BOUND).then((r) => {
        settledAt = performance.now();
        return r;
      });

      await vi.advanceTimersByTimeAsync(BOUND - 1);
      expect(settledAt).toBeUndefined(); // still inside the one budget
      // Run the clock well past the old ceil(40 / 4) x BOUND = 10 x BOUND, so a per-host budget
      // fails on the measured number below rather than on the test timeout.
      await vi.advanceTimersByTimeAsync(11 * BOUND);
      expect(settledAt).toBeDefined(); // before awaiting: a regression fails here, not on the test timeout
      const results = await run;
      // One timeout for the call, not one per worker-turn.
      expect((settledAt ?? Number.NaN) - start).toBe(BOUND);

      expect(results.map((r) => r.host)).toEqual(hosts.map((h) => h.host));
      for (const r of results) {
        expect(r.code).toBe(-1);
        expect(r.error).toBe(
          `Connection pool is full (4 connections in use or dialing, the SSH_MCP_MAX_POOL_SIZE cap); no slot became available to this call within ${BOUND}ms. Retry once the calls holding the slots finish, or raise SSH_MCP_MAX_POOL_SIZE in the server's environment.`,
        );
      }
      // Only the first host of each of the min(hosts, cap) workers was ever handed to the pool;
      // the 36 queued behind them were recorded from the starved call without a pool call.
      expect(attempts).toHaveBeenCalledTimes(4);
      expect(mockedConnect).toHaveBeenCalledTimes(4); // the hogs only
      expect(vi.getTimerCount()).toBe(0);
      for (const c of held) pool.release(c);
    } finally {
      pool.drain();
    }
  });

  /**
   * Instant or scripted dials for the self-starvation tests. `slowDials` dial through a fake-clock
   * setTimeout of `dialMs`; every other dial resolves in microtasks, with NO timer, after
   * `dialTicks` microtask hops (default 0). A host in `failDials` then rejects with
   * "connect ETIMEDOUT" instead of connecting. Commands print `out:<host>` and close on a
   * microtask, except on `hangs`, whose stream never closes, so exec() runs to its own timeout.
   */
  function ownHostConnects(opts: {
    hangs?: Set<string>;
    slowDials?: Set<string>;
    failDials?: Set<string>;
    dialMs?: number;
    dialTicks?: number;
  }) {
    mockedConnect.mockImplementation(async (resolved) => {
      const host = String(resolved.connectConfig.host);
      if (opts.slowDials?.has(host)) await new Promise((r) => setTimeout(r, opts.dialMs));
      else for (let i = 0; i < (opts.dialTicks ?? 0); i++) await Promise.resolve();
      if (opts.failDials?.has(host)) throw new Error("connect ETIMEDOUT");
      const client = makeQuietClient() as EventEmitter & { endCalls: number; end: () => void; exec: unknown };
      client.exec = (_command: string, cb: (err: Error | null, stream: unknown) => void) => {
        const stream = new EventEmitter() as EventEmitter & { stderr: EventEmitter };
        stream.stderr = new EventEmitter();
        cb(null, stream);
        if (opts.hangs?.has(host)) return;
        queueMicrotask(() => {
          stream.emit("data", Buffer.from(`out:${host}\n`));
          stream.emit("close", 0);
        });
      };
      return client as never;
    });
  }

  const poolFullCount = (results: { error?: string }[]) =>
    results.filter((r) => /^Connection pool is full \(/.test(r.error ?? "")).length;
  // Distinct hosts, not a call count: with instant dials a woken retry can evict another host's
  // just-registered entry before that host takes its ref, so a host may be dialed more than once.
  const dialedHosts = () => new Set(mockedConnect.mock.calls.map(([resolved]) => String(resolved.connectConfig.host)));

  it("is never starved by its OWN hosts running to the command timeout while a slot is held elsewhere", async () => {
    // The parked worker's budget is stamped when a sibling's fn starts, BEFORE exec() arms its
    // own timer, so the wait ran out at (or a hair before) the moment the sibling's slot came
    // back, and the call reported its whole queue pool-full although the only slots it could not
    // get were its own. The rule now: no starvation verdict while any of the call's hosts holds a
    // slot. The parked worker's deadline and the hanging hosts' exec timers share one due time
    // (both measured from the fn start), and under fake timers a tie fires in creation order. So
    // the dials are INSTANT -- no timer -- but take 50 microtask hops: the queued host's
    // rejection and park finish first, its wait timer is created before the exec timers, and it
    // fires first at T, which is the ordering that starved the call. A dial through setTimeout
    // (even 1ms), or one that connects before the park, flips the order and hides the bug.
    vi.useFakeTimers();
    const T = 200;
    const hosts = fleet("own-hang", 9);
    const hangs = new Set([hosts[0].host, hosts[1].host]);
    ownHostConnects({ hangs, dialTicks: 50 });
    const pool = new ConnectionPool({ maxPoolSize: 3 });
    try {
      const held = await pool.acquire({ host: "held-outside.test" }); // one of the three slots
      let settledAt: number | undefined;
      const start = performance.now();
      const run = multiExec(pool, hosts, "hostname", T).then((r) => {
        settledAt = performance.now();
        return r;
      });

      await vi.advanceTimersByTimeAsync(10 * T);
      expect(settledAt).toBeDefined();
      const results = await run;

      expect(results.map((r) => r.error)).toEqual(
        hosts.map((h) => (hangs.has(h.host) ? `Command timed out after ${T}ms` : undefined)),
      );
      expect(results.map((r) => r.stdout)).toEqual(hosts.map((h) => (hangs.has(h.host) ? "" : `out:${h.host}\n`)));
      expect(poolFullCount(results)).toBe(0);
      expect(dialedHosts()).toEqual(new Set(["held-outside.test", ...hosts.map((h) => h.host)])); // every host dialed
      // The queued hosts ran the moment the hanging ones gave their slots back.
      expect((settledAt ?? Number.NaN) - start).toBe(T);
      pool.release(held);
    } finally {
      pool.drain();
    }
  });

  it("is never starved by its OWN hosts still dialing while a slot is held elsewhere", async () => {
    // A dial in flight holds a slot but stamps no progress until its fn starts, so a first wave
    // of dials slower than the budget starved the call at exactly one timeout: 7 of these 9
    // hosts reported pool-full without a dial. A counter around fn alone does not see a dial;
    // the rule counts every worker of the call that is not parked on the pool.
    vi.useFakeTimers();
    const T = 1_000;
    const SLOW_DIAL = 3_000;
    const hosts = fleet("own-dial", 9);
    const slowDials = new Set([hosts[0].host, hosts[1].host]);
    ownHostConnects({ slowDials, dialMs: SLOW_DIAL });
    const pool = new ConnectionPool({ maxPoolSize: 3 });
    try {
      const held = await pool.acquire({ host: "held-outside.test" });
      let settledAt: number | undefined;
      const start = performance.now();
      const run = multiExec(pool, hosts, "hostname", T).then((r) => {
        settledAt = performance.now();
        return r;
      });

      await vi.advanceTimersByTimeAsync(2 * SLOW_DIAL);
      expect(settledAt).toBeDefined();
      const results = await run;

      expect(results.map((r) => r.error)).toEqual(hosts.map(() => undefined));
      expect(results.map((r) => r.stdout)).toEqual(hosts.map((h) => `out:${h.host}\n`));
      expect(poolFullCount(results)).toBe(0);
      expect(dialedHosts()).toEqual(new Set(["held-outside.test", ...hosts.map((h) => h.host)]));
      expect((settledAt ?? Number.NaN) - start).toBe(SLOW_DIAL);
      pool.release(held);
    } finally {
      pool.drain();
    }
  });

  it("is not starved the moment its own slow dial FAILS and another caller takes the slot it gave back", async () => {
    // A failed dial hands its slot back, which is progress. Unstamped, the call's last progress
    // was its own start, 3x the budget ago, so the instant a foreign caller won that slot the
    // parked hosts read the call as starved and reported pool-full with no wait at all.
    vi.useFakeTimers();
    const T = 1_000;
    const SLOW_DIAL = 3_000;
    const hosts = fleet("own-fail", 3);
    const doomed = new Set([hosts[0].host]);
    ownHostConnects({ slowDials: doomed, failDials: doomed, dialMs: SLOW_DIAL });
    const pool = new ConnectionPool({ maxPoolSize: 2 });
    try {
      const held = await pool.acquire({ host: "held-outside.test" });
      let settledAt: number | undefined;
      const start = performance.now();
      const run = multiExec(pool, hosts, "hostname", T).then((r) => {
        settledAt = performance.now();
        return r;
      });
      // Another caller queues behind the dial on a long budget. The call's parked worker re-parks
      // on every timeout, so this caller is first in line when the dial fails, and wins the slot.
      let foreignSettled = false;
      const foreign = pool.acquire({ host: "foreign-waiter.test" }, { waitForCapacityMs: 60_000 }).finally(() => {
        foreignSettled = true;
      });

      await vi.advanceTimersByTimeAsync(SLOW_DIAL);
      expect(foreignSettled).toBe(true); // before awaiting: a lost wake fails here, not on the test timeout
      const foreignClient = await foreign;
      expect(settledAt).toBeUndefined(); // still waiting with a fresh budget, not starved

      await vi.advanceTimersByTimeAsync(T / 2);
      pool.release(foreignClient);
      await vi.advanceTimersByTimeAsync(1);
      expect(settledAt).toBeDefined();
      const results = await run;

      expect(results[0].error).toMatch(/ETIMEDOUT/);
      expect(results.slice(1).map((r) => r.error)).toEqual([undefined, undefined]);
      expect(results.slice(1).map((r) => r.stdout)).toEqual(hosts.slice(1).map((h) => `out:${h.host}\n`));
      expect(poolFullCount(results)).toBe(0);
      expect((settledAt ?? Number.NaN) - start).toBe(SLOW_DIAL + T / 2);
      pool.release(held);
    } finally {
      pool.drain();
    }
  });

  it("still starves on schedule once its other workers have LEFT the queue, not only while they are parked", async () => {
    // Rule 2 counts the workers still taking hosts, not the pool cap. Here the first worker
    // finishes the only other host and leaves, a foreign caller takes the slot it gave back,
    // and the last host is genuinely starved: it must report pool-full one budget after that
    // release. Measured against `limit`, the departed worker would count as holding a slot
    // forever and the call would never settle.
    vi.useFakeTimers();
    const T = 1_000;
    const DIAL = 1_500;
    const hosts = fleet("left-queue", 2);
    ownHostConnects({ slowDials: new Set([hosts[0].host]), dialMs: DIAL });
    const pool = new ConnectionPool({ maxPoolSize: 2 });
    try {
      const held = await pool.acquire({ host: "held-outside.test" });
      let settledAt: number | undefined;
      const start = performance.now();
      const run = multiExec(pool, hosts, "hostname", T).then((r) => {
        settledAt = performance.now();
        return r;
      });
      // Queues behind the dial on a long budget; the call's parked worker re-parks at T, so this
      // caller is first in line when the first host gives its slot back, and keeps that slot.
      let foreignSettled = false;
      const foreign = pool.acquire({ host: "foreign-waiter.test" }, { waitForCapacityMs: 60_000 }).finally(() => {
        foreignSettled = true;
      });

      await vi.advanceTimersByTimeAsync(DIAL);
      expect(foreignSettled).toBe(true); // before awaiting: a lost wake fails here, not on the test timeout
      const foreignClient = await foreign;
      expect(settledAt).toBeUndefined();

      await vi.advanceTimersByTimeAsync(T);
      expect(settledAt).toBeDefined();
      const results = await run;

      expect(results[0]).toMatchObject({ stdout: `out:${hosts[0].host}\n`, code: 0 });
      expect(results[0].error).toBeUndefined();
      expect(results[1].error).toMatch(/^Connection pool is full \(/);
      expect((settledAt ?? Number.NaN) - start).toBe(DIAL + T);
      pool.release(foreignClient);
      pool.release(held);
    } finally {
      pool.drain();
    }
  });

  it("never trips the bound while the fan-out keeps moving, however long the whole run takes", async () => {
    // Progress resets the budget: with one usable slot for three workers, two are parked at
    // every moment and a host starts or finishes every 310ms, so a 500ms budget is never
    // spent even though the run lasts 1860ms. A budget measured from the call's START would
    // starve it at 500ms with most of the fleet undone. Three workers rather than two on
    // purpose: every wake has one winner and one LOSER that re-parks, and a budget measured
    // per host from its FIRST rejection (rather than from the call's last progress) leaves
    // that loser on its stale deadline -- it starves at 500ms while the winner is still
    // running, which two workers can never show because there is never a loser.
    vi.useFakeTimers();
    const EXEC = 300;
    const BOUND = 500;
    timedConnects(EXEC);
    const pool = new ConnectionPool({ maxPoolSize: 3 });
    try {
      // Two of the three slots, held elsewhere. Their dials are fake-clock setTimeouts too.
      const holding = Promise.all(fleet("hog", 2).map((h) => pool.acquire(h)));
      await vi.advanceTimersByTimeAsync(DIAL_MS);
      const held = await holding;
      const hosts = fleet("moving", 6);
      const start = performance.now();
      let settledAt: number | undefined;
      const run = multiExec(pool, hosts, "hostname", BOUND).then((r) => {
        settledAt = performance.now();
        return r;
      });

      await vi.advanceTimersByTimeAsync(hosts.length * (DIAL_MS + EXEC) + 100);
      expect(settledAt).toBeDefined(); // before awaiting: a regression fails here, not on the test timeout
      const results = await run;

      expect(results.map((r) => r.error)).toEqual(hosts.map(() => undefined));
      expect(results.map((r) => r.stdout)).toEqual(hosts.map((h) => `out:${h.host}\n`));
      // Strictly serial through the one free slot: dial + command per host, nothing overlapped.
      expect((settledAt ?? Number.NaN) - start).toBe(hosts.length * (DIAL_MS + EXEC));
      expect(settledAt !== undefined && settledAt - start > BOUND).toBe(true);
      for (const c of held) pool.release(c);
    } finally {
      pool.drain();
    }
  });

  it("records a capacity rejection at once from a pool-like that cannot be waited on", async () => {
    // multiExec parks on `pool.waitForCapacity`. A pool-like that rejects with a PoolFullError
    // but has no such method must not send the worker into a retry spin for the rest of the
    // budget: with real timers that would be 1000ms of hot looping per host.
    let calls = 0;
    const failFast = {
      maxSize: 2,
      async withConnection() {
        calls++;
        throw new PoolFullError(2);
      },
    } as unknown as ConnectionPool;
    const hosts = fleet("nowait", 5);

    const start = performance.now();
    const results = await multiExec(failFast, hosts, "true", 1_000);

    expect(performance.now() - start).toBeLessThan(500); // settled on microtasks, not the budget
    expect(calls).toBe(hosts.length); // one attempt per host, no retries
    expect(results.map((r) => r.error)).toEqual(
      hosts.map(() => "Connection pool is full (2 connections in use or dialing, the SSH_MCP_MAX_POOL_SIZE cap)"),
    );
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

// ---------------------------------------------------------------------------
// The acquire() retry loop -- the pool's resilience mechanism, and the last
// uncovered region v8 reported in pool.ts. Every branch here fires only when a
// connection dies in the narrow window between connectWithProxy resolving and
// acquire() taking a ref on its entry, which no other test reaches.
// ---------------------------------------------------------------------------

describe("ConnectionPool — the dead-race retry loop", () => {
  beforeEach(() => {
    mockedConnect.mockReset();
  });

  /**
   * A client that marks itself dead the instant the pool registers it: the pool's
   * markDead listener fires on "close", deleting the entry before acquire() can take
   * a ref. That is exactly the race the retry loop exists for.
   */
  function makeSelfClosingClient(): EventEmitter & { endCalls: number; end: () => void } {
    const client = makeQuietClient();
    // Timing is the whole trick. Emitting on a plain queueMicrotask fires BEFORE the
    // pool has attached markDead (the emit is scheduled while connectWithProxy is
    // still resolving), so the entry never gets flagged and no retry happens.
    // Hooking the registration instead puts the close exactly in the race window:
    // the pool has just registered the entry and has NOT yet taken its ref.
    const originalOn = client.on.bind(client);
    client.on = (event: string | symbol, listener: (...a: unknown[]) => void) => {
      const r = originalOn(event as string, listener);
      if (event === "close") queueMicrotask(() => client.emit("close"));
      return r;
    };
    return client;
  }

  it("dials again when the connection dies before acquire can take a ref", async () => {
    let call = 0;
    mockedConnect.mockImplementation(async () => {
      call++;
      // First connection dies in the race window; the second is healthy.
      return (call === 1 ? makeSelfClosingClient() : makeQuietClient()) as never;
    });

    const pool = new ConnectionPool();
    try {
      const client = await pool.acquire({ host: "racy.test" });

      expect(mockedConnect).toHaveBeenCalledTimes(2);
      expect((client as unknown as { endCalls: number }).endCalls).toBe(0);
      expect(pool.size).toBe(1);
      pool.release(client);
    } finally {
      pool.drain();
    }
  });

  it("gives up after MAX_ACQUIRE_ATTEMPTS against a peer that closes every connection", async () => {
    // A pathological peer that accepts then immediately drops. Without the bound the
    // loop would spin forever; the error has to name the host and the attempt count.
    mockedConnect.mockImplementation(async () => makeSelfClosingClient() as never);

    const pool = new ConnectionPool();
    try {
      await expect(pool.acquire({ host: "flapping.test" })).rejects.toThrow(/after 3 attempts/);
      expect(mockedConnect).toHaveBeenCalledTimes(3);
    } finally {
      pool.drain();
    }
  });

  it("carries the underlying cause into the give-up message", async () => {
    mockedConnect.mockImplementation(async () => makeSelfClosingClient() as never);

    const pool = new ConnectionPool();
    try {
      await expect(pool.acquire({ host: "flapping.test" })).rejects.toThrow(
        /connection died before acquire could take a ref/,
      );
    } finally {
      pool.drain();
    }
  });

  it("evicts a dead entry off the fast path instead of handing out a closed client", async () => {
    // Second acquire finds the entry still in the map but flagged dead. It must be
    // deleted and redialed -- returning it would hand the caller a closed socket that
    // fails on first use with an unrelated "Not connected".
    const first = makeQuietClient();
    const second = makeQuietClient();
    let call = 0;
    mockedConnect.mockImplementation(async () => (++call === 1 ? first : second) as never);

    const pool = new ConnectionPool();
    try {
      const a = await pool.acquire({ host: "reaped.test" });
      pool.release(a);
      first.emit("close"); // the server hung up while the entry sat idle

      const b = await pool.acquire({ host: "reaped.test" });

      expect(b).not.toBe(a);
      expect(mockedConnect).toHaveBeenCalledTimes(2);
      pool.release(b);
    } finally {
      pool.drain();
    }
  });
});

// Two distinct on-disk keys. resolveConfig reads privateKeyPath verbatim, so the
// FILE CONTENT is what reaches the fingerprint -- the paths must differ in body,
// not just in name.
const KEY_DIR = mkdtempSync(join(tmpdir(), "pool-keys-"));
const KEY_A = join(KEY_DIR, "a");
const KEY_B = join(KEY_DIR, "b");
writeFileSync(KEY_A, "-----BEGIN OPENSSH PRIVATE KEY-----aaaa-----END OPENSSH PRIVATE KEY-----");
writeFileSync(KEY_B, "-----BEGIN OPENSSH PRIVATE KEY-----bbbb-----END OPENSSH PRIVATE KEY-----");

describe("ConnectionPool — the auth fingerprint covers key material too", () => {
  beforeEach(() => {
    mockedConnect.mockReset();
    mockedConnect.mockImplementation(async () => makeQuietClient() as never);
  });

  it("does not share one pooled connection across two different private keys", async () => {
    // The password case is covered elsewhere; the privateKey arm of the fingerprint
    // was never executed. Two keys to the same host must not collide, or the second
    // caller silently rides the first caller's authenticated session.
    const pool = new ConnectionPool();
    try {
      const a = await pool.acquire({ host: "keyed.test", privateKeyPath: KEY_A });
      const b = await pool.acquire({ host: "keyed.test", privateKeyPath: KEY_B });

      expect(a).not.toBe(b);
      expect(pool.size).toBe(2);
      pool.release(a);
      pool.release(b);
    } finally {
      pool.drain();
    }
  });

  it("DOES reuse the connection when the same key is presented twice", async () => {
    const pool = new ConnectionPool();
    try {
      const a = await pool.acquire({ host: "keyed.test", privateKeyPath: KEY_A });
      pool.release(a);
      const b = await pool.acquire({ host: "keyed.test", privateKeyPath: KEY_A });

      expect(b).toBe(a);
      expect(mockedConnect).toHaveBeenCalledTimes(1);
      pool.release(b);
    } finally {
      pool.drain();
    }
  });
});
