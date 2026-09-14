import type { Client } from "ssh2";
import { type ConnectionPool, isPoolFullError, PoolFullError } from "./pool.js";
import { exec } from "./ssh.js";

// POSIX single-quote wrapping. Used by every helper that interpolates user input into
// a remote shell command -- safe against any byte sequence including embedded quotes.
// Exported so tools.ts can build env-var prefixes for ssh_exec without duplicating the rule.
export function shellQuote(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}

// --- Multi-host execution ---

export interface MultiExecResult {
  host: string;
  stdout: string;
  stderr: string;
  code: number;
  /**
   * Signal name (e.g. "TERM") when the remote channel closed via signal instead of exit --
   * mirrors ExecResult.signal (src/ssh.ts). A signal-killed command reports `code: -1`, the
   * same sentinel exec() uses for "no exit code", so without the signal name a caller cannot
   * tell "the remote was killed" from "the channel died". ssh_exec already surfaces it; this
   * field is what lets ssh_multi_exec do the same instead of printing a bare `[exit code: -1]`.
   */
  signal?: string;
  error?: string;
}

export interface MultiExecHost {
  host: string;
  port?: number;
  username?: string;
  privateKeyPath?: string;
  password?: string;
}

export async function multiExec(
  pool: ConnectionPool,
  hosts: MultiExecHost[],
  command: string,
  timeoutMs = 30000,
): Promise<MultiExecResult[]> {
  // Run at most `pool.maxSize` hosts at once. The pool counts in-flight dials against its
  // cap, so firing every host at once would fail everything past the cap with "Connection
  // pool is full". A worker releases its connection (it goes idle) before taking the next
  // host, and the pool evicts that idle entry for the new one, so a fan-out wider than the
  // cap works through the rest as slots free up. A pool-like object with no usable `maxSize`
  // runs unbounded.
  const cap: unknown = (pool as Partial<Pick<ConnectionPool, "maxSize">>).maxSize;
  const limit = typeof cap === "number" && cap >= 1 ? Math.min(hosts.length, Math.floor(cap)) : hosts.length;

  // The pool is shared by every tool, so pacing our OWN workers to the cap is not enough:
  // slots held by other calls (a concurrent ssh_multi_exec, a long ssh_exec) make our
  // acquires reject with PoolFullError. That rejection is backpressure, not a host failure:
  // recording it and moving on used to fail the rest of the queue within microtasks, because
  // every following host was rejected the same way. So a capacity rejection -- and only
  // that; connect and exec errors are recorded as before -- parks the worker on the pool
  // (`waitForCapacity`) and retries the SAME host on every capacity signal. The worker parks
  // here rather than inside `withConnection` so the call can see which of its workers are
  // parked, which the starvation rule below depends on.
  //
  // Starvation rule. The call is declared starved -- the host whose wait ran out records
  // "Connection pool is full", and every host still queued records the same error at once
  // without being attempted -- only when BOTH hold:
  //   1. a full `timeoutMs` has passed since the call's last progress -- the last time any
  //      of its hosts was handed a slot or gave one back (a host finishing, a failed dial
  //      included).
  //   2. none of the call's own hosts holds a slot: every OTHER worker still taking hosts
  //      from the queue is parked on the pool, so none is dialing, joining a dial, or inside
  //      its command. Workers leave the loop when the queue empties, so this compares the
  //      parked count against the workers still in the loop (`running`), not against `limit`.
  // A parked worker waits out what is left of the budget. When it runs out while an own host
  // still holds a slot, the worker parks again for a full `timeoutMs`, as often as it takes:
  // that slot is bounded (a dial by ssh2's readyTimeout on each handshake and, through a
  // ProxyJump, by the jump client's keepalive on the channel-open; a command by exec()'s own
  // `timeoutMs` plus teardown), and its release or failed dial is a capacity signal that
  // wakes the worker to retry at once. Every wait is a real timed park of at least 1ms,
  // never a retry spin. Without rule 2 a call raced its own hosts: a host stamps progress
  // when its fn starts, BEFORE exec() arms its timer, so a sibling parked behind it ran out
  // of budget at the moment that slot came back; and a dial slower than `timeoutMs` stamps
  // nothing until it connects, so a slow first wave starved the call at one timeout flat.
  //
  // Trade-off, made deliberately: the budget is one for the whole call, not per host. A
  // per-host budget let a call whose slots freed only after 2.5x timeout still complete its
  // later hosts -- at the cost of a starved 40-host call settling only after
  // ceil(40 / cap) timeouts (10s at cap 4, timeout 1s), each host waiting its own full budget
  // in turn.
  let lastProgressAt = performance.now();
  // Once set, the call is starved: every host still queued reports this without a dial.
  let starvedError: string | undefined;
  // Aborted with the verdict, so every park of this call ends at once (see the starved branch).
  const starvation = new AbortController();
  // Workers still taking hosts from the queue, and how many of them are parked on the pool.
  // A running worker that is not parked holds a slot, or is a few microtasks from taking or
  // being refused one (see rule 2 above).
  let running = 0;
  let parked = 0;
  const canWait = typeof (pool as Partial<Pick<ConnectionPool, "waitForCapacity">>).waitForCapacity === "function";
  // Written as `>= 1` so a NaN or sub-millisecond timeout still parks for a real 1ms.
  const freshBudgetMs = timeoutMs >= 1 ? timeoutMs : 1;

  const errorResult = (host: string, error: string): MultiExecResult => ({
    host,
    stdout: "",
    stderr: "",
    code: -1,
    error,
  });

  const runHost = async (hostConfig: MultiExecHost): Promise<MultiExecResult> => {
    for (;;) {
      if (starvedError !== undefined) return errorResult(hostConfig.host, starvedError);
      let rejection: PoolFullError;
      try {
        return await pool.withConnection(hostConfig, async (client) => {
          lastProgressAt = performance.now(); // a slot was granted: progress
          try {
            const result = await exec(client, command, timeoutMs);
            // Spreading the whole ExecResult carries `signal` (and the truncation flags) through
            // per-host without re-listing every field; `signal` is declared on MultiExecResult so
            // the ssh_multi_exec formatter can actually see it.
            return { host: hostConfig.host, ...result };
          } finally {
            // A slot is about to be given back: progress too, or a worker coming off a
            // command longer than `timeoutMs` would read the call as starved the moment a
            // foreign caller won the slot it just released.
            lastProgressAt = performance.now();
          }
        });
      } catch (reason: unknown) {
        if (!isPoolFullError(reason)) {
          // The host is finished. A failed dial gave its slot back, which is progress (rule 1):
          // without the stamp a parked sibling would find the budget spent the moment it lost
          // that slot to another caller.
          lastProgressAt = performance.now();
          return errorResult(hostConfig.host, reason instanceof Error ? reason.message : String(reason));
        }
        // A pool-like with no `waitForCapacity` cannot be waited on, and retrying against it
        // would spin, so its capacity rejection is recorded at once like any other error.
        if (!canWait) return errorResult(hostConfig.host, reason.message);
        rejection = reason;
      }

      // Park until a capacity signal (then retry the same host) or until the call is starved.
      for (;;) {
        if (starvedError !== undefined) return errorResult(hostConfig.host, starvedError);
        const remaining = lastProgressAt + timeoutMs - performance.now();
        let waitMs: number;
        if (remaining > 0) {
          waitMs = Math.ceil(remaining); // rule 1 not met yet: wait out the rest of the budget
        } else if (running - parked > 1) {
          // Rule 2 not met: some other worker of this call (this one is running, not parked)
          // holds a slot. Its release or failed dial wakes this park.
          waitMs = freshBudgetMs;
        } else {
          // Starved. The pool's suffix would name only this wait; report the call-level bound
          // instead, the same text for every host.
          starvedError ??= new PoolFullError(rejection.maxPoolSize, timeoutMs).message;
          // End the call's other parks now. A sibling that re-parked for a fresh budget in the
          // same turn -- counted as holding a slot while it was still between its rejection and
          // its park -- would otherwise sit out that whole timer, since nothing in the pool
          // changed to wake it, and the call would settle one `timeoutMs` after the verdict.
          starvation.abort();
          return errorResult(hostConfig.host, starvedError);
        }
        parked++;
        let woken: boolean;
        try {
          woken = await pool.waitForCapacity(waitMs, starvation.signal);
        } finally {
          parked--;
        }
        if (woken) break;
        // Timed out with no capacity signal: no slot freed for a new host since this worker
        // parked (every site that frees one notifies, and the wait re-checks when it parks), so
        // re-apply the rule without another pool call.
      }
    }
  };

  const results = new Array<MultiExecResult>(hosts.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    running++;
    try {
      while (next < hosts.length) {
        const i = next++;
        results[i] = await runHost(hosts[i]);
      }
    } finally {
      running--;
    }
  };

  await Promise.all(Array.from({ length: limit }, worker));
  return results;
}

// --- Remote file search ---

export interface FindOptions {
  path: string;
  name?: string;
  type?: "f" | "d" | "l";
  maxdepth?: number;
  minsize?: string;
  maxsize?: string;
  newer?: string;
}

// GNU findutils -size units: c=bytes, w=2-byte words, b=512-byte blocks
// (default), k=kibibytes, M=mebibytes, G=gibibytes. BSD/macOS find also accepts
// T and P, but GNU does not, so we allow only the intersection-safe GNU set --
// a remote host's find implementation is not known ahead of time.
// Keep the operator-facing strings below in sync with this character class.
const VALID_FIND_SIZE = /^\d+[cwbkMG]?$/;

// find's expression operators that do NOT start with `-`. Both GNU and BSD match these as
// operators only when the operand is EXACTLY the token, so the set is exact-match, not a
// leading-character class: `(archive)/2024` and `!important` are already read as paths and
// must stay untouched.
const FIND_EXPRESSION_TOKENS = new Set(["(", ")", "!", ","]);

export async function find(client: Client, options: FindOptions, timeoutMs = 30000): Promise<string[]> {
  if (options.minsize && !VALID_FIND_SIZE.test(options.minsize)) {
    throw new Error(
      `Invalid minsize format: "${options.minsize}". Expected: digits followed by optional c/w/b/k/M/G (e.g. "1M", "100k")`,
    );
  }
  if (options.maxsize && !VALID_FIND_SIZE.test(options.maxsize)) {
    throw new Error(
      `Invalid maxsize format: "${options.maxsize}". Expected: digits followed by optional c/w/b/k/M/G (e.g. "10M", "500k")`,
    );
  }

  // Two kinds of path operand get reparsed by find's own argument grammar instead of being
  // treated as a path: one starting with `-` (read as an option), and one that is exactly an
  // expression operator -- `(`, `)`, `!` or `,` -- none of which start with `-`. `find '('`
  // fails with "find: paths must precede expression", which surfaces below as a stderr throw.
  // shellQuote alone doesn't help either case -- it only blocks shell-level injection; the
  // operand still reaches find intact.
  //
  // `find -- <path>` fixes both on GNU findutils but is NOT portable: `--` is a GNU
  // extension, and BSD/macOS find treats it as a literal path operand, so the command breaks
  // against a BSD remote. Same reasoning as the VALID_FIND_SIZE set above -- the remote's
  // find implementation is not known ahead of time, so only use what both flavors accept.
  //
  // `./`-prefixing is understood identically by every find implementation: `./-rf` and `./(`
  // are unambiguously path operands, not a flag or an operator. The rewrite is deliberately
  // narrow -- a leading `-`, or an operand that is exactly one of the four operator tokens.
  // Every other path is passed through untouched, so ordinary absolute and relative paths
  // (and the printed results for them) are unchanged.
  const pathOperand =
    options.path.startsWith("-") || FIND_EXPRESSION_TOKENS.has(options.path) ? `./${options.path}` : options.path;
  const args: string[] = [shellQuote(pathOperand)];

  if (options.maxdepth !== undefined) args.push("-maxdepth", String(options.maxdepth));
  if (options.type) args.push("-type", options.type);
  if (options.name) args.push("-name", shellQuote(options.name));
  if (options.minsize) args.push("-size", `+${options.minsize}`);
  if (options.maxsize) args.push("-size", `-${options.maxsize}`);
  if (options.newer) args.push("-newer", shellQuote(options.newer));

  const command = `find ${args.join(" ")}`;
  const result = await exec(client, command, timeoutMs);

  // If find produced no usable output and only errors, surface the error so the
  // caller can tell "empty directory" from "path doesn't exist" or "permission
  // denied". Partial errors (some subtrees denied, others readable) still return
  // the readable results — stderr is dropped in that case.
  if (!result.stdout.trim() && result.stderr.trim()) {
    throw new Error(result.stderr.trim());
  }

  return result.stdout.split("\n").filter(Boolean);
}

// --- Log tailing ---

export async function tail(
  client: Client,
  path: string,
  lines = 100,
  grep?: string,
  timeoutMs = 30000,
): Promise<string> {
  // `--` so a path starting with `-` isn't parsed as a tail flag.
  let command = `tail -n ${lines} -- ${shellQuote(path)}`;
  if (grep) {
    // `-e PATTERN` so a grep pattern starting with `-` isn't parsed as a flag.
    command += ` | grep -i -e ${shellQuote(grep)}`;
  }

  const result = await exec(client, command, timeoutMs);
  // Surface real errors from tail (file missing, permission denied, etc.).
  // grep returning no matches exits with code 1 but writes nothing to stderr —
  // that's not an error and we pass through the empty output.
  if (result.stderr.trim()) {
    throw new Error(result.stderr.trim());
  }
  return result.stdout;
}

// --- Service status ---

export interface ServiceStatus {
  name: string;
  active: boolean;
  status: string;
  description?: string;
  since?: string;
  pid?: number;
  raw: string;
  /**
   * True when systemctl could not report on the unit at all: no `Active:` line
   * parseable AND non-zero exit. Typical causes: typo'd unit name, unit file
   * doesn't exist, systemd unreachable. Distinct from "service exists but is
   * stopped" (active=false but unknown=false).
   */
  unknown: boolean;
}

export async function serviceStatus(client: Client, serviceName: string, timeoutMs = 30000): Promise<ServiceStatus> {
  // `--` so a service name starting with `-` isn't parsed as a systemctl flag.
  const result = await exec(client, `systemctl status -- ${shellQuote(serviceName)} 2>&1`, timeoutMs);
  const raw = result.stdout;

  const activeMatch = raw.match(/Active:\s+(\S+)\s+\(([^)]+)\)/);
  // systemctl puts the description on the UNINDENTED header line, e.g.
  // "* nginx.service - A high performance web server" (optionally led by a status
  // bullet). Match an optional bullet/leading non-word run, the unit token, " - ",
  // then the description. The old /^\s+/ anchor required leading whitespace and so
  // never matched the header (the indented lines below it have no " - " separator),
  // leaving description permanently undefined.
  const descMatch = raw.match(/^[^\w\n]*\S+\s+-\s+(.+)$/m);
  const pidMatch = raw.match(/Main PID:\s+(\d+)/);
  const sinceMatch = raw.match(/since\s+(.+?);/);

  // No `Active:` line + non-zero exit means systemctl could not answer (unit missing,
  // systemd not running, permission denied). That's an error case agents need to
  // distinguish from "service exists but is stopped" -- the latter still has a parseable
  // `Active: inactive (dead)` line and a zero or one exit code depending on systemd version.
  const unknown = !activeMatch && result.code !== 0;
  const fallbackStatus = result.code === 0 ? "active" : "inactive";

  return {
    name: serviceName,
    active: activeMatch?.[1] === "active",
    status: activeMatch ? `${activeMatch[1]} (${activeMatch[2]})` : fallbackStatus,
    description: descMatch?.[1]?.trim(),
    since: sinceMatch?.[1]?.trim(),
    pid: pidMatch ? Number.parseInt(pidMatch[1], 10) : undefined,
    raw,
    unknown,
  };
}
