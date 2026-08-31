import type { Client } from "ssh2";
import type { ConnectionPool } from "./pool.js";
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
  const results = await Promise.allSettled(
    hosts.map(async (hostConfig) => {
      return pool.withConnection(hostConfig, async (client) => {
        const result = await exec(client, command, timeoutMs);
        // Spreading the whole ExecResult carries `signal` (and the truncation flags) through
        // per-host without re-listing every field; `signal` is declared on MultiExecResult so
        // the ssh_multi_exec formatter can actually see it.
        return { host: hostConfig.host, ...result };
      });
    }),
  );

  return results.map((result, i) => {
    if (result.status === "fulfilled") {
      return result.value;
    }
    return {
      host: hosts[i].host,
      stdout: "",
      stderr: "",
      code: -1,
      error: result.reason instanceof Error ? result.reason.message : String(result.reason),
    };
  });
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
