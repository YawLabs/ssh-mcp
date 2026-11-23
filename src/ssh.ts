import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  Client,
  type ClientChannel,
  type ConnectConfig,
  type ServerHostKeyAlgorithm,
  type SFTPWrapper,
  type Stats,
} from "ssh2";
import {
  agentStartSuggestion,
  checkKnownHosts,
  checkSshAgent,
  checkSshConfig,
  checkSshKeys,
  type DiagnosticResult,
  isStrictHostKeyMode,
  isValidHostname,
  keyscanCommand,
  runArgs,
  WINDOWS_AGENT_PIPE,
} from "./diagnose.js";
import { parseSshConfigOutput } from "./ssh-config.js";

export interface SSHConfig {
  host: string;
  port?: number;
  username?: string;
  privateKeyPath?: string;
  password?: string;
  agent?: string;
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  code: number;
  /** True when stdout was truncated at the byte cap. */
  stdoutTruncated?: boolean;
  /** True when stderr was truncated at the byte cap. */
  stderrTruncated?: boolean;
  /** Signal name (e.g. "TERM") if the remote channel closed via signal instead of exit. */
  signal?: string;
}

interface SshConfigResult {
  hostname: string;
  user: string;
  port: string;
  identityFiles: string[];
  proxyJump?: string;
}

/** Why the hostVerifier turned a server's host key down. */
export type HostKeyRejectionReason =
  /** No known_hosts entry at all, and strict mode is on (SSH_MCP_STRICT_HOSTKEYS, see isStrictHostKeyMode). */
  | "unknown-host-strict"
  /** known_hosts has entries for this host, but none of the algorithm the server offered. */
  | "algorithm-not-in-known-hosts"
  /** known_hosts has an entry of the offered algorithm and the bytes differ. */
  | "key-mismatch";

export interface HostKeyRejection {
  reason: HostKeyRejectionReason;
  message: string;
}

export interface ResolvedConfig {
  connectConfig: ConnectConfig;
  proxyJump?: string;
  /**
   * Side channel written by `connectConfig.hostVerifier` when it rejects a key.
   * ssh2 reports every rejection with the same opaque "Host denied (verification
   * failed)" string (lib/protocol/kex.js), so the verifier records the reason here
   * and `enhanceSshError` folds it into the thrown error.
   */
  hostKeyRejection?: { current: HostKeyRejection | null };
  /**
   * Materializes `connectConfig.algorithms` (the host-key preference order).
   * DELIBERATELY LAZY -- see the comment at its definition in `resolveConfig`.
   * `connectWithProxy` calls it immediately before dialing; nothing else should,
   * because nothing else can use the answer. Idempotent, and absent on a
   * hand-built ResolvedConfig, so callers use `?.()`.
   */
  applyHostKeyAlgorithms?: () => void;
}

// `ssh -G <host>` is a synchronous subprocess spawn costing ~0.3-0.9s (worst on
// Windows). resolveConfig() runs on EVERY pool acquire, including hits on an
// already-warm pooled connection, so without this memo N concurrent acquires of
// one host pay N spawns for an answer that cannot differ between them. A
// SUCCESSFUL answer is cached for process lifetime: ssh_config is read at
// startup-ish cadence and a running server is expected to be restarted after
// config edits. A FAILED probe is cached only briefly (SSH_CONFIG_FAILURE_TTL_MS):
// caching it for the process lifetime would let one transient failure (runArgs'
// 10s timeout, a slow `Match exec`) drop that host's HostName / User / Port /
// IdentityFile / ProxyJump until restart, while not caching it at all made a
// DETERMINISTIC failure (e.g. a macOS-only `UseKeychain` line -> "Bad configuration
// option", exit 255) pay a blocking spawn on every single acquire.
const SSH_CONFIG_FAILURE_TTL_MS = 30_000;
const sshConfigCache = new Map<string, SshConfigResult>();
const sshConfigFailures = new Map<string, number>();

/** Test-only: drop memoized `ssh -G` results so a suite can vary ssh_config. */
export function clearSshConfigCache(): void {
  sshConfigCache.clear();
  sshConfigFailures.clear();
}

function resolveFromSshConfig(host: string): SshConfigResult | null {
  const cached = sshConfigCache.get(host);
  if (cached) return cached;
  const failedAt = sshConfigFailures.get(host);
  if (failedAt !== undefined && Date.now() - failedAt < SSH_CONFIG_FAILURE_TTL_MS) return null;
  const result = resolveFromSshConfigUncached(host);
  if (result) {
    sshConfigCache.set(host, result);
    sshConfigFailures.delete(host);
  } else {
    sshConfigFailures.set(host, Date.now());
  }
  return result;
}

function resolveFromSshConfigUncached(host: string): SshConfigResult | null {
  // Validate before spawning, and put `--` before the host as well: a host such as
  // `-E/path` or `-oProxyCommand=x` must never reach ssh as an option. IPv6 is
  // checked in its bracketed form, the only shape isValidHostname recognizes.
  const bare = unbracketHost(host);
  if (!isValidHostname(bare.includes(":") ? `[${bare}]` : bare)) return null;
  // runArgs never throws (it folds every spawn failure into ok:false) and the
  // parser is pure string work, so there is nothing here to catch.
  const { stdout, ok } = runArgs("ssh", ["-G", "--", host]);
  if (!ok) return null;

  const { all, identityFiles } = parseSshConfigOutput(stdout);

  return {
    hostname: all.hostname || host,
    user: all.user || "",
    port: all.port || "22",
    identityFiles,
    proxyJump: all.proxyjump && all.proxyjump !== "none" ? all.proxyjump : undefined,
  };
}

/**
 * Expand a leading `~` the way a shell does for the CURRENT user only: `~` alone,
 * `~/...`, and on Windows `~\...`. Every other spelling is returned untouched --
 * `~alice/.ssh/id` names another user's home (which we cannot resolve portably) and
 * `~backup.key` is a relative file whose name starts with a tilde; joining either
 * onto our own home produced an ENOENT for a path the caller never named.
 */
export function expandTilde(path: string, home: string = homedir()): string {
  if (path === "~") return home;
  if (path.startsWith("~/") || (process.platform === "win32" && path.startsWith("~\\"))) {
    return join(home, path.slice(2));
  }
  return path;
}

/**
 * Strip the brackets off an IPv6 literal. Both spellings reach us: a caller may
 * pass `[::1]` (the form `isValidHostname` accepts), while `ssh -G '[::1]'`
 * answers `hostname ::1`, so `resolveConfig` also carries the bare form.
 */
export function unbracketHost(host: string): string {
  return host.length > 2 && host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

/**
 * The known_hosts spellings `ssh-keygen -F` will actually match, in lookup order.
 *
 * Verified against OpenSSH's ssh-keygen: for a default-port entry the address is
 * stored (and looked up) BARE -- `-F '::1'` hits a `::1` line while `-F '[::1]'`
 * misses it -- and for a non-default port it is `[::1]:2222`, never the
 * double-bracketed `[[::1]]:2222` the old `[${host}]:${port}` template produced
 * when handed an already-bracketed host.
 *
 * Returns [] when the host fails injection validation. IPv6 is validated in its
 * bracketed form because that is the only shape `isValidHostname` recognizes
 * (its plain-host regex has no ':'), which is why a bare `::1` -- the exact
 * string `ssh -G` hands back -- used to fail validation and silently yield no
 * known_hosts keys at all.
 */
export function knownHostsTargets(host: string, port?: number): string[] {
  const bare = unbracketHost(host);
  const isIpv6 = bare.includes(":");
  if (!isValidHostname(isIpv6 ? `[${bare}]` : bare)) return [];
  return port && port !== 22 ? [`[${bare}]:${port}`, bare] : [bare];
}

export interface KnownHostEntry {
  /** Host key type as recorded in known_hosts, e.g. "ssh-ed25519" or "ssh-rsa". */
  type: string;
  /** Raw public key blob (base64-decoded). */
  key: Buffer;
}

// Looks up entries via `ssh-keygen -F` so hashed known_hosts lines (|1|...) resolve
// transparently without us reimplementing HMAC.
//
// Returns the entries for EVERY spelling knownHostsTargets yields (for a non-22
// port: `[host]:port` and the bare host). Neither the accept/reject decision nor
// the algorithm ordering may use that union -- see buildHostVerifier and
// cachedKnownHostTypes, which both prefer the port-qualified entries.
export function readKnownHostsEntries(host: string, port?: number): KnownHostEntry[] {
  return knownHostsTargets(host, port).flatMap(readKnownHostsTarget);
}

/**
 * Entries for ONE known_hosts target spelling (one `ssh-keygen -F` lookup). The
 * target must come from knownHostsTargets, which is what validates it.
 */
function readKnownHostsTarget(target: string): KnownHostEntry[] {
  const entries: KnownHostEntry[] = [];
  const { stdout, ok } = runArgs("ssh-keygen", ["-F", target]);
  if (!ok || !stdout.trim()) return entries;
  for (const line of stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    // Format: <host-or-hash> <keytype> <base64> [comment]
    const parts = trimmed.split(/\s+/);
    // ...UNLESS the line carries a marker. `ssh-keygen -F` echoes matching lines
    // VERBATIM, and a marker line has an extra LEADING field, so every index
    // shifts by one: for "@cert-authority *.corp.example.com ssh-ed25519 AAAA..."
    // parts[1] is the host PATTERN (stored as if it were the key type) and parts[2]
    // is the literal string "ssh-ed25519". The visible symptom was a rejection
    // message naming a host pattern where a key type belongs.
    //
    // Skipping them is a security fix as much as a parse one: a @cert-authority
    // line holds a CA's key, not this host's, and a @revoked line records a key
    // that must NEVER be accepted as valid.
    if (parts[0].startsWith("@")) continue;
    if (parts.length < 3) continue;
    // Node's base64 decoder never throws -- it drops characters it does not know --
    // so a corrupt line still "decodes", to junk. A junk entry would make the host
    // count as KNOWN and then reject every key it is offered. The blob carries its
    // own algorithm name, so keep the entry only when that agrees with the type
    // column; anything else is not a usable host key.
    const key = Buffer.from(parts[2], "base64");
    if (hostKeyBlobType(key) !== parts[1]) continue;
    entries.push({ type: parts[1], key });
  }
  return entries;
}

export function readKnownHostsKeys(host: string, port?: number): Buffer[] {
  return readKnownHostsEntries(host, port).map((e) => e.key);
}

/**
 * Parse the algorithm name out of an SSH public-key blob. The wire format always
 * begins with an SSH string: a uint32 big-endian length followed by that many
 * bytes, e.g. "ssh-ed25519". Returns null if the blob is not shaped like one.
 */
export function hostKeyBlobType(key: Buffer): string | null {
  if (key.length < 4) return null;
  const len = key.readUInt32BE(0);
  if (len === 0 || len > 64 || key.length < 4 + len) return null;
  const type = key.toString("utf8", 4, 4 + len);
  return /^[a-zA-Z0-9@._-]+$/.test(type) ? type : null;
}

// A known_hosts entry records the host key TYPE; the KEX negotiates a host-key
// ALGORITHM. The two strings are identical except for RSA, where RFC 8332 defines
// rsa-sha2-256 / rsa-sha2-512 as different SIGNATURE algorithms over the same
// ssh-rsa key -- so one ssh-rsa known_hosts line makes all three preferable.
const HOST_KEY_TYPE_TO_ALGORITHMS: Readonly<Record<string, readonly string[]>> = {
  "ssh-rsa": ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"],
};

// The one specifier both routes below load. Kept as a shared constant ONLY so the
// two spellings can never drift apart -- route 1 must keep the string LITERAL at
// its call site (that is the whole point), so this is deliberately not used there.
const SSH2_CONSTANTS_MODULE = "ssh2/lib/protocol/constants.js";

/**
 * Load ssh2's internal constants module, which is the only place it publishes its
 * negotiable host-key algorithm list (`require("ssh2")` re-exports Client / Server
 * / utils and nothing else). Its package.json has `main` and no `exports` map, so
 * the deep path resolves today; if that ever stops being true, every route here
 * fails and the caller skips the reorder entirely (no behavior change) rather than
 * hardcoding a list that could drift out of sync with the installed ssh2 and make
 * connect() throw "Unsupported algorithm".
 *
 * TWO routes, because the two builds this ships in have opposite needs and neither
 * route covers both:
 *
 *  1. A LITERAL `require(...)`. esbuild resolves that specifier at BUILD time, so
 *     a single-file binary build (bundle:true, format:cjs) INLINES the constants
 *     module into the binary -- which has no node_modules to resolve against at
 *     runtime. Route 2 alone was therefore dead in every Homebrew/Scoop binary:
 *     `createRequire(import.meta.url)` is opaque to any bundler, so it threw
 *     there, returned null, and the whole reorder silently no-opped. In the tsup
 *     ESM build ssh2 stays EXTERNAL and esbuild rewrites this call into its
 *     `__require` shim, which throws "Dynamic require ... is not supported" under
 *     a real ESM loader -- hence the try, and hence route 2.
 *  2. `createRequire(import.meta.url)`. The route that works in the published ESM
 *     dist (and under vitest / tsx), and the one a single-file binary cannot use.
 *
 * Verified by bundling this exact shape with both configurations: the CJS bundle
 * inlines the module and route 1 answers with no node_modules reachable at all,
 * while the ESM bundle keeps ssh2 external and falls through to route 2.
 */
function loadSsh2Constants(): { DEFAULT_SERVER_HOST_KEY?: unknown } | null {
  try {
    // Route 1 -- do NOT hoist this specifier into a variable: a bundler can only
    // follow a string literal, and hiding it behind SSH2_CONSTANTS_MODULE would
    // reintroduce exactly the invisibility this exists to fix.
    return require("ssh2/lib/protocol/constants.js");
  } catch {
    // Not a bundled/CJS context (`require` is undefined under a real ESM loader,
    // and esbuild's ESM shim throws for the same reason) -- try route 2.
  }
  try {
    return createRequire(import.meta.url)(SSH2_CONSTANTS_MODULE);
  } catch {
    return null;
  }
}

let ssh2DefaultHostKeyAlgos: string[] | null | undefined;
function defaultServerHostKeyAlgorithms(): string[] | null {
  if (ssh2DefaultHostKeyAlgos !== undefined) return ssh2DefaultHostKeyAlgos;
  const DEFAULT_SERVER_HOST_KEY = loadSsh2Constants()?.DEFAULT_SERVER_HOST_KEY;
  ssh2DefaultHostKeyAlgos =
    Array.isArray(DEFAULT_SERVER_HOST_KEY) &&
    DEFAULT_SERVER_HOST_KEY.length > 0 &&
    DEFAULT_SERVER_HOST_KEY.every((a) => typeof a === "string")
      ? (DEFAULT_SERVER_HOST_KEY as string[]).slice()
      : null;
  return ssh2DefaultHostKeyAlgos;
}

/**
 * Order the host-key algorithms so the ones we hold a known_hosts entry for are
 * negotiated first -- what OpenSSH does, and the reason it does not reject a host
 * whose known_hosts line is ecdsa while the server would rather offer ed25519.
 *
 * This is a PREFERENCE, never a restriction: the result is a permutation of
 * ssh2's own default list, so exactly the same algorithm set stays negotiable and
 * no reachable host becomes unconnectable. Deliberately built from ssh2's DEFAULT
 * list rather than its SUPPORTED list -- the latter additionally contains ssh-dss,
 * which ssh2 disables by default and we are not in the business of re-enabling.
 *
 * Returns null when there is nothing to do (no known_hosts types, ssh2's list
 * unreadable, or the preferred set already covers all-or-none of the defaults),
 * in which case the caller leaves `algorithms` unset.
 */
export function hostKeyAlgorithmOrder(knownHostTypes: ReadonlyArray<string>): string[] | null {
  if (knownHostTypes.length === 0) return null;
  const defaults = defaultServerHostKeyAlgorithms();
  if (!defaults) return null;

  const preferred = new Set<string>();
  for (const type of knownHostTypes) {
    for (const algo of HOST_KEY_TYPE_TO_ALGORITHMS[type] ?? [type]) preferred.add(algo);
  }

  const front = defaults.filter((a) => preferred.has(a));
  const back = defaults.filter((a) => !preferred.has(a));
  if (front.length === 0 || back.length === 0) return null;
  return [...front, ...back];
}

// `ssh-keygen -F` is a subprocess spawn (~0.2s each), so memoize the key TYPES
// briefly for the dial path -- one bastion fronting N targets, a pool retry after a
// dead connection, or two credentials against one host all dial the same host in
// quick succession. This memo is NOT what keeps the cost off a warm pool acquire:
// that is `applyHostKeyAlgorithms` being lazy (see resolveConfig), so nothing here
// runs at all unless we are actually connecting.
//
// This memo feeds the algorithm-PREFERENCE ordering only -- never the accept /
// reject decision, which buildHostVerifier always recomputes from a fresh read.
// A stale entry here can therefore only produce a slightly suboptimal negotiation
// order, never a wrong security outcome. Kept short so a mid-session
// `ssh-keyscan >> known_hosts` is picked up almost immediately.
const KNOWN_HOST_TYPE_TTL_MS = 5000;
const knownHostTypeCache = new Map<string, { at: number; types: string[] }>();

/** Test-only: drop the memoized known_hosts key types. */
export function clearKnownHostTypeCache(): void {
  knownHostTypeCache.clear();
}

// The types come from the SAME entry set buildHostVerifier decides with. For a
// non-22 port that means: the `[host]:port` entries ALONE when any exist (they are
// authoritative, and only they can accept), else the bare-host fallback entries.
// Ordering from the union instead -- `[h]:2222 ssh-rsa` plus a bare `h ssh-ed25519`
// line for the port-22 sshd -- negotiated ed25519 first, and the verifier then
// rejected that key as algorithm-not-in-known-hosts because the bare entry cannot
// accept once a port-qualified one exists. OpenSSH orders from the port-qualified
// entries the same way.
function cachedKnownHostTypes(hosts: ReadonlyArray<string>, port: number | undefined): string[] {
  const cacheKey = `${hosts.join(" ")}:${port ?? ""}`;
  const now = Date.now();
  const hit = knownHostTypeCache.get(cacheKey);
  if (hit && now - hit.at < KNOWN_HOST_TYPE_TTL_MS) return hit.types;
  const targets = hosts.map((h) => knownHostsTargets(h, port)).filter((t) => t.length > 0);
  let entries = targets.flatMap((t) => readKnownHostsTarget(t[0]));
  if (entries.length === 0) entries = targets.flatMap((t) => t.slice(1).flatMap(readKnownHostsTarget));
  const types = [...new Set(entries.map((e) => e.type))];
  knownHostTypeCache.set(cacheKey, { at: now, types });
  return types;
}

// Build a hostVerifier that compares the server's key against ~/.ssh/known_hosts.
// - Known host, key matches: accept.
// - Known host, key mismatch: reject (MITM protection).
// - Unknown host: ACCEPT unless strict mode is on (isStrictHostKeyMode), then reject.
//
// That last branch is trust-ALWAYS, not trust-on-first-use, and the distinction is
// worth stating plainly: real TOFU pins the key it saw the first time and rejects a
// change afterwards. We never write to known_hosts, so nothing is ever pinned by
// connecting -- every connection to a host absent from known_hosts is a "first" use
// and is accepted, including one where an attacker swapped the key since the last
// call. Only hosts a user (or ssh-keyscan) put into known_hosts out of band get MITM
// protection. Set SSH_MCP_STRICT_HOSTKEYS=1 to require an entry.
//
// Checks known_hosts under both the user-supplied host (e.g. a ssh_config alias) and
// the resolved hostname, matching OpenSSH's CheckHostIP behavior. For a non-22 port
// only the `[host]:port` entries can reject; a bare-host entry can only accept (see
// the comment inside buildHostVerifier).
// isStrictHostKeyMode lives in diagnose.ts so the ssh_test / ssh_diagnose probe
// can honour it too (diagnose.ts cannot import this module); re-exported here.
// keyscanCommand lives in diagnose.ts (one implementation for both modules) and
// is re-exported here for callers that import it from ssh.js.
export { isStrictHostKeyMode, keyscanCommand };

function buildHostVerifier(
  hosts: ReadonlyArray<string>,
  port: number | undefined,
  rejection: { current: HostKeyRejection | null },
  remediation: { host: string; port: number | undefined },
): (key: Buffer) => boolean {
  const strict = isStrictHostKeyMode();
  const label = port && port !== 22 ? `${hosts.join(" / ")} (port ${port})` : hosts.join(" / ");
  // Built from the RESOLVED hostname and port, not hosts[0] (the caller's alias,
  // port-less): see keyscanCommand.
  const keyscan = keyscanCommand(remediation.host, remediation.port);
  // Per verifier host: [authoritative spelling, ...fallback spellings]. For port 22
  // that is just the bare host; otherwise `[host]:port`, then the bare host.
  const targets = hosts.map((h) => knownHostsTargets(h, port)).filter((t) => t.length > 0);
  return (key: Buffer) => {
    rejection.current = null;
    // OpenSSH semantics for a non-default port. The port-qualified `[host]:port`
    // entries are AUTHORITATIVE: if any exist, they alone decide accept vs reject.
    // A bare-host entry describes whatever answers on port 22 -- often a different
    // sshd than the one on :2222 (a git server, a container) -- so it may ACCEPT a
    // key it matches, but it is never grounds for a reject: merging the two sets
    // used to turn an unknown second sshd into a hard "key-mismatch". With no
    // authoritative entry and no fallback match, the host is UNKNOWN, exactly like
    // a host absent from known_hosts (accepted, or rejected under strict mode).
    const known: Array<KnownHostEntry & { target: string }> = targets.flatMap((t) =>
      readKnownHostsTarget(t[0]).map((e) => ({ ...e, target: t[0] })),
    );
    if (known.length === 0) {
      const fallback = targets.flatMap((t) => t.slice(1).flatMap(readKnownHostsTarget));
      if (fallback.some((e) => e.key.equals(key))) return true;
      if (strict) {
        rejection.current = {
          reason: "unknown-host-strict",
          message: `no known_hosts entry for ${label}, and strict mode (SSH_MCP_STRICT_HOSTKEYS=1) requires one. Add it: ${keyscan}`,
        };
      }
      return !strict;
    }
    if (known.some((e) => e.key.equals(key))) return true;

    // Rejected -- record WHICH kind of rejection. ssh2 collapses both into the same
    // "Host denied (verification failed)" error, and sending an operator to hunt a
    // man-in-the-middle when the real cause is a missing entry for the algorithm the
    // server happened to offer costs far more than this branch does.
    const offered = hostKeyBlobType(key);
    const knownTypes = [...new Set(known.map((e) => e.type))];
    if (offered && !knownTypes.includes(offered)) {
      rejection.current = {
        reason: "algorithm-not-in-known-hosts",
        message: `the server offered a ${offered} host key, but known_hosts has only ${knownTypes.join(", ")} for ${label}. This is NOT a key mismatch -- there is no ${offered} entry to compare it against. Refresh the entry: ${keyscan}`,
      };
      return false;
    }
    // The `-R` target is the exact spelling the conflicting entry was found under
    // (`[host]:port` for a non-22 port; bare otherwise, IPv6 included). The caller's
    // port-less spelling would remove the port-22 line and leave the stale one.
    const sameType = known.filter((e) => e.type === offered);
    const removeTargets = [...new Set((sameType.length > 0 ? sameType : known).map((e) => e.target))];
    const removal = removeTargets.map((t) => `ssh-keygen -R "${t}"`).join(" and ");
    rejection.current = {
      reason: "key-mismatch",
      message: `the server's ${offered ?? "offered"} host key does NOT match the known_hosts entry of the same type for ${label}. This can mean a man-in-the-middle attack, or that the host was legitimately rekeyed. Verify the fingerprint out of band before removing the old entry with: ${removal}`,
    };
    return false;
  };
}

// Does this file even CLAIM to be a private key? Only the armor is inspected. An
// empty file carries none, and neither does a `.pub` (the classic `IdentityFile
// ~/.ssh/id_ed25519.pub` typo), a stray known_hosts, or any text file left at a
// key's path. The identity walk skips whatever fails this WHETHER OR NOT an agent
// is configured -- unlike the encrypted-key skip below, this one is not a heuristic
// about which credential to prefer: such a file is not a key in any format, so
// offering it can only shadow the real key further down the list and hand ssh2
// bytes it must error on.
//
// The marker set is deliberately WIDER than what ssh2 can parse (PKCS#8 and the
// PuTTY header included). The question here is "is a key present at all", not "will
// ssh2 like it" -- a file that genuinely holds a key should reach ssh2 so that ITS
// error is what the user sees, rather than vanishing behind a silent skip. A
// zero-byte file needs no special case: it carries no marker, so it fails here like
// any other non-key.
const PRIVATE_KEY_MARKER = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;
function looksLikePrivateKey(content: Buffer): boolean {
  const text = content.toString("utf8");
  return PRIVATE_KEY_MARKER.test(text) || text.trimStart().startsWith("PuTTY-User-Key-File-");
}

// Heuristic: is this private-key file passphrase-encrypted -- or malformed in a way
// that makes it unusable? An encrypted key is useless in a non-interactive ssh2
// connect (it errors with "no passphrase given"), so we must not fold one in
// alongside the agent -- the common setup is an encrypted key on disk with its
// decrypted copy held in the agent. Detects the classic PEM markers (Proc-Type/
// DEK-Info, PKCS#8 "BEGIN ENCRYPTED PRIVATE KEY") and reads the ciphername field of
// the OpenSSH new format ("none" => unencrypted).
//
// A file wearing OPENSSH armor whose body is NOT a valid openssh-key-v1 container
// answers true as well, and BOTH ways of being malformed land there. The magic
// mismatch is the reachable one: Node's base64 decoder is LENIENT -- it drops
// characters it does not recognise instead of throwing -- so a corrupted body still
// decodes, just to bytes whose magic does not match. The catch needs a container
// truncated to ~17 bytes, where the magic survives but the length field does not.
// Answering "encrypted" for both is what makes the caller's `agentSock &&` skip keep
// such a file away from ssh2, instead of letting it kill a connect the agent alone
// would have completed. With no agent the caller loads it regardless and ssh2 still
// surfaces its own parse error -- there is nothing else left to offer.
function isEncryptedKey(content: Buffer): boolean {
  const text = content.toString("utf8");
  if (text.includes("ENCRYPTED")) return true;
  const m = text.match(/-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END/);
  if (m) {
    try {
      const raw = Buffer.from(m[1].replace(/\s+/g, ""), "base64");
      const magic = "openssh-key-v1\0";
      if (raw.toString("latin1", 0, magic.length) !== magic) return true; // malformed container
      const cipherLen = raw.readUInt32BE(magic.length);
      const cipher = raw.toString("latin1", magic.length + 4, magic.length + 4 + cipherLen);
      return cipher !== "none";
    } catch {
      return true; // unparseable -> be conservative, don't fold it in
    }
  }
  return false;
}

export function resolveConfig(config: SSHConfig): ResolvedConfig {
  // Resolve SSH config for the host (hostname aliases, user, port, identity files, proxy)
  const sshConfig = resolveFromSshConfig(config.host);

  const port = config.port || (sshConfig ? Number.parseInt(sshConfig.port, 10) : 22);
  // Dedupe on the unbracketed form, not the raw string: `ssh -G '[::1]'` answers
  // `hostname ::1`, so the two spellings of one IPv6 literal would otherwise both
  // land here and every known_hosts lookup would run (and report) twice.
  const verifierHosts: string[] = [];
  const seenHosts = new Set<string>();
  for (const candidate of [config.host, sshConfig?.hostname]) {
    if (!candidate) continue;
    const canonical = unbracketHost(candidate);
    if (seenHosts.has(canonical)) continue;
    seenHosts.add(canonical);
    verifierHosts.push(candidate);
  }
  const hostKeyRejection: { current: HostKeyRejection | null } = { current: null };
  const dialHost = sshConfig?.hostname || config.host;
  // Username fallback chain: explicit > ssh_config User > $USER/$USERNAME > "root".
  // The trailing "root" is a last-ditch default for env-stripped contexts (containers
  // without USER/USERNAME and without ssh installed for `ssh -G` to provide a user).
  // In those cases the SSH server's "Permission denied" is the source of truth -- we
  // don't try to second-guess it client-side.
  const connectConfig: ConnectConfig = {
    host: dialHost,
    port,
    username: config.username || sshConfig?.user || process.env.USER || process.env.USERNAME || "root",
    keepaliveInterval: 15_000,
    keepaliveCountMax: 3,
    hostVerifier: buildHostVerifier(verifierHosts, port, hostKeyRejection, { host: dialHost, port }),
  };

  // Prefer the host-key algorithms we already have a known_hosts entry for, the way
  // OpenSSH orders HostKeyAlgorithms from known_hosts. Without this, a host whose
  // only known_hosts line is ecdsa but whose server would rather offer ed25519 gets
  // rejected by the verifier as though it were a MITM. The order is a permutation of
  // ssh2's defaults -- nothing is removed, so this can only change WHICH valid key we
  // are offered, never whether a host can be reached.
  //
  // LAZY on purpose. Computing it reads known_hosts through `ssh-keygen -F`: one
  // subprocess spawn per verifier host, two targets each when the port is not 22.
  // resolveConfig() runs on EVERY pool acquire -- including a hit on an already-warm
  // pooled connection, which returns before any dial and can never use the answer --
  // so computing it here charged every tool call for a value only the dial path reads
  // (measured ~235ms per spawn; the short TTL memo below does not cover a tool-call
  // cadence slower than a few seconds). This is exactly the cost sshConfigCache above
  // exists to keep off that path. `connectWithProxy` invokes this thunk immediately
  // before dialing, so the work lands on the connection it can actually influence.
  let algorithmsApplied = false;
  const applyHostKeyAlgorithms = () => {
    if (algorithmsApplied) return; // one dial, one lookup (the pool may retry on `resolved`)
    algorithmsApplied = true;
    const algorithmOrder = hostKeyAlgorithmOrder(cachedKnownHostTypes(verifierHosts, port));
    if (algorithmOrder) {
      // Safe by construction: every element came out of ssh2's own default list.
      connectConfig.algorithms = { serverHostKey: algorithmOrder as ServerHostKeyAlgorithm[] };
    }
  };

  // Auth resolution. An EXPLICIT credential short-circuits everything else, in
  // this order -- that is the predictable way to force one specific method:
  //
  //   1. privateKeyPath -- read from disk; nothing else is offered.
  //   2. password.
  //
  // With neither, we offer what OpenSSH offers, which is NOT a first-match-wins
  // chain: the agent and an on-disk identity are set TOGETHER and ssh2 presents
  // both, letting the server pick.
  //
  //   3. the agent (explicit `agent`, else $SSH_AUTH_SOCK, else the Windows
  //      OpenSSH named pipe), AND
  //   4. the ssh_config IdentityFile list, else
  //   5. the default key paths (~/.ssh/id_ed25519, id_rsa, id_ecdsa).
  //
  // First-match-wins applies WITHIN 4/5 -- the first USABLE key file in the list is
  // the one loaded -- but step 3 never suppresses them. "Usable" is doing real work
  // there: a candidate that carries no private-key armor at all is passed over, as
  // is an encrypted or malformed one when an agent is configured. Both filters live
  // on that branch; see the comment there.
  const home = homedir();
  if (config.privateKeyPath) {
    connectConfig.privateKey = readFileSync(expandTilde(config.privateKeyPath, home));
  } else if (config.password) {
    connectConfig.password = config.password;
  } else {
    const agentSock =
      config.agent || process.env.SSH_AUTH_SOCK || (process.platform === "win32" ? WINDOWS_AGENT_PIPE : undefined);
    if (agentSock) {
      connectConfig.agent = agentSock;
    }

    // Also load an on-disk key (SSH config identity files, else the default key
    // paths) so the documented "agent + config identity + default keys" offer stays
    // reachable. The agent branch above deliberately does NOT short-circuit this --
    // and because the Windows named-pipe default above is always truthy, a
    // short-circuit would leave the identity-file/default-key steps dead on Windows
    // whenever the OpenSSH agent service is up, even with no usable key loaded in
    // it. ssh2 offers BOTH the agent keys and this privateKey, matching OpenSSH's
    // client behavior.
    //
    // The walk takes the first USABLE candidate, not merely the first READABLE one,
    // so a junk file at the head of the list cannot shadow a good key behind it:
    //
    //   absent / unreadable   -> skip; the candidate simply is not there.
    //   not key-shaped        -> skip ALWAYS, agent or not (looksLikePrivateKey).
    //                            A zero-byte file or a `.pub` is not a key in any
    //                            format, so offering it buys nothing and costs the
    //                            real key further down the list.
    //   encrypted / malformed -> skip ONLY when an agent is configured
    //                            (isEncryptedKey). ssh2 parses `privateKey` eagerly
    //                            and would throw "no passphrase given", breaking the
    //                            encrypted-key-on-disk / decrypted-copy-in-the-agent
    //                            setup. With no agent there is nothing else to
    //                            offer, so we load it and let ssh2 surface the
    //                            passphrase (or parse) error itself.
    //
    // If every candidate is skipped, privateKey stays unset and the agent -- if
    // there is one -- is offered alone, rather than alongside bytes that can only
    // fail. First-existing-key-wins still holds; it now holds among the candidates
    // that survive these two filters.
    const keyPaths =
      sshConfig && sshConfig.identityFiles.length > 0
        ? sshConfig.identityFiles.map((p) => expandTilde(p, home))
        : [join(home, ".ssh", "id_ed25519"), join(home, ".ssh", "id_rsa"), join(home, ".ssh", "id_ecdsa")];

    for (const keyPath of keyPaths) {
      let keyData: Buffer;
      try {
        keyData = readFileSync(keyPath);
      } catch {
        continue; // Key doesn't exist, try next
      }
      if (!looksLikePrivateKey(keyData)) continue;
      if (agentSock && isEncryptedKey(keyData)) continue;
      connectConfig.privateKey = keyData;
      break;
    }
  }

  return { connectConfig, proxyJump: sshConfig?.proxyJump, hostKeyRejection, applyHostKeyAlgorithms };
}

// Short TTL cache for the non-host-specific diagnostic checks. Under a burst of
// concurrent failures (say, 20 parallel tool calls when the agent is down) these
// checks spawn processes repeatedly — `ssh-add -l`, filesystem scans — even though
// the answer hasn't changed. Host-specific checks (`checkSshConfig`, `checkKnownHosts`)
// still run every time because they can legitimately differ per host.
const DIAG_CACHE_TTL_MS = 2000;
let diagAgentCache: { at: number; result: DiagnosticResult } | null = null;
let diagKeysCache: { at: number; result: DiagnosticResult } | null = null;

function cachedAgentCheck(): DiagnosticResult {
  const now = Date.now();
  if (diagAgentCache && now - diagAgentCache.at < DIAG_CACHE_TTL_MS) {
    return diagAgentCache.result;
  }
  const result = checkSshAgent();
  diagAgentCache = { at: now, result };
  return result;
}

function cachedKeysCheck(): DiagnosticResult {
  const now = Date.now();
  if (diagKeysCache && now - diagKeysCache.at < DIAG_CACHE_TTL_MS) {
    return diagKeysCache.result;
  }
  const result = checkSshKeys();
  diagKeysCache = { at: now, result };
  return result;
}

/**
 * `dial` is the RESOLVED hostname and port when the caller has them (enhanceSshError
 * passes the ResolvedConfig's). It only steers the ssh-keyscan suggestion, which must
 * name what ssh-keyscan can actually reach -- see keyscanCommand.
 */
export function formatDiagnostics(host: string, dial?: { host: string; port?: number }): string {
  // Run fast local checks only — skip connectivity re-test to avoid adding seconds of delay
  try {
    const checks = [
      { name: "SSH Agent", ...cachedAgentCheck() },
      { name: "SSH Keys", ...cachedKeysCheck() },
      { name: "SSH Config", ...checkSshConfig(host) },
      // known_hosts records the RESOLVED name and port, not the ssh_config alias.
      { name: "Known Hosts", ...checkKnownHosts(dial?.host ?? host, dial?.port ?? 22) },
    ];

    const parts: string[] = [];
    const suggestions: string[] = [];

    for (const check of checks) {
      if (check.status !== "ok") {
        parts.push(`[${check.status.toUpperCase()}] ${check.name}: ${check.message}`);
      }
    }

    const agent = checks[0];
    if (agent.status === "error") suggestions.push(agentStartSuggestion());
    if (agent.status === "warning") suggestions.push("Load a key: ssh-add ~/.ssh/id_ed25519");

    const keys = checks[1];
    if (keys.status === "error") suggestions.push('Generate a key: ssh-keygen -t ed25519 -C "your@email.com"');

    const known = checks[3];
    if (known.status === "warning") {
      suggestions.push(`Add host key: ${keyscanCommand(dial?.host ?? host, dial?.port)}`);
    }

    if (suggestions.length > 0) {
      parts.push(`Suggested fixes: ${suggestions.join(" | ")}`);
    }

    return parts.length > 0 ? parts.join("\n") : "";
  } catch {
    return "";
  }
}

// Connects with the exact ConnectConfig as given — no hostVerifier is applied unless the
// caller supplied one. Use connect() for known_hosts-verified connections.
export function connectRaw(connectConfig: ConnectConfig): Promise<Client> {
  return new Promise((resolve, reject) => {
    const client = new Client();
    client
      .on("ready", () => resolve(client))
      .on("error", (err) => reject(err))
      .connect(connectConfig);
  });
}

/** One hop of a ProxyJump chain, split into the fields `resolveConfig` accepts. */
export interface JumpHop {
  /** Hostname or ssh_config alias. IPv6 literals are UNBRACKETED, as `ssh -G` reports them. */
  host: string;
  /** Port from the spec; undefined leaves the choice to ssh_config / the default. */
  port?: number;
  /** Login from the spec; undefined leaves the choice to ssh_config / the environment. */
  username?: string;
}

function parsePort(text: string): number | undefined {
  if (!/^\d{1,5}$/.test(text)) return undefined;
  const port = Number.parseInt(text, 10);
  return port >= 1 && port <= 65535 ? port : undefined;
}

/**
 * Parse an OpenSSH ProxyJump value into its hops.
 *
 * `ssh -G <host>` prints the ProxyJump value VERBATIM -- it is the one field ssh
 * does not resolve for us -- so everything OpenSSH accepts in `ProxyJump` / `-J`
 * arrives here as one raw string and has to be split apart before any of it can be
 * handed to `resolveConfig`. Feeding the whole string back in as a `host` (what
 * this replaced) mangles every form but the bare hostname:
 *
 *   - "jeff@bastion.example.com:2222" resolved to hostname "bastion.example.com:2222"
 *     on port 22 -- DNS fails before a byte is sent.
 *   - "[2001:db8::1]:2222" resolved to host 2001:db8::1 on port 22 -- WORSE than
 *     failing: it connects, silently, to the wrong port.
 *   - a comma list ("first:2201,second:2202") was treated as a single hostname.
 *
 * It is also a host-key issue, not only a connectivity one: `knownHostsTargets`
 * rejects those mangled spellings and returns [], and a verifier with zero known
 * entries accepts ANY key unless SSH_MCP_STRICT_HOSTKEYS=1. Parsing correctly is
 * what puts the bastion hop back under real known_hosts checking.
 *
 * Grammar (OpenSSH ssh_config(5)): `[user@]host[:port]`, or the equivalent
 * `ssh://[user@]host[:port]` URI, with multiple hops separated by commas and
 * visited left to right. Rules that matter:
 *   - the login is split at the LAST "@" (an IPv6 literal has no "@", and a
 *     password-style "user@domain@host" spelling keeps the trailing host).
 *   - brackets come off FIRST, so only a ":port" that follows "]" is a port. A
 *     BARE IPv6 literal is all colons and no port -- never split it.
 *   - a ":" suffix that is not a valid port number is left as part of the host, so
 *     a typo fails loudly instead of quietly dialing somewhere else.
 */
export function parseJumpSpec(spec: string): JumpHop[] {
  const hops: JumpHop[] = [];
  for (const piece of spec.split(",")) {
    const hop = parseJumpHop(piece.trim());
    if (hop) hops.push(hop);
  }
  return hops;
}

function parseJumpHop(piece: string): JumpHop | null {
  if (!piece) return null;
  let rest = piece.startsWith("ssh://") ? piece.slice("ssh://".length) : piece;
  if (!rest) return null;

  let username: string | undefined;
  const at = rest.lastIndexOf("@");
  if (at !== -1) {
    username = rest.slice(0, at) || undefined;
    rest = rest.slice(at + 1);
  }

  let host = rest;
  let port: number | undefined;
  if (host.startsWith("[")) {
    const close = host.indexOf("]");
    // Unterminated bracket: leave the string alone rather than guess. It will fail
    // `isValidHostname` downstream, which is the correct outcome for a malformed spec.
    if (close !== -1) {
      const after = host.slice(close + 1);
      host = host.slice(1, close);
      if (after.startsWith(":")) port = parsePort(after.slice(1));
    }
  } else if (host.indexOf(":") !== -1 && host.indexOf(":") === host.lastIndexOf(":")) {
    // Exactly one colon -> host:port. Two or more means a bare IPv6 literal, which
    // carries no port (a port there requires brackets) and must never be split.
    const colon = host.lastIndexOf(":");
    const parsed = parsePort(host.slice(colon + 1));
    if (parsed !== undefined) {
      port = parsed;
      host = host.slice(0, colon);
    }
  }

  if (!host) return null;
  const hop: JumpHop = { host };
  if (port !== undefined) hop.port = port;
  if (username !== undefined) hop.username = username;
  return hop;
}

/**
 * Render a hop back into ProxyJump spelling. Round-trips through `parseJumpSpec`
 * (re-bracketing IPv6 so a port stays unambiguous), which is what lets a multi-hop
 * chain be handed to the recursion below as a plain `proxyJump` string, and what
 * makes the jump-host label in an error read the way the user wrote it.
 */
export function formatJumpHop(hop: JumpHop): string {
  const host = hop.host.includes(":") ? `[${hop.host}]` : hop.host;
  const withPort = hop.port ? `${host}:${hop.port}` : host;
  return hop.username ? `${hop.username}@${withPort}` : withPort;
}

/** Hard cap on ProxyJump nesting, a backstop behind the visited-set loop check. */
export const MAX_PROXY_JUMP_DEPTH = 8;

/**
 * `visited` is internal recursion state: the `host:port` of every hop already on
 * this chain, target included. `ssh -G` catches a self-referential ProxyJump
 * ("jumphost loop via bastion") but not a cycle of two or more hosts (`Host a`
 * ProxyJump b / `Host b` ProxyJump a), which used to recurse until "Maximum call
 * stack size exceeded" -- synchronously, before the first await.
 */
export async function connectWithProxy(
  resolved: ResolvedConfig,
  visited: ReadonlySet<string> = new Set(),
): Promise<Client> {
  // This is the dial path -- the only place `connectConfig.algorithms` is ever read --
  // so materialize the host-key preference order now. Deliberately not done in
  // resolveConfig: see the comment on the thunk there.
  resolved.applyHostKeyAlgorithms?.();

  const hops = resolved.proxyJump ? parseJumpSpec(resolved.proxyJump) : [];
  if (hops.length === 0) {
    return connectRaw(resolved.connectConfig);
  }
  const chain = new Set(visited);
  chain.add(`${resolved.connectConfig.host}:${resolved.connectConfig.port ?? 22}`);

  // OpenSSH visits a ProxyJump list left to right, so the LAST hop is the one
  // adjacent to the target -- it is the client that opens the forwarded channel
  // below. The hops before it are that hop's own proxy chain, which is exactly the
  // shape this function already implements one level down. An explicit multi-hop
  // spec wins over whatever ssh_config says about the last hop's own ProxyJump:
  // the user named the whole path.
  const jumpHop = hops[hops.length - 1];
  const jumpLabel = formatJumpHop(jumpHop);
  // Separate fields, not one re-joined string: resolveConfig honors an explicit
  // `port` / `username` over `ssh -G`, and that is the only mechanism by which a
  // spec-supplied port or login survives at all.
  const jumpResolved = resolveConfig({ host: jumpHop.host, port: jumpHop.port, username: jumpHop.username });
  if (hops.length > 1) {
    jumpResolved.proxyJump = hops.slice(0, -1).map(formatJumpHop).join(",");
  }
  const jumpKey = `${jumpResolved.connectConfig.host}:${jumpResolved.connectConfig.port ?? 22}`;
  if (chain.has(jumpKey)) {
    throw new Error(`ProxyJump loop via ${jumpLabel}: it is already on this connection's jump chain`);
  }
  // `chain` holds the target PLUS every hop so far, so it is one larger than the hop
  // count: `>` lets exactly MAX_PROXY_JUMP_DEPTH hops through and refuses the next.
  if (chain.size > MAX_PROXY_JUMP_DEPTH) {
    throw new Error(`ProxyJump chain via ${jumpLabel} exceeds ${MAX_PROXY_JUMP_DEPTH} hops`);
  }
  let jumpClient: Client;
  try {
    jumpClient = await connectWithProxy(jumpResolved, chain); // recursive for chained proxies
  } catch (err: unknown) {
    // A host-key rejection on the BASTION lands in jumpResolved's own side channel,
    // which nobody upstream ever looks at: connect() and ConnectionPool.acquire hand
    // enhanceSshError the TARGET's resolved. Copy it across, labelled with the jump
    // host; without this a bastion whose known_hosts entry is stale (or missing the
    // offered algorithm) still surfaces as ssh2's bare "Host denied (verification
    // failed)" -- the exact opaque failure the rejection side channel exists to fix.
    // Nothing has dialed the target yet, so `current` here is null by construction.
    const jumpRejection = jumpResolved.hostKeyRejection?.current;
    if (jumpRejection && resolved.hostKeyRejection) {
      resolved.hostKeyRejection.current = {
        reason: jumpRejection.reason,
        message: `on jump host ${jumpLabel} -- ${jumpRejection.message}`,
      };
    }
    throw err;
  }

  // Create tunnel from jump host to target
  const targetHost = resolved.connectConfig.host as string;
  const targetPort = resolved.connectConfig.port as number;

  // Centralize jump-client teardown so the error and close paths can't double-throw on a
  // second end() call. ssh2's Client.end() is normally idempotent, but every other
  // end-call site in this module wraps in try/catch -- these two were the outliers.
  const endJump = () => {
    try {
      jumpClient.end();
    } catch {
      // already ended
    }
  };

  const stream = await new Promise<any>((resolve, reject) => {
    jumpClient.forwardOut("127.0.0.1", 0, targetHost, targetPort, (err, stream) => {
      if (err) {
        endJump();
        return reject(err);
      }
      resolve(stream);
    });
  });

  // Connect through the tunnel
  return new Promise((resolve, reject) => {
    const client = new Client();
    client
      .on("ready", () => resolve(client))
      .on("error", (err) => {
        endJump();
        reject(err);
      })
      .on("close", () => {
        endJump();
      })
      .connect({ ...resolved.connectConfig, sock: stream });
  });
}

/**
 * The single shape for turning an SSH failure into the diagnosed error this server
 * advertises. Used by `connect()` and by `ConnectionPool.acquire()` for BOTH the
 * config-resolution and the connect step, so there is one implementation rather
 * than a copy per call site.
 *
 * Attaches, when available: the host-key rejection reason recorded by our
 * hostVerifier (ssh2 itself only ever says "Host denied (verification failed)"),
 * then the local SSH environment diagnostics. Returns the original error untouched
 * when there is nothing to add, so `cause` chains stay short.
 */
export function enhanceSshError(err: unknown, host: string, resolved?: ResolvedConfig): unknown {
  const extra: string[] = [];

  const rejection = resolved?.hostKeyRejection?.current;
  if (rejection) extra.push(`Host key check failed -- ${rejection.message}`);

  const dialHost = resolved?.connectConfig.host;
  const diag = formatDiagnostics(
    host,
    dialHost ? { host: dialHost, port: resolved?.connectConfig.port as number | undefined } : undefined,
  );
  if (diag) extra.push(`SSH Diagnostics:\n${diag}`);

  if (extra.length === 0) return err;
  const message = err instanceof Error ? err.message : String(err);
  const enhanced = new Error([message, ...extra].join("\n\n"));
  enhanced.cause = err;
  return enhanced;
}

export async function connect(config: SSHConfig): Promise<Client> {
  // resolveConfig() must be INSIDE the wrapper: it does real I/O (readFileSync on
  // privateKeyPath, `ssh -G`), so a bad key path used to escape as a raw ENOENT
  // with none of the diagnostics this server promises.
  let resolved: ResolvedConfig | undefined;
  try {
    resolved = resolveConfig(config);
    return await connectWithProxy(resolved);
  } catch (err: unknown) {
    throw enhanceSshError(err, config.host, resolved);
  }
}

// ssh2's client.exec() runs the command through the remote user's login shell, so shell
// metacharacters (|, &&, >, globs, etc.) are interpreted. This is intentional — callers
// pass shell command strings. Higher-level helpers in ops.ts use shellQuote() when
// interpolating user-supplied values into command templates.
//
// stdout and stderr are each capped at maxBytes to prevent a chatty or misbehaving
// remote command from exhausting process memory. When the cap is hit, further data is
// dropped and a truncation marker is appended to the captured output.
export const DEFAULT_MAX_EXEC_BYTES = 10 * 1024 * 1024; // 10 MB per stream

export function exec(
  client: Client,
  command: string,
  timeoutMs = 30000,
  maxBytes: number = DEFAULT_MAX_EXEC_BYTES,
): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    let settled = false;
    // Tracked so the timeout handler can tear down the remote channel — without
    // this, a timed-out command keeps running on the server and leaks a channel.
    let activeStream: ClientChannel | null = null;
    // Set once the data listeners are wired. Detaches them and drops the captured
    // chunks so a timed-out command's output cannot keep growing (or keep the
    // already-captured megabytes alive) during the gap between our rejection and
    // the channel actually closing. Null until `client.exec` calls back.
    let releaseCapture: (() => void) | null = null;

    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };

    // signal() asks sshd to forward SIGTERM (often disabled server-side);
    // close() tears the channel down regardless. Try both, ignore failures —
    // the only goal is "stop the remote work, don't leak the channel".
    const teardownStream = (stream: ClientChannel) => {
      try {
        stream.signal("TERM");
      } catch {
        /* ignore */
      }
      try {
        stream.close();
      } catch {
        /* ignore */
      }
    };

    const timer = setTimeout(() => {
      // Release first: the stream can keep emitting data between signal/close and
      // the channel actually going away, and nothing will ever read those bytes.
      // The "error" listeners stay attached on purpose -- an EventEmitter with no
      // "error" listener throws, and settle() already makes their reject a no-op.
      releaseCapture?.();
      if (activeStream) teardownStream(activeStream);
      settle(() => reject(new Error(`Command timed out after ${timeoutMs}ms`)));
    }, timeoutMs);

    // ssh2's Client.exec THROWS synchronously ("Not connected") on a client whose
    // socket died while the caller held it. Without this catch the promise still
    // rejected (the executor throwing), but the timer above was never cleared and
    // held the event loop for the full timeoutMs.
    try {
      client.exec(command, onExec);
    } catch (err: unknown) {
      settle(() => reject(err));
    }

    function onExec(err: Error | undefined, stream: ClientChannel): void {
      if (err) {
        settle(() => reject(err));
        return;
      }
      activeStream = stream;

      const out = cappedCapture(maxBytes);
      const errOut = cappedCapture(maxBytes);
      const appendStdout = out.append;
      const appendStderr = errOut.append;

      stream
        .on("close", (code: number | null, signal?: string) => {
          const stdoutTruncated = out.truncated();
          const stderrTruncated = errOut.truncated();
          let stdout = out.text();
          let stderr = errOut.text();
          if (stdoutTruncated) stdout += `\n[output truncated at ${maxBytes} bytes]`;
          if (stderrTruncated) stderr += `\n[stderr truncated at ${maxBytes} bytes]`;
          // ssh2 emits close(code, signal). When the remote channel closes signal-only
          // (server-side kill), code is null/undefined. -1 is a clearer "no exit code"
          // sentinel than the previous 0, which conflated "signaled" with "success."
          // The signal name (if present) is also surfaced so callers can distinguish.
          const exitCode = typeof code === "number" ? code : -1;
          const result: ExecResult = { stdout, stderr, code: exitCode };
          if (stdoutTruncated) result.stdoutTruncated = true;
          if (stderrTruncated) result.stderrTruncated = true;
          if (signal) result.signal = signal;
          settle(() => resolve(result));
        })
        .on("data", appendStdout)
        .on("error", (err: Error) => {
          settle(() => reject(err));
        });

      stream.stderr.on("data", appendStderr).on("error", (err: Error) => {
        settle(() => reject(err));
      });

      releaseCapture = () => {
        stream.removeListener("data", appendStdout);
        stream.stderr.removeListener("data", appendStderr);
        out.clear();
        errOut.clear();
      };

      // The timer can fire BEFORE client.exec() calls back, in which case
      // activeStream was still null and the handler above had nothing to release or
      // tear down. Do both now. (The only settle that can precede this callback is
      // the timeout: the exec-error path returns before we get here.)
      if (settled) {
        releaseCapture();
        teardownStream(stream);
      }
    }
  });
}

/**
 * One output stream's capture, capped at `maxBytes`: data past the cap is dropped
 * and `truncated()` turns true. stdout and stderr each get their own.
 */
function cappedCapture(maxBytes: number) {
  const chunks: Buffer[] = [];
  let bytes = 0;
  let truncated = false;
  return {
    append(data: Buffer): void {
      if (truncated) return;
      const remaining = maxBytes - bytes;
      if (data.length <= remaining) {
        chunks.push(data);
        bytes += data.length;
        return;
      }
      if (remaining > 0) {
        chunks.push(data.subarray(0, remaining));
        bytes += remaining;
      }
      truncated = true;
    },
    text: (): string => Buffer.concat(chunks).toString("utf8"),
    truncated: (): boolean => truncated,
    clear(): void {
      chunks.length = 0;
      bytes = 0;
    },
  };
}

function getSftp(client: Client): Promise<SFTPWrapper> {
  return new Promise((resolve, reject) => {
    client.sftp((err, sftp) => {
      if (err) return reject(err);
      resolve(sftp);
    });
  });
}

/**
 * Per-call deadline for the SFTP helpers. The connection has keepalives and nothing
 * else: ssh2's readyTimeout bounds only the handshake, so a sftp subsystem that
 * stalls while sshd keeps answering keepalives (a hung NFS mount, a FIFO) used to
 * hold the call -- and its pool slot -- forever. Generous on purpose: this exists to
 * end a hang, not to race a slow-but-working server.
 */
export const DEFAULT_SFTP_TIMEOUT_MS = 120_000;
/**
 * The INACTIVITY timeout for whole-file transfers (fastPut / fastGet). Unlike the
 * per-call deadline above it is reset by every chunk the transfer moves, so a
 * healthy multi-gigabyte transfer may run as long as it needs; only a transfer that
 * makes no progress for this long is aborted.
 */
export const DEFAULT_SFTP_TRANSFER_TIMEOUT_MS = 600_000;

/**
 * Open an SFTP session, run `fn` on it, and always end the session -- on success,
 * on failure, and on timeout. When `timeoutMs` elapses first the session is ended
 * (which aborts whatever is in flight on it) and the call rejects; a late result
 * from `fn` is ignored.
 *
 * With `idle` set, `timeoutMs` is an inactivity timeout instead of a whole-call
 * deadline: each call of the `progress` callback handed to `fn` restarts it.
 * Without it `progress` is a no-op, so the deadline stays absolute.
 */
function withSftp<T>(
  client: Client,
  what: string,
  timeoutMs: number,
  fn: (sftp: SFTPWrapper, progress: () => void) => Promise<T>,
  idle = false,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    let sftp: SFTPWrapper | null = null;
    let ended = false;
    const end = () => {
      if (!sftp || ended) return;
      ended = true;
      try {
        sftp.end();
      } catch {
        // already closed
      }
    };
    const finish = (complete: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      end();
      complete();
    };
    const onTimeout = () =>
      finish(() =>
        reject(new Error(`SFTP ${what} timed out after ${timeoutMs}ms${idle ? " with no transfer progress" : ""}`)),
      );
    let timer = setTimeout(onTimeout, timeoutMs);
    const progress = () => {
      if (!idle || settled) return;
      clearTimeout(timer);
      timer = setTimeout(onTimeout, timeoutMs);
    };
    getSftp(client).then(
      (s) => {
        sftp = s;
        // The deadline passed while the subsystem was still opening: close it now.
        if (settled) return end();
        fn(s, progress).then(
          (value) => finish(() => resolve(value)),
          (err: unknown) => finish(() => reject(err)),
        );
      },
      (err: unknown) => finish(() => reject(err)),
    );
  });
}

function sftpStat(sftp: SFTPWrapper, remotePath: string): Promise<Stats> {
  return new Promise((resolve, reject) => {
    sftp.stat(remotePath, (err, st) => (err ? reject(err) : resolve(st)));
  });
}

function sftpOpenRead(sftp: SFTPWrapper, remotePath: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    sftp.open(remotePath, "r", (err, h) => (err ? reject(err) : resolve(h)));
  });
}

/** One SFTP READ. Resolves 0 at end of file. */
function sftpRead(
  sftp: SFTPWrapper,
  handle: Buffer,
  buf: Buffer,
  off: number,
  len: number,
  pos: number,
): Promise<number> {
  return new Promise((resolve, reject) => {
    sftp.read(handle, buf, off, len, pos, (err, bytesRead) => {
      if (err) return reject(err);
      // ssh2 swallows an SFTP EOF status on read and calls back with no count.
      resolve(bytesRead ?? 0);
    });
  });
}

export const DEFAULT_MAX_READ_BYTES = 10 * 1024 * 1024; // 10 MB
const READ_CHUNK_BYTES = 256 * 1024;

const mb = (bytes: number, digits: number) => (bytes / 1024 / 1024).toFixed(digits);

export async function readFile(
  client: Client,
  remotePath: string,
  maxBytes = DEFAULT_MAX_READ_BYTES,
  timeoutMs = DEFAULT_SFTP_TIMEOUT_MS,
): Promise<string> {
  return withSftp(client, `read of ${remotePath}`, timeoutMs, async (sftp) => {
    const stats = await sftpStat(sftp, remotePath);
    // Cheap early refusal for a file that SAYS it is too big -- no bytes move.
    if (stats.size > maxBytes) {
      throw new Error(
        `File is ${mb(stats.size, 1)} MB, exceeds ${mb(maxBytes, 0)} MB limit. Read it a page at a time with ssh_read_file's offset and length arguments (byte offsets; the file is ${stats.size} bytes).`,
      );
    }
    // ...but stat.size is not a bound. /dev/zero, /dev/urandom, a FIFO or a /proc
    // file report size 0, and ssh2's own readFile reads a size-0 file until EOF with
    // no limit, growing this process's memory without end. So read through our own
    // loop and stop one byte past the cap: reaching it proves the file is too big.
    const handle = await sftpOpenRead(sftp, remotePath);
    try {
      const chunks: Buffer[] = [];
      let got = 0;
      while (got <= maxBytes) {
        const buf = Buffer.alloc(Math.min(READ_CHUNK_BYTES, maxBytes + 1 - got));
        const n = await sftpRead(sftp, handle, buf, 0, buf.length, got);
        if (n === 0) break;
        chunks.push(n === buf.length ? buf : buf.subarray(0, n));
        got += n;
      }
      if (got > maxBytes) {
        throw new Error(
          `File exceeds the ${mb(maxBytes, 0)} MB limit: more than ${maxBytes} bytes were read although it reported a size of ${stats.size} bytes (a special file such as a device or FIFO, or one still growing). Read it a page at a time with ssh_read_file's offset and length arguments.`,
        );
      }
      return Buffer.concat(chunks, got).toString("utf8");
    } finally {
      sftp.close(handle, () => {});
    }
  });
}

/** One page of a remote file, plus where it sits in the whole. */
export interface FileRange {
  /** The bytes read, decoded as UTF-8. A page boundary can split a multi-byte character. */
  text: string;
  /** Byte offset the page starts at (as requested). */
  offset: number;
  /** Number of bytes actually read: less than requested at end of file. */
  bytesRead: number;
  /**
   * Size of the whole file, from the same stat. ABSENT when the stat reported 0:
   * for a /proc file, a device or a FIFO that means "unknown", not "empty", so the
   * page may hold data and more may follow. (A genuinely empty file lands here too
   * and simply reads 0 bytes.)
   */
  size?: number;
}

/**
 * Read `length` bytes of a remote file starting at byte `offset`.
 *
 * The paging half of ssh_read_file. A whole-file read is capped at 10 MB here, but a
 * proxy in front of this server can cap far lower -- Yaw MCP keeps 100 KB of a result
 * by default and cuts the rest -- so a large file has to be readable in pages without
 * turning a cap off. `length` is bounded by the same `maxBytes` as a whole read.
 */
export async function readFileRange(
  client: Client,
  remotePath: string,
  offset: number,
  length: number,
  maxBytes = DEFAULT_MAX_READ_BYTES,
  timeoutMs = DEFAULT_SFTP_TIMEOUT_MS,
): Promise<FileRange> {
  if (!Number.isSafeInteger(offset) || offset < 0)
    throw new Error(`offset must be a non-negative integer, got ${offset}`);
  if (!Number.isSafeInteger(length) || length <= 0) throw new Error(`length must be a positive integer, got ${length}`);
  if (length > maxBytes) {
    throw new Error(
      `length ${length} exceeds the ${mb(maxBytes, 0)} MB limit for one read. Use a smaller length and page with offset.`,
    );
  }
  return withSftp(client, `read of ${remotePath}`, timeoutMs, async (sftp) => {
    const stats = await sftpStat(sftp, remotePath);
    // A size of 0 is not "empty" for a /proc file or a device -- it is "unknown" --
    // so do not clamp the page to it; the read loop below stops at EOF either way.
    const sizeKnown = stats.size !== 0;
    const sized = <T extends object>(page: T): T & { size?: number } =>
      sizeKnown ? { ...page, size: stats.size } : page;
    const want = sizeKnown ? Math.max(0, Math.min(length, stats.size - offset)) : length;
    if (want === 0) return sized({ text: "", offset, bytesRead: 0 });
    const handle = await sftpOpenRead(sftp, remotePath);
    try {
      const buf = Buffer.alloc(want);
      let got = 0;
      // A single SFTP READ may return fewer bytes than asked (servers cap a packet,
      // commonly at 32-256 KB), so loop until the page is full or the file ends.
      while (got < want) {
        const n = await sftpRead(sftp, handle, buf, got, want - got, offset + got);
        if (n === 0) break;
        got += n;
      }
      return sized({ text: buf.subarray(0, got).toString("utf8"), offset, bytesRead: got });
    } finally {
      sftp.close(handle, () => {});
    }
  });
}

export async function writeFile(
  client: Client,
  remotePath: string,
  content: string,
  timeoutMs = DEFAULT_SFTP_TIMEOUT_MS,
): Promise<void> {
  return withSftp(
    client,
    `write of ${remotePath}`,
    timeoutMs,
    (sftp) =>
      new Promise<void>((resolve, reject) => {
        sftp.writeFile(remotePath, content, (err) => (err ? reject(err) : resolve()));
      }),
  );
}

export async function uploadFile(
  client: Client,
  localPath: string,
  remotePath: string,
  timeoutMs = DEFAULT_SFTP_TRANSFER_TIMEOUT_MS,
): Promise<void> {
  const resolvedLocal = expandTilde(localPath);
  return withSftp(
    client,
    `upload to ${remotePath}`,
    timeoutMs,
    (sftp, progress) =>
      new Promise<void>((resolve, reject) => {
        sftp.fastPut(resolvedLocal, remotePath, { step: progress }, (err) => (err ? reject(err) : resolve()));
      }),
    true, // an inactivity timeout: a long transfer that keeps moving bytes is not aborted
  );
}

export async function downloadFile(
  client: Client,
  remotePath: string,
  localPath: string,
  timeoutMs = DEFAULT_SFTP_TRANSFER_TIMEOUT_MS,
): Promise<void> {
  const resolvedLocal = expandTilde(localPath);
  return withSftp(
    client,
    `download of ${remotePath}`,
    timeoutMs,
    (sftp, progress) =>
      new Promise<void>((resolve, reject) => {
        sftp.fastGet(remotePath, resolvedLocal, { step: progress }, (err) => (err ? reject(err) : resolve()));
      }),
    true, // an inactivity timeout, as for uploadFile
  );
}

export async function listDir(
  client: Client,
  remotePath: string,
  timeoutMs = DEFAULT_SFTP_TIMEOUT_MS,
): Promise<string[]> {
  return withSftp(
    client,
    `listing of ${remotePath}`,
    timeoutMs,
    (sftp) =>
      new Promise<string[]>((resolve, reject) => {
        sftp.readdir(remotePath, (err, list) => (err ? reject(err) : resolve(list.map((item) => item.filename))));
      }),
  );
}

export interface FileStats {
  size: number;
  /** POSIX mode as a decimal number. Use modeOctal for the human-readable form. */
  mode: number;
  /** POSIX mode formatted as a 4-digit octal string (e.g. "0755"). */
  modeOctal: string;
  uid: number;
  gid: number;
  /** Unix timestamp (seconds since epoch) of last modification. */
  mtime: number;
  /** Unix timestamp (seconds since epoch) of last access. */
  atime: number;
  isFile: boolean;
  isDirectory: boolean;
  isSymbolicLink: boolean;
  /**
   * Set only when isSymbolicLink is true. `false` means the link's target could not be
   * resolved (dangling, or a loop): the metadata above is then the LINK's own, and
   * isFile/isDirectory are both false. Absent for a non-symlink.
   */
  targetResolved?: boolean;
}

// SFTP status code (draft-ietf-secsh-filexfer-02), as ssh2 sets it on `err.code`.
// OpenSSH's sftp-server (errno_to_portable) maps ENOENT, ENOTDIR, EBADF and ELOOP
// ALL to NO_SUCH_FILE, so a dangling link and a looping one both arrive as this
// code. FAILURE (4) is the catch-all for every errno it has no code for (EIO,
// ESTALE, ...): an unknown error, never evidence that the target is missing.
const SFTP_NO_SUCH_FILE = 2;
// The status-less error ssh2's SFTP cleanupRequests() hands every pending callback when
// the channel goes away (node_modules/ssh2/lib/protocol/SFTP.js).
const SSH2_SFTP_CHANNEL_LOST = "No response from server";

/**
 * Two calls, deliberately, because one cannot answer both questions.
 *
 * TYPE comes from `lstat`, which reports on the path itself. SFTP `stat` FOLLOWS
 * symlinks, so it can never report `isSymbolicLink: true` -- the flag this function
 * has always returned, and which `ssh_stat` advertises, was dead: a symlink to a
 * directory arrived as `isDirectory` and a dangling one rejected ENOENT before
 * anything was formatted. `deleteFile` below already uses `lstat` for exactly this
 * distinction.
 *
 * SIZE and the rest come from `stat`, the TARGET's metadata, because "how big is
 * this" means the target -- a symlink's own size is the length of its path string,
 * which is never the answer anyone wants. When the target cannot be resolved (a
 * dangling link, or a loop) we fall back to the link's own stats, mark the result
 * `targetResolved: false` so the caller knows the metadata is the link's, and still
 * report it rather than failing the call the way `stat` alone did. Only those two
 * outcomes fall back: any other SFTP status on the target -- PERMISSION_DENIED above
 * all -- and ssh2's status-less lost-channel error are rethrown, because "the target
 * is unreadable" (or "never checked") is not "the target is missing" and used to
 * render identically.
 *
 * For a non-symlink the two calls agree by definition, so nothing changes there.
 */
export function statFile(client: Client, remotePath: string, timeoutMs = DEFAULT_SFTP_TIMEOUT_MS): Promise<FileStats> {
  return withSftp(client, `stat of ${remotePath}`, timeoutMs, (sftp) => statOn(sftp, remotePath));
}

async function statOn(sftp: SFTPWrapper, remotePath: string): Promise<FileStats> {
  const call = (fn: "lstat" | "stat") =>
    new Promise<Stats>((resolve, reject) => {
      sftp[fn](remotePath, (err, stats) => (err ? reject(err) : resolve(stats)));
    });
  // lstat first: it succeeds for anything that exists, link or not. If this fails
  // the path is genuinely absent, which is the same rejection as before.
  const link = await call("lstat");
  const isSymbolicLink = link.isSymbolicLink();
  // Only pay the second round-trip when it can differ.
  let meta = link;
  let targetResolved: boolean | undefined;
  if (isSymbolicLink) {
    try {
      meta = await call("stat");
      targetResolved = true;
    } catch (err) {
      // Dangling or looping symlink (both NO_SUCH_FILE from OpenSSH) -- keep the link's
      // own stats and report it as an unresolved symlink rather than rejecting. Any
      // other SFTP status (PERMISSION_DENIED, and the FAILURE catch-all for an I/O
      // error) is a real failure and propagates. A
      // lost connection carries NO status: ssh2 fails every pending request with a bare
      // "No response from server" when the channel closes, so that one is matched by
      // message and rethrown too -- rendering it as "dangling" would report a missing
      // target that was never checked. Any other status-less error keeps the fallback.
      const code = (err as { code?: unknown }).code;
      if (typeof code === "number" && code !== SFTP_NO_SUCH_FILE) throw err;
      if (code === undefined && err instanceof Error && err.message === SSH2_SFTP_CHANNEL_LOST) throw err;
      targetResolved = false;
    }
  }
  // ssh2 exposes the type checks as methods, not boolean fields -- materialize them
  // up front so the result is a plain JSON-safe object the MCP layer can serialize.
  return {
    size: meta.size,
    mode: meta.mode,
    modeOctal: (meta.mode & 0o7777).toString(8).padStart(4, "0"),
    uid: meta.uid,
    gid: meta.gid,
    mtime: meta.mtime,
    atime: meta.atime,
    // isFile / isDirectory describe the TARGET (they pair with the metadata above);
    // isSymbolicLink describes the PATH. A symlink to a directory is therefore both
    // a directory and a symlink, and the caller decides which matters.
    isFile: meta.isFile(),
    isDirectory: meta.isDirectory(),
    isSymbolicLink,
    // Only on a symlink, so a plain path's result shape is unchanged.
    ...(targetResolved === undefined ? {} : { targetResolved }),
  };
}

// Single-shot path removal. Stats first to dispatch to unlink (files / symlinks) vs rmdir
// (empty dirs) -- both give better error messages than blind try-unlink-fallback-rmdir,
// and a directory delete on a non-empty dir fails clearly with ENOTEMPTY rather than the
// generic "Failure" that SFTP returns when unlink hits a directory.
//
// The dispatch uses lstat, NOT stat, so it describes the path itself instead of whatever
// it points at. With stat (which follows symlinks) a symlink to a directory reported
// isDirectory() and got sent to rmdir(<symlink path>) -- which fails, since the link is
// not a directory -- and a DANGLING symlink could not be deleted at all, because stat
// rejected with ENOENT on the missing target before we ever reached unlink. lstat makes
// both cases what the comment always claimed: a symlink is unlinked, target irrelevant.
//
// Recursive delete is intentionally NOT supported here. Agents that want it should call
// `ssh_exec rm -rf <path>` explicitly so the destructive intent is visible in the tool
// trace, not hidden behind a flag on a "delete" tool.
export async function deleteFile(
  client: Client,
  remotePath: string,
  timeoutMs = DEFAULT_SFTP_TIMEOUT_MS,
): Promise<void> {
  return withSftp(client, `delete of ${remotePath}`, timeoutMs, async (sftp) => {
    const stats = await new Promise<{ isDirectory: () => boolean }>((resolve, reject) => {
      sftp.lstat(remotePath, (err, stats) => {
        if (err) return reject(err);
        resolve(stats);
      });
    });
    await new Promise<void>((resolve, reject) => {
      const done = (err: Error | null | undefined) => (err ? reject(err) : resolve());
      if (stats.isDirectory()) {
        sftp.rmdir(remotePath, done);
      } else {
        sftp.unlink(remotePath, done);
      }
    });
  });
}

// Create a directory via SFTP. With recursive=true, walks the path and creates each
// missing segment in order -- SFTP has no native `mkdir -p` equivalent -- with
// `mkdir -p` semantics: a segment that already exists AS A DIRECTORY (the leaf
// included) is fine, so the call is idempotent. Any other failure is surfaced with
// its own error. Non-recursive mode is plain `mkdir`: an existing path errors.
export async function makeDir(
  client: Client,
  remotePath: string,
  recursive = false,
  timeoutMs = DEFAULT_SFTP_TIMEOUT_MS,
): Promise<void> {
  return withSftp(client, `mkdir of ${remotePath}`, timeoutMs, (sftp) => makeDirOn(sftp, remotePath, recursive));
}

async function makeDirOn(sftp: SFTPWrapper, remotePath: string, recursive: boolean): Promise<void> {
  const mkOne = (path: string) =>
    new Promise<void>((resolve, reject) => {
      sftp.mkdir(path, (err) => (err ? reject(err) : resolve()));
    });
  // `stat`, not `lstat`: like `mkdir -p`, a symlink to a directory (e.g. a /home
  // that links to /usr/home) counts as an existing directory to walk through.
  const isDirectory = (path: string) =>
    new Promise<boolean>((resolve) => {
      sftp.stat(path, (err, st) => resolve(!err && st.isDirectory()));
    });

  if (!recursive) {
    await mkOne(remotePath);
    return;
  }

  // Normalize and walk segments. POSIX absolute paths start with /, agents may also pass
  // home-relative paths -- we don't expand ~ here; ssh_exec'd shell handles that.
  //
  // The seed carries the absolute/relative distinction on its own: "" grows to "/a",
  // "/a/b"; "." grows to "./a", "./a/b". The per-iteration append is therefore the same
  // expression either way (it used to be a ternary with two byte-identical branches).
  const parts = remotePath.split("/").filter(Boolean);
  let cur = remotePath.startsWith("/") ? "" : ".";
  for (const part of parts) {
    cur = `${cur}/${part}`;
    try {
      await mkOne(cur);
    } catch (e: unknown) {
      // SFTP answers an existing directory with the same generic "Failure" it uses
      // for much else, so the error alone cannot tell "already there" from a real
      // problem. Ask: a directory already at this path is exactly what we wanted.
      // Anything else -- a FILE in the way, or a permission denial on a segment
      // that does not exist -- rethrows THIS segment's error, rather than being
      // swallowed and resurfacing as a misleading "No such file" on the leaf.
      if (!(await isDirectory(cur))) throw e;
    }
  }
}
