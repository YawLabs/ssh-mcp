import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { join } from "node:path";
import { Client, type ClientChannel, type ConnectConfig, type ServerHostKeyAlgorithm, type SFTPWrapper } from "ssh2";
import {
  checkKnownHosts,
  checkSshAgent,
  checkSshConfig,
  checkSshKeys,
  type DiagnosticResult,
  isValidHostname,
  runArgs,
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
  /** No known_hosts entry at all, and SSH_MCP_STRICT_HOST_KEY=1. */
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
// one host pay N spawns for an answer that cannot differ between them. Cached
// for process lifetime: ssh_config is read at startup-ish cadence and a running
// server is expected to be restarted after config edits.
const sshConfigCache = new Map<string, SshConfigResult | null>();

/** Test-only: drop memoized `ssh -G` results so a suite can vary ssh_config. */
export function clearSshConfigCache(): void {
  sshConfigCache.clear();
}

function resolveFromSshConfig(host: string): SshConfigResult | null {
  const cached = sshConfigCache.get(host);
  if (cached !== undefined) return cached;
  const result = resolveFromSshConfigUncached(host);
  sshConfigCache.set(host, result);
  return result;
}

function resolveFromSshConfigUncached(host: string): SshConfigResult | null {
  try {
    const { stdout, ok } = runArgs("ssh", ["-G", host]);
    if (!ok) return null;

    const { all, identityFiles } = parseSshConfigOutput(stdout);

    return {
      hostname: all.hostname || host,
      user: all.user || "",
      port: all.port || "22",
      identityFiles,
      proxyJump: all.proxyjump && all.proxyjump !== "none" ? all.proxyjump : undefined,
    };
  } catch {
    return null;
  }
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
export function readKnownHostsEntries(host: string, port?: number): KnownHostEntry[] {
  const entries: KnownHostEntry[] = [];
  for (const target of knownHostsTargets(host, port)) {
    const { stdout, ok } = runArgs("ssh-keygen", ["-F", target]);
    if (!ok || !stdout.trim()) continue;
    for (const line of stdout.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      // Format: <host-or-hash> <keytype> <base64> [comment]
      const parts = trimmed.split(/\s+/);
      // ...UNLESS the line carries a marker. `ssh-keygen -F` echoes matching lines
      // VERBATIM, and a marker line has an extra LEADING field, so every index
      // shifts by one: for "@cert-authority *.corp.example.com ssh-ed25519 AAAA..."
      // parts[1] is the host PATTERN (stored below as if it were the key type) and
      // parts[2] is the literal string "ssh-ed25519" -- which Buffer.from(_, "base64")
      // happily decodes to 8 junk bytes rather than throwing, so the try/catch never
      // fired and the junk landed in the comparison set. The visible symptom was a
      // rejection message naming a host pattern where a key type belongs.
      //
      // Skipping them is a security fix as much as a parse one: a @cert-authority
      // line holds a CA's key, not this host's, and a @revoked line records a key
      // that must NEVER be accepted as valid.
      if (parts[0].startsWith("@")) continue;
      if (parts.length < 3) continue;
      try {
        entries.push({ type: parts[1], key: Buffer.from(parts[2], "base64") });
      } catch {
        // Skip malformed entry
      }
    }
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
 *     `scripts/build-binary.mjs` (bundle:true, format:cjs) INLINES the constants
 *     module into the Node SEA single-file binary -- which has no node_modules to
 *     resolve against at runtime. Route 2 alone was therefore dead in every
 *     Homebrew/Scoop binary: `createRequire(import.meta.url)` is opaque to any
 *     bundler, so it threw there, returned null, and the whole reorder silently
 *     no-opped. In the tsup ESM build ssh2 stays EXTERNAL and esbuild rewrites this
 *     call into its `__require` shim, which throws "Dynamic require ... is not
 *     supported" under a real ESM loader -- hence the try, and hence route 2.
 *  2. `createRequire(import.meta.url)`. The route that works in the published ESM
 *     dist (and under vitest / tsx), and the one the SEA cannot use.
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

function cachedKnownHostTypes(hosts: ReadonlyArray<string>, port: number | undefined): string[] {
  const cacheKey = `${hosts.join(" ")}:${port ?? ""}`;
  const now = Date.now();
  const hit = knownHostTypeCache.get(cacheKey);
  if (hit && now - hit.at < KNOWN_HOST_TYPE_TTL_MS) return hit.types;
  const types = [...new Set(hosts.flatMap((h) => readKnownHostsEntries(h, port).map((e) => e.type)))];
  knownHostTypeCache.set(cacheKey, { at: now, types });
  return types;
}

// Build a hostVerifier that compares the server's key against ~/.ssh/known_hosts.
// - Known host, key matches: accept.
// - Known host, key mismatch: reject (MITM protection).
// - Unknown host: ACCEPT unless SSH_MCP_STRICT_HOST_KEY=1, then reject.
//
// That last branch is trust-ALWAYS, not trust-on-first-use, and the distinction is
// worth stating plainly: real TOFU pins the key it saw the first time and rejects a
// change afterwards. We never write to known_hosts, so nothing is ever pinned by
// connecting -- every connection to a host absent from known_hosts is a "first" use
// and is accepted, including one where an attacker swapped the key since the last
// call. Only hosts a user (or ssh-keyscan) put into known_hosts out of band get MITM
// protection. Set SSH_MCP_STRICT_HOST_KEY=1 to require an entry.
//
// Checks known_hosts under both the user-supplied host (e.g. a ssh_config alias) and
// the resolved hostname, matching OpenSSH's CheckHostIP behavior.
function buildHostVerifier(
  hosts: ReadonlyArray<string>,
  port: number | undefined,
  rejection: { current: HostKeyRejection | null },
): (key: Buffer) => boolean {
  const strict = process.env.SSH_MCP_STRICT_HOST_KEY === "1";
  const label = hosts.join(" / ");
  // The host to paste into the ssh-keyscan / ssh-keygen -R remediation below. Both
  // tools have the same bracket sensitivity documented for `-F` on knownHostsTargets:
  // probed on OpenSSH 10.2p1, `ssh-keygen -R '[::1]'` prints "Host [::1] not found"
  // and removes nothing, while `-R '::1'` works. `hosts` preserves the caller's
  // spelling (resolveConfig dedupes on the bare form but keeps the original), so an
  // IPv6 caller who passed `[::1]` would otherwise be handed a silent no-op to run.
  const remediationHost = unbracketHost(hosts[0]);
  return (key: Buffer) => {
    rejection.current = null;
    const known = hosts.flatMap((h) => readKnownHostsEntries(h, port));
    if (known.length === 0) {
      if (strict) {
        rejection.current = {
          reason: "unknown-host-strict",
          message: `no known_hosts entry for ${label}, and SSH_MCP_STRICT_HOST_KEY=1 requires one. Add it: ssh-keyscan -H "${remediationHost}" >> ~/.ssh/known_hosts`,
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
    rejection.current =
      offered && !knownTypes.includes(offered)
        ? {
            reason: "algorithm-not-in-known-hosts",
            message: `the server offered a ${offered} host key, but known_hosts has only ${knownTypes.join(", ")} for ${label}. This is NOT a key mismatch -- there is no ${offered} entry to compare it against. Refresh the entry: ssh-keyscan -H "${remediationHost}" >> ~/.ssh/known_hosts`,
          }
        : {
            reason: "key-mismatch",
            message: `the server's ${offered ?? "offered"} host key does NOT match the known_hosts entry of the same type for ${label}. This can mean a man-in-the-middle attack, or that the host was legitimately rekeyed. Verify the fingerprint out of band before removing the old entry with: ssh-keygen -R "${remediationHost}"`,
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
  // Username fallback chain: explicit > ssh_config User > $USER/$USERNAME > "root".
  // The trailing "root" is a last-ditch default for env-stripped contexts (containers
  // without USER/USERNAME and without ssh installed for `ssh -G` to provide a user).
  // In those cases the SSH server's "Permission denied" is the source of truth -- we
  // don't try to second-guess it client-side.
  const connectConfig: ConnectConfig = {
    host: sshConfig?.hostname || config.host,
    port,
    username: config.username || sshConfig?.user || process.env.USER || process.env.USERNAME || "root",
    keepaliveInterval: 15_000,
    keepaliveCountMax: 3,
    hostVerifier: buildHostVerifier(verifierHosts, port, hostKeyRejection),
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
    const keyPath = config.privateKeyPath.startsWith("~")
      ? join(home, config.privateKeyPath.slice(1))
      : config.privateKeyPath;
    connectConfig.privateKey = readFileSync(keyPath);
  } else if (config.password) {
    connectConfig.password = config.password;
  } else {
    const agentSock =
      config.agent ||
      process.env.SSH_AUTH_SOCK ||
      (process.platform === "win32" ? "\\\\.\\pipe\\openssh-ssh-agent" : undefined);
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
        ? sshConfig.identityFiles.map((p) => (p.startsWith("~") ? join(home, p.slice(1)) : p))
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

export function formatDiagnostics(host: string): string {
  // Run fast local checks only — skip connectivity re-test to avoid adding seconds of delay
  try {
    const checks = [
      { name: "SSH Agent", ...cachedAgentCheck() },
      { name: "SSH Keys", ...cachedKeysCheck() },
      { name: "SSH Config", ...checkSshConfig(host) },
      { name: "Known Hosts", ...checkKnownHosts(host) },
    ];

    const parts: string[] = [];
    const suggestions: string[] = [];

    for (const check of checks) {
      if (check.status !== "ok") {
        parts.push(`[${check.status.toUpperCase()}] ${check.name}: ${check.message}`);
      }
    }

    const agent = checks[0];
    if (agent.status === "error") suggestions.push('Start ssh-agent: eval "$(ssh-agent -s)"');
    if (agent.status === "warning") suggestions.push("Load a key: ssh-add ~/.ssh/id_ed25519");

    const keys = checks[1];
    if (keys.status === "error") suggestions.push('Generate a key: ssh-keygen -t ed25519 -C "your@email.com"');

    const known = checks[3];
    if (known.status === "warning") suggestions.push(`Add host key: ssh-keyscan -H "${host}" >> ~/.ssh/known_hosts`);

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
 * entries accepts ANY key unless SSH_MCP_STRICT_HOST_KEY=1. Parsing correctly is
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

export async function connectWithProxy(resolved: ResolvedConfig): Promise<Client> {
  // This is the dial path -- the only place `connectConfig.algorithms` is ever read --
  // so materialize the host-key preference order now. Deliberately not done in
  // resolveConfig: see the comment on the thunk there.
  resolved.applyHostKeyAlgorithms?.();

  const hops = resolved.proxyJump ? parseJumpSpec(resolved.proxyJump) : [];
  if (hops.length === 0) {
    return connectRaw(resolved.connectConfig);
  }

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
  let jumpClient: Client;
  try {
    jumpClient = await connectWithProxy(jumpResolved); // recursive for chained proxies
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

  const diag = formatDiagnostics(host);
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

    client.exec(command, (err, stream) => {
      if (err) {
        settle(() => reject(err));
        return;
      }
      activeStream = stream;

      const stdoutChunks: Buffer[] = [];
      const stderrChunks: Buffer[] = [];
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let stdoutTruncated = false;
      let stderrTruncated = false;

      const appendStdout = (data: Buffer) => {
        if (stdoutTruncated) return;
        const remaining = maxBytes - stdoutBytes;
        if (data.length <= remaining) {
          stdoutChunks.push(data);
          stdoutBytes += data.length;
        } else {
          if (remaining > 0) {
            stdoutChunks.push(data.subarray(0, remaining));
            stdoutBytes += remaining;
          }
          stdoutTruncated = true;
        }
      };
      const appendStderr = (data: Buffer) => {
        if (stderrTruncated) return;
        const remaining = maxBytes - stderrBytes;
        if (data.length <= remaining) {
          stderrChunks.push(data);
          stderrBytes += data.length;
        } else {
          if (remaining > 0) {
            stderrChunks.push(data.subarray(0, remaining));
            stderrBytes += remaining;
          }
          stderrTruncated = true;
        }
      };

      stream
        .on("close", (code: number | null, signal?: string) => {
          let stdout = Buffer.concat(stdoutChunks).toString("utf8");
          let stderr = Buffer.concat(stderrChunks).toString("utf8");
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
        stdoutChunks.length = 0;
        stderrChunks.length = 0;
        stdoutBytes = 0;
        stderrBytes = 0;
      };

      // The timer can fire BEFORE client.exec() calls back, in which case
      // activeStream was still null and the handler above had nothing to release or
      // tear down. Do both now. (The only settle that can precede this callback is
      // the timeout: the exec-error path returns before we get here.)
      if (settled) {
        releaseCapture();
        teardownStream(stream);
      }
    });
  });
}

function getSftp(client: Client): Promise<SFTPWrapper> {
  return new Promise((resolve, reject) => {
    client.sftp((err, sftp) => {
      if (err) return reject(err);
      resolve(sftp);
    });
  });
}

const DEFAULT_MAX_READ_BYTES = 10 * 1024 * 1024; // 10 MB

export async function readFile(client: Client, remotePath: string, maxBytes = DEFAULT_MAX_READ_BYTES): Promise<string> {
  const sftp = await getSftp(client);
  try {
    const stats = await new Promise<{ size: number }>((resolve, reject) => {
      sftp.stat(remotePath, (err, stats) => {
        if (err) return reject(err);
        resolve(stats);
      });
    });
    if (stats.size > maxBytes) {
      throw new Error(
        `File is ${(stats.size / 1024 / 1024).toFixed(1)} MB, exceeds ${(maxBytes / 1024 / 1024).toFixed(0)} MB limit. Use ssh_exec with head/tail to read a portion.`,
      );
    }
    return await new Promise((resolve, reject) => {
      sftp.readFile(remotePath, (err, data) => {
        if (err) return reject(err);
        resolve(data.toString("utf8"));
      });
    });
  } finally {
    sftp.end();
  }
}

export async function writeFile(client: Client, remotePath: string, content: string): Promise<void> {
  const sftp = await getSftp(client);
  try {
    await new Promise<void>((resolve, reject) => {
      sftp.writeFile(remotePath, content, (err) => {
        if (err) return reject(err);
        resolve();
      });
    });
  } finally {
    sftp.end();
  }
}

export async function uploadFile(client: Client, localPath: string, remotePath: string): Promise<void> {
  const resolvedLocal = localPath.startsWith("~") ? join(homedir(), localPath.slice(1)) : localPath;
  const sftp = await getSftp(client);
  try {
    await new Promise<void>((resolve, reject) => {
      sftp.fastPut(resolvedLocal, remotePath, (err) => {
        if (err) return reject(err);
        resolve();
      });
    });
  } finally {
    sftp.end();
  }
}

export async function downloadFile(client: Client, remotePath: string, localPath: string): Promise<void> {
  const resolvedLocal = localPath.startsWith("~") ? join(homedir(), localPath.slice(1)) : localPath;
  const sftp = await getSftp(client);
  try {
    await new Promise<void>((resolve, reject) => {
      sftp.fastGet(remotePath, resolvedLocal, (err) => {
        if (err) return reject(err);
        resolve();
      });
    });
  } finally {
    sftp.end();
  }
}

export async function listDir(client: Client, remotePath: string): Promise<string[]> {
  const sftp = await getSftp(client);
  try {
    return await new Promise((resolve, reject) => {
      sftp.readdir(remotePath, (err, list) => {
        if (err) return reject(err);
        resolve(list.map((item) => item.filename));
      });
    });
  } finally {
    sftp.end();
  }
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
}

export async function statFile(client: Client, remotePath: string): Promise<FileStats> {
  const sftp = await getSftp(client);
  try {
    return await new Promise((resolve, reject) => {
      sftp.stat(remotePath, (err, stats) => {
        if (err) return reject(err);
        // ssh2 exposes the type checks as methods, not boolean fields -- materialize them
        // up front so the result is a plain JSON-safe object the MCP layer can serialize.
        resolve({
          size: stats.size,
          mode: stats.mode,
          modeOctal: (stats.mode & 0o7777).toString(8).padStart(4, "0"),
          uid: stats.uid,
          gid: stats.gid,
          mtime: stats.mtime,
          atime: stats.atime,
          isFile: stats.isFile(),
          isDirectory: stats.isDirectory(),
          isSymbolicLink: stats.isSymbolicLink(),
        });
      });
    });
  } finally {
    sftp.end();
  }
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
export async function deleteFile(client: Client, remotePath: string): Promise<void> {
  const sftp = await getSftp(client);
  try {
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
  } finally {
    sftp.end();
  }
}

// Create a directory via SFTP. With recursive=true, walks the path and creates each
// missing segment in order -- SFTP has no native `mkdir -p` equivalent. Existing
// intermediate dirs are tolerated; existing leaf is still an error (matches mkdir -p
// semantics for the deepest segment).
export async function makeDir(client: Client, remotePath: string, recursive = false): Promise<void> {
  const sftp = await getSftp(client);
  try {
    const mkOne = (path: string) =>
      new Promise<void>((resolve, reject) => {
        sftp.mkdir(path, (err) => (err ? reject(err) : resolve()));
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
    for (let i = 0; i < parts.length; i++) {
      cur = `${cur}/${parts[i]}`;
      const isLeaf = i === parts.length - 1;
      try {
        await mkOne(cur);
      } catch (e: unknown) {
        // SFTP returns a generic "Failure" string when a dir already exists. Tolerate it
        // for intermediate segments; surface it for the leaf so `mkdir -p` on an existing
        // leaf still errors (matches POSIX `mkdir -p` -- which doesn't error -- only if
        // the leaf is also a dir; on file collision it does. We can't distinguish cheaply
        // without re-stating, so we err on the side of surfacing it).
        if (isLeaf) throw e;
        // Intermediate segment -- swallow and continue.
      }
    }
  } finally {
    sftp.end();
  }
}
