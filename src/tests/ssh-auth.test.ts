import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// What this suite pins
//
// Three branches in ssh.ts that nothing else asserts, and that between them decide
// whether identity-file auth happens AT ALL on Windows:
//
//   1. isEncryptedKey()      -- the private-key format classifier.
//   2. looksLikePrivateKey() -- "is this file a key at all", the filter in front of
//                               it.
//   3. the resolveConfig auth block -- the agent-AND-key invariant, plus a walk that
//      takes the first USABLE candidate rather than the first merely READABLE one.
//
// The connection path sets `agentSock` to the Windows named pipe UNCONDITIONALLY
// (no service probe), so on Windows an agent is always "configured" and the
// encrypted-key skip is always in force. A false "encrypted" verdict therefore
// silently deletes identity-file auth for every Windows user; a false "plain"
// verdict makes ssh2 throw "no passphrase given" and kills the connect outright.
//
// The two filters differ ON PURPOSE, and the tests below hold them apart:
// looksLikePrivateKey rejects ALWAYS -- a `.pub` or a zero-byte file is not a
// credential in any format, so offering it can only shadow a real key later in the
// list. isEncryptedKey rejects only when an agent is configured, because with no
// agent an encrypted key is still the best thing left to offer and ssh2's own
// passphrase error is the one worth showing.
//
// Fixtures are REAL `ssh-keygen` output written to a temp dir. isEncryptedKey
// parses the OpenSSH v1 container and reads its ciphername field, so a
// hand-written string fixture would only pin this file's guess about the format.
// ---------------------------------------------------------------------------

// `ssh -G` is the only impure edge resolveConfig touches here (known_hosts is read
// lazily on the dial path, which these tests never take), so scripting runArgs makes
// identity-file resolution fully deterministic -- no real ssh binary, no dependence
// on the developer's ~/.ssh/config.
const stubs = vi.hoisted(() => ({
  /** Home directory ssh.ts sees. Set once the temp tree exists. */
  home: "",
  /** `ssh -G <host>` script. null => the probe fails, as if ssh were not installed. */
  sshConfigLines: null as string[] | null,
  runArgsCalls: [] as Array<{ cmd: string; args: string[] }>,
}));

vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  return { ...actual, homedir: () => stubs.home };
});

vi.mock("../diagnose.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../diagnose.js")>();
  return {
    ...actual,
    runArgs: (cmd: string, args: string[]) => {
      stubs.runArgsCalls.push({ cmd, args });
      if (cmd === "ssh" && args[0] === "-G") {
        return stubs.sshConfigLines === null
          ? { stdout: "", ok: false }
          : { stdout: stubs.sshConfigLines.join("\n"), ok: true };
      }
      // Everything else (ssh-keygen -F) misses: an unknown host, which the
      // hostVerifier accepts and which these tests never invoke anyway.
      return { stdout: "", ok: false };
    },
  };
});

// ---------------------------------------------------------------- fixtures

const FIXTURE_ROOT = mkdtempSync(join(tmpdir(), "ssh-mcp-auth-"));
const KEYS = join(FIXTURE_ROOT, "keys");
const FAKE_HOME = join(FIXTURE_ROOT, "home");
mkdirSync(KEYS, { recursive: true });
mkdirSync(join(FAKE_HOME, ".ssh"), { recursive: true });
stubs.home = FAKE_HOME;

/** ssh-keygen writes <name> and <name>.pub; we only ever read the private half. */
function keygen(name: string, args: string[]): string {
  const path = join(KEYS, name);
  execFileSync("ssh-keygen", [...args, "-C", "", "-f", path, "-q"], { stdio: "ignore" });
  return path;
}

let keygenError: unknown = null;
const fixtures = {
  /** OpenSSH v1 container, ciphername "none". */
  ed25519Plain: "",
  /** The PUBLIC half ssh-keygen wrote beside it -- the `IdentityFile ...id_ed25519.pub` typo. */
  ed25519Pub: "",
  /** OpenSSH v1 container, ciphername "aes256-ctr" (ssh-keygen's default KDF cipher). */
  ed25519Encrypted: "",
  /** Same container, a DIFFERENT cipher -- proves the check is "not none", not "not aes256-ctr". */
  ed25519EncryptedAes128: "",
  rsaPlain: "",
  ecdsaPlain: "",
  /** Traditional PEM, unencrypted: "BEGIN RSA PRIVATE KEY", no markers at all. */
  rsaPemPlain: "",
  /** Traditional PEM, encrypted: the classic Proc-Type: 4,ENCRYPTED / DEK-Info header. */
  rsaPemEncrypted: "",
  /** PKCS#8: "BEGIN ENCRYPTED PRIVATE KEY". */
  rsaPkcs8Encrypted: "",
  /** A real OpenSSH container truncated to 17 bytes -- too short for the ciphername length field. */
  truncatedContainer: "",
  /** Random bytes wrapped in OpenSSH markers: decodes, but the magic does not match. */
  garbageInMarkers: "",
  /** Not key-shaped at all. */
  garbageNoMarkers: "",
  /** Zero bytes. */
  empty: "",
  /** PuTTY's header: no PEM armor, but ssh2 has a real parser for it, so it IS a key. */
  ppk: "",
};

try {
  fixtures.ed25519Plain = keygen("ed_plain", ["-t", "ed25519", "-N", ""]);
  fixtures.ed25519Encrypted = keygen("ed_enc", ["-t", "ed25519", "-N", "hunter2"]);
  fixtures.ed25519EncryptedAes128 = keygen("ed_enc_aes128", ["-t", "ed25519", "-N", "hunter2", "-Z", "aes128-ctr"]);
  fixtures.rsaPlain = keygen("rsa_plain", ["-t", "rsa", "-b", "2048", "-N", ""]);
  fixtures.ecdsaPlain = keygen("ecdsa_plain", ["-t", "ecdsa", "-N", ""]);
  fixtures.rsaPemPlain = keygen("rsa_pem_plain", ["-t", "rsa", "-b", "2048", "-m", "PEM", "-N", ""]);
  fixtures.rsaPemEncrypted = keygen("rsa_pem_enc", ["-t", "rsa", "-b", "2048", "-m", "PEM", "-N", "hunter2"]);
  fixtures.rsaPkcs8Encrypted = keygen("rsa_pkcs8_enc", ["-t", "rsa", "-b", "2048", "-m", "PKCS8", "-N", "hunter2"]);

  // Truncate a REAL container: decode its base64 body, keep the first 17 bytes
  // (the 15-byte "openssh-key-v1\0" magic plus 2), re-wrap. readUInt32BE(15) then
  // runs off the end and throws -- the one input that actually reaches the catch.
  const body = readFileSync(fixtures.ed25519Plain, "utf8").match(
    /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END/,
  ) as RegExpMatchArray;
  const raw = Buffer.from(body[1].replace(/\s+/g, ""), "base64");
  fixtures.truncatedContainer = join(KEYS, "truncated");
  writeFileSync(
    fixtures.truncatedContainer,
    `-----BEGIN OPENSSH PRIVATE KEY-----\n${raw.subarray(0, 17).toString("base64")}\n-----END OPENSSH PRIVATE KEY-----\n`,
  );

  fixtures.garbageInMarkers = join(KEYS, "garbage_in_markers");
  writeFileSync(
    fixtures.garbageInMarkers,
    "-----BEGIN OPENSSH PRIVATE KEY-----\nbm90LWEtcmVhbC1rZXktYXQtYWxs\n-----END OPENSSH PRIVATE KEY-----\n",
  );

  fixtures.garbageNoMarkers = join(KEYS, "garbage");
  writeFileSync(fixtures.garbageNoMarkers, "this file is not a private key in any format\n");

  fixtures.empty = join(KEYS, "empty");
  writeFileSync(fixtures.empty, "");

  // ssh-keygen already wrote the public half beside every private key above.
  fixtures.ed25519Pub = `${fixtures.ed25519Plain}.pub`;

  // Shape-only PPK -- enough of the header to answer "is a key present here", which
  // is all looksLikePrivateKey asks. ssh2 parses this format, so it must NOT be
  // skipped; a full valid .ppk would pin ssh2's parser, not ssh.ts's filter.
  fixtures.ppk = join(KEYS, "putty.ppk");
  writeFileSync(
    fixtures.ppk,
    [
      "PuTTY-User-Key-File-2: ssh-rsa",
      "Encryption: none",
      "Comment: fixture",
      "Public-Lines: 1",
      "AAAA",
      "Private-Lines: 1",
      "AAAA",
      "Private-MAC: 00",
      "",
    ].join("\n"),
  );
} catch (err) {
  keygenError = err;
}

afterAll(() => {
  rmSync(FIXTURE_ROOT, { recursive: true, force: true });
});

const { clearSshConfigCache, resolveConfig } = await import("../ssh.js");

// ---------------------------------------------------------------- environment control

const realPlatform = process.platform;
const realAuthSock = process.env.SSH_AUTH_SOCK;

/**
 * `agentSock` falls back to the Windows named pipe on win32, so BOTH knobs have to be
 * pinned for a test to answer the same on every developer's machine.
 */
function setEnvironment(opts: { platform: NodeJS.Platform; authSock?: string }) {
  Object.defineProperty(process, "platform", { value: opts.platform, configurable: true });
  if (opts.authSock === undefined) delete process.env.SSH_AUTH_SOCK;
  else process.env.SSH_AUTH_SOCK = opts.authSock;
}

const WINDOWS_AGENT_PIPE = "\\\\.\\pipe\\openssh-ssh-agent";
const FAKE_SOCK = "/tmp/ssh-mcp-test-agent.sock";
const HOST = "auth-fixture.test";

/** Script `ssh -G` to hand back this identity-file list (and nothing else notable). */
function stubIdentityFiles(paths: string[]) {
  stubs.sshConfigLines = [
    `hostname ${HOST}`,
    "user scripted-user",
    "port 22",
    ...paths.map((p) => `identityfile ${p}`),
  ];
}

/** Script `ssh -G` to fail, which is what drives the hardcoded default-key-path list. */
function stubNoSshBinary() {
  stubs.sshConfigLines = null;
}

beforeEach(() => {
  stubs.runArgsCalls.length = 0;
  stubs.home = FAKE_HOME;
  stubIdentityFiles([]);
  clearSshConfigCache();
  // Default: a POSIX box with no agent. Each test that cares sets its own.
  setEnvironment({ platform: "linux" });
});

afterEach(() => {
  Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
  if (realAuthSock === undefined) delete process.env.SSH_AUTH_SOCK;
  else process.env.SSH_AUTH_SOCK = realAuthSock;
});

/**
 * Ask the classifier about ONE key, through the only path that exposes it.
 *
 * With an agent configured, `resolveConfig` folds an on-disk key in only when
 * `isEncryptedKey` says no. So: privateKey absent => classified ENCRYPTED,
 * privateKey present => classified PLAIN. The agent is passed explicitly, which
 * keeps this answer independent of platform and of $SSH_AUTH_SOCK.
 *
 * ONLY MEANINGFUL FOR A FILE THAT CARRIES PRIVATE-KEY ARMOR. The walk runs two
 * filters now, and an absent privateKey no longer identifies which one fired: a
 * candidate that `looksLikePrivateKey` rejects never reaches `isEncryptedKey` at
 * all. Ask about those with `offeredKey` below, which puts the question the way the
 * walk actually answers it.
 */
function classifiedAsEncrypted(keyPath: string): boolean {
  clearSshConfigCache();
  stubIdentityFiles([keyPath]);
  const { connectConfig } = resolveConfig({ host: HOST, agent: FAKE_SOCK });
  expect(connectConfig.agent).toBe(FAKE_SOCK); // the guard is genuinely armed
  return connectConfig.privateKey === undefined;
}

/**
 * What the identity walk ends up OFFERING for a given identityfile list, or
 * undefined when every candidate was skipped.
 *
 * `agent: false` clears BOTH agent sources ($SSH_AUTH_SOCK and the win32 pipe) so
 * the no-agent branch is the one under test; the assertion inside keeps that from
 * drifting silently if the fallback chain changes.
 */
function offeredKey(paths: string[], opts: { agent: boolean }): Buffer | string | undefined {
  clearSshConfigCache();
  stubIdentityFiles(paths);
  setEnvironment({ platform: "linux", authSock: opts.agent ? FAKE_SOCK : undefined });
  const { connectConfig } = resolveConfig({ host: HOST });
  expect(connectConfig.agent).toBe(opts.agent ? FAKE_SOCK : undefined);
  return connectConfig.privateKey;
}

// ---------------------------------------------------------------- gap 1

describe("private-key fixtures", () => {
  it("were generated by a real ssh-keygen", () => {
    // Loud rather than silently skipped: every classification test below is only
    // meaningful because these bytes came out of OpenSSH, not out of this file.
    expect(keygenError).toBeNull();
    expect(readFileSync(fixtures.ed25519Plain, "utf8")).toMatch(/^-----BEGIN OPENSSH PRIVATE KEY-----/);
    expect(readFileSync(fixtures.rsaPemEncrypted, "utf8")).toContain("Proc-Type: 4,ENCRYPTED");
    expect(readFileSync(fixtures.rsaPkcs8Encrypted, "utf8")).toMatch(/^-----BEGIN ENCRYPTED PRIVATE KEY-----/);

    // The premise of the `IdentityFile ...id_ed25519.pub` case: a real .pub is a
    // one-line base64 blob with no private-key armor anywhere in it.
    const pub = readFileSync(fixtures.ed25519Pub, "utf8");
    expect(pub).toMatch(/^ssh-ed25519 /);
    expect(pub).not.toContain("PRIVATE KEY");
  });
});

describe("isEncryptedKey classification (via the agent-configured skip)", () => {
  it("calls an unencrypted OpenSSH v1 key PLAIN -- ed25519, rsa and ecdsa alike", () => {
    // All three are the same container with ciphername "none". Misreading any of
    // them as encrypted silently removes identity-file auth on every Windows box.
    expect(classifiedAsEncrypted(fixtures.ed25519Plain)).toBe(false);
    expect(classifiedAsEncrypted(fixtures.rsaPlain)).toBe(false);
    expect(classifiedAsEncrypted(fixtures.ecdsaPlain)).toBe(false);
  });

  it("calls a passphrase-protected OpenSSH v1 key ENCRYPTED, whichever cipher it used", () => {
    // The header is byte-identical to the plain one -- only the ciphername field
    // inside the base64 container differs, which is why this needs real key bytes.
    expect(classifiedAsEncrypted(fixtures.ed25519Encrypted)).toBe(true);
    expect(classifiedAsEncrypted(fixtures.ed25519EncryptedAes128)).toBe(true);
    // Pin the premise: nothing in the ARMORED text says "encrypted".
    const armored = readFileSync(fixtures.ed25519Encrypted, "utf8");
    expect(armored).toMatch(/^-----BEGIN OPENSSH PRIVATE KEY-----/);
    expect(armored.split("\n")[1]).not.toContain("ENCRYPTED");
  });

  it("calls a traditional PEM key PLAIN, and its Proc-Type/DEK-Info sibling ENCRYPTED", () => {
    expect(classifiedAsEncrypted(fixtures.rsaPemPlain)).toBe(false);
    expect(classifiedAsEncrypted(fixtures.rsaPemEncrypted)).toBe(true);
  });

  it("calls a PKCS#8 'BEGIN ENCRYPTED PRIVATE KEY' file ENCRYPTED", () => {
    expect(classifiedAsEncrypted(fixtures.rsaPkcs8Encrypted)).toBe(true);
  });

  it("is conservative about a truncated OpenSSH container (the catch)", () => {
    // 17 bytes: the magic fits, the ciphername length field does not, so
    // readUInt32BE throws and the catch answers "encrypted" -- don't fold it in.
    expect(classifiedAsEncrypted(fixtures.truncatedContainer)).toBe(true);
  });

  it("is conservative about OpenSSH markers wrapping non-container bytes", () => {
    // CHANGED -- this test used to assert `false` and was labelled a pin on the
    // trailing `return false`. That WAS the bug, and it is the one that actually
    // fires in the field: Node's base64 decoder is LENIENT, dropping characters it
    // does not recognise instead of throwing, so a corrupted body still decodes --
    // just to bytes whose openssh-key-v1 magic does not match. The old code read
    // that as "plain", folded the corrupt file in, and ssh2 died on parse. A magic
    // mismatch is now treated exactly like the throw beneath it, which is what the
    // "unparseable -> be conservative" comment always claimed.
    expect(classifiedAsEncrypted(fixtures.garbageInMarkers)).toBe(true);

    // Premise: the body really does decode, so this is the MISMATCH branch and not
    // the catch. The catch still needs the truncated container from the test above.
    const body = readFileSync(fixtures.garbageInMarkers, "utf8").match(
      /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END/,
    ) as RegExpMatchArray;
    expect(Buffer.from(body[1].replace(/\s+/g, ""), "base64").toString("latin1")).toBe("not-a-real-key-at-all");
  });
});

// ---------------------------------------------------------------- gap 3

describe("resolveConfig identity walk -- candidates that are not keys at all", () => {
  // CHANGED, all of it. These cases used to be pinned AS BUGS: the walk accepted the
  // first READABLE candidate and broke out, so a zero-byte file, a `.pub`, or any
  // stray text at the head of the identityfile list became connectConfig.privateKey
  // and the real key behind it was never reached. `looksLikePrivateKey` now skips a
  // candidate that carries no private-key marker -- ALWAYS, agent or not, since such
  // a file is not a credential in any format and offering it can only cost us the
  // key further down.

  it("skips an EMPTY file and offers the real key behind it (was: offered zero bytes)", () => {
    expect(offeredKey([fixtures.empty, fixtures.rsaPlain], { agent: true })).toEqual(readFileSync(fixtures.rsaPlain));
  });

  it("skips the empty file with NO agent too -- this filter is not agent-gated", () => {
    // Deliberately unlike the encrypted-key skip, which stays gated on `agentSock &&`
    // because an encrypted key is at least a key. Zero bytes never are.
    expect(offeredKey([fixtures.empty, fixtures.rsaPlain], { agent: false })).toEqual(readFileSync(fixtures.rsaPlain));
  });

  it("skips a .pub at the head of the list -- the `IdentityFile ...id_ed25519.pub` typo", () => {
    // The reachable real-world case: a public key has no BEGIN/END markers, so the
    // old walk classified it plain, loaded it, and identity auth was dead.
    expect(offeredKey([fixtures.ed25519Pub, fixtures.ed25519Plain], { agent: true })).toEqual(
      readFileSync(fixtures.ed25519Plain),
    );
  });

  it("skips a non-key text file and offers the key behind it", () => {
    expect(offeredKey([fixtures.garbageNoMarkers, fixtures.ed25519Plain], { agent: true })).toEqual(
      readFileSync(fixtures.ed25519Plain),
    );
  });

  it("skips markers-around-garbage when an agent is present, reaching the key behind it", () => {
    // Armor IS present here, so looksLikePrivateKey passes it through; what rejects
    // it is isEncryptedKey's newly conservative answer to a magic mismatch.
    expect(offeredKey([fixtures.garbageInMarkers, fixtures.rsaPlain], { agent: true })).toEqual(
      readFileSync(fixtures.rsaPlain),
    );
  });

  it("leaves privateKey UNSET when every candidate is unusable, instead of offering garbage", () => {
    // The agent is then offered alone -- the same shape as "no identity file exists".
    // Previously the first of these three became the privateKey and ssh2 was handed
    // bytes that could only fail to parse.
    const junk = [fixtures.empty, fixtures.ed25519Pub, fixtures.garbageNoMarkers];
    expect(offeredKey(junk, { agent: true })).toBeUndefined();
    expect(offeredKey(junk, { agent: false })).toBeUndefined();
  });

  it("does NOT skip a PuTTY-format key -- ssh2 parses that format, so it is a key", () => {
    // The predicate asks "is a key present here", not "is this PEM". Narrowing it to
    // the PEM armor alone would silently drop a working .ppk identity, which is the
    // exact failure mode this whole describe block exists to prevent.
    expect(offeredKey([fixtures.ppk, fixtures.rsaPlain], { agent: true })).toEqual(readFileSync(fixtures.ppk));
  });
});

// ---------------------------------------------------------------- gap 2

describe("resolveConfig auth block -- the agent-AND-key invariant", () => {
  it("(a) sets agent AND privateKey TOGETHER when no credential was passed", () => {
    // THE load-bearing invariant. Restoring the old short-circuit (`else if`
    // after the agent branch) makes every Windows user whose OpenSSH agent
    // service is up but holds no usable key lose identity-file auth entirely.
    stubIdentityFiles([fixtures.ed25519Plain]);
    setEnvironment({ platform: "linux", authSock: FAKE_SOCK });

    const { connectConfig } = resolveConfig({ host: HOST });
    expect(connectConfig.agent).toBe(FAKE_SOCK);
    expect(connectConfig.privateKey).toEqual(readFileSync(fixtures.ed25519Plain));
    expect(connectConfig.password).toBeUndefined();
  });

  it("(a) holds on Windows with no SSH_AUTH_SOCK, where the pipe is assumed unconditionally", () => {
    stubIdentityFiles([fixtures.ed25519Plain]);
    setEnvironment({ platform: "win32" });

    const { connectConfig } = resolveConfig({ host: HOST });
    expect(connectConfig.agent).toBe(WINDOWS_AGENT_PIPE);
    expect(connectConfig.privateKey).toEqual(readFileSync(fixtures.ed25519Plain));
  });

  it("(b) an explicit privateKeyPath sets privateKey and NOT agent, even with an agent available", () => {
    stubIdentityFiles([fixtures.rsaPlain]);
    setEnvironment({ platform: "win32", authSock: FAKE_SOCK });

    const { connectConfig } = resolveConfig({ host: HOST, privateKeyPath: fixtures.ed25519Plain });
    expect(connectConfig.privateKey).toEqual(readFileSync(fixtures.ed25519Plain));
    expect(connectConfig.agent).toBeUndefined();
    expect(connectConfig.password).toBeUndefined();
  });

  it("(b) an explicit privateKeyPath is used VERBATIM -- an encrypted one is not filtered out", () => {
    // The skip is an agent-fallback heuristic only. An explicitly named key is
    // what the caller asked for; ssh2 surfaces the passphrase error itself.
    setEnvironment({ platform: "win32", authSock: FAKE_SOCK });
    const { connectConfig } = resolveConfig({ host: HOST, privateKeyPath: fixtures.ed25519Encrypted });
    expect(connectConfig.privateKey).toEqual(readFileSync(fixtures.ed25519Encrypted));
    expect(connectConfig.agent).toBeUndefined();
  });

  it("(c) an explicit password sets password and neither agent nor privateKey", () => {
    stubIdentityFiles([fixtures.ed25519Plain]);
    setEnvironment({ platform: "win32", authSock: FAKE_SOCK });

    const { connectConfig } = resolveConfig({ host: HOST, password: "s3cret" });
    expect(connectConfig.password).toBe("s3cret");
    expect(connectConfig.agent).toBeUndefined();
    expect(connectConfig.privateKey).toBeUndefined();
  });

  it("(c) privateKeyPath wins over password when both are given", () => {
    const { connectConfig } = resolveConfig({
      host: HOST,
      privateKeyPath: fixtures.ed25519Plain,
      password: "s3cret",
    });
    expect(connectConfig.privateKey).toEqual(readFileSync(fixtures.ed25519Plain));
    expect(connectConfig.password).toBeUndefined();
  });

  it("(d) with an agent, an ENCRYPTED key is skipped and the next readable one is folded in", () => {
    // The setup this protects: an encrypted key on disk whose decrypted copy lives
    // in the agent. Folding the encrypted bytes in makes ssh2 throw "no passphrase
    // given" on parse, killing a connect the agent alone would have completed.
    stubIdentityFiles([fixtures.ed25519Encrypted, fixtures.rsaPlain]);
    setEnvironment({ platform: "linux", authSock: FAKE_SOCK });

    const { connectConfig } = resolveConfig({ host: HOST });
    expect(connectConfig.agent).toBe(FAKE_SOCK);
    expect(connectConfig.privateKey).toEqual(readFileSync(fixtures.rsaPlain));
    expect(connectConfig.privateKey).not.toEqual(readFileSync(fixtures.ed25519Encrypted));
  });

  it("(d) with an agent and ONLY encrypted keys, the agent is offered alone", () => {
    stubIdentityFiles([fixtures.ed25519Encrypted, fixtures.rsaPemEncrypted, fixtures.rsaPkcs8Encrypted]);
    setEnvironment({ platform: "linux", authSock: FAKE_SOCK });

    const { connectConfig } = resolveConfig({ host: HOST });
    expect(connectConfig.agent).toBe(FAKE_SOCK);
    expect(connectConfig.privateKey).toBeUndefined();
  });

  it("(e) with NO agent, the first existing key is loaded regardless of encryption", () => {
    stubIdentityFiles([fixtures.ed25519Encrypted, fixtures.rsaPlain]);
    setEnvironment({ platform: "linux" }); // no SSH_AUTH_SOCK, not win32 -> no agent

    const { connectConfig } = resolveConfig({ host: HOST });
    expect(connectConfig.agent).toBeUndefined();
    // The ENCRYPTED one, precisely because the skip is gated on `agentSock &&`.
    expect(connectConfig.privateKey).toEqual(readFileSync(fixtures.ed25519Encrypted));
  });

  it("(e) holds for every encrypted format, not just the OpenSSH container", () => {
    setEnvironment({ platform: "linux" });
    for (const path of [fixtures.rsaPemEncrypted, fixtures.rsaPkcs8Encrypted, fixtures.truncatedContainer]) {
      clearSshConfigCache();
      stubIdentityFiles([path]);
      const { connectConfig } = resolveConfig({ host: HOST });
      expect(connectConfig.agent).toBeUndefined();
      expect(connectConfig.privateKey).toEqual(readFileSync(path));
    }
  });
});

describe("resolveConfig identity-file walk", () => {
  it("stops at the FIRST existing key -- there is no walk of the whole list", () => {
    stubIdentityFiles([fixtures.ed25519Plain, fixtures.rsaPlain]);
    setEnvironment({ platform: "linux", authSock: FAKE_SOCK });

    const { connectConfig } = resolveConfig({ host: HOST });
    expect(connectConfig.privateKey).toEqual(readFileSync(fixtures.ed25519Plain));
  });

  it("skips entries that do not exist and keeps going", () => {
    stubIdentityFiles([join(KEYS, "does_not_exist"), join(KEYS, "also_missing"), fixtures.rsaPlain]);
    setEnvironment({ platform: "linux", authSock: FAKE_SOCK });

    const { connectConfig } = resolveConfig({ host: HOST });
    expect(connectConfig.privateKey).toEqual(readFileSync(fixtures.rsaPlain));
  });

  it("expands a ~ in an ssh_config identityfile against the home directory", () => {
    const homeKey = join(FAKE_HOME, ".ssh", "config_identity");
    writeFileSync(homeKey, readFileSync(fixtures.ed25519Plain));
    stubIdentityFiles(["~/.ssh/config_identity"]);
    setEnvironment({ platform: "linux", authSock: FAKE_SOCK });

    const { connectConfig } = resolveConfig({ host: HOST });
    expect(connectConfig.privateKey).toEqual(readFileSync(homeKey));
  });

  it("falls back to ~/.ssh/id_ed25519, id_rsa, id_ecdsa in order when `ssh -G` fails", () => {
    // The hardcoded list is only reachable with no ssh client -- OpenSSH emits an
    // identityfile list for every host even with no IdentityFile line.
    stubNoSshBinary();
    setEnvironment({ platform: "linux", authSock: FAKE_SOCK });

    // id_ed25519 absent, id_rsa present -> id_rsa wins over the later id_ecdsa.
    const idRsa = join(FAKE_HOME, ".ssh", "id_rsa");
    const idEcdsa = join(FAKE_HOME, ".ssh", "id_ecdsa");
    writeFileSync(idRsa, readFileSync(fixtures.rsaPlain));
    writeFileSync(idEcdsa, readFileSync(fixtures.ecdsaPlain));

    const first = resolveConfig({ host: "no-ssh-binary.test" }).connectConfig;
    expect(first.privateKey).toEqual(readFileSync(idRsa));

    // Now add id_ed25519: it precedes id_rsa in the list, so it takes over.
    const idEd = join(FAKE_HOME, ".ssh", "id_ed25519");
    writeFileSync(idEd, readFileSync(fixtures.ed25519Plain));
    clearSshConfigCache();
    const second = resolveConfig({ host: "no-ssh-binary-2.test" }).connectConfig;
    expect(second.privateKey).toEqual(readFileSync(idEd));

    rmSync(idEd);
    rmSync(idRsa);
    rmSync(idEcdsa);
  });

  it("leaves privateKey unset when no identity file exists at all", () => {
    stubIdentityFiles([join(KEYS, "nope_1"), join(KEYS, "nope_2")]);
    setEnvironment({ platform: "linux", authSock: FAKE_SOCK });

    const { connectConfig } = resolveConfig({ host: HOST });
    expect(connectConfig.privateKey).toBeUndefined();
    expect(connectConfig.agent).toBe(FAKE_SOCK);
  });
});
