import { EventEmitter } from "node:events";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// What this suite pins
//
// Four ssh.ts behaviors that decide whether a normal day goes wrong quietly:
//
//   1. readFile's size guard -- the refusal AND the `finally { sftp.end() }` that
//      runs on that throw path. Pointing ssh_read_file at a production log is an
//      ordinary mistake; a regression buffers the whole file into a string and an
//      MCP frame, and leaks one SFTP session per attempt.
//   2. connectWithProxy's jump-client teardown on ALL THREE exits -- forwardOut
//      failing, the target erroring, the target closing. A bastion with forwarding
//      restricted (PermitOpen) fails at forwardOut, and without endJump every
//      attempt leaves a live bastion connection behind. The close path is what
//      backs the documented "jump connections close with the target".
//   3. statFile turning ssh2's isFile/isDirectory/isSymbolicLink METHODS into plain
//      booleans, and masking mode to 4-digit octal. ssh2 reports mode with the
//      file-type bits SET (33188 for an 0644 file), so a bare toString(8) surfaces
//      "100644"; dropping the method-to-boolean step makes the whole ssh_stat
//      result serialize as `{}` over MCP.
//   4. The explicit-password short-circuit: password set => NEITHER agent nor
//      privateKey. On Windows `agentSock` defaults to the named pipe with no service
//      check, so a regression that lets the agent through changes which method is
//      negotiated -- and, because pool.ts fingerprints the resolved auth material,
//      changes the pooled connection's identity with it.
// ---------------------------------------------------------------------------

const stubs = vi.hoisted(() => ({
  /** Home directory ssh.ts sees. Pointed at a temp path with no ~/.ssh. */
  home: "",
  /** `ssh -G <host>` script. null => the probe fails, as if ssh were not installed. */
  sshConfigLines: null as string[] | null,
  // --- fake ssh2 Client (see the vi.mock below) ---
  /** Every FakeClient that has been dialed, in dial order. */
  clients: [] as any[],
  /** Non-null => forwardOut hands this error back instead of a stream. */
  forwardOutError: null as Error | null,
  /** How the TARGET dial (the one carrying `sock`) behaves once connected. */
  targetOutcome: { kind: "ready" } as { kind: "ready" } | { kind: "error"; err: Error },
  /** When true, a SECOND end() on a client throws -- proving endJump's try/catch. */
  endThrowsOnSecondCall: false,
  /**
   * `ssh-keygen -F <target>` script, keyed by the exact target string. Anything not
   * listed is a miss. This is what lets a test have known_hosts answer for the
   * RESOLVED hostname while missing on the alias the caller actually typed.
   */
  knownHosts: {} as Record<string, string>,
  /** Every runArgs call, so a test can count subprocess spawns (the memo tests). */
  runArgsCalls: [] as { cmd: string; args: string[] }[],
}));

// A fake ssh2 Client. ssh2's runtime `Client` is imported by ssh.ts alone, so faking
// it here buys the REAL connectRaw / connectWithProxy path with no socket. Each
// instance counts its own end() calls, which is the whole point: every assertion
// below is about how many times the JUMP client got torn down.
vi.mock("ssh2", async () => {
  const { EventEmitter: EE } = await import("node:events");

  class FakeClient extends EE {
    /** "jump" until a dial arrives carrying `sock`, which only the target does. */
    role: "jump" | "target" = "jump";
    ends = 0;
    connectConfig: Record<string, any> | null = null;

    connect(cfg: Record<string, any>) {
      this.connectConfig = cfg;
      this.role = cfg.sock ? "target" : "jump";
      stubs.clients.push(this);
      queueMicrotask(() => {
        if (this.role === "jump") return void this.emit("ready");
        const outcome = stubs.targetOutcome;
        if (outcome.kind === "error") return void this.emit("error", outcome.err);
        this.emit("ready");
      });
      return this;
    }

    end() {
      this.ends++;
      // Real ssh2 end() is idempotent; this models the defensive contract the
      // endJump wrapper exists for -- a second call must not escape as a throw.
      if (stubs.endThrowsOnSecondCall && this.ends > 1) throw new Error("already ended");
      queueMicrotask(() => this.emit("close"));
    }

    forwardOut(_srcIp: string, _srcPort: number, _dstHost: string, _dstPort: number, cb: (e: any, s?: any) => void) {
      queueMicrotask(() => {
        if (stubs.forwardOutError) return cb(stubs.forwardOutError);
        cb(null, new EE());
      });
    }
  }

  return { Client: FakeClient };
});

// homedir() drives resolveConfig's default key paths. Pin it at a temp path with no
// .ssh so the jump-host resolve inside connectWithProxy never picks up the
// developer's real keys, and so the auth tests see exactly the fixture they set up.
vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  return { ...actual, homedir: () => stubs.home };
});

// `ssh -G` is the only impure edge resolveConfig touches here (known_hosts is read
// lazily on the dial path via ssh-keygen, which answers "miss" below).
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
      if (cmd === "ssh-keygen" && args[0] === "-F") {
        const hit = stubs.knownHosts[args[1]];
        return hit ? { stdout: hit, ok: true } : { stdout: "", ok: false };
      }
      return { stdout: "", ok: false };
    },
  };
});

const {
  clearKnownHostTypeCache,
  clearSshConfigCache,
  connectWithProxy,
  downloadFile,
  exec,
  formatDiagnostics,
  listDir,
  readFile,
  resolveConfig,
  statFile,
  uploadFile,
  writeFile,
} = await import("../ssh.js");

// ---------------------------------------------------------------- fixtures

const FIXTURE_ROOT = mkdtempSync(join(tmpdir(), "ssh-mcp-io-"));
/** Deliberately never created: resolveConfig must find no default keys under it. */
const FAKE_HOME = join(FIXTURE_ROOT, "home");
stubs.home = FAKE_HOME;

// Traditional PEM armor with no passphrase markers: looksLikePrivateKey says yes and
// isEncryptedKey says no, so resolveConfig folds it in alongside the agent. That is
// what gives the "the password suppressed it" assertions something to suppress.
const PLAIN_KEY = join(FIXTURE_ROOT, "id_plain");
writeFileSync(PLAIN_KEY, "-----BEGIN RSA PRIVATE KEY-----\nZmFrZS1idXQtcGxhaW4=\n-----END RSA PRIVATE KEY-----\n");

const WINDOWS_AGENT_PIPE = "\\\\.\\pipe\\openssh-ssh-agent";
const FAKE_SOCK = "/tmp/ssh-mcp-io-agent.sock";
const HOST = "io-fixture.test";

const realPlatform = process.platform;
const realAuthSock = process.env.SSH_AUTH_SOCK;

function setEnvironment(opts: { platform: NodeJS.Platform; authSock?: string }) {
  Object.defineProperty(process, "platform", { value: opts.platform, configurable: true });
  if (opts.authSock === undefined) delete process.env.SSH_AUTH_SOCK;
  else process.env.SSH_AUTH_SOCK = opts.authSock;
}

beforeEach(() => {
  stubs.sshConfigLines = null;
  stubs.clients.length = 0;
  stubs.forwardOutError = null;
  stubs.targetOutcome = { kind: "ready" };
  stubs.endThrowsOnSecondCall = false;
  clearSshConfigCache();
  clearKnownHostTypeCache();
  setEnvironment({ platform: "linux" });
});

afterEach(() => {
  Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
  if (realAuthSock === undefined) delete process.env.SSH_AUTH_SOCK;
  else process.env.SSH_AUTH_SOCK = realAuthSock;
});

// ---------------------------------------------------------------- SFTP fakes

interface SftpProbe {
  stat: string[];
  lstat: string[];
  readFile: string[];
  ended: number;
}

/**
 * ssh2 hands back a Stats OBJECT WITH METHODS, and reports `mode` with the file-type
 * bits set (S_IFREG 0o100000, S_IFDIR 0o40000, S_IFLNK 0o120000). Both details are
 * the point of the statFile tests, so the fake reproduces them faithfully instead of
 * handing over a plain bag of booleans that would pass either way.
 */
function ssh2Stats(
  mode: number,
  over: Partial<{ size: number; uid: number; gid: number; mtime: number; atime: number }> = {},
) {
  const type = mode & 0o170000;
  return {
    size: 4096,
    mode,
    uid: 1000,
    gid: 1000,
    mtime: 1_700_000_000,
    atime: 1_700_000_100,
    ...over,
    isFile: () => type === 0o100000,
    isDirectory: () => type === 0o40000,
    isSymbolicLink: () => type === 0o120000,
  };
}

/** A fake SFTPWrapper plus the client that hands it out, with an end() counter. */
function fakeSftpClient(opts: {
  stat?: (path: string) => unknown;
  lstat?: (path: string) => unknown;
  readFile?: (path: string) => Buffer | Error;
}): {
  client: any;
  probe: SftpProbe;
} {
  const probe: SftpProbe = { stat: [], lstat: [], readFile: [], ended: 0 };
  const settle = (result: unknown, cb: (err: any, value?: any) => void) => {
    queueMicrotask(() => (result instanceof Error ? cb(result) : cb(undefined, result)));
  };
  const sftp = {
    stat: (path: string, cb: (err: any, stats?: any) => void) => {
      probe.stat.push(path);
      settle(opts.stat?.(path) ?? new Error("stat not stubbed"), cb);
    },
    // statFile calls lstat FIRST (the path's own type), then stat only when that
    // says symlink. With no explicit lstat stub we fall back to the stat stub,
    // which mirrors a real server: for a non-symlink the two calls agree.
    lstat: (path: string, cb: (err: any, stats?: any) => void) => {
      probe.lstat.push(path);
      settle(opts.lstat?.(path) ?? opts.stat?.(path) ?? new Error("lstat not stubbed"), cb);
    },
    readFile: (path: string, cb: (err: any, data?: Buffer) => void) => {
      probe.readFile.push(path);
      settle(opts.readFile?.(path) ?? new Error("readFile not stubbed"), cb);
    },
    end: () => {
      probe.ended++;
    },
  };
  return { client: { sftp: (cb: (err: any, s: any) => void) => cb(null, sftp) } as any, probe };
}

const MB = 1024 * 1024;

// ---------------------------------------------------------------- gap 1

describe("readFile size guard", () => {
  it("refuses an oversize file, names the head/tail escape hatch, and never reads the bytes", async () => {
    const { client, probe } = fakeSftpClient({
      stat: () => ({ size: 3.5 * MB }),
      readFile: () => Buffer.from("should never be read"),
    });

    await expect(readFile(client, "/var/log/huge.log", MB)).rejects.toThrow(
      "File is 3.5 MB, exceeds 1 MB limit. Use ssh_exec with head/tail to read a portion.",
    );
    // The guard is worthless if the transfer already happened: the whole point is
    // that neither a 3.5 MB string nor a 3.5 MB MCP frame is ever materialized.
    expect(probe.readFile).toEqual([]);
    expect(probe.stat).toEqual(["/var/log/huge.log"]);
  });

  it("still ends the SFTP session on the oversize THROW path", async () => {
    // The leak this pins: `finally { sftp.end() }`. Without it every ssh_read_file
    // aimed at a big log burns one SFTP channel on the pooled connection, and the
    // pool keeps that connection warm for another 60s of further attempts.
    const { client, probe } = fakeSftpClient({ stat: () => ({ size: 50 * MB }) });
    await expect(readFile(client, "/var/log/huge.log", MB)).rejects.toThrow(/exceeds/);
    expect(probe.ended).toBe(1);
  });

  it("ends the SFTP session on the stat-failure throw path too", async () => {
    const { client, probe } = fakeSftpClient({ stat: () => new Error("Permission denied") });
    await expect(readFile(client, "/root/secret")).rejects.toThrow(/Permission denied/);
    expect(probe.ended).toBe(1);
  });

  it("ends the SFTP session on the readFile-failure throw path too", async () => {
    const { client, probe } = fakeSftpClient({
      stat: () => ({ size: 10 }),
      readFile: () => new Error("No such file"),
    });
    await expect(readFile(client, "/gone.txt")).rejects.toThrow(/No such file/);
    expect(probe.ended).toBe(1);
  });

  it("allows a file exactly at the cap -- the comparison is >, not >=", async () => {
    const { client, probe } = fakeSftpClient({
      stat: () => ({ size: MB }),
      readFile: () => Buffer.from("at the limit"),
    });
    await expect(readFile(client, "/var/log/exact.log", MB)).resolves.toBe("at the limit");
    expect(probe.readFile).toEqual(["/var/log/exact.log"]);
    expect(probe.ended).toBe(1);
  });

  it("defaults the cap to 10 MB when no maxBytes is passed", async () => {
    const over = fakeSftpClient({ stat: () => ({ size: 10 * MB + 1 }) });
    await expect(readFile(over.client, "/var/log/app.log")).rejects.toThrow(/exceeds 10 MB limit/);

    const under = fakeSftpClient({ stat: () => ({ size: 10 * MB }), readFile: () => Buffer.from("ok") });
    await expect(readFile(under.client, "/var/log/app.log")).resolves.toBe("ok");
  });

  it("decodes the payload as UTF-8, not a byte-per-char encoding", async () => {
    // Escaped rather than literal so this file stays ASCII on disk like its
    // neighbours; the Buffer below still carries real multi-byte UTF-8.
    const text = "caf\u00e9 -- \u65e5\u672c\u8a9e";
    const { client } = fakeSftpClient({
      stat: () => ({ size: 64 }),
      readFile: () => Buffer.from(text, "utf8"),
    });
    await expect(readFile(client, "/srv/notes.txt")).resolves.toBe(text);
  });
});

// ---------------------------------------------------------------- gap 2

describe("connectWithProxy jump-client teardown", () => {
  /** A target ResolvedConfig that routes through one bastion. */
  function targetThrough(jump: string) {
    return {
      connectConfig: { host: "target.internal", port: 22, username: "deploy" },
      proxyJump: jump,
    } as any;
  }

  const jumpClient = () => stubs.clients.find((c) => c.role === "jump");
  const targetClient = () => stubs.clients.find((c) => c.role === "target");

  it("ends the jump client when forwardOut is refused (bastion forbids direct-tcpip)", async () => {
    // PermitOpen / AllowTcpForwarding no on the bastion: the SSH session comes up,
    // the channel open does not. Without endJump each attempt leaks a live,
    // authenticated bastion connection that nothing ever closes.
    stubs.forwardOutError = new Error("Channel open failure: administratively prohibited");

    await expect(connectWithProxy(targetThrough("bastion.test"))).rejects.toThrow(/administratively prohibited/);

    expect(jumpClient().ends).toBe(1);
    // The target was never dialed, so the only thing that could leak is the jump.
    expect(targetClient()).toBeUndefined();
  });

  it("ends the jump client when the TARGET dial errors", async () => {
    stubs.targetOutcome = { kind: "error", err: new Error("All configured authentication methods failed") };

    await expect(connectWithProxy(targetThrough("bastion.test"))).rejects.toThrow(/authentication methods failed/);

    expect(jumpClient().ends).toBe(1);
  });

  it("ends the jump client when the target connection later CLOSES", async () => {
    // The documented promise: "jump host connections close when target connection
    // closes". Nothing else in the process is holding the bastion open.
    const client: any = await connectWithProxy(targetThrough("bastion.test"));

    // Not before: a live target must keep its bastion.
    expect(jumpClient().ends).toBe(0);

    client.emit("close");
    expect(jumpClient().ends).toBe(1);
  });

  it("survives an error followed by a close without a second end() escaping", async () => {
    // ssh2 emits close after error, so BOTH handlers fire and endJump runs twice.
    // The try/catch is what keeps that second call from escaping as a throw out of
    // an EventEmitter handler. The close is emitted from the test rather than from
    // the fake's own timer so the throw, if the guard is gone, lands synchronously
    // in the assertion below instead of drifting off as an unhandled error.
    stubs.endThrowsOnSecondCall = true;
    stubs.targetOutcome = { kind: "error", err: new Error("Connection reset") };

    await expect(connectWithProxy(targetThrough("bastion.test"))).rejects.toThrow(/Connection reset/);
    expect(jumpClient().ends).toBe(1);

    expect(() => targetClient().emit("close")).not.toThrow();
    expect(jumpClient().ends).toBe(2);
  });

  it("dials the target through the jump and leaves both up on the happy path", async () => {
    const client = await connectWithProxy(targetThrough("bastion.test"));

    expect(jumpClient().ends).toBe(0);
    expect(targetClient()).toBe(client);
    // The target rides the forwarded channel and keeps its own identity.
    expect(targetClient().connectConfig.sock).toBeInstanceOf(EventEmitter);
    expect(targetClient().connectConfig.host).toBe("target.internal");
    expect(jumpClient().connectConfig.host).toBe("bastion.test");
  });

  it("opens no jump client at all when there is no ProxyJump", async () => {
    const resolved = { connectConfig: { host: "direct.internal", port: 22, username: "deploy" } } as any;
    await connectWithProxy(resolved);
    expect(stubs.clients).toHaveLength(1);
    expect(stubs.clients[0].connectConfig.sock).toBeUndefined();
  });
});

// ---------------------------------------------------------------- gap 3

describe("statFile symlink handling -- lstat for TYPE, stat for METADATA", () => {
  // These are the only tests that can tell the two calls apart, so they are what
  // actually pins the fix. Every other statFile test lets lstat fall back to the
  // stat stub, which makes both calls return the same object -- a mutation from
  // lstat to stat is then invisible. Verified: reverting the source to stat-only
  // fails EXACTLY the three tests below and nothing else in the suite.
  const linkStats = () => ({
    size: 11, // a symlink's own "size" is the length of its target path
    mode: 0o120777,
    uid: 0,
    gid: 0,
    mtime: 100,
    atime: 100,
    isFile: () => false,
    isDirectory: () => false,
    isSymbolicLink: () => true,
  });
  const targetDirStats = () => ({
    size: 4096,
    mode: 0o40755,
    uid: 7,
    gid: 8,
    mtime: 900,
    atime: 901,
    isFile: () => false,
    isDirectory: () => true,
    isSymbolicLink: () => false, // stat FOLLOWS the link, so it never reports one
  });

  it("takes isSymbolicLink from lstat, which stat can never report", async () => {
    const { client } = fakeSftpClient({ lstat: linkStats, stat: targetDirStats });
    const result = await statFile(client, "/link");
    expect(result.isSymbolicLink).toBe(true);
    // ...and the target's own type still comes through alongside it.
    expect(result.isDirectory).toBe(true);
  });

  it("takes size and mode from stat -- the TARGET, not the link", async () => {
    const { client } = fakeSftpClient({ lstat: linkStats, stat: targetDirStats });
    const result = await statFile(client, "/link");
    // 4096 (the directory) rather than 11 (the length of the link's path string).
    expect(result.size).toBe(4096);
    expect(result.modeOctal).toBe("0755");
    expect(result.mtime).toBe(900);
    expect(result.uid).toBe(7);
  });

  it("reports a DANGLING symlink instead of failing the call", async () => {
    // stat rejects ENOENT because the target is gone; lstat still describes the link.
    // Before this, ssh_stat on a dangling link just errored.
    const { client, probe } = fakeSftpClient({
      lstat: linkStats,
      stat: () => new Error("No such file or directory"),
    });
    const result = await statFile(client, "/broken");
    expect(result.isSymbolicLink).toBe(true);
    expect(result.size).toBe(11); // falls back to the link's own stats
    expect(probe.ended).toBe(1); // and the session is still closed
  });

  it("does not pay a second round-trip for a non-symlink", async () => {
    const { client, probe } = fakeSftpClient({
      lstat: () => ({
        size: 1,
        mode: 0o100644,
        uid: 0,
        gid: 0,
        mtime: 1,
        atime: 1,
        isFile: () => true,
        isDirectory: () => false,
        isSymbolicLink: () => false,
      }),
      stat: () => new Error("stat must not be called for a plain file"),
    });
    const result = await statFile(client, "/plain");
    expect(result.isFile).toBe(true);
    expect(probe.stat).toEqual([]);
    expect(probe.lstat).toEqual(["/plain"]);
  });
});

describe("statFile result shape", () => {
  it("materializes ssh2's type-check METHODS into booleans that survive JSON", async () => {
    // ssh2 exposes isFile/isDirectory/isSymbolicLink as methods. JSON.stringify drops
    // functions, so handing the raw Stats to the MCP layer serializes those keys away
    // -- and in the shape ssh2 actually returns, the whole result reads as `{}`.
    const { client } = fakeSftpClient({ stat: () => ssh2Stats(33188) }); // 0o100644
    const stats = await statFile(client, "/etc/hosts");

    expect(typeof stats.isFile).toBe("boolean");
    expect(typeof stats.isDirectory).toBe("boolean");
    expect(typeof stats.isSymbolicLink).toBe("boolean");
    expect(stats.isFile).toBe(true);
    expect(stats.isDirectory).toBe(false);
    expect(stats.isSymbolicLink).toBe(false);

    // The MCP round trip, asserted directly rather than inferred.
    const overTheWire = JSON.parse(JSON.stringify(stats));
    expect(overTheWire).toEqual(stats);
    expect(Object.keys(overTheWire).sort()).toEqual([
      "atime",
      "gid",
      "isDirectory",
      "isFile",
      "isSymbolicLink",
      "mode",
      "modeOctal",
      "mtime",
      "size",
      "uid",
    ]);
  });

  it("masks the file-type bits out of modeOctal but leaves `mode` raw", async () => {
    // 33188 is what ssh2 reports for a plain 0644 file: S_IFREG (0o100000) is SET.
    // A bare stats.mode.toString(8) would surface "100644" -- not a permission mode.
    const { client } = fakeSftpClient({ stat: () => ssh2Stats(33188) });
    const stats = await statFile(client, "/etc/hosts");

    expect(stats.modeOctal).toBe("0644");
    expect(stats.mode).toBe(33188);
  });

  it("keeps the setuid/sticky bits, which sit outside a 0o777 mask", async () => {
    const suid = fakeSftpClient({ stat: () => ssh2Stats(0o104755) }); // a setuid root binary
    await expect(statFile(suid.client, "/usr/bin/sudo")).resolves.toMatchObject({ modeOctal: "4755", isFile: true });

    const sticky = fakeSftpClient({ stat: () => ssh2Stats(0o41777) }); // /tmp
    await expect(statFile(sticky.client, "/tmp")).resolves.toMatchObject({ modeOctal: "1777", isDirectory: true });
  });

  it("pads modeOctal to four digits", async () => {
    const { client } = fakeSftpClient({ stat: () => ssh2Stats(0o100004) });
    await expect(statFile(client, "/srv/odd")).resolves.toMatchObject({ modeOctal: "0004" });
  });

  it("reports a directory and a symlink by their type bits", async () => {
    const dir = fakeSftpClient({ stat: () => ssh2Stats(0o40755) });
    await expect(statFile(dir.client, "/srv")).resolves.toMatchObject({
      modeOctal: "0755",
      isDirectory: true,
      isFile: false,
      isSymbolicLink: false,
    });

    const link = fakeSftpClient({ stat: () => ssh2Stats(0o120777) });
    await expect(statFile(link.client, "/srv/current")).resolves.toMatchObject({
      modeOctal: "0777",
      isSymbolicLink: true,
      isFile: false,
      isDirectory: false,
    });
  });

  it("carries size, ownership and timestamps through unchanged", async () => {
    const { client, probe } = fakeSftpClient({
      stat: () => ssh2Stats(33188, { size: 12_345, uid: 0, gid: 42, mtime: 1_600_000_000, atime: 1_600_000_500 }),
    });
    await expect(statFile(client, "/etc/hosts")).resolves.toMatchObject({
      size: 12_345,
      uid: 0,
      gid: 42,
      mtime: 1_600_000_000,
      atime: 1_600_000_500,
    });
    expect(probe.ended).toBe(1);
  });

  it("ends the SFTP session on the stat-failure throw path", async () => {
    const { client, probe } = fakeSftpClient({ stat: () => new Error("No such file") });
    await expect(statFile(client, "/nope")).rejects.toThrow(/No such file/);
    expect(probe.ended).toBe(1);
  });
});

// ---------------------------------------------------------------- gap 4

describe("resolveConfig -- the explicit-password short-circuit", () => {
  /** Script `ssh -G` to hand back one usable identity file for this host. */
  function stubIdentityFile(path: string) {
    stubs.sshConfigLines = [`hostname ${HOST}`, "user scripted-user", "port 22", `identityfile ${path}`];
  }

  it("sets password and NEITHER agent nor privateKey on Windows, where the pipe is unconditional", () => {
    // ssh.ts defaults agentSock to the named pipe on win32 with NO service probe, so
    // "no SSH_AUTH_SOCK" is not protection here: only the short-circuit keeps the
    // agent out. Letting it through would offer publickey ahead of password AND
    // change the pool's auth fingerprint, splitting or colliding pooled connections.
    stubIdentityFile(PLAIN_KEY);
    setEnvironment({ platform: "win32" });

    const { connectConfig } = resolveConfig({ host: HOST, password: "s3cret" });

    expect(connectConfig.password).toBe("s3cret");
    expect(connectConfig.agent).toBeUndefined();
    expect(connectConfig.privateKey).toBeUndefined();
  });

  it("the same fixture WITHOUT a password does offer the pipe and the key -- the control", () => {
    // Without this, the assertions above would pass against a fixture that could
    // never have produced an agent or a key in the first place.
    stubIdentityFile(PLAIN_KEY);
    setEnvironment({ platform: "win32" });

    const { connectConfig } = resolveConfig({ host: HOST });

    expect(connectConfig.agent).toBe(WINDOWS_AGENT_PIPE);
    expect(connectConfig.privateKey).toBeInstanceOf(Buffer);
    expect(connectConfig.password).toBeUndefined();
  });

  it("holds on Linux with a live SSH_AUTH_SOCK", () => {
    stubIdentityFile(PLAIN_KEY);
    setEnvironment({ platform: "linux", authSock: FAKE_SOCK });

    const { connectConfig } = resolveConfig({ host: HOST, password: "s3cret" });

    expect(connectConfig.password).toBe("s3cret");
    expect(connectConfig.agent).toBeUndefined();
    expect(connectConfig.privateKey).toBeUndefined();
  });

  it("suppresses an EXPLICIT agent socket too, not just the discovered one", () => {
    stubIdentityFile(PLAIN_KEY);
    setEnvironment({ platform: "linux" });

    const { connectConfig } = resolveConfig({ host: HOST, password: "s3cret", agent: FAKE_SOCK });

    expect(connectConfig.password).toBe("s3cret");
    expect(connectConfig.agent).toBeUndefined();
  });

  it("leaves the rest of the resolved config intact -- the short-circuit is auth-only", () => {
    stubs.sshConfigLines = ["hostname real-host.internal", "user scripted-user", "port 2222"];
    setEnvironment({ platform: "win32" });

    const { connectConfig } = resolveConfig({ host: HOST, password: "s3cret" });

    expect(connectConfig.host).toBe("real-host.internal");
    expect(connectConfig.username).toBe("scripted-user");
    expect(connectConfig.port).toBe(2222);
    expect(typeof connectConfig.hostVerifier).toBe("function");
  });

  it("an empty-string password is NOT treated as a credential -- the agent path runs", () => {
    // Behavior of the falsy `else if (config.password)` check, pinned so a change to
    // `!== undefined` is a deliberate decision rather than an accident.
    stubIdentityFile(PLAIN_KEY);
    setEnvironment({ platform: "win32" });

    const { connectConfig } = resolveConfig({ host: HOST, password: "" });

    expect(connectConfig.password).toBeUndefined();
    expect(connectConfig.agent).toBe(WINDOWS_AGENT_PIPE);
    expect(connectConfig.privateKey).toBeInstanceOf(Buffer);
  });
});

// ---------------------------------------------------------------------------
// Gaps closed one at a time from a coverage sweep, each verified against the
// existing suite first. `stubs.knownHosts` scripts `ssh-keygen -F` per target and
// `stubs.runArgsCalls` records every spawn, which is what makes the two-name
// verifier lookup and the memo observable at all.
// ---------------------------------------------------------------------------

describe("G8 -- the host verifier checks BOTH the alias and the resolved hostname", () => {
  const KEY = Buffer.from("AAAAC3NzaC1lZDI1NTE5AAAAIGrealkeybytes", "base64");
  const line = (name: string) => `${name} ssh-ed25519 ${KEY.toString("base64")}`;

  beforeEach(() => {
    stubs.knownHosts = {};
    stubs.runArgsCalls = [];
    clearKnownHostTypeCache();
    clearSshConfigCache();
  });

  it("accepts when known_hosts answers for the RESOLVED hostname, not the alias", () => {
    // The real shape: `Host prod` in ssh_config maps to 10.0.0.5, and ssh-keyscan
    // wrote the entry under the address. Looking up only the alias would reject a
    // host the operator has legitimately trusted.
    stubs.sshConfigLines = ["hostname 10.0.0.5", "user deploy", "port 22"];
    stubs.knownHosts = { "10.0.0.5": line("10.0.0.5") };

    const verify = resolveConfig({ host: "prod" }).connectConfig.hostVerifier as (k: Buffer) => boolean;

    expect(verify(KEY)).toBe(true);
    // Both spellings were tried -- the alias first, then what `ssh -G` resolved.
    const targets = stubs.runArgsCalls
      .filter((c) => c.cmd === "ssh-keygen" && c.args[0] === "-F")
      .map((c) => c.args[1]);
    expect(targets).toContain("prod");
    expect(targets).toContain("10.0.0.5");
  });

  it("accepts when known_hosts answers for the ALIAS instead", () => {
    stubs.sshConfigLines = ["hostname 10.0.0.5", "user deploy", "port 22"];
    stubs.knownHosts = { prod: line("prod") };

    const verify = resolveConfig({ host: "prod" }).connectConfig.hostVerifier as (k: Buffer) => boolean;

    expect(verify(KEY)).toBe(true);
  });

  it("rejects a key that matches NEITHER name, and says which names it looked under", () => {
    stubs.sshConfigLines = ["hostname 10.0.0.5", "user deploy", "port 22"];
    stubs.knownHosts = { "10.0.0.5": line("10.0.0.5") };

    const resolved = resolveConfig({ host: "prod" });
    const verify = resolved.connectConfig.hostVerifier as (k: Buffer) => boolean;

    expect(verify(Buffer.from("a-completely-different-key"))).toBe(false);
    // The rejection names both spellings, so an operator can see where we looked.
    expect(resolved.hostKeyRejection?.current?.message).toContain("prod");
  });

  it("does not look up the same name twice when the alias IS the hostname", () => {
    // `ssh -G` echoes the host back as hostname for an unconfigured host, so the two
    // verifier names collapse to one and the second lookup would be pure waste.
    stubs.sshConfigLines = ["hostname web1.test", "user deploy", "port 22"];
    stubs.knownHosts = {};

    const verify = resolveConfig({ host: "web1.test" }).connectConfig.hostVerifier as (k: Buffer) => boolean;
    verify(KEY);

    const targets = stubs.runArgsCalls
      .filter((c) => c.cmd === "ssh-keygen" && c.args[0] === "-F")
      .map((c) => c.args[1]);
    expect(new Set(targets).size).toBe(targets.length);
  });
});

describe("G13 -- the known-host type memo feeding algorithm ordering", () => {
  beforeEach(() => {
    stubs.knownHosts = { "memo.test": "memo.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG" };
    stubs.runArgsCalls = [];
    clearKnownHostTypeCache();
    clearSshConfigCache();
    stubs.sshConfigLines = ["hostname memo.test", "user deploy", "port 22"];
  });

  const keygenSpawns = () => stubs.runArgsCalls.filter((c) => c.cmd === "ssh-keygen" && c.args[0] === "-F").length;

  it("reuses one `ssh-keygen -F` across repeated resolves inside the TTL", () => {
    // resolveConfig runs on every pool acquire, so without the memo a bastion
    // fronting several targets pays a spawn per call for an answer that cannot differ.
    const a = resolveConfig({ host: "memo.test" });
    a.applyHostKeyAlgorithms?.();
    const afterFirst = keygenSpawns();
    expect(afterFirst).toBeGreaterThan(0);

    const b = resolveConfig({ host: "memo.test" });
    b.applyHostKeyAlgorithms?.();

    expect(keygenSpawns()).toBe(afterFirst);
  });

  it("re-reads once the memo is cleared, so a mid-session ssh-keyscan is picked up", () => {
    const a = resolveConfig({ host: "memo.test" });
    a.applyHostKeyAlgorithms?.();
    const afterFirst = keygenSpawns();

    clearKnownHostTypeCache(); // stands in for the 5s TTL lapsing
    const b = resolveConfig({ host: "memo.test" });
    b.applyHostKeyAlgorithms?.();

    expect(keygenSpawns()).toBeGreaterThan(afterFirst);
  });

  it("feeds ORDERING only -- the verifier always re-reads known_hosts itself", () => {
    // The memo can only ever produce a suboptimal negotiation order, never a wrong
    // accept/reject, because buildHostVerifier does its own lookup on every call.
    const resolved = resolveConfig({ host: "memo.test" });
    const verify = resolved.connectConfig.hostVerifier as (k: Buffer) => boolean;
    const before = keygenSpawns();

    verify(Buffer.from("x"));
    verify(Buffer.from("y"));

    expect(keygenSpawns()).toBeGreaterThan(before);
  });
});

describe("G12 -- resolveConfig's username fallback chain", () => {
  beforeEach(() => {
    clearSshConfigCache();
    clearKnownHostTypeCache();
  });

  it("prefers an explicit username over everything else", () => {
    stubs.sshConfigLines = ["hostname u.test", "user fromconfig", "port 22"];
    expect(resolveConfig({ host: "u.test", username: "explicit" }).connectConfig.username).toBe("explicit");
  });

  it("falls back to the ssh_config User when no username is passed", () => {
    stubs.sshConfigLines = ["hostname u.test", "user fromconfig", "port 22"];
    expect(resolveConfig({ host: "u.test" }).connectConfig.username).toBe("fromconfig");
  });

  it("prefers $USER over $USERNAME when ssh_config supplies none", () => {
    // Both are set on a Git-Bash-on-Windows box, and they can disagree.
    stubs.sshConfigLines = ["hostname u.test", "port 22"];
    const priorUser = process.env.USER;
    const priorUsername = process.env.USERNAME;
    process.env.USER = "unix-name";
    process.env.USERNAME = "windows-name";
    try {
      expect(resolveConfig({ host: "u.test" }).connectConfig.username).toBe("unix-name");
    } finally {
      if (priorUser === undefined) delete process.env.USER;
      else process.env.USER = priorUser;
      if (priorUsername === undefined) delete process.env.USERNAME;
      else process.env.USERNAME = priorUsername;
    }
  });

  it('ends at "root" in an env-stripped container with no ssh client', () => {
    // The last-ditch default. Getting it wrong means the SSH server's "Permission
    // denied" names a user the operator never chose, which reads as a key problem.
    stubs.sshConfigLines = null; // `ssh -G` fails outright
    const priorUser = process.env.USER;
    const priorUsername = process.env.USERNAME;
    delete process.env.USER;
    delete process.env.USERNAME;
    try {
      expect(resolveConfig({ host: "u.test" }).connectConfig.username).toBe("root");
    } finally {
      if (priorUser !== undefined) process.env.USER = priorUser;
      if (priorUsername !== undefined) process.env.USERNAME = priorUsername;
    }
  });
});

describe("G14 -- getSftp's rejection path, shared by every SFTP helper", () => {
  /** A client whose sftp() hands back an error, as a server with the subsystem disabled does. */
  const noSftpClient = () =>
    ({
      sftp: (cb: (err: any, s?: any) => void) => cb(new Error("Channel open failure: administratively prohibited")),
    }) as any;

  it("rejects rather than hanging when the SFTP subsystem is refused", async () => {
    await expect(readFile(noSftpClient(), "/etc/hostname")).rejects.toThrow(/administratively prohibited/);
  });

  it("surfaces the same failure through every helper, not just readFile", async () => {
    // One shared getSftp, so a regression here breaks all eight tools at once.
    await expect(writeFile(noSftpClient(), "/tmp/a", "x")).rejects.toThrow(/administratively prohibited/);
    await expect(listDir(noSftpClient(), "/tmp")).rejects.toThrow(/administratively prohibited/);
    await expect(statFile(noSftpClient(), "/tmp/a")).rejects.toThrow(/administratively prohibited/);
  });
});

describe("G9 -- the SFTP helpers reject AND still close the session", () => {
  /** An sftp whose named op fails; everything else is unused. `ended` counts end(). */
  function failingSftp(op: string, err = new Error("Permission denied")) {
    const probe = { ended: 0 };
    const make =
      (name: string) =>
      (...args: unknown[]) => {
        const cb = args[args.length - 1] as (e: any, v?: any) => void;
        queueMicrotask(() => (name === op ? cb(err) : cb(null, undefined)));
      };
    const sftp = {
      writeFile: make("writeFile"),
      readdir: make("readdir"),
      fastPut: make("fastPut"),
      fastGet: make("fastGet"),
      end: () => {
        probe.ended++;
      },
    };
    return { client: { sftp: (cb: (e: any, s: any) => void) => cb(null, sftp) } as any, probe };
  }

  it("writeFile rejects and ends the session", async () => {
    const { client, probe } = failingSftp("writeFile");
    await expect(writeFile(client, "/tmp/a", "x")).rejects.toThrow("Permission denied");
    expect(probe.ended).toBe(1);
  });

  it("listDir rejects and ends the session", async () => {
    const { client, probe } = failingSftp("readdir");
    await expect(listDir(client, "/nope")).rejects.toThrow("Permission denied");
    expect(probe.ended).toBe(1);
  });

  it("uploadFile rejects and ends the session", async () => {
    const { client, probe } = failingSftp("fastPut");
    await expect(uploadFile(client, "/local/a", "/remote/a")).rejects.toThrow("Permission denied");
    expect(probe.ended).toBe(1);
  });

  it("downloadFile rejects and ends the session", async () => {
    const { client, probe } = failingSftp("fastGet");
    await expect(downloadFile(client, "/remote/a", "/local/a")).rejects.toThrow("Permission denied");
    expect(probe.ended).toBe(1);
  });
});

describe("G10 -- exec rejects on a channel error before the command settles", () => {
  /** A client whose exec hands back a stream that errors instead of closing. */
  function erroringExec(which: "stdout" | "stderr") {
    return {
      exec: (_cmd: string, cb: (err: any, stream?: any) => void) => {
        const stream: any = new EventEmitter();
        stream.stderr = new EventEmitter();
        cb(null, stream);
        queueMicrotask(() => {
          const target = which === "stdout" ? stream : stream.stderr;
          target.emit("error", new Error("Connection lost mid-command"));
        });
      },
    } as any;
  }

  it("rejects when the stdout channel errors", async () => {
    // A dropped connection mid-command. Without this the promise never settles and
    // the tool call hangs until the caller's own timeout.
    await expect(exec(erroringExec("stdout"), "sleep 5")).rejects.toThrow("Connection lost mid-command");
  });

  it("rejects when the stderr channel errors", async () => {
    await expect(exec(erroringExec("stderr"), "sleep 5")).rejects.toThrow("Connection lost mid-command");
  });

  it("propagates an exec() callback error", async () => {
    const client = {
      exec: (_cmd: string, cb: (err: any) => void) => cb(new Error("Session limit reached")),
    } as any;
    await expect(exec(client, "uptime")).rejects.toThrow("Session limit reached");
  });
});

describe("G11 -- formatDiagnostics maps each failing check to its remedy", () => {
  beforeEach(() => {
    stubs.runArgsCalls = [];
    stubs.knownHosts = {};
    clearSshConfigCache();
  });

  it("returns a non-empty report naming the checks that are not ok", () => {
    // Every runArgs call fails under this harness (no agent, no keys, no known_hosts),
    // which is exactly the broken machine formatDiagnostics exists to describe.
    const text = formatDiagnostics("web1.test");
    expect(text).toBeTruthy();
    expect(text).toContain("Suggested fixes:");
  });

  it("suggests adding the host key when known_hosts has no entry", () => {
    const text = formatDiagnostics("web1.test");
    expect(text).toContain('ssh-keyscan -H "web1.test"');
  });

  it("names the host it was asked about, not a fixed string", () => {
    expect(formatDiagnostics("other.test")).toContain("other.test");
  });
});
