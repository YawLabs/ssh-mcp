import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Connection-failure diagnostics must describe THIS failure. The machine these tests
// model is the one the bug was reported on: Windows, SSH_AUTH_SOCK left pointing at a
// dead socket, the OpenSSH agent pipe alive. Before classification, every failure --
// a refused TCP connect, a DNS miss, a strict host-key refusal -- led with the same
// "SSH Agent" warning.
//
// Only the process / OS edges are faked (execFileSync, homedir, ssh2's Client), so
// the REAL checkSshAgent / checkSshKeys / checkKnownHosts / formatDiagnostics run and
// every subprocess they would spawn is recorded in `edges.spawns`.

const DEAD_SOCK = "/tmp/ssh-XXXXdead/agent.123";

const edges = vi.hoisted(() => ({
  home: "",
  spawns: [] as Array<{ cmd: string; args: string[] }>,
  /** The agent at the inherited SSH_AUTH_SOCK: dead, or alive with no identities. */
  inheritedAgent: "dead" as "dead" | "empty",
  /** `ssh -G` answer per host; absent -> ssh fails (no ssh_config data). */
  sshG: new Map<string, string>(),
  /** What the fake ssh2 server does on connect; `errorByHost` wins over `error` for that dialed host. */
  dial: { error: null as Error | null, hostKey: null as Buffer | null, errorByHost: new Map<string, Error>() },
}));

vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  return { ...actual, homedir: () => edges.home };
});

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  const fail = (stderr: string) =>
    Object.assign(new Error(`Command failed: ${stderr}`), { stdout: Buffer.from(""), stderr: Buffer.from(stderr) });
  return {
    ...actual,
    execFileSync: (cmd: string, args: string[], opts?: { env?: Record<string, string> }) => {
      edges.spawns.push({ cmd, args });
      if (cmd === "ssh-add") {
        // runArgs passes an env copy only when it deliberately DROPS SSH_AUTH_SOCK to
        // reach the Windows pipe: that agent is alive. The inherited, dead socket is not.
        if (opts?.env && !("SSH_AUTH_SOCK" in opts.env)) return "256 SHA256:abc me@box (ED25519)\n";
        if (edges.inheritedAgent === "empty") throw fail("The agent has no identities.");
        throw fail("Error connecting to agent: No such file or directory");
      }
      if (cmd === "ssh" && args[0] === "-G") {
        const answer = edges.sshG.get(String(args.at(-1)));
        if (answer !== undefined) return answer;
        throw fail("ssh: unavailable in this test");
      }
      throw fail(`${cmd}: not found`); // ssh-keygen -F: no known_hosts entry
    },
  };
});

vi.mock("ssh2", async () => {
  const { EventEmitter } = await import("node:events");
  class FakeClient extends EventEmitter {
    connect(cfg: Record<string, any>) {
      queueMicrotask(() => {
        if (edges.dial.hostKey && typeof cfg.hostVerifier === "function" && !cfg.hostVerifier(edges.dial.hostKey)) {
          return void this.emit("error", new Error("Host denied (verification failed)"));
        }
        const error = edges.dial.errorByHost.get(cfg.host) ?? edges.dial.error;
        if (error) return void this.emit("error", error);
        this.emit("ready");
      });
      return this;
    }
    // A reached jump host opens the forwarded channel; the target is then dialed over it.
    forwardOut(_a: string, _b: number, _c: string, _d: number, cb: (e: unknown, s?: unknown) => void) {
      queueMicrotask(() => cb(undefined, new EventEmitter()));
    }
    end() {}
  }
  return { Client: FakeClient };
});

const {
  classifySshFailure,
  clearSshConfigCache,
  connect,
  connectWithProxy,
  enhanceSshError,
  formatDiagnostics,
  resolveConfig,
} = await import("../ssh.js");
const { ConnectionPool } = await import("../pool.js");

// ---------------------------------------------------------------- fixtures

const homes: string[] = [];
function makeHome(withKey: boolean): string {
  const home = mkdtempSync(join(process.env.TMPDIR || process.env.TEMP || "/tmp", "ssh-mcp-diag-"));
  homes.push(home);
  mkdirSync(join(home, ".ssh"));
  writeFileSync(join(home, ".ssh", "known_hosts"), "");
  if (withKey) {
    writeFileSync(
      join(home, ".ssh", "id_ed25519"),
      "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
    );
  }
  return home;
}
const HOME_WITH_KEY = makeHome(true);
const HOME_NO_KEYS = makeHome(false);
afterAll(() => {
  for (const h of homes) rmSync(h, { recursive: true, force: true });
});

const savedPlatform = Object.getOwnPropertyDescriptor(process, "platform") as PropertyDescriptor;
const savedEnv = { SSH_AUTH_SOCK: process.env.SSH_AUTH_SOCK, STRICT: process.env.SSH_MCP_STRICT_HOSTKEYS };
function setPlatform(p: NodeJS.Platform) {
  Object.defineProperty(process, "platform", { value: p, configurable: true });
}
function setEnv(name: string, value: string | undefined) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

// The agent/keys checks are memoized for 2s on Date.now(). Each test runs a minute
// after the last on a fake clock, so no answer leaks between tests.
let clock = Date.UTC(2030, 0, 1);

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  clock += 60_000;
  vi.setSystemTime(clock);
  clearSshConfigCache();
  edges.home = HOME_WITH_KEY;
  edges.spawns = [];
  edges.inheritedAgent = "dead";
  edges.sshG.clear();
  edges.dial = { error: null, hostKey: null, errorByHost: new Map() };
  // The reported machine.
  setPlatform("win32");
  setEnv("SSH_AUTH_SOCK", DEAD_SOCK);
  setEnv("SSH_MCP_STRICT_HOSTKEYS", undefined);
});

afterEach(() => {
  vi.useRealTimers();
  Object.defineProperty(process, "platform", savedPlatform);
  setEnv("SSH_AUTH_SOCK", savedEnv.SSH_AUTH_SOCK);
  setEnv("SSH_MCP_STRICT_HOSTKEYS", savedEnv.STRICT);
});

const netErr = (code: string, message: string, level = "client-socket") =>
  Object.assign(new Error(message), { code, level });

/** The `[TAG] Name` heads of a diagnostics block, in order. */
function sections(message: string): string[] {
  const block = message.split("SSH Diagnostics:\n")[1] ?? "";
  return block
    .split("\n")
    .map(
      (line) =>
        line.match(/^\[(?:ERROR|WARNING|INFO)\] ([^:]+):/)?.[1] ??
        (line.startsWith("Suggested fixes:") ? "Suggested fixes" : null),
    )
    .filter((s): s is string => s !== null);
}

const spawned = (cmd: string) => edges.spawns.filter((s) => s.cmd === cmd);

// ---------------------------------------------------------------- classification

describe("classifySshFailure", () => {
  it.each([
    ["ECONNREFUSED", netErr("ECONNREFUSED", "connect ECONNREFUSED 10.0.0.5:22")],
    ["ENOTFOUND", netErr("ENOTFOUND", "getaddrinfo ENOTFOUND nope.test")],
    ["EAI_AGAIN", netErr("EAI_AGAIN", "getaddrinfo EAI_AGAIN nope.test")],
    ["ETIMEDOUT", netErr("ETIMEDOUT", "connect ETIMEDOUT 10.0.0.5:22")],
    ["EHOSTUNREACH", netErr("EHOSTUNREACH", "connect EHOSTUNREACH 10.0.0.5:22")],
    [
      "a code with no ssh2 level",
      Object.assign(new Error("connect ECONNREFUSED 1.2.3.4:22"), { code: "ECONNREFUSED" }),
    ],
    ["a code only in the message", new Error("ECONNREFUSED 10.0.0.9:22")],
    [
      "ssh2's handshake timeout",
      Object.assign(new Error("Timed out while waiting for handshake"), { level: "client-timeout" }),
    ],
    ["an ssh2 DNS failure", Object.assign(new Error("Error while looking up IPv4 address"), { level: "client-dns" })],
    ["a ProxyJump channel failure", new Error("(SSH) Channel open failure: Connection refused")],
  ])("network: %s", (_label, err) => {
    expect(classifySshFailure(err)).toBe("network");
  });

  it.each([
    [
      "ssh2's auth exhaustion",
      Object.assign(new Error("All configured authentication methods failed"), { level: "client-authentication" }),
    ],
    ["the same text with no level", new Error("All configured authentication methods failed")],
    ["a dead agent (cygwin path)", Object.assign(new Error("Invalid cygwin unix socket path"), { level: "agent" })],
    ["a dead agent pipe", Object.assign(new Error("Failed to connect to agent"), { level: "agent" })],
    // The trap: an agent socket that refuses carries a NETWORK code. The level says
    // it is the agent, and the level is read first.
    [
      "an agent socket refusing with ECONNREFUSED",
      Object.assign(new Error("connect ECONNREFUSED /tmp/a.sock"), { code: "ECONNREFUSED", level: "agent" }),
    ],
    [
      "an unparseable key file",
      new Error("Cannot parse privateKey: Encrypted private OpenSSH key detected, but no passphrase given"),
    ],
  ])("auth: %s", (_label, err) => {
    expect(classifySshFailure(err)).toBe("auth");
  });

  it("host-key: a recorded rejection wins over whatever the error says", () => {
    const resolved = {
      connectConfig: {},
      hostKeyRejection: { current: { reason: "key-mismatch" as const, message: "x" } },
    };
    expect(classifySshFailure(new Error("Host denied (verification failed)"), resolved)).toBe("host-key");
    expect(classifySshFailure(new Error("anything"), resolved)).toBe("host-key");
    expect(classifySshFailure(new Error("Host denied (verification failed)"))).toBe("host-key");
  });

  it.each([
    ["a generic error", new Error("boom")],
    [
      "a missing privateKeyPath",
      Object.assign(new Error("ENOENT: no such file or directory, open 'x'"), { code: "ENOENT" }),
    ],
    ["a ProxyJump loop", new Error("ProxyJump loop via b: it is already on this connection's jump chain")],
    ["a non-Error value", "plain string"],
    ["null", null],
  ])("unknown: %s", (_label, err) => {
    expect(classifySshFailure(err)).toBe("unknown");
  });
});

// ---------------------------------------------------------------- network

describe("a network failure reports the dial target, not the agent", () => {
  it.each([
    ["ECONNREFUSED", netErr("ECONNREFUSED", "connect ECONNREFUSED 10.0.0.5:22")],
    ["ENOTFOUND", netErr("ENOTFOUND", "getaddrinfo ENOTFOUND web.test")],
    [
      "handshake timeout",
      Object.assign(new Error("Timed out while waiting for handshake"), { level: "client-timeout" }),
    ],
  ])("connect(): %s carries only the Target line", async (_label, error) => {
    edges.dial.error = error;
    const err = (await connect({ host: "web.test" }).catch((e: unknown) => e)) as Error;
    expect(err.message.startsWith(error.message)).toBe(true);
    expect(sections(err.message)).toEqual(["Target"]);
    expect(err.message).toContain("[INFO] Target: dialed web.test port 22.");
    expect(err.message).not.toContain("SSH_AUTH_SOCK");
    expect(err.message).not.toContain("ssh-keyscan");
  });

  it("spawns no ssh-add and no ssh-keygen while diagnosing", () => {
    const resolved = resolveConfig({ host: "web.test" });
    edges.spawns = []; // the `ssh -G` resolve is not a diagnostic
    const enhanced = enhanceSshError(netErr("ECONNREFUSED", "connect ECONNREFUSED 10.0.0.5:22"), "web.test", resolved);
    expect((enhanced as Error).message).toContain("[INFO] Target");
    expect(edges.spawns).toEqual([]);
  });

  it("names the resolved HostName, port and ProxyJump the alias went to", async () => {
    edges.sshG.set("prod", "hostname 10.0.0.5\nport 2222\nuser deploy\nproxyjump bastion.test\n");
    edges.sshG.set("bastion.test", "hostname bastion.test\nport 22\nuser deploy\n");
    // The bastion is reached; the target, dialed over its channel, refuses.
    edges.dial.errorByHost.set("10.0.0.5", netErr("ECONNREFUSED", "connect ECONNREFUSED 10.0.0.5:2222"));
    const err = (await connect({ host: "prod" }).catch((e: unknown) => e)) as Error;
    expect(err.message).toContain(
      '[INFO] Target: dialed 10.0.0.5 port 2222 for "prod" (its HostName from ssh_config), through ProxyJump "bastion.test" from ssh_config, so the failure may be on that hop.',
    );
    expect(sections(err.message)).toEqual(["Target"]);
  });

  it("a refused jump host is named as the failure, with ITS dial target", async () => {
    edges.sshG.set("prod", "hostname 10.0.0.5\nport 2222\nuser deploy\nproxyjump bastion-alias\n");
    edges.sshG.set("bastion-alias", "hostname bastion.test\nport 2200\nuser jump\n");
    edges.dial.errorByHost.set("bastion.test", netErr("ECONNREFUSED", "connect ECONNREFUSED 10.9.9.9:2200"));
    const err = (await connect({ host: "prod" }).catch((e: unknown) => e)) as Error;
    expect(sections(err.message)).toEqual(["Jump host", "Target"]);
    expect(err.message).toContain(
      '[INFO] Jump host: the connection failed on ProxyJump hop "bastion-alias", so "prod" was never reached; the lines below describe that hop.',
    );
    expect(err.message).toContain(
      '[INFO] Target: dialed bastion.test port 2200 for "bastion-alias" (its HostName from ssh_config).',
    );
    expect(err.message).not.toContain("10.0.0.5");
  });

  it("a host that differs from its HostName only in case is not reported as an ssh_config alias", async () => {
    // `ssh -G Example.COM` prints `hostname example.com` with no ssh_config entry at all.
    edges.sshG.set("Example.COM", "hostname example.com\nport 22\nuser deploy\n");
    edges.dial.error = netErr("ECONNREFUSED", "connect ECONNREFUSED 10.0.0.5:22");
    const err = (await connect({ host: "Example.COM" }).catch((e: unknown) => e)) as Error;
    expect(err.message).toContain("[INFO] Target: dialed example.com port 22.");
    expect(err.message).not.toContain("its HostName from ssh_config");
  });

  it("pool.acquire() gets the same relevant block", async () => {
    edges.dial.error = netErr("ENOTFOUND", "getaddrinfo ENOTFOUND web.test");
    const pool = new ConnectionPool();
    try {
      const err = (await pool.acquire({ host: "web.test" }).catch((e: unknown) => e)) as Error;
      expect(sections(err.message)).toEqual(["Target"]);
      expect(spawned("ssh-add")).toEqual([]);
    } finally {
      pool.drain();
    }
  });
});

// ---------------------------------------------------------------- host key

describe("a host-key failure reports the host key, not the agent", () => {
  it("a strict-mode refusal carries the verifier's reason and no environment checks", async () => {
    setEnv("SSH_MCP_STRICT_HOSTKEYS", "1");
    edges.dial.hostKey = Buffer.from("\0\0\0\x0bssh-ed25519offered");
    const err = (await connect({ host: "new.test" }).catch((e: unknown) => e)) as Error;
    expect(err.message).toContain("Host key check failed -- no known_hosts entry for new.test");
    expect(err.message).not.toContain("SSH Diagnostics");
    expect(err.message).not.toContain("SSH Agent");
    expect(spawned("ssh-add")).toEqual([]);
  });

  it("with no recorded reason, falls back to the Known Hosts check alone", () => {
    const resolved = resolveConfig({ host: "old.test" });
    edges.spawns = [];
    const err = enhanceSshError(new Error("Host denied (verification failed)"), "old.test", resolved) as Error;
    expect(sections(err.message)).toEqual(["Known Hosts", "Suggested fixes"]);
    expect(err.message).toContain('Add host key: ssh-keyscan -H "old.test"');
    expect(spawned("ssh-add")).toEqual([]);
  });
});

// ---------------------------------------------------------------- auth

describe("an auth failure keeps the agent warning, and says why it applies", () => {
  const AUTH = () =>
    Object.assign(new Error("All configured authentication methods failed"), { level: "client-authentication" });

  it("the dead-SSH_AUTH_SOCK warning leads, tied to this connection, then what was offered", async () => {
    edges.dial.error = AUTH();
    const err = (await connect({ host: "web.test", username: "jeff" }).catch((e: unknown) => e)) as Error;
    expect(sections(err.message)).toEqual(["SSH Agent", "Authentication"]);
    const agentLine = err.message.split("\n").find((l) => l.startsWith("[WARNING] SSH Agent:")) ?? "";
    expect(agentLine).toContain(`SSH_AUTH_SOCK is set to "${DEAD_SOCK}", where no agent answers`);
    expect(agentLine).toContain(
      `This connection offered the agent at SSH_AUTH_SOCK (${JSON.stringify(DEAD_SOCK)}) for authentication, so no agent key was tried.`,
    );
    expect(err.message).toContain(
      `[INFO] Authentication: user "jeff" at web.test port 22 offered the agent at SSH_AUTH_SOCK (${JSON.stringify(DEAD_SOCK)}) and the key file ${JSON.stringify(join(HOME_WITH_KEY, ".ssh", "id_ed25519"))}.`,
    );
    // The stale-socket warning's fix is in its own text; loading a key is not it.
    expect(err.message).not.toContain("Load a key");
    expect(err.message).not.toContain("Known Hosts");
  });

  it("ssh2's own agent error on that machine is treated as an auth failure too", async () => {
    edges.dial.error = Object.assign(new Error("Invalid cygwin unix socket path"), { level: "agent" });
    const err = (await connect({ host: "web.test" }).catch((e: unknown) => e)) as Error;
    expect(sections(err.message)).toEqual(["SSH Agent", "Authentication"]);
  });

  it("orders agent, keys, offer, fixes when ~/.ssh has no key either", async () => {
    edges.home = HOME_NO_KEYS;
    edges.dial.error = AUTH();
    const err = (await connect({ host: "web.test" }).catch((e: unknown) => e)) as Error;
    expect(sections(err.message)).toEqual(["SSH Agent", "SSH Keys", "Authentication", "Suggested fixes"]);
    expect(err.message).toContain("offered the agent at SSH_AUTH_SOCK");
    expect(err.message).toContain("Generate a key");
  });

  it("an explicit password offers no agent or key, so neither check runs", async () => {
    edges.dial.error = AUTH();
    const err = (await connect({ host: "web.test", password: "pw" }).catch((e: unknown) => e)) as Error;
    expect(sections(err.message)).toEqual(["Authentication"]);
    expect(err.message).toContain("offered the password given (no key, no agent).");
    expect(err.message).not.toContain("pw.");
    expect(spawned("ssh-add")).toEqual([]);
  });

  it("an explicit privateKeyPath offers no agent, so the agent check does not run", async () => {
    edges.dial.error = AUTH();
    const keyFile = join(HOME_WITH_KEY, ".ssh", "id_ed25519");
    const err = (await connect({ host: "web.test", privateKeyPath: keyFile }).catch((e: unknown) => e)) as Error;
    expect(sections(err.message)).toEqual(["Authentication"]);
    expect(err.message).toContain(`offered only the key file ${JSON.stringify(keyFile)} given as privateKeyPath`);
    expect(spawned("ssh-add")).toEqual([]);
  });

  it("an explicit agent elsewhere is not described by the SSH_AUTH_SOCK check", async () => {
    edges.dial.error = AUTH();
    const err = (await connect({ host: "web.test", agent: "\\\\.\\pipe\\pageant-bridge" }).catch(
      (e: unknown) => e,
    )) as Error;
    expect(sections(err.message)).toEqual(["Authentication"]);
    expect(err.message).toContain('offered the agent at "\\\\\\\\.\\\\pipe\\\\pageant-bridge"');
  });

  describe("through a ProxyJump whose bastion refuses the login", () => {
    beforeEach(() => {
      edges.sshG.set("prod", "hostname 10.0.0.5\nport 22\nuser deploy\nproxyjump jumpuser@bastion.test\n");
      edges.sshG.set("bastion.test", "hostname bastion.test\nport 22\nuser someone\n");
      edges.dial.errorByHost.set("bastion.test", AUTH());
    });

    const BASTION_OFFER = `[INFO] Authentication: user "jumpuser" at bastion.test port 22 offered the agent at SSH_AUTH_SOCK (${JSON.stringify(DEAD_SOCK)}) and the key file ${JSON.stringify(join(HOME_WITH_KEY, ".ssh", "id_ed25519"))}.`;

    it("a target called with a password still gets the bastion's agent check and offer", async () => {
      const err = (await connect({ host: "prod", password: "pw" }).catch((e: unknown) => e)) as Error;
      expect(sections(err.message)).toEqual(["Jump host", "SSH Agent", "Authentication"]);
      expect(err.message).toContain('failed on ProxyJump hop "jumpuser@bastion.test", so "prod" was never reached');
      expect(err.message).toContain(`SSH_AUTH_SOCK is set to "${DEAD_SOCK}", where no agent answers`);
      expect(err.message).toContain(
        'The connection to jump host "jumpuser@bastion.test" offered the agent at SSH_AUTH_SOCK',
      );
      expect(err.message).toContain(BASTION_OFFER);
      // Nothing about the target's credentials, user or address.
      expect(err.message).not.toContain("password given");
      expect(err.message).not.toContain("10.0.0.5");
      expect(err.message).not.toContain('"deploy"');
    });

    it("a target on the default offer names the bastion's user and host, not its own", async () => {
      const err = (await connect({ host: "prod" }).catch((e: unknown) => e)) as Error;
      expect(sections(err.message)).toEqual(["Jump host", "SSH Agent", "Authentication"]);
      expect(err.message).toContain(BASTION_OFFER);
      expect(err.message).not.toContain('user "deploy" at 10.0.0.5');
    });

    it("pool.acquire() describes the bastion too", async () => {
      const pool = new ConnectionPool();
      try {
        const err = (await pool.acquire({ host: "prod", password: "pw" }).catch((e: unknown) => e)) as Error;
        expect(sections(err.message)).toEqual(["Jump host", "SSH Agent", "Authentication"]);
        expect(err.message).toContain(BASTION_OFFER);
      } finally {
        pool.drain();
      }
    });

    it("the deepest failing hop of a multi-hop chain is the one described", async () => {
      edges.sshG.set("prod", "hostname 10.0.0.5\nport 22\nuser deploy\nproxyjump jumpuser@bastion.test,inner.test\n");
      edges.sshG.set("inner.test", "hostname inner.test\nport 22\nuser deploy\n");
      const err = (await connect({ host: "prod", password: "pw" }).catch((e: unknown) => e)) as Error;
      expect(err.message).toContain('failed on ProxyJump hop "jumpuser@bastion.test"');
      expect(err.message).toContain(BASTION_OFFER);
      expect(err.message).not.toContain("inner.test port");
    });

    it("a later dial on the same resolved config that fails on the target is not blamed on the bastion", async () => {
      const resolved = resolveConfig({ host: "prod", password: "pw" });
      await connectWithProxy(resolved).catch(() => {});
      expect(resolved.failedJumpHop?.label).toBe("jumpuser@bastion.test");
      edges.dial.errorByHost.delete("bastion.test");
      edges.dial.errorByHost.set("10.0.0.5", AUTH());
      const err = await connectWithProxy(resolved).catch((e: unknown) => e);
      expect(resolved.failedJumpHop).toBeUndefined();
      const enhanced = enhanceSshError(err, "prod", resolved) as Error;
      expect(sections(enhanced.message)).toEqual(["Authentication"]);
      expect(enhanced.message).toContain('user "deploy" at 10.0.0.5 port 22 offered the password given');
    });
  });

  it("on Linux, a dead SSH_AUTH_SOCK is an error for auth, absent for a refused connect", async () => {
    setPlatform("linux");
    edges.dial.error = AUTH();
    const auth = (await connect({ host: "web.test" }).catch((e: unknown) => e)) as Error;
    expect(sections(auth.message)[0]).toBe("SSH Agent");
    expect(auth.message).toContain(`[ERROR] SSH Agent: SSH_AUTH_SOCK is set to "${DEAD_SOCK}" but`);
    expect(auth.message).toContain("This connection offered the agent at SSH_AUTH_SOCK");

    clock += 60_000;
    vi.setSystemTime(clock);
    edges.spawns = [];
    edges.dial.error = netErr("ECONNREFUSED", "connect ECONNREFUSED 10.0.0.5:22");
    const net = (await connect({ host: "web.test" }).catch((e: unknown) => e)) as Error;
    expect(sections(net.message)).toEqual(["Target"]);
    expect(spawned("ssh-add")).toEqual([]);
  });
});

// ---------------------------------------------------------------- unknown

describe("an unclassified failure keeps the full set", () => {
  it("runs every check, in the original order", () => {
    edges.home = HOME_NO_KEYS;
    const text = formatDiagnostics("web.test");
    expect(text.split("\n").map((l) => l.match(/^\[\w+\] ([^:]+):/)?.[1] ?? l.split(":")[0])).toEqual([
      "SSH Agent",
      "SSH Keys",
      "Known Hosts",
      "Suggested fixes",
    ]);
  });

  it("does not suggest loading a key for the stale-SSH_AUTH_SOCK warning", () => {
    const text = formatDiagnostics("web.test");
    expect(text).toContain("[WARNING] SSH Agent: Windows OpenSSH agent is running, but SSH_AUTH_SOCK");
    expect(text).not.toContain("Load a key");
    expect(text).not.toContain("This connection offered");
  });

  it("still suggests loading a key when the agent really has none", () => {
    setPlatform("linux");
    edges.inheritedAgent = "empty";
    const text = formatDiagnostics("web.test");
    expect(text).toContain("[WARNING] SSH Agent: ssh-agent is running but has no keys loaded");
    expect(text).toContain("Load a key: ssh-add ~/.ssh/id_ed25519");
  });
});
