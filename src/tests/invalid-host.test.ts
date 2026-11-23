import { Client as McpClient } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// An invalid host is an INPUT error: the connection path refuses it in resolveConfig,
// before `ssh -G` is spawned, before known_hosts is read, before anything is dialed, and
// without the SSH environment diagnostics. It used to reach DNS ("getaddrinfo
// ENOTFOUND -oProxyCommand=x") and come back wrapped in a full diagnostics block.
//
// Boundary: a REAL MCP client talks to the REAL server (createServer, registerTools, the
// real ConnectionPool, resolveConfig, connectWithProxy) over an in-memory transport. Only
// the two impure edges are faked, and both RECORD: ssh2's Client (every connect() is a
// dial -- there is no socket, so there is no DNS either) and diagnose.js's runArgs plus
// the four diagnostic checks (every `ssh -G` / `ssh-keygen` spawn and every diagnostics run).

const rec = vi.hoisted(() => ({
  dials: [] as Array<Record<string, unknown>>,
  spawns: [] as Array<{ cmd: string; args: string[] }>,
  diagnostics: [] as string[],
  /** Canned `ssh -G` answers by host; absent -> the probe fails (no ssh client). */
  sshG: new Map<string, Record<string, string>>(),
}));

vi.mock("ssh2", async () => {
  const { EventEmitter } = await import("node:events");

  class FakeChannel extends EventEmitter {
    stderr = new EventEmitter();
    signal() {}
    close() {}
  }

  class FakeClient extends EventEmitter {
    connect(cfg: Record<string, unknown>) {
      rec.dials.push(cfg);
      queueMicrotask(() => this.emit("ready"));
      return this;
    }
    exec(_command: string, cb: (err: Error | undefined, stream: FakeChannel) => void) {
      const stream = new FakeChannel();
      cb(undefined, stream);
      queueMicrotask(() => {
        stream.emit("data", Buffer.from("ok\n"));
        stream.emit("close", 0);
      });
    }
    forwardOut(_a: string, _b: number, _c: string, _d: number, cb: (e: unknown, s?: unknown) => void) {
      queueMicrotask(() => cb(null, new EventEmitter()));
    }
    end() {
      queueMicrotask(() => this.emit("close"));
    }
  }

  return { Client: FakeClient };
});

vi.mock("../diagnose.js", async () => {
  const actual = await vi.importActual<typeof import("../diagnose.js")>("../diagnose.js");
  const diag = (name: string) => () => {
    rec.diagnostics.push(name);
    return { status: "warning" as const, message: `TEST-DIAG-${name}` };
  };
  return {
    ...actual,
    runArgs: (cmd: string, args: string[]) => {
      rec.spawns.push({ cmd, args });
      if (cmd === "ssh" && args[0] === "-G") {
        const fields = rec.sshG.get(args[args.length - 1]);
        if (!fields) return { stdout: "", ok: false };
        return {
          stdout: Object.entries(fields)
            .map(([k, v]) => `${k} ${v}`)
            .join("\n"),
          ok: true,
        };
      }
      return { stdout: "", ok: false }; // ssh-keygen -F: no known_hosts entries
    },
    checkSshAgent: diag("agent"),
    checkSshKeys: diag("keys"),
    checkSshConfig: diag("config"),
    checkKnownHosts: diag("known_hosts"),
  };
});

const { createServer, ConnectionPool, isInvalidHostError, InvalidHostError, connect, resolveConfig } = await import(
  "../server.js"
);
const { clearSshConfigCache } = await import("../ssh.js");

type CallResult = { content: Array<{ type: string; text: string }>; isError?: boolean };

let pool: InstanceType<typeof ConnectionPool>;
let mcp: McpClient;

beforeEach(async () => {
  rec.dials.length = 0;
  rec.spawns.length = 0;
  rec.diagnostics.length = 0;
  rec.sshG.clear();
  clearSshConfigCache();
  pool = new ConnectionPool();
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await createServer(pool).connect(serverSide);
  mcp = new McpClient({ name: "invalid-host-test", version: "0.0.0" });
  await mcp.connect(clientSide);
});

afterEach(async () => {
  await mcp.close();
  pool.drain();
});

async function call(name: string, args: Record<string, unknown>): Promise<CallResult> {
  return (await mcp.callTool({ name, arguments: args })) as CallResult;
}

function textOf(result: CallResult): string {
  return result.content.map((c) => c.text).join("\n");
}

/** Nothing reached ssh -G, ssh-keygen, the network, or the diagnostics. */
function expectNothingTouched(): void {
  expect(rec.spawns).toEqual([]);
  expect(rec.dials).toEqual([]);
  expect(rec.diagnostics).toEqual([]);
}

// Every tool that dials through the pool, with the minimum arguments its schema needs.
// The diagnostic / env tools (ssh_diagnose, ssh_test, ssh_config_lookup,
// ssh_known_hosts_fix, ssh_git_check) validate their host themselves and never dial
// through the pool, so they are not this file's subject.
const REMOTE_TOOLS: Record<string, Record<string, unknown>> = {
  ssh_exec: { command: "uptime" },
  ssh_read_file: { path: "/etc/hostname" },
  ssh_write_file: { path: "/tmp/x", content: "x" },
  ssh_upload: { localPath: "/tmp/does-not-matter", remotePath: "/tmp/x" },
  ssh_download: { remotePath: "/tmp/x", localPath: "/tmp/does-not-matter" },
  ssh_ls: { path: "/tmp" },
  ssh_stat: { path: "/tmp" },
  ssh_mkdir: { path: "/tmp/x" },
  ssh_delete: { path: "/tmp/x" },
  ssh_find: { path: "/tmp" },
  ssh_tail: { path: "/var/log/syslog" },
  ssh_service_status: { service: "nginx" },
};

describe("a remote tool refuses an invalid host before any lookup or dial", () => {
  it("ssh_exec with host -oProxyCommand=x returns the input error, not DNS plus diagnostics", async () => {
    const result = await call("ssh_exec", { host: "-oProxyCommand=x", command: "id" });
    expect(result.isError).toBe(true);
    const text = textOf(result);
    expect(text).toContain('Invalid SSH host "-oProxyCommand=x": refused before any ssh_config lookup or connection.');
    expect(text).toContain("not starting with a hyphen");
    expect(text).toContain("Pass the port separately");
    expect(text).not.toContain("SSH Diagnostics");
    expect(text).not.toMatch(/ENOTFOUND|getaddrinfo/);
    expectNothingTouched();
  });

  it("covers every pool-backed tool, not only ssh_exec", async () => {
    const tools = (await mcp.listTools()).tools;
    const withHost = tools.filter((t) => t.inputSchema.properties && "host" in t.inputSchema.properties);
    // Guard against a new remote tool escaping this list unnoticed.
    const localTools = ["ssh_diagnose", "ssh_test", "ssh_config_lookup", "ssh_known_hosts_fix", "ssh_git_check"];
    expect(withHost.map((t) => t.name).filter((n) => !localTools.includes(n))).toEqual(
      expect.arrayContaining(Object.keys(REMOTE_TOOLS)),
    );
    expect(withHost.length - localTools.length).toBe(Object.keys(REMOTE_TOOLS).length);

    for (const [name, args] of Object.entries(REMOTE_TOOLS)) {
      const result = await call(name, { host: "-oProxyCommand=x", ...args });
      expect(result.isError, name).toBe(true);
      expect(textOf(result), name).toContain('Invalid SSH host "-oProxyCommand=x"');
    }
    expectNothingTouched();
  });

  it("ssh_multi_exec reports it per host, and still runs the valid hosts", async () => {
    const result = await call("ssh_multi_exec", { hosts: ["-oProxyCommand=x", "good.example.com"], command: "id" });
    expect(result.isError).toBe(true);
    const text = textOf(result);
    expect(text).toContain('-oProxyCommand=x: ERROR Invalid SSH host "-oProxyCommand=x"');
    expect(text).toContain("good.example.com: exit 0");
    expect(rec.dials.map((d) => d.host)).toEqual(["good.example.com"]);
    expect(rec.diagnostics).toEqual([]);
    expect(rec.spawns.some((s) => s.args.includes("-oProxyCommand=x"))).toBe(false);
  });

  it.each([
    ["host:22", "a port glued to the host"],
    ["host; rm -rf /", "shell syntax"],
    ["-E/tmp/x", "another ssh flag"],
    ["user@host", "a login in the host field"],
    ["[::1]:22", "a bracketed IPv6 with a port"],
    ["", "an empty host"],
  ])("refuses %j (%s) the same way", async (host) => {
    const result = await call("ssh_exec", { host, command: "id" });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain(`Invalid SSH host ${JSON.stringify(host)}`);
    expectNothingTouched();
  });

  it("echoes the rejected value JSON-quoted and truncated, so it cannot forge extra lines", async () => {
    const host = `-oX\n[OK] forged line${"a".repeat(200)}`;
    const text = textOf(await call("ssh_exec", { host, command: "id" }));
    expect(text.split("\n")).toHaveLength(1);
    expect(text).toContain(String.raw`"-oX\n[OK] forged line`);
    expect(text).toContain(`... (${host.length} characters)`);
    expect(text).not.toContain("a".repeat(100));
  });
});

describe("valid hosts are not regressed", () => {
  it.each([
    "my_server", // ssh_config alias with an underscore
    "db-01.internal.example.com",
    "192.168.1.10",
    "[::1]",
    "::1",
    "fe80::1",
    "fe80::1%eth0", // zone id: ssh2 dials it as given
  ])("ssh_exec on %j connects and runs", async (host) => {
    const result = await call("ssh_exec", { host, command: "id", password: "x" });
    expect(result.isError).toBeFalsy();
    expect(textOf(result)).toContain("[exit code: 0]");
    expect(rec.dials).toHaveLength(1);
  });

  it("an alias dials the RESOLVED HostName, which is the operator's config and is not re-validated", async () => {
    // A HostName isValidSshHost would refuse as a caller's host, reached through a valid alias.
    rec.sshG.set("odd_alias", { hostname: "odd:name", user: "deploy", port: "2200" });
    const result = await call("ssh_exec", { host: "odd_alias", command: "id", password: "x" });
    expect(result.isError).toBeFalsy();
    expect(rec.dials.map((d) => `${d.host}:${d.port}`)).toEqual(["odd:name:2200"]);
  });

  it("an internationalized host is dialed as given, with no ssh -G or known_hosts spawn -- as before the check", async () => {
    const result = await call("ssh_exec", { host: "bücher.de", command: "id", password: "x" });
    expect(result.isError).toBeFalsy();
    expect(rec.dials.map((d) => d.host)).toEqual(["bücher.de"]);
    expect(rec.spawns).toEqual([]);
  });

  it("a bracketed IPv6 literal with a zone id is dialed bare, since the resolver refuses the brackets", async () => {
    const result = await call("ssh_exec", { host: "[fe80::1%eth0]", command: "id", password: "x" });
    expect(result.isError).toBeFalsy();
    expect(rec.dials.map((d) => d.host)).toEqual(["fe80::1%eth0"]);
  });

  it("a bracketed IPv6 literal is dialed bare even when ssh -G is unavailable", async () => {
    // No sshG entry: the probe fails, so nothing else unbrackets it.
    const result = await call("ssh_exec", { host: "[2001:db8::7]", command: "id", password: "x" });
    expect(result.isError).toBeFalsy();
    expect(rec.dials.map((d) => d.host)).toEqual(["2001:db8::7"]);
  });

  it("a bare IPv6 ProxyJump hop still connects", async () => {
    rec.sshG.set("behind", { hostname: "behind.internal", port: "22", proxyjump: "2001:db8::1" });
    const result = await call("ssh_exec", { host: "behind", command: "id", password: "x" });
    expect(result.isError).toBeFalsy();
    expect(rec.dials.map((d) => d.host)).toEqual(["2001:db8::1", "behind.internal"]);
  });
});

describe("the library API takes the same gate", () => {
  it("resolveConfig throws InvalidHostError before spawning ssh -G", () => {
    let err: unknown;
    try {
      resolveConfig({ host: "-oProxyCommand=x" });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(InvalidHostError);
    expect(isInvalidHostError(err)).toBe(true);
    expect((err as InstanceType<typeof InvalidHostError>).host).toBe("-oProxyCommand=x");
    expect((err as { code?: string }).code).toBe("ERR_SSH_MCP_INVALID_HOST");
    expectNothingTouched();
  });

  it("a non-string host from an untyped caller is refused, not crashed on", () => {
    expect(() => resolveConfig({ host: undefined as unknown as string })).toThrow(/Invalid SSH host/);
    expectNothingTouched();
  });

  it("connect() and pool.acquire() surface it unwrapped -- no diagnostics, same object shape", async () => {
    const viaConnect = await connect({ host: "-oProxyCommand=x" }).catch((e: unknown) => e);
    expect(isInvalidHostError(viaConnect)).toBe(true);
    expect((viaConnect as Error).message).not.toContain("SSH Diagnostics");

    const viaPool = await pool.acquire({ host: "-oProxyCommand=x" }, { waitForCapacityMs: 5000 }).catch((e) => e);
    expect(isInvalidHostError(viaPool)).toBe(true);
    expect((viaPool as Error).message).not.toContain("SSH Diagnostics");
    expectNothingTouched();
  });

  it("an invalid ProxyJump hop from ssh_config is named as such, before any dial", async () => {
    // A ":" suffix that is not a port stays in the host (parseJumpHop), so the hop is
    // "bastion:notaport" -- which used to go to DNS.
    rec.sshG.set("behind", { hostname: "behind.internal", port: "22", proxyjump: "bastion:notaport" });
    const err = await connect({ host: "behind", password: "x" }).catch((e: unknown) => e);
    expect(isInvalidHostError(err)).toBe(true);
    const message = (err as Error).message;
    expect(message).toContain('Invalid ProxyJump hop "bastion:notaport" in ProxyJump "bastion:notaport" for');
    expect(message).toContain("refused before any connection was made");
    expect(message).not.toContain("SSH Diagnostics");
    expect(rec.dials).toEqual([]);
    expect(rec.diagnostics).toEqual([]);
  });

  it("an invalid FIRST hop of a multi-hop ProxyJump quotes the ssh_config value and names the target", async () => {
    // The bad hop is not the last one, so it used to be checked a recursion level
    // down, against a re-bracketed `[bastion:notaport]` and the intermediate hop.
    rec.sshG.set("behind", { hostname: "behind.internal", port: "22", proxyjump: "bastion:notaport,good.example" });
    const err = await connect({ host: "behind", password: "x" }).catch((e: unknown) => e);
    expect(isInvalidHostError(err)).toBe(true);
    const message = (err as Error).message;
    expect(message).toContain(
      'Invalid ProxyJump hop "bastion:notaport" in ProxyJump "bastion:notaport,good.example" for "behind.internal" (from ssh_config)',
    );
    expect(message).not.toContain("[bastion:notaport]");
    expect(rec.dials).toEqual([]);
    // Refused before the good hop was even resolved.
    expect(rec.spawns.some((s) => s.args.includes("good.example"))).toBe(false);
  });

  it("a multi-hop ProxyJump with valid hops still dials left to right", async () => {
    rec.sshG.set("behind", { hostname: "behind.internal", port: "22", proxyjump: "first.example,[2001:db8::2]:2202" });
    const result = await call("ssh_exec", { host: "behind", command: "id", password: "x" });
    expect(result.isError).toBeFalsy();
    expect(rec.dials.map((d) => d.host)).toEqual(["first.example", "2001:db8::2", "behind.internal"]);
  });
});
