import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Client } from "ssh2";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AgentResult, ConfigLookupResult, KeyInfo, SshKeyListing } from "../env.js";
import { ConnectionPool } from "../pool.js";
import type { SSHConfig } from "../ssh.js";
import { registerTools } from "../tools.js";

// Coverage for the eight tool HANDLERS in src/tools.ts that do purely local/environment
// work and never open an SSH connection:
//
//   ssh_diagnose, ssh_agent_ensure, ssh_key_list, ssh_key_load,
//   ssh_config_lookup, ssh_known_hosts_fix, ssh_test, ssh_git_check
//
// The functions BENEATH them (diagnose.ts / env.ts) already have their own suites. What
// had no coverage at all is the wrapper: the text each handler assembles from the result
// object, the `isError` flag it derives, and the argument defaults it applies before
// calling down. Those are the whole of the MCP contract an agent caller sees.
//
// `isError` is set from a DIFFERENT condition in every one of them, so each is pinned in
// BOTH directions:
//
//   ssh_diagnose         report.overall === "error"
//   ssh_agent_ensure     !result.reachable
//   ssh_key_load         result.status === "error"
//   ssh_config_lookup    "error" in result          (key PRESENCE, not a status field)
//   ssh_known_hosts_fix  result.status === "error"
//   ssh_test             result.status === "error"
//   ssh_git_check        result.status === "error"
//   ssh_key_list         listing.status === "unreadable"  (NOT "zero keys")
//
// Boundary: the REAL registered handlers run. ../env.js and ../diagnose.js are mocked at
// the MODULE boundary so nothing shells out to ssh / ssh-add / ssh-keygen / ssh-keyscan
// and nothing reads the real ~/.ssh -- the suite is hermetic and gives the same answer on
// any machine. Each mock spreads the real module and overrides only the functions
// tools.ts imports, so ssh.ts's own imports from diagnose.js (isValidHostname, runArgs)
// stay intact. Every fixture below is the real return shape copied out of env.ts /
// diagnose.ts, not an invented one.

type ToolResult = { content: { type: string; text: string }[]; isError?: boolean };
type ToolHandler = (args: Record<string, unknown>) => Promise<ToolResult>;
type ToolRegistration = { description: string; schema: Record<string, unknown>; handler: ToolHandler };
/** Just enough of a zod schema to exercise one declared parameter directly. The fake server
 *  below captures the raw shape object, so each value is the real zod type tools.ts built. */
type ZodLike = { safeParse: (v: unknown) => { success: boolean; error?: unknown } };

const {
  diagnoseSpy,
  ensureAgentSpy,
  listSshKeysDetailedSpy,
  loadKeySpy,
  configLookupSpy,
  fixKnownHostsSpy,
  testConnectionSpy,
  checkGitSshSpy,
} = vi.hoisted(() => ({
  diagnoseSpy: vi.fn(),
  ensureAgentSpy: vi.fn(),
  listSshKeysDetailedSpy: vi.fn(),
  loadKeySpy: vi.fn(),
  configLookupSpy: vi.fn(),
  fixKnownHostsSpy: vi.fn(),
  testConnectionSpy: vi.fn(),
  checkGitSshSpy: vi.fn(),
}));

vi.mock("../diagnose.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../diagnose.js")>();
  return { ...actual, diagnose: diagnoseSpy as unknown as typeof actual.diagnose };
});

vi.mock("../env.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../env.js")>();
  return {
    ...actual,
    ensureAgent: ensureAgentSpy as unknown as typeof actual.ensureAgent,
    listSshKeysDetailed: listSshKeysDetailedSpy as unknown as typeof actual.listSshKeysDetailed,
    loadKey: loadKeySpy as unknown as typeof actual.loadKey,
    configLookup: configLookupSpy as unknown as typeof actual.configLookup,
    fixKnownHosts: fixKnownHostsSpy as unknown as typeof actual.fixKnownHosts,
    testConnection: testConnectionSpy as unknown as typeof actual.testConnection,
    checkGitSsh: checkGitSshSpy as unknown as typeof actual.checkGitSsh,
  };
});

/** ConnectionPool subclass that never touches the network. None of these eight tools use
 *  it, but registerTools takes one; this guarantees a mistake can't dial out. */
class NoNetworkPool extends ConnectionPool {
  // Signature must match the base exactly -- a widened `unknown` parameter is not a
  // valid override under strict mode. The client is never touched by these eight
  // handlers, so an empty cast stands in for a real ssh2 Client.
  override async withConnection<T>(_config: SSHConfig, fn: (client: Client) => Promise<T>): Promise<T> {
    return fn({} as Client);
  }
}

/** Minimal fake McpServer that captures each registered tool by name. */
function getTool(name: string): ToolRegistration {
  const tools = new Map<string, ToolRegistration>();
  const server = {
    // registerTools calls server.tool(name, description, schema, handler).
    tool: (...args: unknown[]) => {
      tools.set(args[0] as string, {
        description: args[1] as string,
        schema: args[2] as Record<string, unknown>,
        handler: args[args.length - 1] as ToolHandler,
      });
    },
  };
  registerTools(server as never, new NoNetworkPool());
  const tool = tools.get(name);
  if (!tool) throw new Error(`${name} was not registered`);
  return tool;
}

const run = (name: string, args: Record<string, unknown> = {}): Promise<ToolResult> => getTool(name).handler(args);
const textOf = async (name: string, args: Record<string, unknown> = {}): Promise<string> =>
  (await run(name, args)).content[0].text;

beforeEach(() => {
  for (const spy of [
    diagnoseSpy,
    ensureAgentSpy,
    listSshKeysDetailedSpy,
    loadKeySpy,
    configLookupSpy,
    fixKnownHostsSpy,
    testConnectionSpy,
    checkGitSshSpy,
  ]) {
    spy.mockReset();
  }
});

// ---------------------------------------------------------------------------
// ssh_diagnose
// ---------------------------------------------------------------------------

describe("ssh_diagnose renders the DiagnosticReport", () => {
  // Shape copied from DiagnosticReport (diagnose.ts) and from what diagnose() actually
  // pushes: five named checks in a fixed order, plus the suggestions its status branches
  // append. This is the report a broken machine produces -- agent up, key on disk, host
  // missing from known_hosts, and the connection then refused for auth.
  const brokenMachineReport = {
    overall: "error" as const,
    checks: [
      { name: "SSH Agent", status: "ok" as const, message: "ssh-agent running with 2 key(s) loaded" },
      { name: "SSH Keys", status: "ok" as const, message: "Found SSH keys: id_ed25519" },
      { name: "SSH Config", status: "ok" as const, message: "No ~/.ssh/config file (using defaults)" },
      {
        name: "Known Hosts",
        status: "warning" as const,
        message: 'Host "web1.test" not in known_hosts. First connection will need verification.',
      },
      {
        name: "Connectivity",
        status: "error" as const,
        message: "Permission denied connecting to web1.test:22. Your key is not authorized on this host.",
      },
    ],
    suggestions: [
      'Add host key: ssh-keyscan -H "web1.test" >> ~/.ssh/known_hosts',
      "Check loaded keys: ssh-add -l",
      "Verify correct username for this host",
    ],
  };

  it("builds the whole report verbatim: header, overall, one PASS/WARN/FAIL block per check, then the fixes", async () => {
    diagnoseSpy.mockReturnValue(brokenMachineReport);
    expect(await textOf("ssh_diagnose", { host: "web1.test" })).toBe(
      [
        "SSH Diagnostic Report for web1.test:22",
        "Overall: ERROR",
        "",
        "[PASS] SSH Agent",
        "  ssh-agent running with 2 key(s) loaded",
        "",
        "[PASS] SSH Keys",
        "  Found SSH keys: id_ed25519",
        "",
        "[PASS] SSH Config",
        "  No ~/.ssh/config file (using defaults)",
        "",
        "[WARN] Known Hosts",
        '  Host "web1.test" not in known_hosts. First connection will need verification.',
        "",
        "[FAIL] Connectivity",
        "  Permission denied connecting to web1.test:22. Your key is not authorized on this host.",
        "",
        "Suggested fixes:",
        '  - Add host key: ssh-keyscan -H "web1.test" >> ~/.ssh/known_hosts',
        "  - Check loaded keys: ssh-add -l",
        "  - Verify correct username for this host",
      ].join("\n"),
    );
  });

  it("maps each check status to its own icon -- ok/warning/anything-else", async () => {
    diagnoseSpy.mockReturnValue({
      overall: "warning",
      checks: [
        { name: "A", status: "ok", message: "a" },
        { name: "B", status: "warning", message: "b" },
        { name: "C", status: "error", message: "c" },
      ],
      suggestions: [],
    });
    const text = await textOf("ssh_diagnose", { host: "h.test" });
    expect(text).toContain("[PASS] A");
    expect(text).toContain("[WARN] B");
    expect(text).toContain("[FAIL] C");
    // The icon ladder ends in a bare `else`, so an unrecognised status fails CLOSED to FAIL
    // rather than rendering as a pass.
    expect(text).not.toContain("[PASS] C");
  });

  it("upper-cases the overall verdict", async () => {
    for (const overall of ["ok", "warning", "error"] as const) {
      diagnoseSpy.mockReturnValue({ overall, checks: [], suggestions: [] });
      expect(await textOf("ssh_diagnose", { host: "h.test" })).toContain(`Overall: ${overall.toUpperCase()}`);
    }
  });

  it("omits the 'Suggested fixes:' section entirely when there is nothing to suggest", async () => {
    diagnoseSpy.mockReturnValue({
      overall: "ok",
      checks: [{ name: "SSH Agent", status: "ok", message: "fine" }],
      suggestions: [],
    });
    const text = await textOf("ssh_diagnose", { host: "h.test" });
    expect(text).not.toContain("Suggested fixes:");
    // Each check block pushes a trailing blank line, so with no fixes section the report
    // ends on that blank. Pinned because the exact tail is what a caller string-matches.
    expect(text).toBe("SSH Diagnostic Report for h.test:22\nOverall: OK\n\n[PASS] SSH Agent\n  fine\n");
  });

  it("isError is TRUE when overall is error", async () => {
    diagnoseSpy.mockReturnValue(brokenMachineReport);
    expect((await run("ssh_diagnose", { host: "web1.test" })).isError).toBe(true);
  });

  it("isError is FALSE for overall 'warning' -- a warning is not an error", async () => {
    // The flag keys off `overall === "error"` alone, so a report full of WARN blocks is
    // still reported as a successful tool call. That is the machine-readable half of the
    // contract and is easy to break by switching to `!== "ok"`.
    diagnoseSpy.mockReturnValue({
      overall: "warning",
      checks: [{ name: "Known Hosts", status: "warning", message: "not in known_hosts" }],
      suggestions: ['Add host key: ssh-keyscan -H "h.test" >> ~/.ssh/known_hosts'],
    });
    const result = await run("ssh_diagnose", { host: "h.test" });
    expect(result.isError).toBe(false);
    expect(result.content[0].text).toContain("[WARN] Known Hosts");
  });

  it("isError is FALSE for overall 'ok'", async () => {
    diagnoseSpy.mockReturnValue({ overall: "ok", checks: [], suggestions: [] });
    expect((await run("ssh_diagnose", { host: "h.test" })).isError).toBe(false);
  });

  it("renders the invalid-hostname report -- the shape diagnose() short-circuits to", async () => {
    // diagnose() returns this exact report before running any check when isValidHostname
    // rejects the host, e.g. a flag smuggled in as a hostname.
    const host = "-oProxyCommand=evil";
    diagnoseSpy.mockReturnValue({
      overall: "error",
      checks: [{ name: "Input Validation", status: "error", message: `Invalid hostname: "${host}"` }],
      suggestions: ["Provide a valid hostname (alphanumeric, dots, hyphens, colons, brackets only)"],
    });
    const result = await run("ssh_diagnose", { host });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe(
      [
        `SSH Diagnostic Report for ${host}:22`,
        "Overall: ERROR",
        "",
        "[FAIL] Input Validation",
        `  Invalid hostname: "${host}"`,
        "",
        "Suggested fixes:",
        "  - Provide a valid hostname (alphanumeric, dots, hyphens, colons, brackets only)",
      ].join("\n"),
    );
  });

  it("defaults the port to 22 -- in the call AND in the header", async () => {
    diagnoseSpy.mockReturnValue({ overall: "ok", checks: [], suggestions: [] });
    const text = await textOf("ssh_diagnose", { host: "h.test" });
    expect(diagnoseSpy).toHaveBeenCalledWith("h.test", 22);
    expect(text).toContain("SSH Diagnostic Report for h.test:22");
  });

  it("passes an explicit port through to diagnose and into the header", async () => {
    diagnoseSpy.mockReturnValue({ overall: "ok", checks: [], suggestions: [] });
    const text = await textOf("ssh_diagnose", { host: "h.test", port: 2222 });
    expect(diagnoseSpy).toHaveBeenCalledWith("h.test", 2222);
    expect(text).toContain("SSH Diagnostic Report for h.test:2222");
  });
});

// ---------------------------------------------------------------------------
// ssh_agent_ensure
// ---------------------------------------------------------------------------

describe("ssh_agent_ensure renders the AgentResult", () => {
  // AgentResult shape from env.ts. This is probeAgent()'s success return.
  const runningWithKeys: AgentResult = {
    running: true,
    reachable: true,
    socket: "/tmp/ssh-Xh8Kd2/agent.4711",
    keys: ["256 SHA256:abc123 jeff@box (ED25519)", "3072 SHA256:def456 old@box (RSA)"],
    started: false,
    message: "ssh-agent running with 2 key(s) loaded",
  };

  it("prints message, socket, and every loaded key", async () => {
    ensureAgentSpy.mockReturnValue(runningWithKeys);
    expect(await textOf("ssh_agent_ensure")).toBe(
      [
        "ssh-agent running with 2 key(s) loaded",
        "Socket: /tmp/ssh-Xh8Kd2/agent.4711",
        "Loaded keys:",
        "  256 SHA256:abc123 jeff@box (ED25519)",
        "  3072 SHA256:def456 old@box (RSA)",
      ].join("\n"),
    );
  });

  it("omits the 'Loaded keys:' header when the agent is up but empty", async () => {
    // probeAgent's other success return: reachable, zero identities.
    ensureAgentSpy.mockReturnValue({
      running: true,
      reachable: true,
      socket: "/tmp/ssh-a/agent.9",
      keys: [],
      started: false,
      message: "ssh-agent running but no keys loaded. Use ssh_key_load to add one.",
    } satisfies AgentResult);
    const result = await run("ssh_agent_ensure");
    expect(result.content[0].text).toBe(
      "ssh-agent running but no keys loaded. Use ssh_key_load to add one.\nSocket: /tmp/ssh-a/agent.9",
    );
    expect(result.content[0].text).not.toContain("Loaded keys:");
    // Reachable, so NOT an error -- "no keys" is a state to act on, not a failure.
    expect(result.isError).toBe(false);
  });

  it("prints the env block after starting a new agent, skipping a missing SSH_AGENT_PID", async () => {
    // ensureAgent's Unix start path sets `env: { SSH_AUTH_SOCK, SSH_AGENT_PID: pidMatch?.[1] }`
    // -- the PID is genuinely optional, so the handler's per-key `if` guards matter.
    ensureAgentSpy.mockReturnValue({
      running: true,
      reachable: true,
      socket: "/tmp/ssh-new/agent.55",
      keys: [],
      started: true,
      env: { SSH_AUTH_SOCK: "/tmp/ssh-new/agent.55", SSH_AGENT_PID: undefined },
      message: "Started new ssh-agent scoped to the ssh-mcp server process.",
    } satisfies AgentResult);
    const text = await textOf("ssh_agent_ensure");
    expect(text).toBe(
      [
        "Started new ssh-agent scoped to the ssh-mcp server process.",
        "Socket: /tmp/ssh-new/agent.55",
        "Environment variables set in this session:",
        "  SSH_AUTH_SOCK=/tmp/ssh-new/agent.55",
      ].join("\n"),
    );
    expect(text).not.toContain("SSH_AGENT_PID");
  });

  it("prints both env vars when the PID was captured", async () => {
    ensureAgentSpy.mockReturnValue({
      running: true,
      reachable: true,
      socket: "/tmp/ssh-new/agent.55",
      keys: [],
      started: true,
      env: { SSH_AUTH_SOCK: "/tmp/ssh-new/agent.55", SSH_AGENT_PID: "4712" },
      message: "Started new ssh-agent scoped to the ssh-mcp server process.",
    } satisfies AgentResult);
    const text = await textOf("ssh_agent_ensure");
    expect(text).toContain("  SSH_AUTH_SOCK=/tmp/ssh-new/agent.55");
    expect(text).toContain("  SSH_AGENT_PID=4712");
    expect(text.indexOf("SSH_AUTH_SOCK=")).toBeLessThan(text.indexOf("SSH_AGENT_PID="));
  });

  it("omits the env block entirely when no env was set", async () => {
    ensureAgentSpy.mockReturnValue(runningWithKeys);
    expect(await textOf("ssh_agent_ensure")).not.toContain("Environment variables set in this session:");
  });

  it("agent not running: isError TRUE, message only, no Socket line", async () => {
    // ensureAgent's win32 dead-end return -- the branch a real operator hits on a Windows
    // box where the OpenSSH agent service is stopped. No socket, no keys, no env.
    ensureAgentSpy.mockReturnValue({
      running: false,
      reachable: false,
      keys: [],
      started: false,
      message:
        "Windows OpenSSH agent not running. Start it: Get-Service ssh-agent | Set-Service -StartupType Automatic; Start-Service ssh-agent",
    } satisfies AgentResult);
    const result = await run("ssh_agent_ensure");
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe(
      "Windows OpenSSH agent not running. Start it: Get-Service ssh-agent | Set-Service -StartupType Automatic; Start-Service ssh-agent",
    );
    expect(result.content[0].text).not.toContain("Socket:");
    expect(result.content[0].text).not.toContain("Loaded keys:");
  });

  it("the Unix could-not-start dead end is also isError TRUE", async () => {
    ensureAgentSpy.mockReturnValue({
      running: false,
      reachable: false,
      keys: [],
      started: false,
      message: 'Could not start ssh-agent. Run manually: eval "$(ssh-agent -s)"',
    } satisfies AgentResult);
    expect((await run("ssh_agent_ensure")).isError).toBe(true);
  });

  it("isError keys off `reachable`, NOT `running`", async () => {
    // The two fields are distinct in AgentResult and the handler deliberately uses
    // reachable. A hypothetical running-but-unreachable agent must still flag as an error.
    ensureAgentSpy.mockReturnValue({
      running: true,
      reachable: false,
      keys: [],
      started: false,
      message: "agent process exists but the socket is dead",
    } satisfies AgentResult);
    expect((await run("ssh_agent_ensure")).isError).toBe(true);
  });

  it("takes no arguments", () => {
    expect(getTool("ssh_agent_ensure").schema).toEqual({});
  });
});

// ---------------------------------------------------------------------------
// ssh_key_list
// ---------------------------------------------------------------------------

describe("ssh_key_list renders a SshKeyListing", () => {
  const SSH_DIR = "/home/jeff/.ssh";
  /** The "the directory was read" listing -- the only status that carries keys. */
  const ok = (keys: KeyInfo[]): SshKeyListing => ({ status: "ok", dir: SSH_DIR, keys });

  const keys: KeyInfo[] = [
    {
      name: "id_ed25519",
      path: "/home/jeff/.ssh/id_ed25519",
      type: "ed25519",
      fingerprint: "SHA256:abc123",
      loadedInAgent: true,
    },
    {
      name: "id_rsa",
      path: "/home/jeff/.ssh/id_rsa",
      type: "rsa",
      fingerprint: "SHA256:def456",
      loadedInAgent: false,
    },
  ];

  it("renders the count, then name/type/marker + path + fingerprint per key", async () => {
    listSshKeysDetailedSpy.mockReturnValue(ok(keys));
    expect(await textOf("ssh_key_list")).toBe(
      [
        "Found 2 SSH key(s):",
        "",
        "id_ed25519 (ed25519) [LOADED]",
        "  Path: /home/jeff/.ssh/id_ed25519",
        "  Fingerprint: SHA256:abc123",
        "",
        "id_rsa (rsa) [not loaded]",
        "  Path: /home/jeff/.ssh/id_rsa",
        "  Fingerprint: SHA256:def456",
        "",
      ].join("\n"),
    );
  });

  it("the LOADED / not loaded marker is driven by loadedInAgent", async () => {
    // This marker is the entire point of the tool -- it is what tells the caller whether
    // to follow up with ssh_key_load. Flipping it would be silent otherwise.
    listSshKeysDetailedSpy.mockReturnValue(ok([{ ...keys[0], loadedInAgent: false }]));
    expect(await textOf("ssh_key_list")).toContain("id_ed25519 (ed25519) [not loaded]");
    listSshKeysDetailedSpy.mockReturnValue(ok([{ ...keys[1], loadedInAgent: true }]));
    expect(await textOf("ssh_key_list")).toContain("id_rsa (rsa) [LOADED]");
  });

  it("omits the Fingerprint line when ssh-keygen could not produce one", async () => {
    // listSshKeysDetailed leaves `fingerprint` undefined when `ssh-keygen -lf` fails, and
    // such a key is then reported as not-loaded regardless of the agent.
    listSshKeysDetailedSpy.mockReturnValue(
      ok([{ name: "legacy_key", path: "/home/jeff/.ssh/legacy_key", type: "unknown", loadedInAgent: false }]),
    );
    const text = await textOf("ssh_key_list");
    expect(text).toBe("Found 1 SSH key(s):\n\nlegacy_key (unknown) [not loaded]\n  Path: /home/jeff/.ssh/legacy_key\n");
    expect(text).not.toContain("Fingerprint");
  });

  it("the count in the header tracks the array length", async () => {
    listSshKeysDetailedSpy.mockReturnValue(ok([keys[0]]));
    expect(await textOf("ssh_key_list")).toContain("Found 1 SSH key(s):");
    listSshKeysDetailedSpy.mockReturnValue(ok(keys));
    expect(await textOf("ssh_key_list")).toContain("Found 2 SSH key(s):");
  });

  it("a READABLE but keyless ~/.ssh is the ssh-keygen hint, and is NOT an error", async () => {
    // status "ok" with zero keys -- the only one of the three empty results that generating
    // a key actually fixes. Note it is NOT the "Found 0 SSH key(s):" fall-through: an early
    // return with actionable remediation.
    listSshKeysDetailedSpy.mockReturnValue(ok([]));
    const result = await run("ssh_key_list");
    expect(result.content[0].text).toBe(
      'No SSH private keys found in ~/.ssh/. Generate one: ssh-keygen -t ed25519 -C "your@email.com"',
    );
    expect(result.content[0].text).not.toContain("Found 0");
    expect(result.isError).toBe(false);
  });

  it("a MISSING ~/.ssh says the directory does not exist, names it, and is still not an error", async () => {
    // status "no-dir": a fresh machine. Same remediation as the keyless case (ssh-keygen
    // creates the directory), but the message must not claim a directory was searched --
    // the operator needs to know none exists yet.
    listSshKeysDetailedSpy.mockReturnValue({ status: "no-dir", dir: SSH_DIR, keys: [] } satisfies SshKeyListing);
    const result = await run("ssh_key_list");
    expect(result.content[0].text).toBe(
      `No ~/.ssh directory yet (${SSH_DIR} does not exist). Generate a key to create it: ssh-keygen -t ed25519 -C "your@email.com"`,
    );
    expect(result.isError).toBe(false);
    // Distinct from the keyless-directory wording, so the two cannot be conflated again.
    expect(result.content[0].text).not.toContain("No SSH private keys found");
  });

  it("an UNREADABLE ~/.ssh is an ERROR that names the directory and the errno reason", async () => {
    // status "unreadable": EACCES on ~/.ssh, or a plain file where the directory should be.
    // This is the case the old single empty-message branch reported as a success while
    // advising ssh-keygen -- advice that cannot help, since the keys may well be right there.
    listSshKeysDetailedSpy.mockReturnValue({
      status: "unreadable",
      dir: SSH_DIR,
      keys: [],
      reason: `EACCES: permission denied, scandir '${SSH_DIR}'`,
    } satisfies SshKeyListing);
    const result = await run("ssh_key_list");
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe(
      `Could not read ${SSH_DIR}: EACCES: permission denied, scandir '${SSH_DIR}'. ` +
        `This is NOT "no keys" -- the directory exists but could not be listed. ` +
        `Check that it is a directory and that you own it: ls -ld ${SSH_DIR}, then chmod 700 ${SSH_DIR}.`,
    );
    // It must NOT send the operator off to generate a key: their keys may be intact and
    // simply unreadable, and a new key would not be listable either.
    expect(result.content[0].text).not.toContain("ssh-keygen -t ed25519");
  });

  it("an ENOTDIR ~/.ssh (a file where the directory should be) is the same error branch", async () => {
    listSshKeysDetailedSpy.mockReturnValue({
      status: "unreadable",
      dir: SSH_DIR,
      keys: [],
      reason: `ENOTDIR: not a directory, scandir '${SSH_DIR}'`,
    } satisfies SshKeyListing);
    const result = await run("ssh_key_list");
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("ENOTDIR: not a directory");
  });

  it("every branch emits an EXPLICIT boolean isError, error only for the unreadable one", async () => {
    // The three empty results used to be one message with no flag at all, so an agent could
    // not tell a broken ~/.ssh from an empty one. Each branch is checked here in one place.
    const cases: [listing: SshKeyListing, isError: boolean][] = [
      [ok(keys), false],
      [ok([]), false],
      [{ status: "no-dir", dir: SSH_DIR, keys: [] }, false],
      [{ status: "unreadable", dir: SSH_DIR, keys: [], reason: "EACCES: permission denied" }, true],
    ];
    for (const [listing, isError] of cases) {
      listSshKeysDetailedSpy.mockReturnValue(listing);
      const result = await run("ssh_key_list");
      expect("isError" in result).toBe(true);
      expect(result.isError).toBe(isError);
    }
  });

  it("reads the keys off the listing, never off a bare array", async () => {
    // Guards the call boundary itself: the handler must go through listSshKeysDetailed (the
    // only function that reports WHY a scan came back empty), not the KeyInfo[] wrapper.
    listSshKeysDetailedSpy.mockReturnValue(ok(keys));
    await run("ssh_key_list");
    expect(listSshKeysDetailedSpy).toHaveBeenCalledTimes(1);
    expect(listSshKeysDetailedSpy).toHaveBeenCalledWith();
  });

  it("takes no arguments", () => {
    expect(getTool("ssh_key_list").schema).toEqual({});
  });
});

// ---------------------------------------------------------------------------
// listSshKeysDetailed -- the classification the ssh_key_list handler renders
// ---------------------------------------------------------------------------

describe("listSshKeysDetailed tells the three empty results apart", () => {
  // The handler above is mocked at the env.js boundary, so these drive the REAL function --
  // otherwise nothing would hold the classification itself (the part that decides which of
  // the three messages an operator gets). Hermetic: HOME / USERPROFILE are pointed at a
  // fresh temp directory for the duration, which is what os.homedir() reads on both
  // platforms, so the machine's own ~/.ssh is never touched.
  const realEnv = () => vi.importActual<typeof import("../env.js")>("../env.js");

  let tmpHome: string;
  let savedHome: string | undefined;
  let savedUserProfile: string | undefined;

  beforeEach(() => {
    tmpHome = mkdtempSync(join(tmpdir(), "ssh-mcp-keylist-"));
    savedHome = process.env.HOME;
    savedUserProfile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
  });

  afterEach(() => {
    if (savedHome === undefined) delete process.env.HOME;
    else process.env.HOME = savedHome;
    if (savedUserProfile === undefined) delete process.env.USERPROFILE;
    else process.env.USERPROFILE = savedUserProfile;
    rmSync(tmpHome, { recursive: true, force: true });
  });

  it("no ~/.ssh at all -> status 'no-dir', with the path it looked for", async () => {
    const { listSshKeysDetailed } = await realEnv();
    const listing = listSshKeysDetailed();
    expect(listing.status).toBe("no-dir");
    expect(listing.keys).toEqual([]);
    expect(listing.dir).toBe(join(tmpHome, ".ssh"));
  });

  it("a readable ~/.ssh holding no private keys -> status 'ok' with zero keys", async () => {
    mkdirSync(join(tmpHome, ".ssh"));
    const { listSshKeysDetailed } = await realEnv();
    const listing = listSshKeysDetailed();
    expect(listing.status).toBe("ok");
    expect(listing.keys).toEqual([]);
  });

  it("a ~/.ssh that cannot be listed -> status 'unreadable', carrying the errno message", async () => {
    // A plain FILE where the directory should be: existsSync says yes, readdir throws
    // ENOTDIR. Portable stand-in for the EACCES case, which chmod cannot produce on Windows.
    writeFileSync(join(tmpHome, ".ssh"), "not a directory");
    const { listSshKeysDetailed } = await realEnv();
    const listing = listSshKeysDetailed();
    expect(listing.status).toBe("unreadable");
    expect(listing.keys).toEqual([]);
    // The reason is what the handler shows the operator, so it has to be the real errno text.
    expect(listing.status === "unreadable" && listing.reason).toContain("ENOTDIR");
  });

  it("listSshKeys stays a plain KeyInfo[] for every existing caller", async () => {
    // The wrapper is what env.test.ts / env-hardening.test.ts and server.ts still use; it
    // must keep returning the array, empty, for all three statuses.
    const { listSshKeys } = await realEnv();
    expect(listSshKeys()).toEqual([]);
    mkdirSync(join(tmpHome, ".ssh"));
    expect(listSshKeys()).toEqual([]);
    rmSync(join(tmpHome, ".ssh"), { recursive: true });
    writeFileSync(join(tmpHome, ".ssh"), "not a directory");
    expect(listSshKeys()).toEqual([]);
  });

  it("finds a real private key in a readable ~/.ssh and reports status 'ok'", async () => {
    // The positive control for the sweep above: without it, a mutation that always returned
    // an empty listing would still satisfy every "keys is empty" assertion.
    mkdirSync(join(tmpHome, ".ssh"));
    writeFileSync(
      join(tmpHome, ".ssh", "id_test"),
      "-----BEGIN OPENSSH PRIVATE KEY-----\nnotarealkey\n-----END OPENSSH PRIVATE KEY-----\n",
    );
    const { listSshKeysDetailed } = await realEnv();
    const listing = listSshKeysDetailed();
    expect(listing.status).toBe("ok");
    expect(listing.keys.map((k) => k.name)).toEqual(["id_test"]);
  });
});

// ---------------------------------------------------------------------------
// ssh_key_load
// ---------------------------------------------------------------------------

describe("ssh_key_load surfaces loadKey's message and status", () => {
  it("passes the keyPath through verbatim -- no ~ expansion in the handler", async () => {
    // loadKey owns the ~ resolution (env.ts). The handler must not pre-resolve it, or a
    // path would be expanded twice against different homedirs.
    loadKeySpy.mockReturnValue({ status: "ok", message: "Key loaded: /home/jeff/.ssh/id_ed25519" });
    await run("ssh_key_load", { keyPath: "~/.ssh/id_ed25519" });
    expect(loadKeySpy).toHaveBeenCalledWith("~/.ssh/id_ed25519");
  });

  it("success: the message alone, isError false", async () => {
    loadKeySpy.mockReturnValue({ status: "ok", message: "Key loaded: /home/jeff/.ssh/id_ed25519" });
    const result = await run("ssh_key_load", { keyPath: "/home/jeff/.ssh/id_ed25519" });
    expect(result.content[0].text).toBe("Key loaded: /home/jeff/.ssh/id_ed25519");
    expect(result.isError).toBe(false);
  });

  // Every error shape loadKey can return -- these are the messages an operator on a broken
  // machine actually sees, and each must arrive with isError set.
  const failures: [label: string, message: string][] = [
    ["agent unreachable", 'Could not start ssh-agent. Run manually: eval "$(ssh-agent -s)"'],
    ["key file missing", "Key not found: /home/jeff/.ssh/nope"],
    [
      "permissions too open",
      "Key /home/jeff/.ssh/id_rsa has too-open permissions. Fix: chmod 600 /home/jeff/.ssh/id_rsa",
    ],
    [
      "passphrase required",
      "Key /home/jeff/.ssh/id_rsa requires a passphrase. Add it manually: ssh-add /home/jeff/.ssh/id_rsa",
    ],
    ["generic ssh-add failure", "Failed to load key: Error loading key: invalid format"],
  ];

  it.each(failures)("%s: isError TRUE and the message passed through unchanged", async (_label, message) => {
    loadKeySpy.mockReturnValue({ status: "error", message });
    const result = await run("ssh_key_load", { keyPath: "/home/jeff/.ssh/id_rsa" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe(message);
  });

  it("emits exactly one text block, never a wrapped or decorated message", async () => {
    loadKeySpy.mockReturnValue({ status: "error", message: "Key not found: /nope" });
    const result = await run("ssh_key_load", { keyPath: "/nope" });
    expect(result.content).toEqual([{ type: "text", text: "Key not found: /nope" }]);
  });
});

// ---------------------------------------------------------------------------
// ssh_config_lookup
// ---------------------------------------------------------------------------

describe("ssh_config_lookup renders ConfigLookupResult", () => {
  // Shape from env.ts. `all` and `raw` are deliberately NOT rendered -- only the six
  // resolved fields below.
  const resolved: ConfigLookupResult = {
    hostname: "10.0.0.7",
    user: "deploy",
    port: "2222",
    identityFile: ["/home/jeff/.ssh/id_ed25519", "/home/jeff/.ssh/id_rsa"],
    proxyJump: "bastion.example.test",
    proxyCommand: undefined,
    all: { hostname: "10.0.0.7", user: "deploy", port: "2222", proxyjump: "bastion.example.test" },
    raw: "hostname 10.0.0.7\nuser deploy\n",
  };

  it("renders the resolved fields, quoting the alias the caller asked about", async () => {
    configLookupSpy.mockReturnValue(resolved);
    expect(await textOf("ssh_config_lookup", { host: "prod-web" })).toBe(
      [
        'SSH config for "prod-web":',
        "",
        "  Hostname: 10.0.0.7",
        "  User: deploy",
        "  Port: 2222",
        "  Identity files: /home/jeff/.ssh/id_ed25519, /home/jeff/.ssh/id_rsa",
        "  ProxyJump: bastion.example.test",
      ].join("\n"),
    );
  });

  it("joins multiple identity files with ', ' on ONE line", async () => {
    configLookupSpy.mockReturnValue(resolved);
    const text = await textOf("ssh_config_lookup", { host: "prod-web" });
    expect(text).toContain("  Identity files: /home/jeff/.ssh/id_ed25519, /home/jeff/.ssh/id_rsa");
    expect(text.split("\n").filter((l) => l.includes("Identity files"))).toHaveLength(1);
  });

  it("does NOT leak the `all` map or the raw `ssh -G` dump", async () => {
    configLookupSpy.mockReturnValue(resolved);
    const text = await textOf("ssh_config_lookup", { host: "prod-web" });
    expect(text).not.toContain("hostname 10.0.0.7");
    expect(text).not.toContain("proxyjump");
  });

  it("renders ProxyCommand when that is the proxy in play", async () => {
    configLookupSpy.mockReturnValue({
      ...resolved,
      proxyJump: undefined,
      proxyCommand: "ssh -W %h:%p jump.example.test",
    } satisfies ConfigLookupResult);
    const text = await textOf("ssh_config_lookup", { host: "prod-web" });
    expect(text).toContain("  ProxyCommand: ssh -W %h:%p jump.example.test");
    expect(text).not.toContain("ProxyJump:");
  });

  it("omits the identity-files and proxy lines when there are none", async () => {
    // `ssh -G` on a plain host with no config: no ProxyJump/ProxyCommand, and configLookup
    // maps an absent user to the empty string.
    configLookupSpy.mockReturnValue({
      hostname: "plain.test",
      user: "",
      port: "22",
      identityFile: [],
      proxyJump: undefined,
      proxyCommand: undefined,
      all: {},
      raw: "",
    } satisfies ConfigLookupResult);
    const text = await textOf("ssh_config_lookup", { host: "plain.test" });
    // Note the trailing space after "User:" -- the empty user renders as a bare label.
    expect(text).toBe('SSH config for "plain.test":\n\n  Hostname: plain.test\n  User: \n  Port: 22');
    expect(text).not.toContain("Identity files:");
    expect(text).not.toContain("Proxy");
  });

  it("isError is set by the PRESENCE of an `error` key, and prints that string alone", async () => {
    // configLookup returns a `{ error }` union member -- there is no status field to read.
    configLookupSpy.mockReturnValue({ error: 'Invalid hostname: "-oProxyCommand=evil"' });
    const result = await run("ssh_config_lookup", { host: "-oProxyCommand=evil" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe('Invalid hostname: "-oProxyCommand=evil"');
    // The success formatting is skipped entirely -- no header, no field labels.
    expect(result.content[0].text).not.toContain("SSH config for");
  });

  it("narrows on the PRESENCE of the key, not on its truthiness", async () => {
    // `"error" in result` is the only thing keeping a failed lookup out of the success
    // formatter. A truthiness check (`if (result.error)`) would send this one down the
    // success path, where every field is undefined -- the caller would get
    // "Hostname: undefined" instead of a reason.
    configLookupSpy.mockReturnValue({ error: "" });
    const result = await run("ssh_config_lookup", { host: "prod-web" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe("");
    expect(result.content[0].text).not.toContain("undefined");
  });

  it("a result carrying BOTH an error and resolved-looking fields still takes the error branch", async () => {
    // Guards the narrowing itself rather than the union: rewriting the check to key off a
    // resolved field (`if (!result.hostname)`) would format this as a success and bury the
    // reason.
    configLookupSpy.mockReturnValue({ error: "Failed to resolve SSH config for prod-web", hostname: "10.0.0.7" });
    const result = await run("ssh_config_lookup", { host: "prod-web" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe("Failed to resolve SSH config for prod-web");
    expect(result.content[0].text).not.toContain("10.0.0.7");
  });

  it("an `ssh -G` failure is the same error shape", async () => {
    configLookupSpy.mockReturnValue({
      error: "Failed to resolve SSH config for prod-web: ssh: command not found",
    });
    const result = await run("ssh_config_lookup", { host: "prod-web" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe("Failed to resolve SSH config for prod-web: ssh: command not found");
  });

  it("the success branch does NOT set isError at all", async () => {
    // Pinning ACTUAL behavior. Unlike its six siblings, this handler emits the flag only
    // on the failure path; a successful lookup carries no `isError` key. Semantically
    // equivalent for MCP (absent reads as not-an-error) but asymmetric with the rest.
    configLookupSpy.mockReturnValue(resolved);
    const result = await run("ssh_config_lookup", { host: "prod-web" });
    expect(result.isError).toBeUndefined();
    expect("isError" in result).toBe(false);
  });

  it("passes the host through untouched", async () => {
    configLookupSpy.mockReturnValue(resolved);
    await run("ssh_config_lookup", { host: "prod-web" });
    expect(configLookupSpy).toHaveBeenCalledWith("prod-web");
    // No port parameter on this tool -- it resolves an alias, it does not connect.
    expect(configLookupSpy.mock.calls[0]).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// ssh_known_hosts_fix
// ---------------------------------------------------------------------------

describe("ssh_known_hosts_fix renders message + actions", () => {
  it("prints the message, a blank line, then an 'Actions taken:' bullet per action", async () => {
    fixKnownHostsSpy.mockReturnValue({
      status: "ok",
      message: "Host key refreshed for web1.test",
      actions: ["Removed old host key for web1.test", "Added new host key for web1.test"],
    });
    const result = await run("ssh_known_hosts_fix", { host: "web1.test" });
    expect(result.content[0].text).toBe(
      [
        "Host key refreshed for web1.test",
        "",
        "Actions taken:",
        "  - Removed old host key for web1.test",
        "  - Added new host key for web1.test",
      ].join("\n"),
    );
    expect(result.isError).toBe(false);
  });

  it("renders the first-time-host wording fixKnownHosts actually emits", async () => {
    // removeKnownHostEntry fails CLOSED to "absent", so a host that was never in
    // known_hosts must NOT be reported as removed. The handler has to carry that
    // distinction through verbatim.
    fixKnownHostsSpy.mockReturnValue({
      status: "ok",
      message: "Host key refreshed for new.test",
      actions: ["No existing host key for new.test (nothing to remove)", "Added new host key for new.test"],
    });
    const text = await textOf("ssh_known_hosts_fix", { host: "new.test" });
    expect(text).toContain("  - No existing host key for new.test (nothing to remove)");
    expect(text).not.toContain("Removed old host key");
  });

  it("omits the whole 'Actions taken:' block when the action list is empty", async () => {
    // The invalid-hostname return: rejected before anything was attempted.
    fixKnownHostsSpy.mockReturnValue({ status: "error", message: 'Invalid hostname: "-E"', actions: [] });
    const result = await run("ssh_known_hosts_fix", { host: "-E" });
    expect(result.content[0].text).toBe('Invalid hostname: "-E"');
    expect(result.content[0].text).not.toContain("Actions taken:");
    expect(result.isError).toBe(true);
  });

  it("a failure still reports the actions that DID happen before it", async () => {
    // The scan-succeeded-but-write-failed path: the stale key really was removed, so the
    // operator needs to see that even though the call is an error overall.
    fixKnownHostsSpy.mockReturnValue({
      status: "error",
      message: "Scanned key but failed to write known_hosts: EACCES: permission denied",
      actions: ["Removed old host key for web1.test"],
    });
    const result = await run("ssh_known_hosts_fix", { host: "web1.test" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe(
      [
        "Scanned key but failed to write known_hosts: EACCES: permission denied",
        "",
        "Actions taken:",
        "  - Removed old host key for web1.test",
      ].join("\n"),
    );
  });

  it("unreachable host: isError TRUE", async () => {
    fixKnownHostsSpy.mockReturnValue({
      status: "error",
      message: "Could not scan host key for down.test. Host may be unreachable.",
      actions: ["No existing host key for down.test (nothing to remove)"],
    });
    expect((await run("ssh_known_hosts_fix", { host: "down.test" })).isError).toBe(true);
  });

  it("defaults the port to 22", async () => {
    fixKnownHostsSpy.mockReturnValue({ status: "ok", message: "ok", actions: [] });
    await run("ssh_known_hosts_fix", { host: "web1.test" });
    expect(fixKnownHostsSpy).toHaveBeenCalledWith("web1.test", 22);
  });

  it("passes an explicit non-standard port through (it selects the [host]:port removal)", async () => {
    fixKnownHostsSpy.mockReturnValue({ status: "ok", message: "ok", actions: [] });
    await run("ssh_known_hosts_fix", { host: "web1.test", port: 2222 });
    expect(fixKnownHostsSpy).toHaveBeenCalledWith("web1.test", 2222);
  });
});

// ---------------------------------------------------------------------------
// ssh_test
// ---------------------------------------------------------------------------

describe("ssh_test surfaces testConnection's message and status", () => {
  it("success: the timing message alone, isError false", async () => {
    testConnectionSpy.mockReturnValue({ status: "ok", message: "Connected to web1.test:22 in 143ms" });
    const result = await run("ssh_test", { host: "web1.test" });
    expect(result.content).toEqual([{ type: "text", text: "Connected to web1.test:22 in 143ms" }]);
    expect(result.isError).toBe(false);
  });

  // The five error classifications probeSshConnection can produce, with the exact wording
  // testConnection attaches to each. The handler must pass all of them through untouched.
  const failures: [label: string, message: string][] = [
    [
      "auth rejected",
      "Authentication failed to web1.test:22 (91ms). Key not authorized. Check: ssh-add -l, verify correct username, verify key is in remote authorized_keys.",
    ],
    ["connection refused", "Connection refused at web1.test:22. SSH server not running or port blocked."],
    ["timed out", "Connection timed out to web1.test:22. Host down or firewall blocking."],
    [
      "host key mismatch",
      "Host key mismatch for web1.test. Instance was likely recreated. Fix with ssh_known_hosts_fix.",
    ],
    ["dns failure", 'Could not resolve "web1.test". Check DNS, /etc/hosts, or SSH config.'],
    ["invalid hostname", 'Invalid hostname: "-E"'],
  ];

  it.each(failures)("%s: isError TRUE, message verbatim", async (_label, message) => {
    testConnectionSpy.mockReturnValue({ status: "error", message });
    const result = await run("ssh_test", { host: "web1.test" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe(message);
  });

  it("a 'warning' status is NOT flagged as an error", async () => {
    // testConnection's return type declares "ok" | "warning" | "error"; the handler keys
    // strictly off "error". Pinned so the middle status can never be silently promoted.
    testConnectionSpy.mockReturnValue({ status: "warning", message: "Connected, but the host key is new" });
    const result = await run("ssh_test", { host: "web1.test" });
    expect(result.isError).toBe(false);
    expect(result.content[0].text).toBe("Connected, but the host key is new");
  });

  it("defaults the port to 22", async () => {
    testConnectionSpy.mockReturnValue({ status: "ok", message: "Connected to web1.test:22 in 10ms" });
    await run("ssh_test", { host: "web1.test" });
    expect(testConnectionSpy).toHaveBeenCalledWith("web1.test", 22);
  });

  it("passes an explicit port through", async () => {
    testConnectionSpy.mockReturnValue({ status: "ok", message: "Connected to web1.test:2222 in 10ms" });
    await run("ssh_test", { host: "web1.test", port: 2222 });
    expect(testConnectionSpy).toHaveBeenCalledWith("web1.test", 2222);
  });
});

// ---------------------------------------------------------------------------
// ssh_git_check
// ---------------------------------------------------------------------------

describe("ssh_git_check renders the git-over-SSH result", () => {
  it("success: message plus an 'Authenticated as:' line, isError false", async () => {
    checkGitSshSpy.mockReturnValue({
      status: "ok",
      message: "Git SSH authentication to github.com succeeded as octocat",
      authenticatedAs: "octocat",
    });
    const result = await run("ssh_git_check", {});
    expect(result.content[0].text).toBe(
      "Git SSH authentication to github.com succeeded as octocat\nAuthenticated as: octocat",
    );
    expect(result.isError).toBe(false);
  });

  it("omits the 'Authenticated as:' line when no username could be parsed", async () => {
    // checkGitSsh only fills authenticatedAs when one of its three regexes matches; a
    // provider whose success banner carries no username still returns status ok.
    checkGitSshSpy.mockReturnValue({
      status: "ok",
      message: "Git SSH authentication to bitbucket.org succeeded",
    });
    const result = await run("ssh_git_check", { host: "bitbucket.org" });
    expect(result.content[0].text).toBe("Git SSH authentication to bitbucket.org succeeded");
    expect(result.content[0].text).not.toContain("Authenticated as:");
    expect(result.isError).toBe(false);
  });

  it("permission denied: isError TRUE with the remediation intact", async () => {
    // The branch a real operator hits -- key not registered with the provider. The message
    // names the follow-up tools, so it must survive the handler unedited.
    const message =
      "Permission denied for github.com. Either no key is loaded in the agent or your key isn't registered with github.com. Run ssh_key_list to check, then ssh_key_load if needed.";
    checkGitSshSpy.mockReturnValue({ status: "error", message });
    const result = await run("ssh_git_check", {});
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe(message);
    expect(result.content[0].text).toContain("ssh_key_list");
    expect(result.content[0].text).toContain("ssh_key_load");
  });

  const otherFailures: [label: string, message: string][] = [
    ["connection refused", "Connection refused by git.internal. SSH may not be available on this host."],
    ["timeout", "Connection to github.com timed out. Check your network or firewall."],
    ["dns failure", 'Could not resolve hostname "githbu.com". Check DNS or spelling.'],
    ["no response at all", "Git SSH check for github.com: no response (agent may not be running)"],
    ["invalid hostname", 'Invalid hostname: "-oProxyCommand=evil"'],
  ];

  it.each(otherFailures)("%s: isError TRUE, message verbatim", async (_label, message) => {
    checkGitSshSpy.mockReturnValue({ status: "error", message });
    const result = await run("ssh_git_check", {});
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe(message);
  });

  it("defaults to github.com and the git user when neither is supplied", async () => {
    checkGitSshSpy.mockReturnValue({ status: "ok", message: "ok" });
    await run("ssh_git_check", {});
    expect(checkGitSshSpy).toHaveBeenCalledWith("github.com", "git");
  });

  it("an explicit host and user override the defaults", async () => {
    checkGitSshSpy.mockReturnValue({ status: "ok", message: "ok" });
    await run("ssh_git_check", { host: "gitlab.example.test", user: "gitolite" });
    expect(checkGitSshSpy).toHaveBeenCalledWith("gitlab.example.test", "gitolite");
  });

  it("each argument defaults independently", async () => {
    checkGitSshSpy.mockReturnValue({ status: "ok", message: "ok" });
    await run("ssh_git_check", { host: "gitlab.example.test" });
    expect(checkGitSshSpy).toHaveBeenCalledWith("gitlab.example.test", "git");
    checkGitSshSpy.mockClear();
    await run("ssh_git_check", { user: "gitolite" });
    expect(checkGitSshSpy).toHaveBeenCalledWith("github.com", "gitolite");
  });

  it("an EMPTY host or user is REJECTED by the schema, not silently defaulted", () => {
    // The handler defaults with `host || "github.com"`, a truthiness fallback, so an
    // explicitly-empty host would probe github.com and report on a host the caller never
    // named -- and "" would never reach checkGitSsh, skipping the isValidHostname check
    // every other host-taking tool routes its input through. .min(1) closes that at the
    // schema boundary: omitting the field is how you ask for the default.
    const schema = getTool("ssh_git_check").schema as unknown as Record<string, ZodLike>;
    for (const field of ["host", "user"]) {
      expect(schema[field].safeParse("").success).toBe(false);
      // Still optional, and still accepts a real value.
      expect(schema[field].safeParse(undefined).success).toBe(true);
    }
    expect(schema.host.safeParse("gitlab.example.test").success).toBe(true);
    expect(schema.user.safeParse("gitolite").success).toBe(true);
  });

  it("the rejection message tells the caller to omit the field instead", () => {
    const schema = getTool("ssh_git_check").schema as unknown as Record<string, ZodLike>;
    const hostResult = schema.host.safeParse("");
    expect(hostResult.success).toBe(false);
    expect(JSON.stringify(hostResult.error)).toContain("host must not be empty");
    expect(JSON.stringify(schema.user.safeParse("").error)).toContain("user must not be empty");
  });

  it("whitespace-only values are NOT rejected -- .min(1) counts characters, not content", () => {
    // Pinned as actual behavior so the boundary is honest about where it stops. " " reaches
    // checkGitSsh, which routes it through isValidHostname and rejects it there -- the same
    // validator every sibling host-taking tool uses.
    const schema = getTool("ssh_git_check").schema as unknown as Record<string, ZodLike>;
    expect(schema.host.safeParse(" ").success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Cross-cutting: no local-work handler opens a connection
// ---------------------------------------------------------------------------

describe("none of the eight local handlers touch the connection pool", () => {
  const LOCAL_TOOLS = [
    "ssh_diagnose",
    "ssh_agent_ensure",
    "ssh_key_list",
    "ssh_key_load",
    "ssh_config_lookup",
    "ssh_known_hosts_fix",
    "ssh_test",
    "ssh_git_check",
  ];

  it.each(LOCAL_TOOLS)("%s is registered", (name) => {
    expect(getTool(name).handler).toBeTypeOf("function");
  });

  it("runs all eight without withConnection ever being called", async () => {
    diagnoseSpy.mockReturnValue({ overall: "ok", checks: [], suggestions: [] });
    ensureAgentSpy.mockReturnValue({ running: true, reachable: true, keys: [], started: false, message: "up" });
    listSshKeysDetailedSpy.mockReturnValue({ status: "ok", dir: "/home/jeff/.ssh", keys: [] });
    loadKeySpy.mockReturnValue({ status: "ok", message: "loaded" });
    configLookupSpy.mockReturnValue({
      hostname: "h.test",
      user: "u",
      port: "22",
      identityFile: [],
      all: {},
      raw: "",
    });
    fixKnownHostsSpy.mockReturnValue({ status: "ok", message: "ok", actions: [] });
    testConnectionSpy.mockReturnValue({ status: "ok", message: "ok" });
    checkGitSshSpy.mockReturnValue({ status: "ok", message: "ok" });

    const tools = new Map<string, ToolRegistration>();
    const server = {
      tool: (...args: unknown[]) => {
        tools.set(args[0] as string, {
          description: args[1] as string,
          schema: args[2] as Record<string, unknown>,
          handler: args[args.length - 1] as ToolHandler,
        });
      },
    };
    const pool = new NoNetworkPool();
    const withConnection = vi.spyOn(pool, "withConnection");
    registerTools(server as never, pool);

    await tools.get("ssh_diagnose")!.handler({ host: "h.test" });
    await tools.get("ssh_agent_ensure")!.handler({});
    await tools.get("ssh_key_list")!.handler({});
    await tools.get("ssh_key_load")!.handler({ keyPath: "/k" });
    await tools.get("ssh_config_lookup")!.handler({ host: "h.test" });
    await tools.get("ssh_known_hosts_fix")!.handler({ host: "h.test" });
    await tools.get("ssh_test")!.handler({ host: "h.test" });
    await tools.get("ssh_git_check")!.handler({});

    expect(withConnection).not.toHaveBeenCalled();
    // ...and every underlying local function was reached exactly once.
    for (const spy of [
      diagnoseSpy,
      ensureAgentSpy,
      listSshKeysDetailedSpy,
      loadKeySpy,
      configLookupSpy,
      fixKnownHostsSpy,
      testConnectionSpy,
      checkGitSshSpy,
    ]) {
      expect(spy).toHaveBeenCalledTimes(1);
    }
  });
});
