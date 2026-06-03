import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { shellQuote } from "../ops.js";
import { ConnectionPool } from "../pool.js";
import { registerTools } from "../tools.js";

// These tests cover two HIGH-severity gaps in the ssh_exec handler (src/tools.ts:54-78):
//
//   Gap 1 -- env-var prefixing: when `env` is supplied the handler builds a
//   `KEY='value' ...` prefix via shellQuote and prepends it to the command. Hostile
//   values (a'b, "; rm -rf /") must be POSIX-single-quoted so the remote shell treats
//   them as inert literal bytes, never as breakout metacharacters.
//
//   Gap 2 -- policy is enforced against finalCommand (the env-PREFIXED string), not the
//   raw command. A whitelist anchored with `^` is therefore evaluated against the prefix,
//   not the command verb: `^ls` does NOT match `FOO='x' ls`. This is documented behavior
//   (the tool description says "policy is checked against the env-prefixed command") and a
//   real footgun, so it is pinned here.
//
// Boundary: we run the REAL registered ssh_exec handler with the REAL shellQuote and the
// REAL enforcePolicy (which reads SSH_MCP_COMMAND_* from the env). Only the network is
// faked -- a ConnectionPool subclass whose withConnection hands the handler a fake client
// that records the exact command string passed to exec(). Nothing about quoting or policy
// is mocked, so what we assert is what the production code actually does.

type ToolHandler = (args: Record<string, unknown>) => Promise<unknown>;

/** Minimal fake McpServer that captures each registered tool's handler by name. */
function captureHandlers(): { server: { tool: (...args: unknown[]) => void }; handlers: Map<string, ToolHandler> } {
  const handlers = new Map<string, ToolHandler>();
  const server = {
    // registerTools calls server.tool(name, description, schema, handler).
    tool: (...args: unknown[]) => {
      const name = args[0] as string;
      const handler = args[args.length - 1] as ToolHandler;
      handlers.set(name, handler);
    },
  };
  return { server, handlers };
}

/**
 * ConnectionPool subclass that never touches the network. Its withConnection runs the
 * handler's callback against a dummy client without connecting. The handler then calls the
 * module-level exec(client, finalCommand, ...) from ssh.js -- which we mock below to record
 * finalCommand. So this pool only has to skip the real acquire()/connect path.
 */
class RecordingPool extends ConnectionPool {
  override async withConnection<T>(_config: any, fn: (client: any) => Promise<T>): Promise<T> {
    return fn({});
  }
}

// The handler calls the module-level `exec(client, finalCommand, timeout)` from ssh.js.
// Mock that single function to record finalCommand (the second positional arg); everything
// else (shellQuote, enforcePolicy, the handler body) runs for real.
//
// vi.mock is hoisted above all top-level declarations, so the spy + recorder must be
// created with vi.hoisted to exist by the time the factory runs.
const { execSpy, recorder } = vi.hoisted(() => {
  const recorder: { command: string | undefined } = { command: undefined };
  const execSpy = vi.fn(async (_client: unknown, command: string, ..._rest: unknown[]) => {
    recorder.command = command;
    return { stdout: "out", stderr: "", code: 0 };
  });
  return { execSpy, recorder };
});

vi.mock("../ssh.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../ssh.js")>();
  return { ...actual, exec: execSpy as unknown as typeof actual.exec };
});

async function getExecHandler(): Promise<{ handler: ToolHandler; pool: RecordingPool }> {
  const { server, handlers } = captureHandlers();
  const pool = new RecordingPool();
  registerTools(server as any, pool);
  const handler = handlers.get("ssh_exec");
  if (!handler) throw new Error("ssh_exec handler was not registered");
  return { handler, pool };
}

const baseConn = { host: "example.test" };

describe("ssh_exec env-var prefixing (gap 1)", () => {
  beforeEach(() => {
    recorder.command = undefined;
    execSpy.mockClear();
    // No policy configured -- gap 1 is about quoting, not gating.
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "");
    vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "");
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("builds a KEY='value' prefix and prepends it to the command", async () => {
    const { handler } = await getExecHandler();
    await handler({ ...baseConn, command: "printenv FOO", env: { FOO: "bar" } });
    expect(recorder.command).toBe("FOO='bar' printenv FOO");
  });

  it("single-quotes a value containing an embedded single quote (a'b) so it is inert", async () => {
    const { handler } = await getExecHandler();
    await handler({ ...baseConn, command: "printenv X", env: { X: "a'b" } });
    // shellQuote turns a'b into 'a'\''b' -- the embedded quote is escaped via the
    // close-quote / literal-quote / reopen-quote idiom, so the remote shell sees the
    // three literal bytes a ' b with no breakout.
    expect(recorder.command).toBe("X='a'\\''b' printenv X");
    // Cross-check against the production primitive directly.
    expect(recorder.command).toBe(`X=${shellQuote("a'b")} printenv X`);
  });

  it('neutralizes a command-injection payload in the value ("; rm -rf /")', async () => {
    const { handler } = await getExecHandler();
    const payload = '"; rm -rf /"';
    await handler({ ...baseConn, command: "printenv EVIL", env: { EVIL: payload } });
    // The entire payload is wrapped in a single-quoted literal. There is no unquoted
    // `;` or `rm` -- the value cannot break out of the assignment into a new command.
    expect(recorder.command).toBe(`EVIL=${shellQuote(payload)} printenv EVIL`);
    // The literal payload survives intact INSIDE the quotes...
    expect(recorder.command).toContain('"; rm -rf /"');
    // ...but it is bracketed by single quotes (assignment value), so `rm` is not a
    // standalone token. The only ` rm ` substring is the one inside the quoted value.
    const prefix = recorder.command!.slice(0, recorder.command!.indexOf(" printenv"));
    expect(prefix).toBe(`EVIL='"; rm -rf /"'`);
    // The dangerous metacharacters live strictly between the opening and closing quote.
    expect(prefix.startsWith("EVIL='")).toBe(true);
    expect(prefix.endsWith("'")).toBe(true);
  });

  it("single-quotes a value containing a literal single quote inside an injection payload", async () => {
    const { handler } = await getExecHandler();
    // Worst case: a value that mixes a quote breakout attempt with shell metacharacters.
    const payload = "'; rm -rf / #";
    await handler({ ...baseConn, command: "id", env: { K: payload } });
    expect(recorder.command).toBe(`K=${shellQuote(payload)} id`);
    // Every literal single quote in the payload became the '\'' escape sequence; there is
    // no way for the value to terminate its own quoting early.
    expect(recorder.command).toContain("'\\''");
  });

  it("joins multiple env vars with a single space, each independently quoted", async () => {
    const { handler } = await getExecHandler();
    await handler({ ...baseConn, command: "env", env: { A: "1", B: "two words", C: "x'y" } });
    expect(recorder.command).toBe(`A='1' B='two words' C=${shellQuote("x'y")} env`);
  });

  it("passes the raw command through unchanged when env is omitted", async () => {
    const { handler } = await getExecHandler();
    await handler({ ...baseConn, command: "uptime" });
    expect(recorder.command).toBe("uptime");
  });

  it("passes the raw command through unchanged when env is an empty object", async () => {
    const { handler } = await getExecHandler();
    // The handler guards on Object.keys(env).length > 0, so {} adds no prefix.
    await handler({ ...baseConn, command: "uptime", env: {} });
    expect(recorder.command).toBe("uptime");
  });
});

describe("ssh_exec policy enforced against the env-PREFIXED command (gap 2)", () => {
  beforeEach(() => {
    recorder.command = undefined;
    execSpy.mockClear();
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "");
    vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "");
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("an ^ls-anchored whitelist BLOCKS `ls` once an env prefix shifts the start (documented footgun)", async () => {
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls( .*)?$");
    const { handler } = await getExecHandler();
    // The finalCommand is `FOO='x' ls` -- the `^` anchor no longer matches because the
    // string starts with FOO=, not ls. The handler throws before any exec runs.
    await expect(handler({ ...baseConn, command: "ls", env: { FOO: "x" } })).rejects.toThrow(
      /does not match any pattern in SSH_MCP_COMMAND_WHITELIST/,
    );
    // exec never ran -- the policy gate fired first.
    expect(execSpy).not.toHaveBeenCalled();
    expect(recorder.command).toBeUndefined();
  });

  it("the SAME ^ls whitelist ALLOWS `ls` when no env prefix is present", async () => {
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls( .*)?$");
    const { handler } = await getExecHandler();
    await expect(handler({ ...baseConn, command: "ls" })).resolves.toBeDefined();
    expect(recorder.command).toBe("ls");
  });

  it("a whitelist that anticipates the prefix (^[A-Z_]+='[^']*' ls) DOES match the prefixed command", async () => {
    // Shows the footgun is escapable: an admin who knows the prefix shape can write a
    // pattern that allows it. This pins the exact env-prefixed string the policy sees.
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^FOO='x' ls$,^ls$");
    const { handler } = await getExecHandler();
    await expect(handler({ ...baseConn, command: "ls", env: { FOO: "x" } })).resolves.toBeDefined();
    expect(recorder.command).toBe("FOO='x' ls");
  });

  it("a blacklist matches metacharacters that live INSIDE the quoted env value", async () => {
    // Corollary of gap 2: because policy sees the prefixed string, a substring blacklist
    // pattern can match content that is actually inert (safely single-quoted). The env
    // value `; rm -rf /` is harmless on the remote, but a `rm -rf` blacklist still trips
    // on the literal bytes -- policy is purely textual over finalCommand.
    vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "rm -rf");
    const { handler } = await getExecHandler();
    await expect(handler({ ...baseConn, command: "echo hi", env: { X: "; rm -rf /" } })).rejects.toThrow(
      /SSH_MCP_COMMAND_BLACKLIST/,
    );
    expect(execSpy).not.toHaveBeenCalled();
  });

  it("policy runs against finalCommand even with no env (baseline: ^ls allows plain ls)", async () => {
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls$");
    const { handler } = await getExecHandler();
    await expect(handler({ ...baseConn, command: "ls" })).resolves.toBeDefined();
    expect(recorder.command).toBe("ls");
  });
});
