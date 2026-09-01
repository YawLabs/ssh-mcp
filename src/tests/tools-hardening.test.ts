import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { find, multiExec, shellQuote } from "../ops.js";
import { enforcePolicy } from "../policy.js";
import { ConnectionPool } from "../pool.js";
import { registerTools } from "../tools.js";

// Regression coverage for a batch of tool-layer hardening fixes:
//
//   - ssh_write_file reported `content.length` (UTF-16 code units) as "bytes".
//   - ssh_multi_exec had no `env` parameter, so the two exec tools diverged.
//   - a whitelist rejection caused by the env prefix gave no hint that the prefix was why.
//   - command policy silently does NOT cover the mutating SFTP tools.
//   - ssh_mkdir's description claimed "Absolute path" while makeDir accepts relative.
//   - ssh_tail's empty-output message named a case ("does not exist") it cannot reach.
//   - find used the GNU-only `--` operand separator to defend leading-dash paths.
//
// Boundary: the REAL registered handlers run against the REAL shellQuote / enforcePolicy /
// zod schemas. Only the network is faked -- a ConnectionPool subclass that skips connecting,
// plus a module mock over ssh.js for the three functions that would touch SFTP or a channel.

type ToolHandler = (args: Record<string, unknown>) => Promise<{ content: { type: string; text: string }[] }>;
type ToolRegistration = { description: string; schema: Record<string, { description?: string }>; handler: ToolHandler };

/** Minimal fake McpServer that captures each registered tool's description, schema, and handler. */
function captureTools(): { server: { tool: (...args: unknown[]) => void }; tools: Map<string, ToolRegistration> } {
  const tools = new Map<string, ToolRegistration>();
  const server = {
    // registerTools calls server.tool(name, description, schema, handler).
    tool: (...args: unknown[]) => {
      tools.set(args[0] as string, {
        description: args[1] as string,
        schema: args[2] as Record<string, { description?: string }>,
        handler: args[args.length - 1] as ToolHandler,
      });
    },
  };
  return { server, tools };
}

/** ConnectionPool subclass that never touches the network. */
class RecordingPool extends ConnectionPool {
  override async withConnection<T>(_config: any, fn: (client: any) => Promise<T>): Promise<T> {
    return fn({});
  }
}

// exec() is what both ssh_exec and multiExec() ultimately call; writeFile()/makeDir() are the
// SFTP ops behind ssh_write_file / ssh_mkdir. Mock exactly those three and let everything
// else (shellQuote, enforcePolicy, the handler bodies, the zod schemas) run for real.
const { execSpy, writeFileSpy, makeDirSpy, recorder } = vi.hoisted(() => {
  const recorder: { commands: string[]; writes: { path: string; content: string }[]; mkdirs: string[] } = {
    commands: [],
    writes: [],
    mkdirs: [],
  };
  const execSpy = vi.fn(async (_client: unknown, command: string, ..._rest: unknown[]) => {
    recorder.commands.push(command);
    return { stdout: "out", stderr: "", code: 0 };
  });
  const writeFileSpy = vi.fn(async (_client: unknown, path: string, content: string) => {
    recorder.writes.push({ path, content });
  });
  const makeDirSpy = vi.fn(async (_client: unknown, path: string, ..._rest: unknown[]) => {
    recorder.mkdirs.push(path);
  });
  return { execSpy, writeFileSpy, makeDirSpy, recorder };
});

vi.mock("../ssh.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../ssh.js")>();
  return {
    ...actual,
    exec: execSpy as unknown as typeof actual.exec,
    writeFile: writeFileSpy as unknown as typeof actual.writeFile,
    makeDir: makeDirSpy as unknown as typeof actual.makeDir,
  };
});

function getTools(): Map<string, ToolRegistration> {
  const { server, tools } = captureTools();
  registerTools(server as any, new RecordingPool());
  return tools;
}

function getTool(name: string): ToolRegistration {
  const tool = getTools().get(name);
  if (!tool) throw new Error(`${name} was not registered`);
  return tool;
}

const baseConn = { host: "example.test" };

beforeEach(() => {
  recorder.commands = [];
  recorder.writes = [];
  recorder.mkdirs = [];
  execSpy.mockClear();
  writeFileSpy.mockClear();
  makeDirSpy.mockClear();
  vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "");
  vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "");
});
afterEach(() => {
  vi.unstubAllEnvs();
});

describe("ssh_write_file reports real byte length, not UTF-16 code units", () => {
  it("reports byte count for pure ASCII (where the two happen to agree)", async () => {
    const { handler } = getTool("ssh_write_file");
    const result = await handler({ ...baseConn, path: "/tmp/a.txt", content: "hello" });
    expect(result.content[0].text).toBe("Wrote 5 bytes to /tmp/a.txt");
  });

  it("reports UTF-8 bytes, not code units, for accented Latin", async () => {
    const { handler } = getTool("ssh_write_file");
    const content = "héllo"; // 5 code units, 6 UTF-8 bytes (é is 2 bytes)
    expect(content.length).toBe(5);
    const result = await handler({ ...baseConn, path: "/tmp/a.txt", content });
    expect(result.content[0].text).toBe("Wrote 6 bytes to /tmp/a.txt");
  });

  it("reports UTF-8 bytes for a 3-byte CJK character", async () => {
    const { handler } = getTool("ssh_write_file");
    const content = "日本語"; // 3 code units, 9 UTF-8 bytes
    expect(content.length).toBe(3);
    const result = await handler({ ...baseConn, path: "/tmp/a.txt", content });
    expect(result.content[0].text).toBe("Wrote 9 bytes to /tmp/a.txt");
  });

  it("reports UTF-8 bytes for an astral-plane emoji (surrogate pair)", async () => {
    const { handler } = getTool("ssh_write_file");
    const content = "🎉"; // 2 code units (surrogate pair), 4 UTF-8 bytes
    expect(content.length).toBe(2);
    const result = await handler({ ...baseConn, path: "/tmp/a.txt", content });
    expect(result.content[0].text).toBe("Wrote 4 bytes to /tmp/a.txt");
    // The count must match what Node would put on the wire, not the JS string length.
    expect(result.content[0].text).toContain(`${Buffer.byteLength(content, "utf8")} bytes`);
  });

  it("still writes the content through unchanged", async () => {
    const { handler } = getTool("ssh_write_file");
    await handler({ ...baseConn, path: "/tmp/a.txt", content: "héllo 🎉" });
    expect(recorder.writes).toEqual([{ path: "/tmp/a.txt", content: "héllo 🎉" }]);
  });
});

describe("ssh_multi_exec accepts env with the same semantics as ssh_exec", () => {
  it("declares an env parameter", () => {
    expect(getTool("ssh_multi_exec").schema.env).toBeDefined();
  });

  it("prefixes the command with KEY='value' and sends the SAME prefixed string to every host", async () => {
    const { handler } = getTool("ssh_multi_exec");
    await handler({ hosts: ["a.test", "b.test"], command: "printenv FOO", env: { FOO: "bar" } });
    expect(recorder.commands).toEqual(["FOO='bar' printenv FOO", "FOO='bar' printenv FOO"]);
  });

  it("single-quotes hostile values so they are inert (same primitive as ssh_exec)", async () => {
    const { handler } = getTool("ssh_multi_exec");
    const payload = "'; rm -rf / #";
    await handler({ hosts: ["a.test"], command: "id", env: { K: payload } });
    expect(recorder.commands[0]).toBe(`K=${shellQuote(payload)} id`);
    expect(recorder.commands[0]).toContain("'\\''");
  });

  it("joins multiple env vars with a single space, each independently quoted", async () => {
    const { handler } = getTool("ssh_multi_exec");
    await handler({ hosts: ["a.test"], command: "env", env: { A: "1", B: "two words" } });
    expect(recorder.commands[0]).toBe("A='1' B='two words' env");
  });

  it("passes the command through unchanged when env is omitted or empty", async () => {
    const { handler } = getTool("ssh_multi_exec");
    await handler({ hosts: ["a.test"], command: "uptime" });
    await handler({ hosts: ["a.test"], command: "uptime", env: {} });
    expect(recorder.commands).toEqual(["uptime", "uptime"]);
  });

  it("enforces policy against the env-PREFIXED command, before any host is contacted", async () => {
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls( .*)?$");
    const { handler } = getTool("ssh_multi_exec");
    await expect(handler({ hosts: ["a.test", "b.test"], command: "ls", env: { FOO: "x" } })).rejects.toThrow(
      /does not match any pattern in SSH_MCP_COMMAND_WHITELIST/,
    );
    // Fan-out never started -- the gate fired first.
    expect(execSpy).not.toHaveBeenCalled();
    expect(recorder.commands).toEqual([]);
  });

  it("the same whitelist allows the command when no env prefix is present", async () => {
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls( .*)?$");
    const { handler } = getTool("ssh_multi_exec");
    await expect(handler({ hosts: ["a.test"], command: "ls" })).resolves.toBeDefined();
    expect(recorder.commands).toEqual(["ls"]);
  });
});

/**
 * Pull the tolerant pattern the env-prefix rejection message suggests, straight out of the
 * real message. Tests assert against THIS rather than a hand-copied literal, so a change to
 * the suggestion can never leave the tests validating a pattern the operator is not given.
 */
function suggestedPattern(): string {
  vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls( .*)?$");
  let message = "";
  try {
    enforcePolicy("FOO='x' ls", { envPrefixApplied: true });
  } catch (e) {
    message = String(e);
  }
  const quoted = message.match(/e\.g\. `([^`]+)`/);
  if (!quoted) throw new Error(`rejection message carried no suggested pattern: ${message}`);
  return quoted[1];
}

describe("whitelist rejection explains the env-prefix footgun", () => {
  // The enforcement point is deliberate and pinned by exec-env-policy.test.ts. What changed
  // is only the DIAGNOSIS: the operator whose `^ls` whitelist just started rejecting `ls`
  // now gets told the env prefix is why.

  it("enforcePolicy adds the note when envPrefixApplied is set", () => {
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls");
    expect(() => enforcePolicy("FOO='x' ls", { envPrefixApplied: true })).toThrow(/`env` prefix was applied/);
    expect(() => enforcePolicy("FOO='x' ls", { envPrefixApplied: true })).toThrow(/PREFIXED command/);
  });

  it("enforcePolicy omits the note when no env prefix was applied", () => {
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls");
    expect(() => enforcePolicy("rm -rf /")).toThrow(/SSH_MCP_COMMAND_WHITELIST/);
    expect(() => enforcePolicy("rm -rf /")).not.toThrow(/`env` prefix was applied/);
    expect(() => enforcePolicy("rm -rf /", { envPrefixApplied: false })).not.toThrow(/`env` prefix was applied/);
  });

  it("keeps the original message and the configured-patterns list intact", () => {
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls,^df");
    expect(() => enforcePolicy("FOO='x' ls", { envPrefixApplied: true })).toThrow(
      /Command blocked: does not match any pattern in SSH_MCP_COMMAND_WHITELIST\. Configured patterns: \^ls, \^df/,
    );
  });

  it("the suggested tolerant pattern is TAIL-anchored (it must not admit ls-prefixed commands)", () => {
    // This message is the one place an operator sees this advice -- at the moment their
    // working whitelist starts failing -- so the pattern it hands them has to be safe to
    // paste. Without the trailing `( |$)` it is a prefix match: `^(...)*ls` also admits
    // `lsof -i` and `ls; <anything>`, silently converting a tight whitelist into one that
    // permits any command merely PREFIXED by `ls`. README.md documents the anchored form.
    const source = suggestedPattern();
    expect(source.endsWith("( |$)")).toBe(true);

    const suggested = new RegExp(source);
    // Still allows what it is meant to allow.
    expect(suggested.test("ls")).toBe(true);
    expect(suggested.test("ls -la")).toBe(true);
    expect(suggested.test("FOO='x' ls")).toBe(true);
    expect(suggested.test("FOO='x' BAR='y' ls -la")).toBe(true);
    // ...and rejects the two shapes an un-anchored version let through.
    expect(suggested.test("ls; rm -rf /")).toBe(false);
    expect(suggested.test("lsof -i")).toBe(false);
    expect(suggested.test("FOO='x' ls; rm -rf /")).toBe(false);
  });

  it("the suggested pattern really does gate enforcePolicy when configured verbatim", () => {
    // End-to-end: paste it into SSH_MCP_COMMAND_WHITELIST and the dangerous command is
    // blocked while the intended one passes.
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", suggestedPattern());
    expect(() => enforcePolicy("FOO='x' ls -la", { envPrefixApplied: true })).not.toThrow();
    expect(() => enforcePolicy("ls; rm -rf /")).toThrow(/SSH_MCP_COMMAND_WHITELIST/);
    expect(() => enforcePolicy("lsof -i")).toThrow(/SSH_MCP_COMMAND_WHITELIST/);
  });

  it("a blacklist rejection is unaffected by the flag", () => {
    vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "rm -rf");
    expect(() => enforcePolicy("FOO='x' rm -rf /", { envPrefixApplied: true })).toThrow(
      /Command blocked by SSH_MCP_COMMAND_BLACKLIST/,
    );
  });

  it("ssh_exec surfaces the note through the real handler", async () => {
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls( .*)?$");
    const { handler } = getTool("ssh_exec");
    await expect(handler({ ...baseConn, command: "ls", env: { FOO: "x" } })).rejects.toThrow(
      /`env` prefix was applied/,
    );
  });

  it("ssh_multi_exec surfaces the note through the real handler", async () => {
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls( .*)?$");
    const { handler } = getTool("ssh_multi_exec");
    await expect(handler({ hosts: ["a.test"], command: "ls", env: { FOO: "x" } })).rejects.toThrow(
      /`env` prefix was applied/,
    );
  });
});

describe("policy scope gap is documented on the tools it does not cover", () => {
  // SSH_MCP_COMMAND_BLACKLIST=^rm does not stop ssh_delete. That is a real limitation of
  // the design (policy is command-shaped; these tools build no command). It must at least
  // be visible to an admin reading the tool list.
  const MUTATING_SFTP_TOOLS = ["ssh_write_file", "ssh_upload", "ssh_mkdir", "ssh_delete"];

  it.each(MUTATING_SFTP_TOOLS)("%s says it is NOT gated by command policy", (name) => {
    const { description } = getTool(name);
    expect(description).toContain("NOT gated by SSH_MCP_COMMAND_WHITELIST / SSH_MCP_COMMAND_BLACKLIST");
    expect(description).toContain("ssh_exec and ssh_multi_exec");
  });

  it("the exec tools do NOT carry the exemption note (they are the gated ones)", () => {
    for (const name of ["ssh_exec", "ssh_multi_exec"]) {
      const { description } = getTool(name);
      expect(description).not.toContain("NOT gated by");
      expect(description).toContain("SSH_MCP_COMMAND_WHITELIST");
    }
  });

  it("ssh_delete really is unaffected by a ^rm blacklist (the gap the note describes)", async () => {
    vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "^rm");
    const { handler } = getTool("ssh_delete");
    // ssh_delete never calls enforcePolicy, so the blacklist cannot stop it. It gets all the
    // way into the SFTP layer and only fails there because the fake client has no sftp().
    // The point of the assertion is WHERE it fails: not at the policy gate.
    const error = await handler({ ...baseConn, path: "/tmp/victim" }).then(
      () => new Error("expected a rejection from the SFTP layer"),
      (e: unknown) => e,
    );
    expect(String(error)).not.toMatch(/SSH_MCP_COMMAND_BLACKLIST/);
    expect(String(error)).toMatch(/sftp/i);
  });
});

describe("ssh_mkdir description matches makeDir's actual relative-path support", () => {
  it("does not claim the path must be absolute", () => {
    const { description, schema } = getTool("ssh_mkdir");
    const pathDescription = schema.path.description ?? "";
    // The old text was "Absolute path of the directory to create", which contradicts both
    // makeDir (src/ssh.ts, walks segments and handles a CWD-relative path) and the comment
    // on AbsoluteRemotePathSchema that cites ssh_mkdir as the relative-path exception.
    expect(pathDescription).toMatch(/relative/i);
    expect(description).toMatch(/relative/i);
  });

  it("its schema actually accepts a relative path (the described behavior is the real one)", () => {
    const pathSchema = getTool("ssh_mkdir").schema.path as unknown as {
      safeParse: (v: unknown) => { success: boolean };
    };
    expect(pathSchema.safeParse("projects/new").success).toBe(true);
    expect(pathSchema.safeParse("/opt/projects/new").success).toBe(true);
  });

  it("passes a relative path straight through to makeDir", async () => {
    const { handler } = getTool("ssh_mkdir");
    const result = await handler({ ...baseConn, path: "projects/new", recursive: true });
    expect(recorder.mkdirs).toEqual(["projects/new"]);
    expect(result.content[0].text).toBe("Created directory projects/new");
  });

  it("the sibling SFTP tools DO still reject relative paths", () => {
    // Guards against the mkdir fix being over-applied to the shared AbsoluteRemotePathSchema.
    for (const name of ["ssh_write_file", "ssh_delete", "ssh_ls", "ssh_stat"]) {
      const pathSchema = getTool(name).schema.path as unknown as {
        safeParse: (v: unknown) => { success: boolean };
        description?: string;
      };
      expect(pathSchema.safeParse("projects/new").success).toBe(false);
      expect(pathSchema.description ?? "").toMatch(/[Aa]bsolute/);
    }
  });
});

describe("ssh_tail empty-output message only names reachable cases", () => {
  it("does not claim the file might not exist", async () => {
    execSpy.mockImplementationOnce(async () => ({ stdout: "", stderr: "", code: 0 }));
    const { handler } = getTool("ssh_tail");
    const result = await handler({ ...baseConn, path: "/var/log/empty.log" });
    // tail() (src/ops.ts) throws on any non-empty stderr, which is exactly what a missing
    // file produces -- so "does not exist" could never reach this branch.
    expect(result.content[0].text).not.toMatch(/does not exist/);
    expect(result.content[0].text).toMatch(/^File is empty/);
  });

  it("a missing file surfaces as a thrown stderr error, never as the empty-file message", async () => {
    execSpy.mockImplementationOnce(async () => ({
      stdout: "",
      stderr: "tail: cannot open '/nope' for reading: No such file or directory",
      code: 1,
    }));
    const { handler } = getTool("ssh_tail");
    await expect(handler({ ...baseConn, path: "/nope" })).rejects.toThrow(/No such file or directory/);
  });

  it("keeps the distinct no-grep-match message", async () => {
    execSpy.mockImplementationOnce(async () => ({ stdout: "", stderr: "", code: 1 }));
    const { handler } = getTool("ssh_tail");
    const result = await handler({ ...baseConn, path: "/var/log/app.log", grep: "nope", lines: 50 });
    expect(result.content[0].text).toBe('No lines matching "nope" in last 50 lines.');
  });
});

describe("find leading-dash defense is portable across find implementations", () => {
  // Capture the command string passed to client.exec (find() calls the real exec from
  // ssh.js, which is mocked above to record into recorder.commands).
  async function runFind(options: Parameters<typeof find>[1]): Promise<string> {
    await find({} as any, options);
    return recorder.commands[recorder.commands.length - 1];
  }

  it("`./`-prefixes a leading-dash path instead of using the GNU-only `--`", async () => {
    const cmd = await runFind({ path: "-rf" });
    expect(cmd).toMatch(/^find '\.\/-rf'/);
    // `--` is a GNU findutils extension. BSD/macOS find treats it as a literal path
    // operand, so emitting it would break the command against a BSD remote.
    expect(cmd).not.toContain("--");
  });

  it("leaves an ordinary absolute path untouched (no `./`, no `--`)", async () => {
    const cmd = await runFind({ path: "/var/log" });
    expect(cmd).toBe("find '/var/log'");
  });

  it("leaves an ordinary relative path untouched", async () => {
    const cmd = await runFind({ path: "logs/nginx" });
    expect(cmd).toBe("find 'logs/nginx'");
  });

  it("does not double-prefix a path that already starts with ./", async () => {
    const cmd = await runFind({ path: "./-rf" });
    expect(cmd).toBe("find './-rf'");
  });

  it("still emits the option flags after the rewritten path operand", async () => {
    const cmd = await runFind({ path: "-weird", name: "*.log", type: "f", maxdepth: 2 });
    expect(cmd).toBe("find './-weird' -maxdepth 2 -type f -name '*.log'");
  });

  it("keeps shell-injection quoting on the path (the rewrite does not replace shellQuote)", async () => {
    const cmd = await runFind({ path: "-rf; rm -rf /" });
    // Single-quoted as one operand: the `;` and `rm` are inert literal bytes.
    expect(cmd).toBe(`find ${shellQuote("./-rf; rm -rf /")}`);
    expect(cmd).toBe("find './-rf; rm -rf /'");
  });

  it("keeps shell-injection quoting on -name and -newer values", async () => {
    const cmd = await runFind({ path: "/tmp", name: "$(id)", newer: "'; reboot" });
    expect(cmd).toContain(`-name ${shellQuote("$(id)")}`);
    expect(cmd).toContain(`-newer ${shellQuote("'; reboot")}`);
    expect(cmd).toContain("'$(id)'");
  });

  it("size validation still rejects metacharacter payloads", async () => {
    await expect(find({} as any, { path: "/tmp", minsize: "1M; rm -rf /" })).rejects.toThrow("Invalid minsize format");
    await expect(find({} as any, { path: "/tmp", maxsize: "10M$(whoami)" })).rejects.toThrow("Invalid maxsize format");
  });
});

describe("env KEYS are validated, not just quoted (command injection via the key)", () => {
  // shellQuote protects the VALUE side of `KEY='value'`. The key cannot be quoted -- a shell
  // assignment prefix requires a bare name -- so before the fix a key was interpolated raw.
  // `{"A=1; reboot #": "x"}` emitted `A=1; reboot #='x' id`: the remote ran `reboot` and
  // swallowed the real command as a comment. applyEnvPrefix now rejects any key outside the
  // POSIX name grammar, and it throws BEFORE enforcePolicy, so a bad key never reaches a host.
  const KEY_INJECTION = "A=1; reboot #";

  it("zod does NOT reject the hostile key -- the runtime check is the only defense", () => {
    // z.record(z.string(), z.string()) accepts any string as a key, so the schema cannot be
    // what stops this. Pinned so nobody "simplifies" the runtime guard away later.
    const envSchema = getTool("ssh_exec").schema.env as unknown as {
      safeParse: (v: unknown) => { success: boolean };
    };
    expect(envSchema.safeParse({ [KEY_INJECTION]: "x" }).success).toBe(true);
  });

  it("ssh_exec rejects the key-injection payload and sends nothing", async () => {
    const { handler } = getTool("ssh_exec");
    await expect(handler({ ...baseConn, command: "id", env: { [KEY_INJECTION]: "x" } })).rejects.toThrow(
      /Invalid environment variable name/,
    );
    expect(execSpy).not.toHaveBeenCalled();
    expect(recorder.commands).toEqual([]);
  });

  it("ssh_multi_exec rejects the key-injection payload before contacting ANY host", async () => {
    const { handler } = getTool("ssh_multi_exec");
    await expect(
      handler({ hosts: ["a.test", "b.test"], command: "id", env: { [KEY_INJECTION]: "x" } }),
    ).rejects.toThrow(/Invalid environment variable name/);
    expect(execSpy).not.toHaveBeenCalled();
    expect(recorder.commands).toEqual([]);
  });

  it("the rejection fires even when the whitelist would have passed the command verb", async () => {
    // The policy-bypass half of the bug: `command: "ls"` matches an `ls` whitelist while the
    // key smuggles `reboot` past it. The key check runs before enforcePolicy, so this is
    // blocked by the key guard rather than reaching either the gate or the host.
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "ls");
    const { handler } = getTool("ssh_exec");
    await expect(handler({ ...baseConn, command: "ls", env: { [KEY_INJECTION]: "x" } })).rejects.toThrow(
      /Invalid environment variable name/,
    );
    expect(execSpy).not.toHaveBeenCalled();
  });

  const BAD_KEYS: [label: string, key: string][] = [
    ["a space", "FOO BAR"],
    ["a semicolon", "FOO;reboot"],
    ["a leading digit", "1FOO"],
    ["an empty name", ""],
  ];

  it.each(BAD_KEYS)("ssh_exec rejects a key with %s", async (_label, key) => {
    const { handler } = getTool("ssh_exec");
    await expect(handler({ ...baseConn, command: "id", env: { [key]: "x" } })).rejects.toThrow(
      /Invalid environment variable name/,
    );
    expect(execSpy).not.toHaveBeenCalled();
  });

  it.each(BAD_KEYS)("ssh_multi_exec rejects a key with %s", async (_label, key) => {
    const { handler } = getTool("ssh_multi_exec");
    await expect(handler({ hosts: ["a.test"], command: "id", env: { [key]: "x" } })).rejects.toThrow(
      /Invalid environment variable name/,
    );
    expect(execSpy).not.toHaveBeenCalled();
  });

  it("rejects the whole call rather than silently dropping the bad key", async () => {
    // Dropping it would leave the caller believing the variable was set. One bad key among
    // good ones fails the call; no partial prefix is emitted.
    const { handler } = getTool("ssh_exec");
    await expect(
      handler({ ...baseConn, command: "id", env: { GOOD: "1", "BAD KEY": "2", ALSO_GOOD: "3" } }),
    ).rejects.toThrow(/Invalid environment variable name/);
    expect(recorder.commands).toEqual([]);
  });

  it("names the offending key in the error so the caller can fix it", async () => {
    const { handler } = getTool("ssh_exec");
    await expect(handler({ ...baseConn, command: "id", env: { [KEY_INJECTION]: "x" } })).rejects.toThrow(
      /A=1; reboot #/,
    );
  });

  it("legitimate POSIX names (FOO, _BAR, A1) still work through ssh_exec", async () => {
    const { handler } = getTool("ssh_exec");
    await handler({ ...baseConn, command: "env", env: { FOO: "1", _BAR: "2", A1: "3" } });
    expect(recorder.commands).toEqual(["FOO='1' _BAR='2' A1='3' env"]);
  });

  it("legitimate POSIX names still work through ssh_multi_exec", async () => {
    const { handler } = getTool("ssh_multi_exec");
    await handler({ hosts: ["a.test"], command: "env", env: { FOO: "1", _BAR: "2", A1: "3" } });
    expect(recorder.commands).toEqual(["FOO='1' _BAR='2' A1='3' env"]);
  });

  it.each(["A", "_", "_A", "z9", "PATH_1", "__x__", "A0123456789"])("accepts the conforming key %s", async (key) => {
    const { handler } = getTool("ssh_exec");
    await handler({ ...baseConn, command: "id", env: { [key]: "v" } });
    expect(recorder.commands).toEqual([`${key}='v' id`]);
  });

  it("hostile VALUES are still merely quoted, not rejected (the key fix did not over-reach)", async () => {
    const { handler } = getTool("ssh_exec");
    const payload = "'; reboot #";
    await handler({ ...baseConn, command: "id", env: { SAFE_KEY: payload } });
    expect(recorder.commands).toEqual([`SAFE_KEY=${shellQuote(payload)} id`]);
  });
});

describe("the suggested tolerant pattern matches shellQuote's escaped-apostrophe form", () => {
  // The value group used to be `'[^']*'`, which cannot match an env value containing an
  // apostrophe: shellQuote closes, escapes, and reopens (`O'Brien` -> `'O'\''Brien'`), so the
  // suggested pattern blocked exactly the calls it claimed to allow -- and the resulting
  // rejection then re-suggested the same broken pattern. The group is now
  // `(?:'[^']*'|\\')+`, which walks the close-escape-reopen run.
  const APOSTROPHE_VALUE = "O'Brien";

  it("shellQuote really does emit the close-escape-reopen form (the premise)", () => {
    expect(shellQuote(APOSTROPHE_VALUE)).toBe("'O'\\''Brien'");
    // ...which contains a quote outside any `'...'` span, hence the old group's failure.
    expect(shellQuote(APOSTROPHE_VALUE)).toContain("'\\''");
  });

  it("the OLD narrow value group cannot match it (documents the bug being fixed)", () => {
    const old = /^([A-Za-z_][A-Za-z0-9_]*='[^']*' )*ls( |$)/;
    expect(old.test(`NAME=${shellQuote(APOSTROPHE_VALUE)} ls`)).toBe(false);
  });

  it("the suggested pattern matches an env prefix whose value contains an apostrophe", () => {
    const suggested = new RegExp(suggestedPattern());
    expect(suggested.test(`NAME=${shellQuote(APOSTROPHE_VALUE)} ls`)).toBe(true);
    expect(suggested.test(`NAME=${shellQuote(APOSTROPHE_VALUE)} ls -la`)).toBe(true);
    // Several apostrophes, and a mix of escaped and plain values.
    expect(suggested.test(`A=${shellQuote("a'b'c")} B=${shellQuote("plain")} ls -l`)).toBe(true);
  });

  it("widening the value group did NOT widen what commands are allowed", () => {
    const suggested = new RegExp(suggestedPattern());
    // The apostrophe form only ever tolerates the PREFIX; the command verb is still gated.
    expect(suggested.test(`NAME=${shellQuote(APOSTROPHE_VALUE)} reboot`)).toBe(false);
    expect(suggested.test(`NAME=${shellQuote(APOSTROPHE_VALUE)} ls; reboot`)).toBe(false);
    expect(suggested.test("lsof -i")).toBe(false);
  });

  it("the escape branch requires a real backslash -- a bare `'` alternative would be a bypass", () => {
    // Guard against "simplifying" the group to `(?:'[^']*'|')+`. That variant lets a value
    // smuggle the whitelisted verb: `ATTACK=' ls ' reboot` matches, because the lone-quote
    // branch can consume the opening quote and hand the rest of the value to the tail.
    const suggested = new RegExp(suggestedPattern());
    expect(suggested.test("ATTACK=' ls ' reboot")).toBe(false);
    const loneQuoteVariant = /^([A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|')+ )*ls( |$)/;
    expect(loneQuoteVariant.test("ATTACK=' ls ' reboot")).toBe(true); // the bypass, pinned
  });

  it("gates enforcePolicy end-to-end when the apostrophe-carrying call is made for real", async () => {
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", suggestedPattern());
    const { handler } = getTool("ssh_exec");
    // Previously this threw: the operator's whitelist rejected its own documented use case.
    await handler({ ...baseConn, command: "ls -la", env: { NAME: APOSTROPHE_VALUE } });
    expect(recorder.commands).toEqual([`NAME=${shellQuote(APOSTROPHE_VALUE)} ls -la`]);
  });
});

describe("command policy fails CLOSED when no pattern in a configured list compiles", () => {
  // The whole-list-malformed case used to fail OPEN: parsePatterns skipped every bad pattern,
  // the empty result read as "no policy configured", and an arbitrary command was allowed.
  // One typo in a single-pattern whitelist silently disabled the whitelist.
  let errSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    errSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
  });
  afterEach(() => {
    errSpy.mockRestore();
  });

  it("an all-malformed WHITELIST blocks instead of allowing", () => {
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "(unclosed");
    expect(() => enforcePolicy("cat /etc/shadow")).toThrow(/MISCONFIGURED/);
  });

  it("the error names the variable, the offending pattern, and that it is not in effect", () => {
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "(unclosed");
    expect(() => enforcePolicy("ls")).toThrow(/SSH_MCP_COMMAND_WHITELIST/);
    expect(() => enforcePolicy("ls")).toThrow(/NOT IN EFFECT/);
    expect(() => enforcePolicy("ls")).toThrow(/Malformed pattern\(s\): "\(unclosed"/);
    // An operator must be able to act on one read: it says the calls are refused until fixed.
    expect(() => enforcePolicy("ls")).toThrow(/until it is fixed/);
  });

  it("names EVERY offending pattern when several are malformed", () => {
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "(unclosed,[bad,*nope");
    expect(() => enforcePolicy("ls")).toThrow(/"\(unclosed", "\[bad", "\*nope"/);
  });

  it("an all-malformed BLACKLIST also fails closed (it silently protected nothing before)", () => {
    // Symmetric on purpose: a blacklist that compiles to nothing lets through exactly the
    // commands the operator believes are blocked, which is the same trust failure.
    vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "(unclosed");
    expect(() => enforcePolicy("rm -rf /")).toThrow(/MISCONFIGURED/);
    expect(() => enforcePolicy("rm -rf /")).toThrow(/SSH_MCP_COMMAND_BLACKLIST/);
    // Even an innocuous command is refused -- the point is that the gate cannot be evaluated.
    expect(() => enforcePolicy("uptime")).toThrow(/SSH_MCP_COMMAND_BLACKLIST/);
  });

  it("a misconfigured blacklist is reported even when the whitelist would have rejected first", () => {
    // Both lists are compiled before either is tested, so the operator gets the actionable
    // "your blacklist is broken" message rather than a plain whitelist rejection.
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls");
    vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "(unclosed");
    expect(() => enforcePolicy("reboot")).toThrow(/SSH_MCP_COMMAND_BLACKLIST/);
  });

  it("the whitelist's misconfiguration is reported first when both are broken", () => {
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "(unclosed");
    vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "[alsobad");
    expect(() => enforcePolicy("ls")).toThrow(/SSH_MCP_COMMAND_WHITELIST/);
  });

  it("a list that declares only separators fails closed too", () => {
    // `",,"` compiles zero patterns with zero errors. It is still a var the operator set,
    // and isPolicyConfigured() reports it as configured, so allowing everything would break
    // the same invariant by a different route.
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", ",,");
    expect(() => enforcePolicy("ls")).toThrow(/MISCONFIGURED/);
    expect(() => enforcePolicy("ls")).toThrow(/only separators/);
  });

  it("a whitespace-only value is still treated as unset, not as a misconfiguration", () => {
    // Matches isPolicyConfigured()'s own trim test -- it reports false here, so enforcement
    // must agree and allow through rather than block every call.
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "   ");
    expect(() => enforcePolicy("anything at all")).not.toThrow();
  });

  it("ONE malformed pattern among valid ones is still skipped, not fatal", () => {
    // The fix must not over-reach: a typo next to working patterns keeps the working ones.
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "(unclosed,^df");
    expect(() => enforcePolicy("df -h")).not.toThrow();
    expect(() => enforcePolicy("rm foo")).toThrow(/does not match any pattern/);
    expect(() => enforcePolicy("rm foo")).not.toThrow(/MISCONFIGURED/);
    expect(errSpy).toHaveBeenCalled();
  });

  it("still logs the skipped pattern to stderr (stdout is JSON-RPC)", () => {
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "(unclosed");
    expect(() => enforcePolicy("ls")).toThrow();
    expect(errSpy).toHaveBeenCalledWith(expect.stringContaining("(unclosed"));
  });

  it("ssh_exec refuses the call and contacts no host", async () => {
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "(unclosed");
    const { handler } = getTool("ssh_exec");
    await expect(handler({ ...baseConn, command: "ls" })).rejects.toThrow(/MISCONFIGURED/);
    expect(execSpy).not.toHaveBeenCalled();
  });

  it("ssh_multi_exec refuses before fan-out", async () => {
    vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "(unclosed");
    const { handler } = getTool("ssh_multi_exec");
    await expect(handler({ hosts: ["a.test", "b.test"], command: "uptime" })).rejects.toThrow(/MISCONFIGURED/);
    expect(execSpy).not.toHaveBeenCalled();
    expect(recorder.commands).toEqual([]);
  });

  it("a valid policy is unaffected", () => {
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls,^df");
    vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "shadow");
    expect(() => enforcePolicy("ls -la")).not.toThrow();
    expect(() => enforcePolicy("df -h")).not.toThrow();
    // Passes the whitelist (^ls) and is then caught by the blacklist. The command
    // has to clear the whitelist first: the checks run whitelist-then-blacklist, so
    // something failing BOTH reports the whitelist (pinned in policy.test.ts).
    expect(() => enforcePolicy("ls /etc/shadow")).toThrow(/SSH_MCP_COMMAND_BLACKLIST/);
    expect(() => enforcePolicy("reboot")).toThrow(/does not match any pattern/);
  });
});

describe("ssh_multi_exec surfaces the signal that killed a remote command", () => {
  // A signal-killed command comes back as `code: -1` -- the same sentinel exec() uses for
  // "channel closed with no exit code". ssh_exec prints `[signal: TERM]` to disambiguate;
  // ssh_multi_exec dropped it twice over (MultiExecResult had no field, the formatter had
  // no line), leaving a bare `[exit code: -1]`.
  it("prints [signal: ...] above the exit code", async () => {
    execSpy.mockImplementationOnce(async (_c: unknown, command: string) => {
      recorder.commands.push(command);
      return { stdout: "", stderr: "", code: -1, signal: "TERM" };
    });
    const { handler } = getTool("ssh_multi_exec");
    const result = await handler({ hosts: ["a.test"], command: "sleep 60" });
    const text = result.content[0].text;
    expect(text).toContain("[signal: TERM]");
    expect(text.indexOf("[signal: TERM]")).toBeLessThan(text.indexOf("[exit code: -1]"));
  });

  it("uses the same wording as ssh_exec for the same result", async () => {
    const killed = { stdout: "", stderr: "", code: -1, signal: "KILL" };
    execSpy.mockImplementationOnce(async () => killed);
    const single = await getTool("ssh_exec").handler({ ...baseConn, command: "sleep 60" });
    execSpy.mockImplementationOnce(async () => killed);
    const multi = await getTool("ssh_multi_exec").handler({ hosts: ["a.test"], command: "sleep 60" });
    for (const text of [single.content[0].text, multi.content[0].text]) {
      expect(text).toContain("[signal: KILL]");
      expect(text).toContain("[exit code: -1]");
    }
  });

  it("omits the line entirely on a normal exit", async () => {
    const { handler } = getTool("ssh_multi_exec");
    const result = await handler({ hosts: ["a.test"], command: "true" });
    expect(result.content[0].text).not.toContain("[signal:");
    expect(result.content[0].text).toContain("[exit code: 0]");
  });

  it("reports per host, not once for the batch", async () => {
    execSpy
      .mockImplementationOnce(async () => ({ stdout: "fine", stderr: "", code: 0 }))
      .mockImplementationOnce(async () => ({ stdout: "", stderr: "", code: -1, signal: "TERM" }));
    const { handler } = getTool("ssh_multi_exec");
    const text = (await handler({ hosts: ["ok.test", "killed.test"] as string[], command: "sleep 60" })).content[0]
      .text;
    const okBlock = text.slice(text.indexOf("--- ok.test ---"), text.indexOf("--- killed.test ---"));
    const killedBlock = text.slice(text.indexOf("--- killed.test ---"));
    expect(okBlock).not.toContain("[signal:");
    expect(killedBlock).toContain("[signal: TERM]");
  });

  it("multiExec itself carries signal through to MultiExecResult", async () => {
    execSpy.mockImplementationOnce(async () => ({ stdout: "", stderr: "", code: -1, signal: "TERM" }));
    const results = await multiExec(new RecordingPool(), [{ host: "a.test" }], "sleep 60");
    expect(results[0].signal).toBe("TERM");
    expect(results[0].code).toBe(-1);
  });

  it("leaves signal undefined when the remote exited normally", async () => {
    const results = await multiExec(new RecordingPool(), [{ host: "a.test" }], "true");
    expect(results[0].signal).toBeUndefined();
  });

  it("a connection-level failure still renders as [ERROR], with no signal line", async () => {
    class FailingPool extends RecordingPool {
      override async withConnection<T>(): Promise<T> {
        throw new Error("connect ECONNREFUSED");
      }
    }
    const { server, tools } = captureTools();
    registerTools(server as any, new FailingPool());
    const text = (await tools.get("ssh_multi_exec")!.handler({ hosts: ["down.test"], command: "uptime" })).content[0]
      .text;
    expect(text).toContain("[ERROR] connect ECONNREFUSED");
    expect(text).not.toContain("[signal:");
  });
});

describe("the env-prefix docs describe the key check, not just value quoting", () => {
  // The prior pass left two comments asserting the opposite ("so any byte sequence is safe"),
  // which is true of values and was false of keys. The agent-facing schema description is the
  // one an LLM caller actually reads, so it has to state the key grammar.
  it("the shared EnvSchema description states the key grammar on both exec tools", () => {
    for (const name of ["ssh_exec", "ssh_multi_exec"]) {
      const description = (getTool(name).schema.env as { description?: string }).description ?? "";
      expect(description).toMatch(/\[A-Za-z_\]\[A-Za-z0-9_\]\*/);
      expect(description).toMatch(/VALUES are POSIX-single-quoted/);
      expect(description).toMatch(/rejected/i);
    }
  });
});

// ---------------------------------------------------------------------------
// Branches v8 coverage showed were never executed. Small, but each is a line an
// operator actually reads, and none had a single test through the handler.
// ---------------------------------------------------------------------------

describe("ssh_exec renders a stderr block when the remote wrote to stderr", () => {
  it("labels stderr rather than blending it into stdout", async () => {
    // A command that writes to BOTH streams is the normal shape of a partial
    // failure; without the label the agent cannot tell which half is which.
    execSpy.mockImplementationOnce(async () => ({
      stdout: "some output",
      stderr: "warning: deprecated flag",
      code: 0,
    }));
    const { handler } = getTool("ssh_exec");
    const result = (await handler({ ...baseConn, command: "build" })) as { content: { text: string }[] };

    expect(result.content[0].text).toBe("some output\n[stderr]\nwarning: deprecated flag\n[exit code: 0]");
  });

  it("omits the stderr block entirely when stderr is empty", async () => {
    execSpy.mockImplementationOnce(async () => ({ stdout: "clean", stderr: "", code: 0 }));
    const { handler } = getTool("ssh_exec");
    const result = (await handler({ ...baseConn, command: "build" })) as { content: { text: string }[] };

    expect(result.content[0].text).not.toContain("[stderr]");
  });
});

describe("ssh_mkdir defaults `recursive` to false rather than passing undefined", () => {
  it("passes false through to makeDir when the caller omits it", async () => {
    // makeDir's own default is `false` too, but the handler's `?? false` is what
    // stops `undefined` reaching it -- and undefined is what an MCP caller sends
    // when it omits an optional field.
    makeDirSpy.mockClear();
    const { handler } = getTool("ssh_mkdir");
    await handler({ ...baseConn, path: "/tmp/new" });

    expect(makeDirSpy).toHaveBeenCalledWith(expect.anything(), "/tmp/new", false);
  });

  it("passes an explicit true straight through", async () => {
    makeDirSpy.mockClear();
    const { handler } = getTool("ssh_mkdir");
    await handler({ ...baseConn, path: "/tmp/a/b/c", recursive: true });

    expect(makeDirSpy).toHaveBeenCalledWith(expect.anything(), "/tmp/a/b/c", true);
  });
});
