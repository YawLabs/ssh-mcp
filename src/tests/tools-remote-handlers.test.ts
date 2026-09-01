import { beforeEach, describe, expect, it, vi } from "vitest";
import type { FindOptions, ServiceStatus } from "../ops.js";
import { ConnectionPool } from "../pool.js";
import type { FileStats } from "../ssh.js";
import { registerTools } from "../tools.js";

// Handler-layer coverage for the remote/SFTP tools. The underlying functions (find,
// serviceStatus, statFile, listDir, ...) are covered by ops.test.ts / the ssh tests; what is
// exercised here is the code BETWEEN them and the MCP client -- the text formatting, the
// omit-when-absent branches, the isError flag, and the `timeout || 30000` defaulting.
//
// Boundary: the REAL registered handlers run. Only the two module boundaries that would touch
// a network or a real ~/.ssh are faked -- ../ops.js (find, serviceStatus) and ../ssh.js (the
// SFTP ops) -- plus a ConnectionPool subclass whose withConnection hands over a dummy client.
// Everything else (zod schema construction, the handler bodies) is the shipped code.
//
// Every assertion below was written against OBSERVED output from these handlers, not against
// what the formatting arguably should be.
//
// ssh_ls used to render an empty directory as an empty text block -- indistinguishable to a
// caller from a read that produced nothing. It now says so, the way ssh_find does; that is
// asserted below rather than pinned as a defect.
//
// One defect remains pinned as-is because it cannot be fixed from tools.ts: ssh_stat's
// "symlink" kind label is UNREACHABLE in production. statFile (src/ssh.ts) calls SFTP
// `stat`, which follows symlinks, so isSymbolicLink is always false -- a link to a directory
// renders "directory" and a dangling one rejects ENOENT before any formatting happens. The
// fix is an lstat in ssh.ts (deleteFile already uses one for exactly this distinction); the
// tests below drive statFile through a mock, so they exercise the label but cannot prove it
// is reachable.

type ToolResult = { content: { type: string; text: string }[]; isError?: boolean };
type ToolHandler = (args: Record<string, unknown>) => Promise<ToolResult>;
type ToolRegistration = { description: string; schema: Record<string, unknown>; handler: ToolHandler };

const {
  findSpy,
  multiExecSpy,
  serviceStatusSpy,
  statFileSpy,
  listDirSpy,
  readFileSpy,
  downloadFileSpy,
  uploadFileSpy,
  writeFileSpy,
} = vi.hoisted(() => ({
  findSpy: vi.fn(),
  multiExecSpy: vi.fn(),
  serviceStatusSpy: vi.fn(),
  statFileSpy: vi.fn(),
  listDirSpy: vi.fn(),
  readFileSpy: vi.fn(),
  downloadFileSpy: vi.fn(),
  uploadFileSpy: vi.fn(),
  writeFileSpy: vi.fn(),
}));

vi.mock("../ops.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../ops.js")>();
  return {
    ...actual,
    find: findSpy as unknown as typeof actual.find,
    multiExec: multiExecSpy as unknown as typeof actual.multiExec,
    serviceStatus: serviceStatusSpy as unknown as typeof actual.serviceStatus,
  };
});

vi.mock("../ssh.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../ssh.js")>();
  return {
    ...actual,
    statFile: statFileSpy as unknown as typeof actual.statFile,
    listDir: listDirSpy as unknown as typeof actual.listDir,
    readFile: readFileSpy as unknown as typeof actual.readFile,
    downloadFile: downloadFileSpy as unknown as typeof actual.downloadFile,
    uploadFile: uploadFileSpy as unknown as typeof actual.uploadFile,
    writeFile: writeFileSpy as unknown as typeof actual.writeFile,
  };
});

/** Every config object the handlers hand to withConnection, in call order. */
const seenConnections: unknown[] = [];

/** ConnectionPool subclass that never touches the network, and records the resolved config. */
class RecordingPool extends ConnectionPool {
  override async withConnection<T>(config: any, fn: (client: any) => Promise<T>): Promise<T> {
    seenConnections.push(config);
    return fn({});
  }
}

/** Minimal fake McpServer that captures each registered tool's description, schema, and handler. */
function getTools(): Map<string, ToolRegistration> {
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
  registerTools(server as never, new RecordingPool());
  return tools;
}

function getTool(name: string): ToolRegistration {
  const tool = getTools().get(name);
  if (!tool) throw new Error(`${name} was not registered`);
  return tool;
}

function call(name: string, args: Record<string, unknown>): Promise<ToolResult> {
  return getTool(name).handler(args);
}

/** Text of a single-content-block tool result. */
function textOf(result: ToolResult): string {
  expect(result.content).toHaveLength(1);
  expect(result.content[0].type).toBe("text");
  return result.content[0].text;
}

function lastCall(spy: { mock: { calls: unknown[][] } }): unknown[] {
  const c = spy.mock.calls.at(-1);
  if (!c) throw new Error("the mocked callee was never invoked");
  return c;
}

/** find(client, options, timeoutMs) -- the two arguments the handler is responsible for. */
function lastFindCall(): { options: FindOptions; timeoutMs: unknown } {
  const c = lastCall(findSpy);
  return { options: c[1] as FindOptions, timeoutMs: c[2] };
}

/** serviceStatus(client, serviceName, timeoutMs). */
function lastServiceCall(): { service: unknown; timeoutMs: unknown } {
  const c = lastCall(serviceStatusSpy);
  return { service: c[1], timeoutMs: c[2] };
}

const HOST = { host: "example.test" };

/** A complete FileStats, copied field-for-field from the interface in src/ssh.ts. */
function stats(overrides: Partial<FileStats> = {}): FileStats {
  return {
    size: 4096,
    mode: 16877,
    modeOctal: "0755",
    uid: 1000,
    gid: 100,
    // Epoch SECONDS, which is what statFile stores and what the handler multiplies by 1000.
    mtime: 1700000000, // 2023-11-14T22:13:20.000Z
    atime: 1700003600, // 2023-11-14T23:13:20.000Z (one hour later -- catches a swapped pair)
    isFile: false,
    isDirectory: false,
    isSymbolicLink: false,
    ...overrides,
  };
}

/** A complete ServiceStatus, copied field-for-field from the interface in src/ops.ts. */
function service(overrides: Partial<ServiceStatus> = {}): ServiceStatus {
  return {
    name: "nginx",
    active: true,
    status: "active (running)",
    raw: "* nginx.service - A high performance web server",
    unknown: false,
    ...overrides,
  };
}

beforeEach(() => {
  seenConnections.length = 0;
  for (const spy of [
    findSpy,
    multiExecSpy,
    serviceStatusSpy,
    statFileSpy,
    listDirSpy,
    readFileSpy,
    downloadFileSpy,
    uploadFileSpy,
    writeFileSpy,
  ]) {
    spy.mockReset();
  }
  writeFileSpy.mockResolvedValue(undefined);
  uploadFileSpy.mockResolvedValue(undefined);
  downloadFileSpy.mockResolvedValue(undefined);
});

describe("ssh_find handler formatting", () => {
  it("renders the empty result set as 'No files found.' and nothing else", async () => {
    findSpy.mockResolvedValue([]);
    const result = await call("ssh_find", { ...HOST, path: "/var/log" });
    expect(textOf(result)).toBe("No files found.");
  });

  it("does NOT flag an empty result set as an error", async () => {
    // "nothing matched" is a legitimate answer to a search, not a failure. The handler omits
    // isError entirely on both branches -- pinned so a later "helpful" isError: true here
    // cannot start reporting empty searches as tool errors to the agent.
    findSpy.mockResolvedValue([]);
    const result = await call("ssh_find", { ...HOST, path: "/var/log" });
    expect("isError" in result).toBe(false);
  });

  it("renders a populated result set as a count header plus one path per line", async () => {
    findSpy.mockResolvedValue(["/var/log/a.log", "/var/log/b.log"]);
    const result = await call("ssh_find", { ...HOST, path: "/var/log" });
    expect(textOf(result)).toBe("Found 2 result(s):\n/var/log/a.log\n/var/log/b.log");
  });

  it("counts the matches, not the characters or the lines of the joined blob", async () => {
    findSpy.mockResolvedValue(["/a", "/b", "/c", "/d", "/e"]);
    expect(textOf(await call("ssh_find", { ...HOST, path: "/" }))).toMatch(/^Found 5 result\(s\):\n/);
  });

  it("uses the literal 'result(s)' even for a single match (no pluralization branch exists)", async () => {
    findSpy.mockResolvedValue(["/var/log/only.log"]);
    expect(textOf(await call("ssh_find", { ...HOST, path: "/var/log" }))).toBe("Found 1 result(s):\n/var/log/only.log");
  });

  it("preserves the order find returned and does not sort or dedupe", async () => {
    findSpy.mockResolvedValue(["/z", "/a", "/z"]);
    expect(textOf(await call("ssh_find", { ...HOST, path: "/" }))).toBe("Found 3 result(s):\n/z\n/a\n/z");
  });

  it("propagates a rejection from find (e.g. an invalid size) instead of swallowing it", async () => {
    findSpy.mockRejectedValue(new Error('Invalid minsize format: "1M; rm -rf /"'));
    await expect(call("ssh_find", { ...HOST, path: "/tmp", minsize: "1M; rm -rf /" })).rejects.toThrow(
      /Invalid minsize format/,
    );
  });
});

describe("ssh_find threads every typed parameter into find()", () => {
  // find()'s own command construction is covered by ops.test.ts. What is tested here is only
  // that the handler hands each declared parameter DOWN -- a dropped one would silently
  // broaden the search (no -name, no -maxdepth) with no error anywhere.
  it("passes all seven search parameters through in one call", async () => {
    findSpy.mockResolvedValue([]);
    await call("ssh_find", {
      ...HOST,
      path: "/var/log",
      name: "*.log",
      type: "f",
      maxdepth: 3,
      minsize: "1M",
      maxsize: "10M",
      newer: "/etc/passwd",
    });
    expect(lastFindCall().options).toEqual({
      path: "/var/log",
      name: "*.log",
      type: "f",
      maxdepth: 3,
      minsize: "1M",
      maxsize: "10M",
      newer: "/etc/passwd",
    });
  });

  const SOLO_PARAMS: [key: keyof FindOptions, value: unknown][] = [
    ["name", "*.conf"],
    ["type", "d"],
    ["maxdepth", 2],
    ["minsize", "100k"],
    ["maxsize", "500k"],
    ["newer", "/tmp/marker"],
  ];

  it.each(SOLO_PARAMS)("threads %s through on its own", async (key, value) => {
    findSpy.mockResolvedValue([]);
    await call("ssh_find", { ...HOST, path: "/srv", [key]: value });
    expect(lastFindCall().options[key]).toEqual(value);
  });

  it("threads maxdepth: 0 -- a truthiness check would silently drop it", async () => {
    // `-maxdepth 0` means "test the named path only" and is a real query. find() itself
    // guards with `!== undefined`; this pins that the handler does not filter it out first.
    findSpy.mockResolvedValue([]);
    await call("ssh_find", { ...HOST, path: "/srv", maxdepth: 0 });
    expect(lastFindCall().options.maxdepth).toBe(0);
  });

  it("declares the option keys even when the caller omitted them (undefined, not absent)", async () => {
    findSpy.mockResolvedValue([]);
    await call("ssh_find", { ...HOST, path: "/srv" });
    expect(Object.keys(lastFindCall().options)).toEqual([
      "path",
      "name",
      "type",
      "maxdepth",
      "minsize",
      "maxsize",
      "newer",
    ]);
    expect(lastFindCall().options.name).toBeUndefined();
  });

  it("keeps the search parameters OUT of the connection config", async () => {
    // They are destructured off before the rest spread, so a stray `name` can never end up
    // in the pool key or be handed to ssh2 as a connect option.
    findSpy.mockResolvedValue([]);
    await call("ssh_find", {
      host: "h.test",
      port: 2222,
      username: "u",
      privateKeyPath: "/k",
      password: "p",
      path: "/x",
      name: "*.log",
      timeout: 999,
    });
    expect(seenConnections[0]).toEqual({
      host: "h.test",
      port: 2222,
      username: "u",
      privateKeyPath: "/k",
      password: "p",
    });
  });
});

describe("ssh_service_status rendering", () => {
  it("renders every line, in order, with the raw block after a blank separator", async () => {
    serviceStatusSpy.mockResolvedValue(
      service({
        name: "nginx",
        status: "active (running)",
        description: "A high performance web server",
        pid: 1234,
        since: "Mon 2024-01-01 10:00:00 UTC",
        raw: "* nginx.service - A high performance web server\n   Active: active (running)",
      }),
    );
    const text = textOf(await call("ssh_service_status", { ...HOST, service: "nginx" }));
    expect(text).toBe(
      [
        "Service: nginx",
        "Status: active (running)",
        "Description: A high performance web server",
        "PID: 1234",
        "Since: Mon 2024-01-01 10:00:00 UTC",
        "",
        "* nginx.service - A high performance web server\n   Active: active (running)",
      ].join("\n"),
    );
  });

  it("omits Description, PID and Since when the parse did not find them", async () => {
    serviceStatusSpy.mockResolvedValue(
      service({ name: "nginx", active: false, status: "inactive (dead)", raw: "inactive raw" }),
    );
    const text = textOf(await call("ssh_service_status", { ...HOST, service: "nginx" }));
    expect(text).toBe("Service: nginx\nStatus: inactive (dead)\n\ninactive raw");
    expect(text).not.toContain("Description:");
    expect(text).not.toContain("PID:");
    expect(text).not.toContain("Since:");
  });

  const FALSY_FIELDS: [label: string, absentLabel: string, overrides: Partial<ServiceStatus>][] = [
    ["an empty description", "Description:", { description: "" }],
    ["an empty since", "Since:", { since: "" }],
    ["a zero pid", "PID:", { pid: 0 }],
  ];

  it.each(FALSY_FIELDS)("omits the line for %s (pinned actual behavior)", async (_label, absentLabel, overrides) => {
    // The guards are truthiness checks (`if (status.pid)`), so an empty-string description
    // and a numeric pid of 0 render as absent rather than as an empty label. Pinned as the
    // behavior that ships; none of these values is producible by the real systemctl parse.
    serviceStatusSpy.mockResolvedValue(service(overrides));
    expect(textOf(await call("ssh_service_status", { ...HOST, service: "nginx" }))).not.toContain(absentLabel);
  });

  it("appends the raw systemctl block verbatim, multi-line and untrimmed", async () => {
    // Padded on BOTH ends deliberately: an unpadded fixture cannot observe a
    // regression to raw.trim() / raw.trimEnd(), since both are no-ops on it.
    const raw = "\n  Active: active (running)\n\nline four\n  ";
    serviceStatusSpy.mockResolvedValue(service({ raw }));
    expect(textOf(await call("ssh_service_status", { ...HOST, service: "nginx" })).endsWith(`\n\n${raw}`)).toBe(true);
  });

  it("uses the name from the parsed status, not the caller's argument", async () => {
    serviceStatusSpy.mockResolvedValue(service({ name: "nginx.service" }));
    const text = textOf(await call("ssh_service_status", { ...HOST, service: "nginx" }));
    expect(text.startsWith("Service: nginx.service\n")).toBe(true);
  });
});

describe("ssh_service_status isError is driven by `unknown`, never by the service being stopped", () => {
  // This is the whole point of the ServiceStatus.unknown flag. "Stopped" is a legitimate
  // answer to "is this running?"; only "systemctl could not report on this unit at all"
  // (typo'd name, missing unit file, systemd unreachable) is a tool error.
  it("a stopped-but-present service is NOT an error", async () => {
    serviceStatusSpy.mockResolvedValue(
      service({
        active: false,
        status: "inactive (dead)",
        description: "A high performance web server",
        raw: "   Active: inactive (dead)",
        unknown: false,
      }),
    );
    const result = await call("ssh_service_status", { ...HOST, service: "nginx" });
    expect(result.isError).toBe(false);
    // ...and the caller still gets the full answer, not an error string.
    expect(textOf(result)).toContain("Status: inactive (dead)");
  });

  it("a failed-but-present service is NOT an error either", async () => {
    serviceStatusSpy.mockResolvedValue(
      service({ active: false, status: "failed (Result: exit-code)", unknown: false }),
    );
    expect((await call("ssh_service_status", { ...HOST, service: "nginx" })).isError).toBe(false);
  });

  it("a missing unit IS an error", async () => {
    serviceStatusSpy.mockResolvedValue(
      service({
        name: "nope",
        active: false,
        status: "inactive",
        raw: "Unit nope.service could not be found.",
        unknown: true,
      }),
    );
    const result = await call("ssh_service_status", { ...HOST, service: "nope" });
    expect(result.isError).toBe(true);
    // The rendered body is unchanged by the flag -- the raw systemctl text still comes back.
    expect(textOf(result)).toContain("Unit nope.service could not be found.");
  });

  it("`active` alone does not decide the flag, in either direction", async () => {
    // active=false + unknown=false -> not an error (the stopped case above), and the
    // converse: whatever `active` says, unknown=true is still an error.
    serviceStatusSpy.mockResolvedValue(service({ active: true, unknown: true }));
    expect((await call("ssh_service_status", { ...HOST, service: "x" })).isError).toBe(true);
    serviceStatusSpy.mockResolvedValue(service({ active: false, unknown: false }));
    expect((await call("ssh_service_status", { ...HOST, service: "x" })).isError).toBe(false);
  });

  it("always emits an explicit boolean, never an omitted isError", async () => {
    serviceStatusSpy.mockResolvedValue(service());
    const result = await call("ssh_service_status", { ...HOST, service: "nginx" });
    expect("isError" in result).toBe(true);
    expect(typeof result.isError).toBe("boolean");
  });

  it("keeps the service name and timeout out of the connection config", async () => {
    serviceStatusSpy.mockResolvedValue(service());
    await call("ssh_service_status", { host: "h.test", port: 22, service: "nginx", timeout: 5000 });
    expect(seenConnections[0]).toEqual({ host: "h.test", port: 22 });
  });
});

describe("ssh_stat kind label", () => {
  const cases: [label: string, flags: Partial<FileStats>, kind: string][] = [
    ["a directory", { isDirectory: true }, "directory"],
    ["a symlink", { isSymbolicLink: true }, "symlink"],
    ["a plain file", { isFile: true }, "file"],
    ["none of the three (socket, fifo, device)", {}, "other"],
  ];

  it.each(cases)("labels %s as %s", async (_label, flags, kind) => {
    statFileSpy.mockResolvedValue(stats(flags));
    const text = textOf(await call("ssh_stat", { ...HOST, path: "/p" }));
    expect(text.split("\n")[0]).toBe(`/p: ${kind}`);
  });

  it("resolves the ternary directory-first when several flags are set", async () => {
    // This is the shape a symlink-to-a-directory would arrive in IF statFile ever reported
    // the link itself. It cannot today: the real statFile (src/ssh.ts) calls SFTP `stat`,
    // which FOLLOWS symlinks, so isSymbolicLink is always false and such a link arrives as
    // a plain isDirectory=true. Pinned so that whichever way statFile is later fixed, the
    // label precedence here is a deliberate choice rather than an accident. Fixing the
    // unreachability itself needs an lstat in ssh.ts -- see the header note.
    statFileSpy.mockResolvedValue(stats({ isDirectory: true, isSymbolicLink: true, isFile: true }));
    expect(textOf(await call("ssh_stat", { ...HOST, path: "/p" }))).toContain("/p: directory");
  });

  it("prefers symlink over file when both are set", async () => {
    statFileSpy.mockResolvedValue(stats({ isSymbolicLink: true, isFile: true }));
    expect(textOf(await call("ssh_stat", { ...HOST, path: "/p" }))).toContain("/p: symlink");
  });

  it("the flags themselves are never printed -- only the single derived kind word", async () => {
    // The tool description advertises "type flags (isFile, isDirectory, isSymbolicLink)";
    // what the handler actually emits is one kind label per path. Pinned so the description
    // and the output can be compared against each other.
    statFileSpy.mockResolvedValue(stats({ isFile: true }));
    const text = textOf(await call("ssh_stat", { ...HOST, path: "/p" }));
    expect(text).not.toContain("isFile");
    expect(text).not.toContain("isSymbolicLink");
  });

  it("echoes the requested path in the header, not a resolved one", async () => {
    statFileSpy.mockResolvedValue(stats({ isFile: true }));
    const text = textOf(await call("ssh_stat", { ...HOST, path: "/very/deep/path.txt" }));
    expect(text.startsWith("/very/deep/path.txt: file\n")).toBe(true);
  });
});

describe("ssh_stat metadata block", () => {
  it("renders the whole block, with mtime/atime as ISO strings from epoch SECONDS", async () => {
    statFileSpy.mockResolvedValue(stats({ isFile: true, size: 1234, modeOctal: "0644", uid: 1000, gid: 100 }));
    expect(textOf(await call("ssh_stat", { ...HOST, path: "/etc/hosts" }))).toBe(
      [
        "/etc/hosts: file",
        "  Size: 1234 bytes",
        "  Mode: 0644",
        "  Owner: uid=1000 gid=100",
        "  Modified: 2023-11-14T22:13:20.000Z",
        "  Accessed: 2023-11-14T23:13:20.000Z",
      ].join("\n"),
    );
  });

  it("multiplies by 1000 -- an unscaled epoch would land in 1970", async () => {
    statFileSpy.mockResolvedValue(stats({ isFile: true, mtime: 1700000000, atime: 1700000000 }));
    const text = textOf(await call("ssh_stat", { ...HOST, path: "/f" }));
    expect(text).toContain("Modified: 2023-11-14T22:13:20.000Z");
    expect(text).not.toContain("1970-");
  });

  it("does not swap Modified and Accessed", async () => {
    statFileSpy.mockResolvedValue(stats({ isFile: true, mtime: 0, atime: 86400 }));
    const text = textOf(await call("ssh_stat", { ...HOST, path: "/f" }));
    expect(text).toContain("Modified: 1970-01-01T00:00:00.000Z");
    expect(text).toContain("Accessed: 1970-01-02T00:00:00.000Z");
  });

  it("prints modeOctal verbatim, not the decimal mode", async () => {
    statFileSpy.mockResolvedValue(stats({ isDirectory: true, mode: 16877, modeOctal: "0755" }));
    const text = textOf(await call("ssh_stat", { ...HOST, path: "/d" }));
    expect(text).toContain("  Mode: 0755");
    expect(text).not.toContain("16877");
  });

  it("prints size in bytes with the unit spelled out", async () => {
    statFileSpy.mockResolvedValue(stats({ isFile: true, size: 0 }));
    expect(textOf(await call("ssh_stat", { ...HOST, path: "/f" }))).toContain("  Size: 0 bytes");
  });

  it("calls statFile with just the client and the path (no timeout argument exists)", async () => {
    statFileSpy.mockResolvedValue(stats({ isFile: true }));
    await call("ssh_stat", { ...HOST, path: "/f" });
    expect(lastCall(statFileSpy)).toHaveLength(2);
    expect(lastCall(statFileSpy)[1]).toBe("/f");
  });
});

describe("ssh_ls rendering", () => {
  it("joins the entries with newlines, in the order SFTP returned them", async () => {
    listDirSpy.mockResolvedValue(["b.txt", "a.txt", ".hidden"]);
    expect(textOf(await call("ssh_ls", { ...HOST, path: "/srv" }))).toBe("b.txt\na.txt\n.hidden");
  });

  it("renders a single entry with no trailing newline", async () => {
    listDirSpy.mockResolvedValue(["only.txt"]);
    expect(textOf(await call("ssh_ls", { ...HOST, path: "/srv" }))).toBe("only.txt");
  });

  it("says an EMPTY directory is empty, and names it, instead of returning a blank block", async () => {
    // An empty join() is an empty text block, which a caller cannot tell apart from a read
    // that produced nothing at all. ssh_find already says "No files found." for the same
    // situation; this is the ssh_ls counterpart.
    listDirSpy.mockResolvedValue([]);
    const result = await call("ssh_ls", { ...HOST, path: "/empty" });
    expect(textOf(result)).toBe("Directory is empty: /empty");
    expect(textOf(result)).not.toBe("");
  });

  it("an empty directory is NOT an error -- no isError key at all, same as ssh_find", async () => {
    // "Nothing in here" is a legitimate answer to a listing, not a failure. Both ssh_ls
    // branches omit the flag entirely, which is what ssh_find does for its empty result.
    listDirSpy.mockResolvedValue([]);
    const empty = await call("ssh_ls", { ...HOST, path: "/empty" });
    listDirSpy.mockResolvedValue(["a.txt"]);
    const populated = await call("ssh_ls", { ...HOST, path: "/srv" });
    for (const result of [empty, populated]) {
      expect(Object.keys(result)).toEqual(["content"]);
      expect("isError" in result).toBe(false);
    }
  });

  it("the empty message names the REQUESTED path, so two listings cannot be confused", async () => {
    listDirSpy.mockResolvedValue([]);
    expect(textOf(await call("ssh_ls", { ...HOST, path: "/var/spool/nothing" }))).toBe(
      "Directory is empty: /var/spool/nothing",
    );
  });

  it("a directory holding one EMPTY-STRING entry is not mistaken for an empty directory", async () => {
    // The guard is on the array length, not on the joined string: joining a single
    // empty-string entry also yields "", so a truthiness check on the rendered text would
    // report this one-entry directory as empty.
    listDirSpy.mockResolvedValue([""]);
    expect(textOf(await call("ssh_ls", { ...HOST, path: "/srv" }))).toBe("");
  });

  it("does not annotate entries with a type or a path prefix", async () => {
    listDirSpy.mockResolvedValue(["sub", "file.txt"]);
    const text = textOf(await call("ssh_ls", { ...HOST, path: "/srv" }));
    expect(text).not.toContain("/srv/");
    expect(text).toBe("sub\nfile.txt");
  });

  it("calls listDir with just the client and the path", async () => {
    listDirSpy.mockResolvedValue([]);
    await call("ssh_ls", { ...HOST, path: "/srv" });
    expect(lastCall(listDirSpy)).toHaveLength(2);
    expect(lastCall(listDirSpy)[1]).toBe("/srv");
  });
});

describe("ssh_read_file passes content through untouched", () => {
  it("returns the file content verbatim, including the trailing newline", async () => {
    readFileSpy.mockResolvedValue("line1\nline2\n");
    expect(textOf(await call("ssh_read_file", { ...HOST, path: "/etc/hosts" }))).toBe("line1\nline2\n");
  });

  it("does not trim, prefix, or annotate the content", async () => {
    readFileSpy.mockResolvedValue("   padded   ");
    expect(textOf(await call("ssh_read_file", { ...HOST, path: "/f" }))).toBe("   padded   ");
  });

  it("renders an empty file as an empty string (no message branch exists)", async () => {
    readFileSpy.mockResolvedValue("");
    const result = await call("ssh_read_file", { ...HOST, path: "/f" });
    expect(textOf(result)).toBe("");
    expect("isError" in result).toBe(false);
  });

  it("calls readFile with the client and the path only, leaving maxBytes at its default", async () => {
    readFileSpy.mockResolvedValue("x");
    await call("ssh_read_file", { ...HOST, path: "/f" });
    expect(lastCall(readFileSpy)).toHaveLength(2);
  });
});

describe("SFTP confirmation strings", () => {
  it("ssh_write_file confirms with the UTF-8 byte count and the path", async () => {
    expect(textOf(await call("ssh_write_file", { ...HOST, path: "/tmp/a.txt", content: "hello" }))).toBe(
      "Wrote 5 bytes to /tmp/a.txt",
    );
  });

  it("counts BYTES, not UTF-16 code units, for non-ASCII content", async () => {
    // The ASCII case above cannot tell Buffer.byteLength from content.length -- for
    // "hello" both are 5, so a regression to .length survives it. These payloads
    // diverge: e-acute is 1 code unit / 2 bytes, and the emoji is a surrogate pair,
    // 2 code units / 4 bytes. Mutation-verified: reverting tools.ts to content.length
    // fails this test and no other.
    expect(textOf(await call("ssh_write_file", { ...HOST, path: "/tmp/a.txt", content: "h\u00e9llo" }))).toBe(
      "Wrote 6 bytes to /tmp/a.txt",
    );
    expect(textOf(await call("ssh_write_file", { ...HOST, path: "/tmp/e.txt", content: "\u{1F600}" }))).toBe(
      "Wrote 4 bytes to /tmp/e.txt",
    );
  });

  it("ssh_upload confirms local → remote, in that direction", async () => {
    const text = textOf(await call("ssh_upload", { ...HOST, localPath: "C:/work/a.txt", remotePath: "/tmp/a.txt" }));
    expect(text).toBe("Uploaded C:/work/a.txt \u2192 /tmp/a.txt");
    // The separator is a real U+2192 arrow, not the ASCII digraph.
    expect(text).toContain("\u2192");
    expect(text).not.toContain("->");
  });

  it("ssh_download confirms remote → local, which is the REVERSE argument order", async () => {
    const text = textOf(await call("ssh_download", { ...HOST, remotePath: "/tmp/a.txt", localPath: "C:/work/a.txt" }));
    expect(text).toBe("Downloaded /tmp/a.txt \u2192 C:/work/a.txt");
  });

  it("hands uploadFile (client, local, remote) and downloadFile (client, remote, local)", async () => {
    // The two SFTP helpers take their paths in opposite orders; a swap here would upload
    // and download to the wrong side while still printing a plausible confirmation.
    await call("ssh_upload", { ...HOST, localPath: "/local/u", remotePath: "/remote/u" });
    expect(lastCall(uploadFileSpy).slice(1)).toEqual(["/local/u", "/remote/u"]);
    await call("ssh_download", { ...HOST, remotePath: "/remote/d", localPath: "/local/d" });
    expect(lastCall(downloadFileSpy).slice(1)).toEqual(["/remote/d", "/local/d"]);
  });

  it("writes the content through to writeFile unchanged", async () => {
    await call("ssh_write_file", { ...HOST, path: "/tmp/a.txt", content: "a\nb\n" });
    expect(lastCall(writeFileSpy).slice(1)).toEqual(["/tmp/a.txt", "a\nb\n"]);
  });
});

describe("timeout defaulting reaches the callee", () => {
  it("ssh_find defaults to 30000 when the caller omits timeout", async () => {
    findSpy.mockResolvedValue([]);
    await call("ssh_find", { ...HOST, path: "/var/log" });
    expect(lastFindCall().timeoutMs).toBe(30000);
  });

  it("ssh_find forwards an explicit timeout instead of the default", async () => {
    findSpy.mockResolvedValue([]);
    await call("ssh_find", { ...HOST, path: "/var/log", timeout: 5000 });
    expect(lastFindCall().timeoutMs).toBe(5000);
  });

  it("ssh_service_status defaults to 30000 when the caller omits timeout", async () => {
    serviceStatusSpy.mockResolvedValue(service());
    await call("ssh_service_status", { ...HOST, service: "nginx" });
    expect(lastServiceCall()).toEqual({ service: "nginx", timeoutMs: 30000 });
  });

  it("ssh_service_status forwards an explicit timeout instead of the default", async () => {
    serviceStatusSpy.mockResolvedValue(service());
    await call("ssh_service_status", { ...HOST, service: "nginx", timeout: 1234 });
    expect(lastServiceCall().timeoutMs).toBe(1234);
  });

  const TIMEOUT_PARAM: [tool: string, declared: boolean][] = [
    ["ssh_find", true],
    ["ssh_service_status", true],
    ["ssh_ls", false],
    ["ssh_stat", false],
    ["ssh_read_file", false],
    ["ssh_upload", false],
    ["ssh_download", false],
    ["ssh_write_file", false],
  ];

  it.each(TIMEOUT_PARAM)("%s declares a timeout parameter: %s", (name, declared) => {
    // The SFTP tools take no timeout at all -- they are bounded by the connection's own
    // readyTimeout, not a per-call one. Pinned so the "defaults to 30000" claim is scoped
    // to the tools that actually have the parameter.
    expect("timeout" in getTool(name).schema).toBe(declared);
  });
});

// ---------------------------------------------------------------------------
// ssh_multi_exec -- the batch isError predicate
// ---------------------------------------------------------------------------

describe("ssh_multi_exec sets isError for the WHOLE batch", () => {
  // The predicate is `results.some(r => r.error || r.code !== 0)` -- ONE host is enough to
  // flag the batch, and a clean non-zero exit counts the same as a connection error. Nothing
  // asserted either half before, so an inverted (`every`) or narrowed (`error`-only)
  // predicate would ship green while telling an agent a half-failed fan-out succeeded.
  type MultiResult = { host: string; stdout: string; stderr: string; code: number; signal?: string; error?: string };

  const okHost = (host: string): MultiResult => ({ host, stdout: "up", stderr: "", code: 0 });
  const tenHosts = Array.from({ length: 10 }, (_, i) => `web${i + 1}.test`);
  const runBatch = (results: MultiResult[]) => {
    multiExecSpy.mockResolvedValue(results);
    return call("ssh_multi_exec", { hosts: results.map((r) => r.host), command: "uptime" });
  };

  it("an all-zero-exit batch is NOT an error", async () => {
    const result = await runBatch(tenHosts.map(okHost));
    expect(result.isError).toBe(false);
    expect("isError" in result).toBe(true);
  });

  it("ONE unreachable host out of ten flips the batch", async () => {
    const results = tenHosts.map(okHost);
    results[4] = { host: "web5.test", stdout: "", stderr: "", code: -1, error: "Connection refused" };
    const result = await runBatch(results);
    expect(result.isError).toBe(true);
    // ...and the nine that worked are still rendered, so the caller is not left with only
    // the failure.
    expect(textOf(result)).toContain("--- web1.test ---");
    expect(textOf(result)).toContain("[ERROR] Connection refused");
  });

  it("ONE non-zero EXIT out of ten flips the batch, with no connection error anywhere", async () => {
    // The half most likely to be lost in a rewrite: every host answered, one command just
    // failed. `r.error` is undefined for all ten, so only the `code !== 0` term can catch it.
    const results = tenHosts.map(okHost);
    results[9] = { host: "web10.test", stdout: "", stderr: "no such service", code: 3 };
    const result = await runBatch(results);
    expect(result.isError).toBe(true);
    expect(results.every((r) => r.error === undefined)).toBe(true);
    expect(textOf(result)).toContain("[exit code: 3]");
  });

  it("a host carrying an `error` flags the batch even when its exit code is 0", async () => {
    // The two terms of the predicate are not interchangeable, and this is the one that only
    // `r.error` can catch. Today's multiExec (src/ops.ts) always pairs an error with
    // `code: -1`, so this exact shape does not arise in production -- but the RENDERER
    // already branches on `r.error` alone, printing "[ERROR] ..." with no exit-code line.
    // If isError were narrowed to the exit code, this result would render as a failure and
    // report success in the same call. Pinned so the two branches cannot drift apart.
    const result = await runBatch([
      okHost("web1.test"),
      { host: "web2.test", stdout: "", stderr: "", code: 0, error: "Pool acquire failed" },
    ]);
    expect(textOf(result)).toContain("[ERROR] Pool acquire failed");
    expect(result.isError).toBe(true);
  });

  it("a batch where EVERY host failed is an error too, not just a mixed one", async () => {
    const result = await runBatch(tenHosts.map((host) => ({ host, stdout: "", stderr: "", code: 1 })));
    expect(result.isError).toBe(true);
  });

  it("a signal-killed host (code -1) counts as a failure", async () => {
    const result = await runBatch([
      okHost("web1.test"),
      { host: "web2.test", stdout: "", stderr: "", code: -1, signal: "TERM" },
    ]);
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain("[signal: TERM]");
    expect(textOf(result)).toContain("[exit code: -1]");
  });

  it("an EMPTY host list is not an error -- some() over [] is false", async () => {
    // Pinned as actual behavior: nothing ran, so nothing failed.
    multiExecSpy.mockResolvedValue([]);
    const result = await call("ssh_multi_exec", { hosts: [], command: "uptime" });
    expect(result.isError).toBe(false);
    expect(textOf(result)).toBe("");
  });

  it("renders one block per host, in the order multiExec returned them", async () => {
    const result = await runBatch([
      { host: "web1.test", stdout: "10:00:01 up 3 days", stderr: "", code: 0 },
      { host: "web2.test", stdout: "", stderr: "", code: 1, error: "Timed out" },
    ]);
    expect(textOf(result)).toBe(
      [
        "--- web1.test ---",
        "10:00:01 up 3 days",
        "[exit code: 0]",
        "",
        "--- web2.test ---",
        "[ERROR] Timed out",
        "",
      ].join("\n"),
    );
  });

  it("an errored host prints [ERROR] INSTEAD of stdout/stderr/exit-code, even when they are set", async () => {
    const result = await runBatch([
      { host: "web1.test", stdout: "partial", stderr: "boom", code: 7, error: "Connection refused" },
    ]);
    const text = textOf(result);
    expect(text).toContain("[ERROR] Connection refused");
    expect(text).not.toContain("partial");
    expect(text).not.toContain("[exit code: 7]");
  });

  it("defaults the batch timeout to 30000 and forwards an explicit one", async () => {
    multiExecSpy.mockResolvedValue([]);
    await call("ssh_multi_exec", { hosts: ["a.test"], command: "uptime" });
    expect(lastCall(multiExecSpy)[3]).toBe(30000);
    await call("ssh_multi_exec", { hosts: ["a.test"], command: "uptime", timeout: 4321 });
    expect(lastCall(multiExecSpy)[3]).toBe(4321);
  });

  it("hands every host the SAME connection parameters and the same command string", async () => {
    multiExecSpy.mockResolvedValue([]);
    await call("ssh_multi_exec", {
      hosts: ["a.test", "b.test"],
      command: "uptime",
      port: 2222,
      username: "deploy",
      privateKeyPath: "/k",
      password: "p",
    });
    expect(lastCall(multiExecSpy)[1]).toEqual([
      { host: "a.test", port: 2222, username: "deploy", privateKeyPath: "/k", password: "p" },
      { host: "b.test", port: 2222, username: "deploy", privateKeyPath: "/k", password: "p" },
    ]);
    expect(lastCall(multiExecSpy)[2]).toBe("uptime");
  });
});

// ---------------------------------------------------------------------------
// Numeric schema boundaries
// ---------------------------------------------------------------------------

describe("the zod numeric boundaries are the only guard between 'omitted' and an explicit 0", () => {
  // Every handler defaults with `x || default`, so 0 and undefined are indistinguishable by
  // the time the body runs: a widened schema would silently turn `timeout: 0` into 30000 and
  // `port: 0` into 22 instead of telling the caller the value is invalid. An LLM caller
  // emitting 0 for "no limit" is realistic, which is exactly why the schema has to reject it.
  type ZodLike = { safeParse: (v: unknown) => { success: boolean } };
  const field = (tool: string, name: string): ZodLike => getTool(tool).schema[name] as unknown as ZodLike;
  const toolsDeclaring = (name: string): string[] =>
    [...getTools().entries()].filter(([, t]) => name in t.schema).map(([toolName]) => toolName);

  it("every tool taking a port shares ONE schema: an integer in 1..65535", () => {
    const named = toolsDeclaring("port");
    // Sanity check that the sweep is actually sweeping something.
    expect(named.length).toBeGreaterThan(5);
    for (const tool of named) {
      const port = field(tool, "port");
      for (const good of [1, 22, 2222, 65535]) {
        expect(port.safeParse(good).success, `${tool} should accept port ${good}`).toBe(true);
      }
      for (const bad of [0, -1, 65536, 1.5, "22", null]) {
        expect(port.safeParse(bad).success, `${tool} should reject port ${String(bad)}`).toBe(false);
      }
      // Still optional -- omitting it is how you ask for 22.
      expect(port.safeParse(undefined).success).toBe(true);
    }
  });

  it("every tool taking a timeout shares ONE schema: a positive integer", () => {
    const named = toolsDeclaring("timeout");
    expect(named).toEqual(expect.arrayContaining(["ssh_exec", "ssh_multi_exec", "ssh_find", "ssh_tail"]));
    for (const tool of named) {
      const timeout = field(tool, "timeout");
      for (const good of [1, 5000, 600000]) {
        expect(timeout.safeParse(good).success, `${tool} should accept timeout ${good}`).toBe(true);
      }
      for (const bad of [0, -1, 1.5, "5000"]) {
        expect(timeout.safeParse(bad).success, `${tool} should reject timeout ${String(bad)}`).toBe(false);
      }
      expect(timeout.safeParse(undefined).success).toBe(true);
      // No upper bound, deliberately: a long-running command is a legitimate use.
      expect(timeout.safeParse(86_400_000).success).toBe(true);
    }
  });

  it("ssh_tail's `lines` is a positive integer -- 0 would silently mean 100", () => {
    const lines = field("ssh_tail", "lines");
    for (const good of [1, 100, 100000]) expect(lines.safeParse(good).success).toBe(true);
    for (const bad of [0, -1, 2.5, "100"]) expect(lines.safeParse(bad).success).toBe(false);
    expect(lines.safeParse(undefined).success).toBe(true);
  });

  it("ssh_find's `maxdepth` deliberately ALLOWS 0 -- it is a real query, not a missing value", () => {
    // The contrast that makes the rule above meaningful: `-maxdepth 0` tests the named path
    // itself, and find() guards with `!== undefined` rather than truthiness, so a bare
    // z.number() is correct here.
    const maxdepth = field("ssh_find", "maxdepth");
    expect(maxdepth.safeParse(0).success).toBe(true);
    expect(maxdepth.safeParse(undefined).success).toBe(true);
  });
});
