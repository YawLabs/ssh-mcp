import { homedir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Fakes
//
// Both `diagnose.ts` and `env.ts` shell out through `runArgs`, which is a thin
// wrapper over `execFileSync`. Mocking `node:child_process` (rather than
// `runArgs` itself) means the REAL `runArgs`, the REAL classification, and the
// REAL callers all run -- only the subprocess is fake. That is what lets one
// fixture drive both `checkConnectivity` and `testConnection` and prove they
// share a classification.
// ---------------------------------------------------------------------------

type FakeRun = { stdout?: string; stderr?: string; fail?: boolean };

// Set by `fakeExec(...)` in each test. Returns what the fake subprocess should do.
let execHandler: ((cmd: string, args: string[]) => FakeRun) | null = null;

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return {
    ...actual,
    execFileSync: (cmd: string, args: string[], ...rest: unknown[]) => {
      if (!execHandler) return (actual.execFileSync as (...a: unknown[]) => unknown)(cmd, args, ...rest);
      const r = execHandler(cmd, args);
      if (r.fail) {
        // Shape matches what execFileSync throws: an Error carrying stdout/stderr
        // buffers. runArgs joins the two, which is how ssh's stderr-only
        // diagnostics reach the classifier.
        const err = new Error("Command failed") as Error & { stdout?: Buffer; stderr?: Buffer };
        err.stdout = Buffer.from(r.stdout ?? "");
        err.stderr = Buffer.from(r.stderr ?? "");
        throw err;
      }
      return r.stdout ?? "";
    },
  };
});

// ~/.ssh fakes. Both stay null unless a test opts in, so untouched tests keep
// hitting the real filesystem exactly as the other suites in this directory do.
let mockConfig: string | null = null;
let mockSshFiles: Record<string, string> | null = null;

// appendFileSync is ALWAYS stubbed here: fixKnownHosts appends to the real
// ~/.ssh/known_hosts on its success path, and a test must never do that.
const appendSpy = vi.fn();

const posix = (p: unknown) => String(p).replace(/\\/g, "/");
const isSshDir = (p: unknown) => posix(p).endsWith("/.ssh");
const sshChildName = (p: unknown): string | null => {
  const m = posix(p).match(/\/\.ssh\/([^/]+)$/);
  return m ? m[1] : null;
};

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    appendFileSync: (...args: unknown[]) => appendSpy(...args),
    existsSync: (p: unknown) => {
      const name = sshChildName(p);
      if (mockConfig !== null && name === "config") return true;
      if (mockSshFiles) {
        if (isSshDir(p)) return true;
        if (name !== null) return Object.hasOwn(mockSshFiles, name);
      }
      return actual.existsSync(p as string);
    },
    readdirSync: (p: unknown, ...rest: unknown[]) => {
      if (mockSshFiles && isSshDir(p)) return Object.keys(mockSshFiles);
      return (actual.readdirSync as (...a: unknown[]) => unknown)(p, ...rest);
    },
    statSync: (p: unknown, ...rest: unknown[]) => {
      const name = sshChildName(p);
      if (mockSshFiles && name !== null && Object.hasOwn(mockSshFiles, name)) {
        return { isFile: () => true } as unknown as ReturnType<typeof actual.statSync>;
      }
      return (actual.statSync as (...a: unknown[]) => unknown)(p, ...rest);
    },
    readFileSync: (p: unknown, ...rest: unknown[]) => {
      const name = sshChildName(p);
      if (mockConfig !== null && name === "config") return mockConfig;
      if (mockSshFiles && name !== null && Object.hasOwn(mockSshFiles, name)) return mockSshFiles[name];
      return (actual.readFileSync as (...a: unknown[]) => unknown)(p, ...rest);
    },
  };
});

import {
  checkConnectivity,
  checkSshAgent,
  checkSshConfig,
  checkSshKeys,
  classifySshProbe,
  SSH_NON_KEY_FILES,
} from "../diagnose.js";
import { ensureAgent, fixKnownHosts, listSshKeys, loadKey, testConnection } from "../env.js";

function fakeExec(handler: (cmd: string, args: string[]) => FakeRun): void {
  execHandler = handler;
}

afterEach(() => {
  execHandler = null;
  mockConfig = null;
  mockSshFiles = null;
  appendSpy.mockClear();
});

// ---------------------------------------------------------------------------
// Finding 2 -- fixKnownHosts must not claim a removal that did not happen.
//
// `ssh-keygen -R <target>` exits 0 for BOTH "removed it" and "it was not there",
// so the old `if (removeOk)` pushed "Removed old host key for X" on every
// first-time host.
// ---------------------------------------------------------------------------

// Stream placement is the whole point of these fixtures. Probed on
// OpenSSH_10.2p1 with a real known_hosts file:
//   hit  -> exit 0, STDOUT "# Host <t> found: line N" + "<path> updated."
//   miss -> exit 0, STDERR "Host <t> not found in <path>", stdout EMPTY
// `runArgs` merges stderr into stdout only on its FAILURE path, and the fake
// above mirrors that exactly (the success branch returns `stdout` and drops
// `stderr`). So the miss marker never reaches the classifier -- which is why
// removeKnownHostEntry must classify on the HIT markers and fail closed.
const KEYGEN_HIT_OUT = (t: string) =>
  `# Host ${t} found: line 9\n/home/u/.ssh/known_hosts updated.\nOriginal contents retained as /home/u/.ssh/known_hosts.old`;
const KEYGEN_MISS_OUT = (t: string) => `Host ${t} not found in /home/u/.ssh/known_hosts`;

/** The real miss: zero exit, message on stderr, nothing on stdout. */
const keygenMiss = (t: string): FakeRun => ({ stderr: KEYGEN_MISS_OUT(t) });
/** The real hit: zero exit, markers on stdout. */
const keygenHit = (t: string): FakeRun => ({ stdout: KEYGEN_HIT_OUT(t) });

/** ssh-keygen -R answers via `keygen`; ssh-keyscan fails so nothing is appended. */
function keygenOnly(keygen: (target: string) => FakeRun) {
  fakeExec((cmd, args) => {
    if (cmd === "ssh-keygen" && args[0] === "-R") return keygen(args[1]);
    return { fail: true, stderr: "getaddrinfo: Name or service not known" };
  });
}

describe("fixKnownHosts reports the removal that actually happened", () => {
  it("says 'nothing to remove' when the host was not in known_hosts (exit 0, miss line on stderr)", () => {
    keygenOnly(keygenMiss);

    const result = fixKnownHosts("brand-new-host.example.com");

    expect(result.actions).toContain("No existing host key for brand-new-host.example.com (nothing to remove)");
    // The regression: a first-time host used to be told its key was removed.
    expect(result.actions.join("\n")).not.toContain("Removed old host key");
  });

  it("still says 'nothing to remove' if a build prints the miss line to stdout instead", () => {
    // Classification must not depend on which stream carries the miss line.
    keygenOnly((t) => ({ stdout: KEYGEN_MISS_OUT(t) }));

    const result = fixKnownHosts("brand-new-host.example.com");

    expect(result.actions).toContain("No existing host key for brand-new-host.example.com (nothing to remove)");
    expect(result.actions.join("\n")).not.toContain("Removed old host key");
  });

  it("fails CLOSED: an unrecognised zero-exit output is 'absent', never 'removed'", () => {
    // The classifier must key off the HIT markers. Testing for the ABSENCE of
    // the miss marker reports "removed" for any output lacking it -- including
    // the empty stdout of a real miss, which is the original bug.
    keygenOnly(() => ({ stdout: "some future ssh-keygen wording nobody has seen" }));

    const result = fixKnownHosts("mystery-host.example.com");

    expect(result.actions).toContain("No existing host key for mystery-host.example.com (nothing to remove)");
    expect(result.actions.join("\n")).not.toContain("Removed old host key");
  });

  it("treats a completely absent known_hosts file as 'nothing to remove', not a failure", () => {
    // Probed on OpenSSH_10.2p1: `ssh-keygen -R host -f <missing>` exits 255 with
    // "Cannot stat <path>: No such file or directory". That is the normal state on
    // a fresh machine, and it used to surface as "Could not remove existing host
    // key for <host>: Cannot stat ..." even though nothing was wrong.
    keygenOnly(() => ({
      fail: true,
      stderr: "Cannot stat /home/someone/.ssh/known_hosts: No such file or directory",
    }));

    const result = fixKnownHosts("first-ever-host.example.com");

    expect(result.actions).toContain("No existing host key for first-ever-host.example.com (nothing to remove)");
    expect(result.actions.join("\n")).not.toContain("Could not remove");
  });

  it("still reports a genuine ssh-keygen failure as a failure", () => {
    // The absent-file carve-out must not swallow real errors (permissions, a
    // corrupt file). Anything that is not the missing-file shape stays "failed".
    keygenOnly(() => ({ fail: true, stderr: "Permission denied" }));

    const result = fixKnownHosts("locked-down.example.com");

    expect(result.actions.join("\n")).toContain("Could not remove existing host key for locked-down.example.com");
  });

  it("says 'Removed' only when ssh-keygen actually rewrote known_hosts", () => {
    keygenOnly(keygenHit);

    const result = fixKnownHosts("stale-host.example.com");

    expect(result.actions).toContain("Removed old host key for stale-host.example.com");
  });

  it("recognises a hit for a host whose name itself contains 'updated.'", () => {
    // The " updated." marker is end-of-line anchored so a hostname cannot forge
    // it; the "found: line" marker carries this case regardless.
    keygenOnly(keygenHit);

    const result = fixKnownHosts("updated.example.com");

    expect(result.actions).toContain("Removed old host key for updated.example.com");
  });

  it("does not let a hostname containing 'updated.' forge a removal on a miss", () => {
    keygenOnly((t) => ({ stdout: KEYGEN_MISS_OUT(t) }));

    const result = fixKnownHosts("updated.example.com");

    expect(result.actions).toContain("No existing host key for updated.example.com (nothing to remove)");
  });

  it("surfaces a real ssh-keygen failure instead of silently reporting nothing", () => {
    // Fixture deliberately NOT "Cannot stat ... No such file or directory": that
    // is a MISSING known_hosts, which is the normal fresh-machine state and is
    // classified "absent" (covered below), not a failure. A permissions error is
    // a genuine failure -- the file is there and ssh-keygen could not rewrite it.
    keygenOnly(() => ({ fail: true, stderr: "/home/u/.ssh/known_hosts: Permission denied" }));

    const result = fixKnownHosts("some-host.example.com");

    expect(result.actions.join("\n")).toMatch(/Could not remove existing host key for some-host\.example\.com/);
    expect(result.actions.join("\n")).toContain("Permission denied");
  });

  it("classifies the [host]:port entry independently of the bare-host entry", () => {
    // Bare host present, [host]:port absent -- the two must not report the same thing.
    keygenOnly((t) => (t.startsWith("[") ? keygenMiss(t) : keygenHit(t)));

    const result = fixKnownHosts("db.example.com", 2222);

    expect(result.actions).toContain("Removed old host key for db.example.com");
    expect(result.actions).toContain("No existing host key for [db.example.com]:2222 (nothing to remove)");
  });

  // IPv6 targeting. Probed against OpenSSH_10.2p1 with a seeded known_hosts:
  //   -R '[::1]'        -> "not found", removes NOTHING
  //   -R '[[::1]]:2222' -> "not found", removes NOTHING   (the old template's output)
  //   -R '::1' and -R '[::1]:2222' -> both remove the entry
  // The removal silently no-opped while ssh-keyscan still appended a fresh key, so the
  // stale IPv6 key survived alongside the new one -- and the verifier accepts if ANY
  // known key matches, leaving the retired key trusted.
  describe("IPv6 hosts target the spelling ssh-keygen actually matches", () => {
    /** Capture every target handed to `ssh-keygen -R`. */
    function recordRemovalTargets(): string[] {
      const targets: string[] = [];
      fakeExec((cmd, args) => {
        if (cmd === "ssh-keygen" && args[0] === "-R") {
          targets.push(args[1]);
          return keygenHit(args[1]);
        }
        return { fail: true, stderr: "getaddrinfo: Name or service not known" };
      });
      return targets;
    }

    it("removes the BARE address at the default port, never the bracketed form", () => {
      const targets = recordRemovalTargets();
      fixKnownHosts("[::1]");

      expect(targets).toEqual(["::1"]);
      expect(targets).not.toContain("[::1]");
    });

    it("uses [addr]:port on a non-default port, never the double-bracketed form", () => {
      const targets = recordRemovalTargets();
      fixKnownHosts("[::1]", 2222);

      expect(targets).toContain("[::1]:2222");
      expect(targets).toContain("::1");
      // The regression: `[${host}]:${port}` on an already-bracketed host.
      expect(targets).not.toContain("[[::1]]:2222");
    });

    it("hands ssh-keyscan the bare address so its output matches the -R targets", () => {
      let scanArgs: string[] = [];
      fakeExec((cmd, args) => {
        if (cmd === "ssh-keygen" && args[0] === "-R") return keygenHit(args[1]);
        scanArgs = args;
        return { stdout: "::1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" };
      });

      fixKnownHosts("[::1]");

      expect(scanArgs).toEqual(["-H", "::1"]);
    });

    it("leaves ordinary hostnames exactly as before", () => {
      const targets = recordRemovalTargets();
      fixKnownHosts("db.example.com", 2222);

      expect(targets).toContain("db.example.com");
      expect(targets).toContain("[db.example.com]:2222");
    });
  });

  it("keeps the truthful removal line on the success path", () => {
    fakeExec((cmd, args) => {
      if (cmd === "ssh-keygen" && args[0] === "-R") return keygenMiss(args[1]);
      return { stdout: "new-host.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" };
    });

    const result = fixKnownHosts("new-host.example.com");

    expect(result.status).toBe("ok");
    expect(appendSpy).toHaveBeenCalledTimes(1);
    expect(result.actions).toEqual([
      "No existing host key for new-host.example.com (nothing to remove)",
      "Added new host key for new-host.example.com",
    ]);
  });
});

// ---------------------------------------------------------------------------
// Finding 13 -- one shared probe + classifier behind two sets of wording.
// ---------------------------------------------------------------------------

describe("classifySshProbe", () => {
  it("maps ssh output to outcomes in the documented precedence order", () => {
    expect(classifySshProbe(true, "SSH_OK")).toBe("ok");
    expect(classifySshProbe(false, "Permission denied (publickey).")).toBe("permission-denied");
    expect(classifySshProbe(false, "ssh: connect to host h port 22: Connection refused")).toBe("connection-refused");
    expect(classifySshProbe(false, "ssh: connect to host h port 22: Connection timed out")).toBe("timed-out");
    expect(classifySshProbe(false, "Host key verification failed.")).toBe("host-key-mismatch");
    expect(classifySshProbe(false, "ssh: Could not resolve hostname h: Name or service not known")).toBe("dns-failure");
    expect(classifySshProbe(false, "something nobody has seen before")).toBe("unknown");
  });

  it("does not report ok when SSH_OK is absent even on a zero exit", () => {
    expect(classifySshProbe(true, "")).toBe("unknown");
  });

  it("accepts the bare 'timed out' spelling, not just 'Connection timed out'", () => {
    // checkConnectivity used to test both spellings, testConnection only the
    // bare one. The unified classifier must keep the broader match.
    expect(classifySshProbe(false, "operation timed out")).toBe("timed-out");
  });

  it("accepts the broader 'Could not resolve' spelling for both callers", () => {
    // checkConnectivity previously required the narrower "Could not resolve
    // hostname"; unification settled on the broader form.
    expect(classifySshProbe(false, "Could not resolve address for h")).toBe("dns-failure");
  });
});

describe("checkConnectivity and testConnection share one classification", () => {
  /** Every probe result both functions branch on, with each one's own wording. */
  const cases: Array<{
    name: string;
    run: FakeRun;
    connectivity: RegExp;
    test: RegExp;
    status: "ok" | "error";
  }> = [
    {
      name: "success",
      run: { stdout: "SSH_OK" },
      connectivity: /^SSH connection to h\.example\.com:22 succeeded$/,
      test: /^Connected to h\.example\.com:22 in \d+ms$/,
      status: "ok",
    },
    {
      name: "permission denied",
      run: { fail: true, stderr: "Permission denied (publickey)." },
      connectivity: /^Permission denied connecting to h\.example\.com:22\. Your key is not authorized/,
      test: /^Authentication failed to h\.example\.com:22 \(\d+ms\)\. Key not authorized\./,
      status: "error",
    },
    {
      name: "connection refused",
      run: { fail: true, stderr: "ssh: connect to host h port 22: Connection refused" },
      connectivity: /^Connection refused at h\.example\.com:22\. SSH server is not running on this port/,
      test: /^Connection refused at h\.example\.com:22\. SSH server not running or port blocked\.$/,
      status: "error",
    },
    {
      name: "timeout",
      run: { fail: true, stderr: "ssh: connect to host h port 22: Connection timed out" },
      connectivity: /^Connection timed out to h\.example\.com:22\. Host may be down/,
      test: /^Connection timed out to h\.example\.com:22\. Host down or firewall blocking\.$/,
      status: "error",
    },
    {
      name: "host key mismatch",
      run: { fail: true, stderr: "Host key verification failed." },
      connectivity: /^Host key verification failed for h\.example\.com\. The host key changed/,
      test: /^Host key mismatch for h\.example\.com\. Instance was likely recreated\./,
      status: "error",
    },
    {
      name: "dns failure",
      run: { fail: true, stderr: "ssh: Could not resolve hostname h: Name or service not known" },
      connectivity: /^Could not resolve hostname "h\.example\.com"\. Check DNS/,
      test: /^Could not resolve "h\.example\.com"\. Check DNS/,
      status: "error",
    },
    {
      name: "unrecognised failure",
      run: { fail: true, stderr: "kex_exchange_identification: read: Connection reset" },
      connectivity: /^SSH connection failed: kex_exchange_identification/,
      test: /^Connection failed to h\.example\.com:22: kex_exchange_identification/,
      status: "error",
    },
  ];

  for (const c of cases) {
    it(`agrees on "${c.name}" while keeping each caller's own wording`, () => {
      fakeExec(() => c.run);

      const diag = checkConnectivity("h.example.com");
      const tool = testConnection("h.example.com");

      // Same outcome from the shared classifier...
      expect(diag.status).toBe(c.status);
      expect(tool.status).toBe(c.status);
      // ...different, unchanged operator-facing strings.
      expect(diag.message).toMatch(c.connectivity);
      expect(tool.message).toMatch(c.test);
    });
  }

  it("still rejects an invalid hostname before probing, in both callers", () => {
    fakeExec(() => {
      throw new Error("ssh must not be spawned for an invalid hostname");
    });

    expect(checkConnectivity("host; rm -rf /").message).toMatch(/Invalid hostname/);
    expect(testConnection("host; rm -rf /").message).toMatch(/Invalid hostname/);
  });

  it("passes the port through to both callers' messages", () => {
    fakeExec(() => ({ stdout: "SSH_OK" }));

    expect(checkConnectivity("h.example.com", 2222).message).toContain("h.example.com:2222");
    expect(testConnection("h.example.com", 2222).message).toContain("h.example.com:2222");
  });
});

// ---------------------------------------------------------------------------
// Finding 14 -- one skip-list, so env.ts and diagnose.ts cannot drift.
// ---------------------------------------------------------------------------

describe("SSH_NON_KEY_FILES is the single skip-list", () => {
  it("contains every non-key file both scanners must ignore", () => {
    expect([...SSH_NON_KEY_FILES].sort()).toEqual([
      "authorized_keys",
      "config",
      "environment",
      "known_hosts",
      "known_hosts.old",
    ]);
  });

  it("makes checkSshKeys ignore ~/.ssh/environment (it used to report it as a key)", () => {
    // The drift this fixes: env.ts skipped "environment", diagnose.ts did not.
    // A shell-ish ~/.ssh/environment mentioning PRIVATE KEY was reported as a key.
    mockSshFiles = {
      id_ed25519: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
      environment: "NOTE=this file mentions PRIVATE KEY but is not one",
      known_hosts: "h ssh-ed25519 AAAA",
    };
    fakeExec(() => ({ stdout: "" }));

    const result = checkSshKeys();

    expect(result.message).toContain("id_ed25519");
    expect(result.message).not.toContain("environment");
  });

  it("makes listSshKeys ignore the same files", () => {
    mockSshFiles = {
      id_ed25519: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
      environment: "NOTE=this file mentions PRIVATE KEY but is not one",
      known_hosts: "h ssh-ed25519 AAAA",
    };
    fakeExec(() => ({ stdout: "" }));

    const names = listSshKeys().map((k) => k.name);

    expect(names).toContain("id_ed25519");
    expect(names).not.toContain("environment");
    expect(names).not.toContain("known_hosts");
  });
});

// ---------------------------------------------------------------------------
// Finding 18 -- checkSshConfig host-pattern matching.
// ---------------------------------------------------------------------------

describe("checkSshAgent does not report an unreachable agent as healthy", () => {
  // The old code recognised only the literal "Could not open a connection" and
  // otherwise fell through to `return { status: "ok" }` -- so any other ssh-add
  // failure was reported as a running agent, with the error text pasted in where
  // the key list belongs.
  it("reports an unrecognised ssh-add failure as an error, not ok", () => {
    vi.stubEnv("SSH_AUTH_SOCK", "/tmp/ssh-agent.sock");
    fakeExec(() => ({ fail: true, stderr: "error fetching identities: communication with agent failed" }));

    const result = checkSshAgent();

    expect(result.status).toBe("error");
    expect(result.message).not.toMatch(/ssh-agent running with keys/);
    vi.unstubAllEnvs();
  });

  it("keeps the classic wording for the known unreachable phrasing", () => {
    vi.stubEnv("SSH_AUTH_SOCK", "/tmp/ssh-agent.sock");
    fakeExec(() => ({ fail: true, stderr: "Could not open a connection to your authentication agent." }));

    const result = checkSshAgent();

    expect(result.status).toBe("error");
    expect(result.message).toMatch(/agent is not reachable/);
    vi.unstubAllEnvs();
  });

  it("still treats 'no identities' as a running agent, even on a non-zero exit", () => {
    // A reachable agent holding nothing is a warning, never an error.
    vi.stubEnv("SSH_AUTH_SOCK", "/tmp/ssh-agent.sock");
    fakeExec(() => ({ fail: true, stderr: "The agent has no identities." }));

    const result = checkSshAgent();

    expect(result.status).toBe("warning");
    vi.unstubAllEnvs();
  });

  it("still reports a healthy agent as ok", () => {
    vi.stubEnv("SSH_AUTH_SOCK", "/tmp/ssh-agent.sock");
    fakeExec(() => ({ stdout: "256 SHA256:abc123 user@host (ED25519)" }));

    const result = checkSshAgent();

    expect(result.status).toBe("ok");
    expect(result.message).toContain("SHA256:abc123");
    vi.unstubAllEnvs();
  });
});

describe("checkSshConfig host-pattern matching", () => {
  it("honours a negated pattern instead of matching through the wildcard", () => {
    // The wrong-way-round bug: `*` matched prod, and `!prod` was ignored.
    mockConfig = ["Host * !prod", "  ForwardAgent yes"].join("\n");

    expect(checkSshConfig("prod").message).toMatch(/No SSH config entry for "prod"/);
    expect(checkSshConfig("staging").message).toContain("ForwardAgent yes");
  });

  // Commas are NOT pattern separators on a `Host` line -- `Host` takes
  // whitespace-separated patterns and matches each token whole. Both fixtures
  // below were probed against OpenSSH_10.2p1 with `ssh -F <cfg> -G <host>`;
  // the assertions restate what real ssh did.
  it("does not treat a comma as a pattern separator (ssh does not either)", () => {
    // Probed: `Host web1,web2` + `User deploy` -> `ssh -G web1` and `ssh -G web2`
    // BOTH report the default user, i.e. the block applies to NEITHER host. The
    // whole token is one literal pattern that no real hostname can equal.
    mockConfig = ["Host web1,web2", "  User deploy"].join("\n");

    expect(checkSshConfig("web1").message).toMatch(/No SSH config entry for "web1"/);
    expect(checkSshConfig("web2").message).toMatch(/No SSH config entry for "web2"/);
    expect(checkSshConfig("web3").message).toMatch(/No SSH config entry/);
  });

  it("treats `*,!prod` as one literal pattern that selects nothing", () => {
    // Probed: `Host *,!prod` + `User deploy` -> both `ssh -G prod` and
    // `ssh -G other` report the default user. Read as a single glob it means
    // "anything ending in `,!prod`", which no hostname is. Splitting on the
    // comma would wrongly turn this into the working `Host * !prod` form.
    mockConfig = ["Host *,!prod", "  ForwardAgent yes"].join("\n");

    expect(checkSshConfig("prod").message).toMatch(/No SSH config entry for "prod"/);
    expect(checkSshConfig("staging").message).toMatch(/No SSH config entry for "staging"/);
  });

  it("requires at least one positive match -- a lone negation selects nothing", () => {
    mockConfig = ["Host !prod", "  User deploy"].join("\n");

    expect(checkSshConfig("staging").message).toMatch(/No SSH config entry/);
    expect(checkSshConfig("prod").message).toMatch(/No SSH config entry/);
  });

  it("accepts the Host=value separator form", () => {
    mockConfig = ["Host=myserver", "  User myuser"].join("\n");

    const result = checkSshConfig("myserver");
    expect(result.message).toContain("User myuser");
  });

  // `#` comments must be stripped before parsing. Every fixture below was probed
  // against OpenSSH_10.2p1 with `ssh -F <cfg> -G <host>`; the assertions restate
  // what real ssh did. Without stripping, the parser failed in BOTH directions.
  it("does not read a word in a trailing comment as a Host pattern", () => {
    // Probed: `ssh -G prod` reports the DEFAULT user -- ssh strips the comment,
    // leaving the single pattern `bastion`. Tokenising the comment instead made
    // `prod` a pattern and reported the whole block as prod's config.
    mockConfig = ["Host bastion   # jump box for prod", "  User admin"].join("\n");

    expect(checkSshConfig("prod").message).toMatch(/No SSH config entry for "prod"/);
    expect(checkSshConfig("bastion").message).toContain("User admin");
  });

  it("does not honour a negation that lives inside a comment", () => {
    // Probed: `ssh -G prod` DOES apply this block (user commentneg). Reading
    // `!prod` out of the comment disqualified the line and hid a real directive.
    mockConfig = ["Host *  # !prod", "  User commentneg"].join("\n");

    expect(checkSshConfig("prod").message).toContain("User commentneg");
  });

  it("does not echo a commented-out directive as config", () => {
    mockConfig = ["Host foo", "  # User olduser", "  User newuser"].join("\n");

    const result = checkSshConfig("foo");
    expect(result.message).toContain("User newuser");
    expect(result.message).not.toContain("olduser");
  });

  it("does not let a commented-out Host line end the current block", () => {
    // ssh treats `# Host bar` as a comment, so the block continues.
    mockConfig = ["Host foo", "  User myuser", "# Host bar", "  ForwardAgent yes"].join("\n");

    const result = checkSshConfig("foo");
    expect(result.message).toContain("User myuser");
    expect(result.message).toContain("ForwardAgent yes");
  });

  // A `#` is only a comment when it STARTS a token. Probed: with `Host foo#bar`,
  // `ssh -G foo#bar` matches the block and `ssh -G foo` does not.
  it("keeps a mid-token '#' as a literal pattern character", () => {
    mockConfig = ["Host foo#bar", "  User midtoken"].join("\n");

    expect(checkSshConfig("foo#bar").message).toContain("User midtoken");
    // Truncating the pattern to `foo` would select a host ssh does NOT select.
    expect(checkSshConfig("foo").message).toMatch(/No SSH config entry for "foo"/);
  });

  // CRLF fixtures, joined with \r\n rather than \n. Every other fixture in this
  // file uses \n, which is exactly how a CRLF-only defect slipped through: the
  // old `/#.*$/` stripper could never match, because JS `.` excludes \r and a
  // non-multiline `$` only matches end-of-input, so the trailing \r blocked it.
  describe("CRLF config files", () => {
    it("strips a trailing comment on a Host line", () => {
      mockConfig = ["Host bastion   # jump box for prod", "  User admin"].join("\r\n");

      expect(checkSshConfig("prod").message).toMatch(/No SSH config entry for "prod"/);
      expect(checkSshConfig("bastion").message).toContain("User admin");
    });

    it("does not honour a negation inside a comment", () => {
      mockConfig = ["Host *  # !prod", "  User commentneg"].join("\r\n");

      expect(checkSshConfig("prod").message).toContain("User commentneg");
    });

    it("does not leave a trailing carriage return on reported directives", () => {
      mockConfig = ["Host myserver", "  User myuser", "  Port 2222"].join("\r\n");

      const result = checkSshConfig("myserver");
      expect(result.message).toContain("User myuser");
      expect(result.message).not.toContain("\r");
    });

    it("matches a Host pattern that ends the line", () => {
      // With a bare split("\n") the pattern would carry a trailing \r and never
      // equal the host, so the whole block went missing on CRLF files.
      mockConfig = ["Host myserver", "  User myuser"].join("\r\n");

      expect(checkSshConfig("myserver").message).toContain("User myuser");
    });
  });

  it("does not mistake HostName for a Host line", () => {
    mockConfig = ["Host myserver", "  HostName 10.0.0.5", "  User myuser"].join("\n");

    const result = checkSshConfig("myserver");
    expect(result.message).toContain("HostName 10.0.0.5");
    expect(result.message).toContain("User myuser");
  });

  it("ends the Host block at a Match line rather than reporting conditional directives", () => {
    mockConfig = ["Host myserver", "  User myuser", "Match exec true", "  User conditional"].join("\n");

    const result = checkSshConfig("myserver");
    expect(result.message).toContain("User myuser");
    expect(result.message).not.toContain("User conditional");
  });

  it("resumes matching at the next Host line after a Match block", () => {
    mockConfig = ["Match exec true", "  User conditional", "Host myserver", "  User myuser"].join("\n");

    const result = checkSshConfig("myserver");
    expect(result.message).toContain("User myuser");
    expect(result.message).not.toContain("User conditional");
  });

  it("matches Host patterns case-SENSITIVELY, exactly as ssh does", () => {
    // Not a limitation -- ssh agrees. Probed both directions on OpenSSH_10.2p1:
    // config `Host MyServer` -> `ssh -G myserver` gets the DEFAULT user, and
    // config `Host myserver` -> `ssh -G MYSERVER` gets the default user too.
    // Lowercasing either side here would CREATE a divergence from ssh, so this
    // test exists to stop that "fix".
    mockConfig = ["Host MyServer", "  User deploy"].join("\n");

    expect(checkSshConfig("MyServer").message).toContain("User deploy");
    expect(checkSshConfig("myserver").message).toMatch(/No SSH config entry for "myserver"/);
    expect(checkSshConfig("MYSERVER").message).toMatch(/No SSH config entry for "MYSERVER"/);
  });

  it("still treats regex metacharacters in patterns as literals", () => {
    mockConfig = ["Host srv[12].example.com *", "  User deploy"].join("\n");

    // The `[12]` must not act as a character class; the trailing `*` is what
    // makes this block apply to srv1.example.com.
    expect(checkSshConfig("srv1.example.com").message).toContain("User deploy");
    expect(checkSshConfig("srv[12].example.com").message).toContain("User deploy");
  });
});

// ---------------------------------------------------------------------------
// GAP 5 -- loadKey's three-way ssh-add failure classification.
//
// `ssh_key_load` against a 0644 key or a passphrased key is the most common
// operator failure this server exists to explain, and the branch that wins
// decides whether the operator is sent to `chmod` or to `ssh-add`. Sending them
// to the wrong one is worse than saying nothing.
//
// Harness: the module-level `node:child_process` mock above means the REAL
// `runArgs` (diagnose.ts) and the REAL `runArgsWithEnv` (env.ts) run -- only the
// subprocess is fake. `ensureAgent` lives in the same module as `loadKey`, so it
// cannot be mocked out; it is driven through that same fake subprocess instead.
// `agentUp`/`agentDown` below decide what `ssh-add -l` answers, which is exactly
// what `probeAgent` (and therefore `ensureAgent`) classifies on.
// ---------------------------------------------------------------------------

describe("loadKey classifies ssh-add failures into the right operator fix", () => {
  /** Every (cmd, args) pair the fake subprocess saw, in order. */
  let calls: Array<{ cmd: string; args: string[] }> = [];

  /** A key that the ~/.ssh fake reports as existing. */
  const KEY_NAME = "id_gap5";
  const KEY_ARG = `~/.ssh/${KEY_NAME}`;
  /** What loadKey must resolve KEY_ARG to before it touches the filesystem. */
  const KEY_RESOLVED = join(homedir(), ".ssh", KEY_NAME);

  /**
   * Reachable agent: `ssh-add -l` exits 0 with a key list, which is what
   * probeAgent needs to report `reachable: true`. Every OTHER ssh-add
   * invocation -- i.e. the `ssh-add <path>` load itself -- gets `load`.
   */
  function agentUp(load: FakeRun): void {
    vi.stubEnv("SSH_AUTH_SOCK", "/tmp/gap5-agent.sock");
    fakeExec((cmd, args) => {
      calls.push({ cmd, args });
      if (cmd === "ssh-add" && args[0] === "-l") return { stdout: "256 SHA256:abc123 u@h (ED25519)" };
      return load;
    });
  }

  /**
   * Unreachable agent: `ssh-add -l` fails with a message that is NOT "no
   * identities", so probeAgent returns null on every channel. On Unix the
   * `ssh-agent -s` spawn fails too (the fake fails everything), so both
   * platforms land on `reachable: false` -- with platform-specific wording,
   * which is why the assertions below compare against ensureAgent() rather than
   * hardcoding one platform's string.
   */
  function agentDown(): void {
    vi.stubEnv("SSH_AUTH_SOCK", "/tmp/gap5-agent.sock");
    fakeExec((cmd, args) => {
      calls.push({ cmd, args });
      return { fail: true, stderr: "Could not open a connection to your authentication agent." };
    });
  }

  /** Did ssh-add ever get run against the key itself (as opposed to `-l`)? */
  const loadWasAttempted = () => calls.some((c) => c.cmd === "ssh-add" && c.args[0] !== "-l");

  beforeEach(() => {
    calls = [];
    // Present in ~/.ssh, so the not-found branch is only reached deliberately.
    mockSshFiles = { [KEY_NAME]: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----" };
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  // -- the agent-unreachable early return ------------------------------------

  describe("agent unreachable", () => {
    it("returns ensureAgent's own message and never runs ssh-add against the key", () => {
      agentDown();

      const result = loadKey(KEY_ARG);

      expect(result.status).toBe("error");
      // The message is the AGENT's, verbatim -- not a load failure dressed up as
      // one. Compared against a live ensureAgent() under the same fake because
      // the wording is platform-specific (Windows names the service; Unix says
      // to eval ssh-agent -s).
      expect(result.message).toBe(ensureAgent().message);
      expect(result.message).not.toContain("Failed to load key");
      expect(result.message).not.toContain("chmod");
    });

    it("does not spawn ssh-add against a dead agent", () => {
      agentDown();

      loadKey(KEY_ARG);

      // Only the `-l` probes ensureAgent itself makes. Loading a key into an
      // agent that is not there produces a confusing generic failure, which is
      // precisely what the early return exists to prevent.
      expect(loadWasAttempted()).toBe(false);
      expect(calls.every((c) => c.cmd !== "ssh-add" || c.args[0] === "-l")).toBe(true);
    });

    it("reports the dead agent even for a key that does not exist (agent check comes first)", () => {
      agentDown();

      const result = loadKey("~/.ssh/definitely-absent");

      // Ordering pin: a missing agent is the operator's real problem, so it must
      // not be masked by "Key not found".
      expect(result.message).toBe(ensureAgent().message);
      expect(result.message).not.toContain("Key not found");
    });
  });

  // -- `~` expansion ---------------------------------------------------------

  describe("~ expansion", () => {
    it("expands a leading ~ to the home directory before handing the path to ssh-add", () => {
      agentUp({ stdout: "Identity added" });

      const result = loadKey(KEY_ARG);

      const loadCall = calls.find((c) => c.cmd === "ssh-add" && c.args[0] !== "-l");
      // ssh-add gets the EXPANDED path: no shell is involved (execFileSync
      // spawns it directly), so a literal "~/..." would be looked up as a
      // directory actually named "~".
      expect(loadCall?.args).toEqual([KEY_RESOLVED]);
      expect(loadCall?.args[0].startsWith("~")).toBe(false);
      expect(result.message).toBe(`Key loaded: ${KEY_RESOLVED}`);
    });

    it("leaves an already-absolute path untouched", () => {
      agentUp({ stdout: "Identity added" });

      const result = loadKey(KEY_RESOLVED);

      expect(result).toEqual({ status: "ok", message: `Key loaded: ${KEY_RESOLVED}` });
    });

    it("reports the EXPANDED path in error messages, not the ~ form", () => {
      agentUp({ fail: true, stderr: "Permissions 0644 for 'k' are too open." });

      const result = loadKey(KEY_ARG);

      expect(result.message).toContain(KEY_RESOLVED);
      expect(result.message).not.toContain("~/.ssh");
    });

    it("treats a leading ~ as the CURRENT user's home even in the ~user form", () => {
      // Documented limitation, shared with ssh.ts's local-path expansion: only a
      // bare leading "~" is understood, so "~root/.ssh/id_rsa" resolves under the
      // CURRENT user's home rather than root's. Pinned rather than asserted as
      // desirable -- it decides which path the "Key not found" line names, and
      // that path is the only thing the operator has to go on. See bugsFound.
      agentUp({ stdout: "Identity added" });

      const result = loadKey("~root/.ssh/id_rsa");

      expect(result.message).toBe(`Key not found: ${join(homedir(), "root", ".ssh", "id_rsa")}`);
    });
  });

  // -- key not found ---------------------------------------------------------

  describe("key not found", () => {
    it("says so by resolved path and never spawns ssh-add for the key", () => {
      agentUp({ stdout: "Identity added" });

      const result = loadKey("~/.ssh/absent-key");

      expect(result).toEqual({
        status: "error",
        message: `Key not found: ${join(homedir(), ".ssh", "absent-key")}`,
      });
      expect(loadWasAttempted()).toBe(false);
    });
  });

  // -- too-open permissions --------------------------------------------------
  //
  // Real OpenSSH prints all three markers together, but they are three separate
  // substring tests in the source and any one of them can be dropped without the
  // others noticing. Each is therefore pinned on a fixture that isolates it.

  describe("too-open permissions -> chmod", () => {
    const chmodMessage = `Key ${KEY_RESOLVED} has too-open permissions. Fix: chmod 600 ${KEY_RESOLVED}`;

    it("classifies on UNPROTECTED PRIVATE KEY alone", () => {
      agentUp({
        fail: true,
        stderr: [
          "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
          "@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @",
          "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
          "It is required that your private key files are NOT accessible by others.",
          "This private key will be ignored.",
        ].join("\n"),
      });

      expect(loadKey(KEY_ARG)).toEqual({ status: "error", message: chmodMessage });
    });

    it("classifies on 'too open' alone", () => {
      agentUp({ fail: true, stderr: `Permissions 0644 for '${KEY_RESOLVED}' are too open.` });

      expect(loadKey(KEY_ARG)).toEqual({ status: "error", message: chmodMessage });
    });

    it("classifies on 'bad permissions' alone", () => {
      // Recent OpenSSH ends the too-open block with this line; on some builds it
      // is the only marker that survives into ssh-add's output.
      agentUp({ fail: true, stderr: `Error loading key "${KEY_RESOLVED}": bad permissions` });

      expect(loadKey(KEY_ARG)).toEqual({ status: "error", message: chmodMessage });
    });

    it("handles the full real-world block (all three markers at once)", () => {
      agentUp({
        fail: true,
        stderr: [
          "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
          "@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @",
          "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
          `Permissions 0644 for '${KEY_RESOLVED}' are too open.`,
          "It is required that your private key files are NOT accessible by others.",
          "This private key will be ignored.",
          `Error loading key "${KEY_RESOLVED}": bad permissions`,
        ].join("\n"),
      });

      const result = loadKey(KEY_ARG);

      expect(result.message).toBe(chmodMessage);
      // The operator gets a runnable fix, not a wall of ssh-add output.
      expect(result.message).not.toContain("WARNING");
    });
  });

  // -- passphrase ------------------------------------------------------------

  describe("passphrase-protected key -> ssh-add manually", () => {
    const passphraseMessage = `Key ${KEY_RESOLVED} requires a passphrase. Add it manually: ssh-add ${KEY_RESOLVED}`;

    it("classifies on 'passphrase' alone", () => {
      agentUp({ fail: true, stderr: `Enter passphrase for ${KEY_RESOLVED}:` });

      expect(loadKey(KEY_ARG)).toEqual({ status: "error", message: passphraseMessage });
    });

    it("classifies on 'incorrect' alone", () => {
      // Trimmed deliberately: the real line ("incorrect passphrase supplied to
      // decrypt private key") carries BOTH markers, so it cannot show that the
      // "incorrect" test is load-bearing on its own.
      agentUp({ fail: true, stderr: `Error loading key "${KEY_RESOLVED}": incorrect` });

      expect(loadKey(KEY_ARG)).toEqual({ status: "error", message: passphraseMessage });
    });

    it("handles the real non-interactive wording (both markers)", () => {
      agentUp({
        fail: true,
        stderr: `Error loading key "${KEY_RESOLVED}": incorrect passphrase supplied to decrypt private key`,
      });

      expect(loadKey(KEY_ARG).message).toBe(passphraseMessage);
    });
  });

  // -- ordering: permissions BEFORE passphrase -------------------------------

  describe("check order is load-bearing", () => {
    it("prefers the permissions fix when an output carries BOTH sets of markers", () => {
      // The permissions check runs FIRST in the source, and this is why: a
      // too-open key needs `chmod 600`, and telling the operator to re-run
      // `ssh-add` by hand sends them to a command that fails exactly the same
      // way. The reverse ordering is silently wrong on any output that mentions
      // a passphrase alongside the permissions complaint.
      agentUp({
        fail: true,
        stderr: [`Permissions 0644 for '${KEY_RESOLVED}' are too open.`, `Enter passphrase for ${KEY_RESOLVED}:`].join(
          "\n",
        ),
      });

      const result = loadKey(KEY_ARG);

      expect(result.message).toBe(`Key ${KEY_RESOLVED} has too-open permissions. Fix: chmod 600 ${KEY_RESOLVED}`);
      expect(result.message).not.toContain("requires a passphrase");
    });

    it("still reaches the passphrase branch when no permissions marker is present", () => {
      // The other half of the ordering pin: permissions-first must not swallow
      // an ordinary passphrase failure.
      agentUp({ fail: true, stderr: `Enter passphrase for ${KEY_RESOLVED}:` });

      const result = loadKey(KEY_ARG);

      expect(result.message).toContain("requires a passphrase");
      expect(result.message).not.toContain("chmod");
    });
  });

  // -- generic fall-through --------------------------------------------------

  describe("unrecognised failure", () => {
    it("carries the raw ssh-add output through instead of guessing a fix", () => {
      agentUp({ fail: true, stderr: "Error connecting to agent: Connection refused" });

      const result = loadKey(KEY_ARG);

      expect(result).toEqual({
        status: "error",
        message: "Failed to load key: Error connecting to agent: Connection refused",
      });
      // An unknown failure must not be dressed up as one of the two known fixes.
      expect(result.message).not.toContain("chmod");
      expect(result.message).not.toContain("requires a passphrase");
    });

    it("includes BOTH streams of the failed ssh-add, since ssh-add talks on stderr", () => {
      agentUp({ fail: true, stdout: "some stdout noise", stderr: "the actual reason" });

      // runArgs joins stdout and stderr on its failure path, and this branch is
      // the only one that shows the operator that text -- losing a stream here
      // loses the only diagnostic they get.
      expect(loadKey(KEY_ARG).message).toBe("Failed to load key: some stdout noise\nthe actual reason");
    });
  });

  // -- success ---------------------------------------------------------------

  describe("success", () => {
    it("reports ok with the resolved path and runs ssh-add with exactly that one argument", () => {
      agentUp({ stdout: `Identity added: ${KEY_RESOLVED} (u@h)` });

      const result = loadKey(KEY_ARG);

      expect(result).toEqual({ status: "ok", message: `Key loaded: ${KEY_RESOLVED}` });
      // No extra flags: a stray `-q`, `-t`, or `-l` here changes what the agent
      // ends up holding.
      expect(calls.filter((c) => c.cmd === "ssh-add" && c.args[0] !== "-l")).toEqual([
        { cmd: "ssh-add", args: [KEY_RESOLVED] },
      ]);
    });

    it("does not report success merely because ssh-add printed something reassuring", () => {
      // Classification is on the EXIT STATUS, not on the text. A non-zero exit
      // whose output happens to say "Identity added" is still a failure.
      agentUp({ fail: true, stderr: "Identity added: but the process exited non-zero" });

      expect(loadKey(KEY_ARG).status).toBe("error");
    });
  });
});
