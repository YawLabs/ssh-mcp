import { homedir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Harness
//
// Everything under test shells out through `runArgs` (diagnose.ts) or
// `runArgsWithEnv` (env.ts), both thin wrappers over `execFileSync`. Mocking
// `node:child_process` -- rather than the wrappers -- keeps the REAL wrappers,
// the REAL classification and the REAL callers in the run; only the subprocess
// is fake.
//
// The fake records the child ENV as well as argv. That is load-bearing for the
// probeAgent tests: `runArgs` passes NO env (the child inherits process.env) and
// `runArgsWithEnv` passes a full copy, so `call.env === undefined` distinguishes
// the two, and the copy is the only place probeAgent's channel selection is
// observable at all -- it never shows up in the returned AgentResult.
// ---------------------------------------------------------------------------

type FakeRun = { stdout?: string; stderr?: string; fail?: boolean };

interface ExecCall {
  cmd: string;
  args: string[];
  /** The child env, present ONLY when the caller passed one (runArgsWithEnv does; runArgs does not). */
  env?: Record<string, string>;
}

type ExecHandler = (cmd: string, args: string[], env?: Record<string, string>) => FakeRun;

let execHandler: ExecHandler | null = null;
let calls: ExecCall[] = [];

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return {
    ...actual,
    execFileSync: (cmd: string, args: string[], opts?: { env?: Record<string, string> }) => {
      calls.push({ cmd, args, env: opts?.env });
      if (!execHandler) {
        throw new Error(`unexpected subprocess in test: ${cmd} ${args.join(" ")}`);
      }
      const r = execHandler(cmd, args, opts?.env);
      if (r.fail) {
        // Shape matches what execFileSync throws: an Error carrying stdout/stderr
        // buffers. runArgs joins the two, which is how ssh's stderr-only output
        // (ssh -T, ssh-add) reaches the classifiers.
        const err = new Error("Command failed") as Error & { stdout?: Buffer; stderr?: Buffer };
        err.stdout = Buffer.from(r.stdout ?? "");
        err.stderr = Buffer.from(r.stderr ?? "");
        throw err;
      }
      return r.stdout ?? "";
    },
  };
});

// ~/.ssh fake. `sshDir` stays null unless a test opts in, so anything that does
// not touch the directory keeps hitting the real filesystem.
//
//   missing     -> existsSync(~/.ssh) is false          (a fresh machine)
//   unreadable  -> the dir exists, readdirSync THROWS   (EACCES / ENOTDIR)
//   files       -> the dir exists and holds these files
//
// `files` is carried by the unreadable state too, so a test can have readdir
// fail while individual existsSync/readFileSync probes still succeed -- which is
// exactly the situation checkSshKeys' catch block falls back to.
type SshDirState =
  | { kind: "missing" }
  | { kind: "unreadable"; error: Error; files: Record<string, string> }
  | { kind: "files"; files: Record<string, string> };

let sshDir: SshDirState | null = null;

const posix = (p: unknown) => String(p).replace(/\\/g, "/");
const isSshDir = (p: unknown) => posix(p).endsWith("/.ssh");
const sshChildName = (p: unknown): string | null => {
  const m = posix(p).match(/\/\.ssh\/([^/]+)$/);
  return m ? m[1] : null;
};
const stateFiles = (s: SshDirState): Record<string, string> => (s.kind === "missing" ? {} : s.files);

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    existsSync: (p: unknown) => {
      if (sshDir) {
        if (isSshDir(p)) return sshDir.kind !== "missing";
        const name = sshChildName(p);
        if (name !== null) return Object.hasOwn(stateFiles(sshDir), name);
      }
      return actual.existsSync(p as string);
    },
    readdirSync: (p: unknown, ...rest: unknown[]) => {
      if (sshDir && isSshDir(p)) {
        if (sshDir.kind === "unreadable") throw sshDir.error;
        return Object.keys(stateFiles(sshDir));
      }
      return (actual.readdirSync as (...a: unknown[]) => unknown)(p, ...rest);
    },
    statSync: (p: unknown, ...rest: unknown[]) => {
      const name = sshChildName(p);
      if (sshDir && name !== null && Object.hasOwn(stateFiles(sshDir), name)) {
        return { isFile: () => true } as unknown as ReturnType<typeof actual.statSync>;
      }
      return (actual.statSync as (...a: unknown[]) => unknown)(p, ...rest);
    },
    readFileSync: (p: unknown, ...rest: unknown[]) => {
      const name = sshChildName(p);
      if (sshDir && name !== null && Object.hasOwn(stateFiles(sshDir), name)) return stateFiles(sshDir)[name];
      return (actual.readFileSync as (...a: unknown[]) => unknown)(p, ...rest);
    },
  };
});

import { checkConnectivity, checkSshAgent, checkSshKeys, probeSshConnection } from "../diagnose.js";
import { checkGitSsh, ensureAgent, killStartedAgent, listSshKeysDetailed, testConnection } from "../env.js";

// -- process.platform ---------------------------------------------------------
// checkSshAgent's Windows branch and ensureAgent's named-pipe branch are
// platform-exclusive: on any given CI box one of them is unreachable. Both are
// driven explicitly here so BOTH run wherever the suite runs.
const realPlatformDescriptor = Object.getOwnPropertyDescriptor(process, "platform");

function setPlatform(value: NodeJS.Platform): void {
  Object.defineProperty(process, "platform", { value, configurable: true });
}

// -- process.env --------------------------------------------------------------
// ensureAgent MUTATES process.env on its spawn path, so a stub that only tracks
// what the test set would not restore it. Snapshot on first touch instead.
const envSnapshot = new Map<string, string | undefined>();

function setEnv(name: string, value: string | undefined): void {
  if (!envSnapshot.has(name)) envSnapshot.set(name, process.env[name]);
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

/** Env var used to prove the child env is a COPY of process.env, not a fresh object. */
const MARKER = "SSH_MCP_COVERAGE_MARKER";

beforeEach(() => {
  calls = [];
  execHandler = null;
  sshDir = null;
});

afterEach(() => {
  execHandler = null;
  sshDir = null;
  // Drain any pid ensureAgent's spawn path recorded, under a spy, so a leaked
  // module-level pid can never reach a real process.kill.
  const killSpy = vi.spyOn(process, "kill").mockImplementation(() => true);
  killStartedAgent();
  killSpy.mockRestore();
  for (const [k, v] of envSnapshot) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  envSnapshot.clear();
  if (realPlatformDescriptor) Object.defineProperty(process, "platform", realPlatformDescriptor);
});

// ===========================================================================
// GAP -- checkGitSsh carries a SECOND, hand-written copy of the probe
// classification that classifySshProbe unified for checkConnectivity /
// testConnection. Nothing pinned it, so it can drift from the unified one (or
// from the providers' real wording) silently. Every branch and every username
// extraction is pinned here against a real provider transcript.
// ===========================================================================

describe("checkGitSsh classifies each provider's real transcript", () => {
  /** `ssh -T` exits 1 even on success and talks on stderr -- that is the shape runArgs sees. */
  function sshSays(text: string, opts: { exitZero?: boolean } = {}): void {
    execHandler = (cmd) => {
      if (cmd !== "ssh") return { fail: true, stderr: `unexpected command ${cmd}` };
      return opts.exitZero ? { stdout: text } : { fail: true, stderr: text };
    };
  }

  const GITHUB = "Hi jeffy! You've successfully authenticated, but GitHub does not provide shell access.";
  const GITLAB = "Welcome to GitLab, @jeff-yaw!";
  const BITBUCKET =
    "PTY allocation request failed on channel 0\n" +
    "logged in as jeffy.\n\n" +
    "You can use git or hg to connect to Bitbucket. Shell access is disabled.";

  describe("success wordings", () => {
    it("reads GitHub's 'Hi <user>!' + 'successfully authenticated'", () => {
      sshSays(GITHUB);
      const r = checkGitSsh("github.com");
      expect(r.status).toBe("ok");
      expect(r.authenticatedAs).toBe("jeffy");
      expect(r.message).toBe("Git SSH authentication to github.com succeeded as jeffy");
    });

    it("reads GitLab's 'Welcome to GitLab, @<user>!' via the @-form regex", () => {
      sshSays(GITLAB);
      const r = checkGitSsh("gitlab.com");
      expect(r.status).toBe("ok");
      // The GitLab transcript never says "successfully authenticated" -- the
      // "Welcome to GitLab" marker is the only thing that makes this a success.
      expect(r.authenticatedAs).toBe("jeff-yaw");
      expect(r.message).toBe("Git SSH authentication to gitlab.com succeeded as jeff-yaw");
    });

    it("reads Bitbucket's 'logged in as <user>' -- INCLUDING the trailing period (see bugsFound)", () => {
      sshSays(BITBUCKET);
      const r = checkGitSsh("bitbucket.org");
      expect(r.status).toBe("ok");
      // Bitbucket really does write "logged in as jeffy." and `(\S+)` runs to the
      // next whitespace, so the sentence-ending period lands INSIDE the username.
      // Pinned as-is: this documents today's behaviour, it is not an endorsement.
      expect(r.authenticatedAs).toBe("jeffy.");
      expect(r.message).toBe("Git SSH authentication to bitbucket.org succeeded as jeffy.");
    });

    it("reads a period-less 'logged in as <user>' cleanly", () => {
      sshSays("logged in as jeffy");
      expect(checkGitSsh("bitbucket.org").authenticatedAs).toBe("jeffy");
    });

    it("still reports success when no username can be parsed, with no dangling 'as'", () => {
      // A GitHub Enterprise / gitolite instance that says the magic words but not "Hi x!".
      sshSays("You have successfully authenticated to this server.");
      const r = checkGitSsh("ghe.example.test");
      expect(r.status).toBe("ok");
      expect(r.authenticatedAs).toBeUndefined();
      expect(r.message).toBe("Git SSH authentication to ghe.example.test succeeded");
    });

    it("uses the FIRST matching extraction regex: 'Hi <user>!' wins over a later @-form", () => {
      sshSays("Hi jeffy! You've successfully authenticated. Questions? mail @support!");
      expect(checkGitSsh("github.com").authenticatedAs).toBe("jeffy");
    });

    it("lets an @-form in a banner hijack 'logged in as' (see bugsFound)", () => {
      // The @-regex is tried BEFORE the "logged in as" one, so banner text shaped
      // like "@word!" is mistaken for the username. Pinned to lock the extraction
      // ORDER in place; the ordering is what this documents.
      sshSays("Contact @ops-team!\nlogged in as jeffy");
      expect(checkGitSsh("bitbucket.org").authenticatedAs).toBe("ops-team");
    });

    it("checks the success wordings BEFORE the failure wordings", () => {
      // A server that prints a warning alongside the greeting is still a success --
      // the success test is deliberately first.
      sshSays("Permission denied (publickey) for host key check\nHi jeffy! You've successfully authenticated.");
      const r = checkGitSsh("github.com");
      expect(r.status).toBe("ok");
      expect(r.authenticatedAs).toBe("jeffy");
    });

    it("accepts a success transcript delivered on a ZERO exit too", () => {
      sshSays(GITHUB, { exitZero: true });
      expect(checkGitSsh("github.com").status).toBe("ok");
    });
  });

  describe("failure wordings", () => {
    it("maps 'Permission denied' to the key-not-loaded / not-registered fix", () => {
      sshSays("git@github.com: Permission denied (publickey).");
      const r = checkGitSsh("github.com");
      expect(r.status).toBe("error");
      expect(r.authenticatedAs).toBeUndefined();
      expect(r.message).toBe(
        "Permission denied for github.com. Either no key is loaded in the agent or your key isn't registered with github.com. Run ssh_key_list to check, then ssh_key_load if needed.",
      );
    });

    it("maps 'Connection refused'", () => {
      sshSays("ssh: connect to host github.com port 22: Connection refused");
      const r = checkGitSsh("github.com");
      expect(r.status).toBe("error");
      expect(r.message).toBe("Connection refused by github.com. SSH may not be available on this host.");
    });

    it("maps the full 'Connection timed out' spelling", () => {
      sshSays("ssh: connect to host github.com port 22: Connection timed out");
      const r = checkGitSsh("github.com");
      expect(r.status).toBe("error");
      expect(r.message).toBe("Connection to github.com timed out. Check your network or firewall.");
    });

    it("maps the bare 'timed out' spelling as well", () => {
      sshSays("ssh_exchange_identification: read: Operation timed out");
      expect(checkGitSsh("github.com").message).toBe(
        "Connection to github.com timed out. Check your network or firewall.",
      );
    });

    it("maps 'Could not resolve' to a DNS fix", () => {
      sshSays("ssh: Could not resolve hostname githu.com: Name or service not known");
      const r = checkGitSsh("githu.com");
      expect(r.status).toBe("error");
      expect(r.message).toBe('Could not resolve hostname "githu.com". Check DNS or spelling.');
    });

    it("prefers 'Permission denied' over 'Connection refused' when a transcript carries both", () => {
      sshSays("Connection refused\nPermission denied (publickey).");
      expect(checkGitSsh("github.com").message).toContain("Permission denied for github.com");
    });

    it("carries an unrecognised transcript through verbatim instead of guessing", () => {
      sshSays("kex_exchange_identification: banner line contains invalid characters");
      const r = checkGitSsh("github.com");
      expect(r.status).toBe("error");
      expect(r.message).toBe(
        "Git SSH check for github.com: kex_exchange_identification: banner line contains invalid characters",
      );
    });

    it("explains an EMPTY transcript as a possibly-dead agent", () => {
      // A truly silent ssh -- exit 0, nothing on either stream. (A non-zero exit
      // with empty streams is NOT this case: runArgs falls back to the spawn
      // error's own message, so the text is never empty there.)
      sshSays("", { exitZero: true });
      const r = checkGitSsh("github.com");
      expect(r.status).toBe("error");
      expect(r.message).toBe("Git SSH check for github.com: no response (agent may not be running)");
    });
  });

  describe("invocation", () => {
    it("runs exactly `ssh -T -o ConnectTimeout=5 -o BatchMode=yes <user>@<host>`", () => {
      sshSays(GITHUB);
      checkGitSsh("github.com");
      expect(calls).toHaveLength(1);
      expect(calls[0].cmd).toBe("ssh");
      expect(calls[0].args).toEqual(["-T", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes", "git@github.com"]);
    });

    it("passes a non-default user and host through to the ssh target", () => {
      sshSays(GITLAB);
      checkGitSsh("gitlab.example.test", "gitolite");
      expect(calls[0].args.at(-1)).toBe("gitolite@gitlab.example.test");
    });

    it("rejects an invalid hostname BEFORE spawning ssh", () => {
      execHandler = () => ({ stdout: "should not run" });
      const r = checkGitSsh("github.com; whoami");
      expect(r.status).toBe("error");
      expect(r.message).toBe('Invalid hostname: "github.com; whoami"');
      expect(calls).toHaveLength(0);
    });
  });
});

// ===========================================================================
// GAP -- listSshKeys' fingerprint correlation.
//
// `loadedInAgent` is the entire point of ssh_key_list: it is what stops the
// agent from telling an operator to load a key that is already loaded. It is
// computed by matching each key's `ssh-keygen -lf` fingerprint against the set
// parsed out of `ssh-add -l`, and a regression there flips EVERY key to "not
// loaded" while the tool still reports success.
// ===========================================================================

const OPENSSH_PRIV = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----";

const nameOf = (p: string) => posix(p).split("/").pop() as string;

/**
 * Routes the three subprocesses a ~/.ssh scan makes:
 *   ssh-add   -l              -> the agent's loaded set
 *   ssh-keygen -lf <path>     -> one key's fingerprint (the correlation input)
 *   ssh-keygen -l -f <path>   -> detectKeyType's OPENSSH-banner fallback
 * Anything unrouted fails loudly rather than silently answering.
 */
function scanWith(opts: {
  agent?: FakeRun;
  fingerprint?: (name: string) => FakeRun;
  keygenType?: (name: string) => FakeRun;
}): void {
  execHandler = (cmd, args) => {
    if (cmd === "ssh-add" && args[0] === "-l") {
      return opts.agent ?? { fail: true, stderr: "Error connecting to agent: No such file or directory" };
    }
    if (cmd === "ssh-keygen" && args[0] === "-lf") {
      return opts.fingerprint?.(nameOf(args[1])) ?? { fail: true, stderr: "no fingerprint fixture" };
    }
    if (cmd === "ssh-keygen" && args[0] === "-l" && args[1] === "-f") {
      return opts.keygenType?.(nameOf(args[2])) ?? { fail: true, stderr: "no type fixture" };
    }
    return { fail: true, stderr: `unexpected subprocess: ${cmd} ${args.join(" ")}` };
  };
}

describe("listSshKeys correlates ssh-keygen fingerprints against the ssh-add set", () => {
  const FILES = { id_ed25519: OPENSSH_PRIV, work_rsa: OPENSSH_PRIV };

  /** One agent line per loaded key, in `ssh-add -l` shape. */
  const agentHolding = (...lines: string[]): FakeRun => ({ stdout: lines.join("\n") });

  beforeEach(() => {
    sshDir = { kind: "files", files: FILES };
  });

  it("marks only the key whose fingerprint the agent actually holds", () => {
    scanWith({
      agent: agentHolding("256 SHA256:LOADEDaaa jeff@box (ED25519)"),
      fingerprint: (name) =>
        name === "id_ed25519"
          ? { stdout: "256 SHA256:LOADEDaaa jeff@box (ED25519)" }
          : { stdout: "3072 SHA256:OTHERbbb jeff@box (RSA)" },
    });

    const keys = listSshKeysDetailed().keys;
    expect(keys.map((k) => [k.name, k.fingerprint, k.loadedInAgent])).toEqual([
      ["id_ed25519", "SHA256:LOADEDaaa", true],
      ["work_rsa", "SHA256:OTHERbbb", false],
    ]);
  });

  it("requires an EXACT fingerprint match, not a prefix or substring", () => {
    // The agent's entry is one character longer than the key's. A `.includes()`
    // style correlation would call this loaded; set membership must not.
    scanWith({
      agent: agentHolding("256 SHA256:LOADEDaaaX jeff@box (ED25519)"),
      fingerprint: () => ({ stdout: "256 SHA256:LOADEDaaa jeff@box (ED25519)" }),
    });
    expect(listSshKeysDetailed().keys.every((k) => k.loadedInAgent === false)).toBe(true);
  });

  it("treats 'The agent has no identities' as an EMPTY loaded set, not as key data", () => {
    // Without the guard, "The agent has no identities." is parsed for a `\S+:\S+`
    // token like any other line -- there is none here, but the guard is what makes
    // that safe by construction rather than by luck.
    scanWith({
      agent: { stdout: "The agent has no identities." },
      fingerprint: () => ({ stdout: "256 SHA256:LOADEDaaa jeff@box (ED25519)" }),
    });
    const keys = listSshKeysDetailed().keys;
    expect(keys.map((k) => k.loadedInAgent)).toEqual([false, false]);
    // The fingerprints themselves are still reported -- only the correlation is empty.
    expect(keys.map((k) => k.fingerprint)).toEqual(["SHA256:LOADEDaaa", "SHA256:LOADEDaaa"]);
  });

  it("also honours the short 'no identities' spelling", () => {
    scanWith({
      agent: { stdout: "no identities" },
      fingerprint: () => ({ stdout: "256 SHA256:LOADEDaaa jeff@box (ED25519)" }),
    });
    expect(listSshKeysDetailed().keys.map((k) => k.loadedInAgent)).toEqual([false, false]);
  });

  it("reports every key as not-loaded when the agent probe itself fails", () => {
    scanWith({
      agent: { fail: true, stderr: "Could not open a connection to your authentication agent." },
      fingerprint: () => ({ stdout: "256 SHA256:LOADEDaaa jeff@box (ED25519)" }),
    });
    expect(listSshKeysDetailed().keys.map((k) => k.loadedInAgent)).toEqual([false, false]);
  });

  it("leaves fingerprint undefined and loadedInAgent false when ssh-keygen -lf fails for one key", () => {
    scanWith({
      agent: agentHolding("256 SHA256:LOADEDaaa jeff@box (ED25519)"),
      fingerprint: (name) =>
        name === "id_ed25519"
          ? { stdout: "256 SHA256:LOADEDaaa jeff@box (ED25519)" }
          : { fail: true, stderr: "work_rsa is not a public key file." },
    });
    const [ed, rsa] = listSshKeysDetailed().keys;
    expect(ed.loadedInAgent).toBe(true);
    expect(rsa.fingerprint).toBeUndefined();
    expect(rsa.loadedInAgent).toBe(false);
  });

  it("extracts the FIRST colon-bearing token, so a Windows path in the line cannot win", () => {
    // `ssh-keygen -lf C:\Users\jeff\.ssh\id_ed25519` echoes that path back, and
    // "C:\Users\jeff\.ssh\id_ed25519" is itself a `\S+:\S+` token. Anchoring on the
    // first match keeps the fingerprint -- taking the last would correlate paths.
    const line = "256 SHA256:LOADEDaaa C:\\Users\\jeff\\.ssh\\id_ed25519 (ED25519)";
    scanWith({ agent: agentHolding(line), fingerprint: () => ({ stdout: line }) });
    const keys = listSshKeysDetailed().keys;
    expect(keys[0].fingerprint).toBe("SHA256:LOADEDaaa");
    expect(keys.map((k) => k.loadedInAgent)).toEqual([true, true]);
  });

  it("correlates MD5-style fingerprints (`ssh-add -E md5`) as happily as SHA256", () => {
    const md5 = "2048 f0:cd:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee jeff@box (RSA)";
    scanWith({ agent: agentHolding(md5), fingerprint: () => ({ stdout: md5 }) });
    const keys = listSshKeysDetailed().keys;
    expect(keys[0].fingerprint).toBe("f0:cd:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee");
    expect(keys[0].loadedInAgent).toBe(true);
  });

  it("builds the loaded set from EVERY agent line, not just the first", () => {
    scanWith({
      agent: agentHolding("256 SHA256:FIRSTaaa a@box (ED25519)", "3072 SHA256:SECONDbb b@box (RSA)"),
      fingerprint: (name) =>
        name === "id_ed25519"
          ? { stdout: "256 SHA256:FIRSTaaa a@box (ED25519)" }
          : { stdout: "3072 SHA256:SECONDbb b@box (RSA)" },
    });
    expect(listSshKeysDetailed().keys.map((k) => k.loadedInAgent)).toEqual([true, true]);
  });

  it("queries the agent ONCE for the whole scan, not once per key", () => {
    scanWith({
      agent: agentHolding("256 SHA256:LOADEDaaa jeff@box (ED25519)"),
      fingerprint: () => ({ stdout: "256 SHA256:LOADEDaaa jeff@box (ED25519)" }),
    });
    listSshKeysDetailed();
    expect(calls.filter((c) => c.cmd === "ssh-add").length).toBe(1);
    expect(calls.filter((c) => c.cmd === "ssh-keygen" && c.args[0] === "-lf").length).toBe(2);
  });

  it("fingerprints each key by its FULL path, not its bare name", () => {
    scanWith({
      agent: { stdout: "The agent has no identities." },
      fingerprint: () => ({ stdout: "256 SHA256:LOADEDaaa jeff@box (ED25519)" }),
    });
    listSshKeysDetailed();
    const fpCalls = calls.filter((c) => c.cmd === "ssh-keygen" && c.args[0] === "-lf");
    expect(fpCalls.map((c) => c.args[1])).toEqual([
      join(homedir(), ".ssh", "id_ed25519"),
      join(homedir(), ".ssh", "work_rsa"),
    ]);
  });
});

// ===========================================================================
// GAP -- detectKeyType.
//
// Modern ssh-keygen wraps ed25519 -- the DEFAULT key type since OpenSSH 8.5 --
// in the generic `OPENSSH PRIVATE KEY` banner, which none of the type-specific
// PEM banners match. The `ssh-keygen -l -f` fallback is therefore the only thing
// keeping a typical operator's key from being labelled "unknown" in ssh_key_list.
// ===========================================================================

describe("detectKeyType", () => {
  /** Scans a ~/.ssh holding exactly `files` and returns the first key found. */
  function firstKey(files: Record<string, string>, keygenType?: (name: string) => FakeRun) {
    sshDir = { kind: "files", files };
    scanWith({
      agent: { stdout: "The agent has no identities." },
      fingerprint: () => ({ stdout: "256 SHA256:FPaaa jeff@box (ED25519)" }),
      keygenType,
    });
    const keys = listSshKeysDetailed().keys;
    expect(keys).toHaveLength(1);
    return keys[0];
  }

  describe("the .pub sniff comes first", () => {
    it("reads ed25519 out of the public half", () => {
      expect(firstKey({ mykey: OPENSSH_PRIV, "mykey.pub": "ssh-ed25519 AAAAC3NzaC1lZDI1 jeff@box" }).type).toBe(
        "ed25519",
      );
    });

    it("reads rsa out of the public half", () => {
      expect(firstKey({ mykey: OPENSSH_PRIV, "mykey.pub": "ssh-rsa AAAAB3NzaC1yc2E jeff@box" }).type).toBe("rsa");
    });

    it("reads ecdsa out of the public half", () => {
      expect(firstKey({ mykey: OPENSSH_PRIV, "mykey.pub": "ecdsa-sha2-nistp256 AAAAE2VjZHNh jeff@box" }).type).toBe(
        "ecdsa",
      );
    });

    it("reads dsa out of the public half", () => {
      expect(firstKey({ mykey: OPENSSH_PRIV, "mykey.pub": "ssh-dss AAAAB3NzaC1kc3M jeff@box" }).type).toBe("dsa");
    });

    it("beats the filename: an id_rsa holding an ed25519 key is reported as ed25519", () => {
      expect(firstKey({ id_rsa: OPENSSH_PRIV, "id_rsa.pub": "ssh-ed25519 AAAAC3NzaC1lZDI1 jeff@box" }).type).toBe(
        "ed25519",
      );
    });

    it("never shells out when the .pub answered", () => {
      firstKey({ mykey: OPENSSH_PRIV, "mykey.pub": "ssh-ed25519 AAAAC3NzaC1lZDI1 jeff@box" });
      expect(calls.some((c) => c.cmd === "ssh-keygen" && c.args[0] === "-l")).toBe(false);
    });
  });

  describe("filename inference when there is no .pub", () => {
    it("infers ed25519", () => {
      expect(firstKey({ id_ed25519: OPENSSH_PRIV }).type).toBe("ed25519");
    });

    it("infers rsa", () => {
      expect(firstKey({ id_rsa: OPENSSH_PRIV }).type).toBe("rsa");
    });

    it("infers ecdsa -- the check order keeps 'ecdsa' from being read as 'dsa'", () => {
      // "ecdsa".includes("dsa") is true, so a reordering that tests dsa first would
      // label every ECDSA key "dsa".
      expect(firstKey({ id_ecdsa: OPENSSH_PRIV }).type).toBe("ecdsa");
    });

    it("infers dsa", () => {
      expect(firstKey({ legacy_dsa_key: OPENSSH_PRIV }).type).toBe("dsa");
    });

    it("beats the file CONTENT: an id_rsa holding an ed25519 key stays 'rsa' (see bugsFound)", () => {
      // Filename inference runs before the content sniff, so a misnamed key is
      // mislabelled even though ssh-keygen would have said ED25519 -- and the
      // ssh-keygen probe is never issued at all.
      expect(firstKey({ id_rsa: OPENSSH_PRIV }, () => ({ stdout: "256 SHA256:x jeff@box (ED25519)" })).type).toBe(
        "rsa",
      );
      expect(calls.some((c) => c.cmd === "ssh-keygen" && c.args[0] === "-l")).toBe(false);
    });
  });

  describe("PEM banners in the file content", () => {
    it("maps RSA PRIVATE KEY to rsa", () => {
      expect(firstKey({ legacy_pem_a: "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n" }).type).toBe("rsa");
    });

    it("maps EC PRIVATE KEY to ecdsa (not 'ec')", () => {
      expect(firstKey({ legacy_pem_b: "-----BEGIN EC PRIVATE KEY-----\nMHcC\n" }).type).toBe("ecdsa");
    });

    it("maps DSA PRIVATE KEY to dsa", () => {
      expect(firstKey({ legacy_pem_c: "-----BEGIN DSA PRIVATE KEY-----\nMIIB\n" }).type).toBe("dsa");
    });

    it("leaves an unrecognised PKCS#8 banner as 'unknown' without shelling out", () => {
      expect(firstKey({ pkcs8_blob: "-----BEGIN PRIVATE KEY-----\nMIIE\n" }).type).toBe("unknown");
      expect(calls.some((c) => c.cmd === "ssh-keygen" && c.args[0] === "-l")).toBe(false);
    });
  });

  describe("the OPENSSH PRIVATE KEY fallback", () => {
    it("lowercases the trailing (ED25519) that ssh-keygen prints", () => {
      const key = firstKey({ id_default: OPENSSH_PRIV }, () => ({
        stdout: "256 SHA256:FPaaa jeff@box (ED25519)",
      }));
      expect(key.type).toBe("ed25519");
    });

    it("issues `ssh-keygen -l -f <path>` -- the read-only probe that needs no passphrase", () => {
      firstKey({ id_default: OPENSSH_PRIV }, () => ({ stdout: "256 SHA256:FPaaa jeff@box (ED25519)" }));
      const probe = calls.find((c) => c.cmd === "ssh-keygen" && c.args[0] === "-l");
      expect(probe?.args).toEqual(["-l", "-f", join(homedir(), ".ssh", "id_default")]);
    });

    it("handles a hyphenated type such as (ED25519-SK)", () => {
      expect(
        firstKey({ id_default: OPENSSH_PRIV }, () => ({ stdout: "256 SHA256:FPaaa jeff@box (ED25519-SK)" })).type,
      ).toBe("ed25519-sk");
    });

    it("finds the type on the LAST line when ssh-keygen prints a preamble", () => {
      expect(
        firstKey({ id_default: OPENSSH_PRIV }, () => ({
          stdout: "Warning: (deprecated) option ignored\n256 SHA256:FPaaa jeff@box (ED25519)",
        })).type,
      ).toBe("ed25519");
    });

    it("falls back to 'unknown' when ssh-keygen fails", () => {
      expect(firstKey({ id_default: OPENSSH_PRIV }, () => ({ fail: true, stderr: "invalid format" })).type).toBe(
        "unknown",
      );
    });

    it("falls back to 'unknown' when ssh-keygen prints no parenthesised type", () => {
      expect(firstKey({ id_default: OPENSSH_PRIV }, () => ({ stdout: "256 SHA256:FPaaa jeff@box" })).type).toBe(
        "unknown",
      );
    });
  });
});

// ===========================================================================
// GAP -- probeAgent's channel selection.
//
// A `\\.\pipe\` socket must be probed with SSH_AUTH_SOCK DELETED from the child
// env (Windows ssh-add only reaches the OpenSSH agent's named pipe when no
// SSH_AUTH_SOCK is present), while a Unix socket must be probed with
// SSH_AUTH_SOCK SET to the socket the caller asked about. That is the documented
// fix that lets a Windows box carrying a stale WSL-style SSH_AUTH_SOCK still
// reach its named-pipe agent -- and it is invisible in the returned AgentResult,
// so only the CHILD ENV can catch a regression.
// ===========================================================================

const NAMED_PIPE = "\\\\.\\pipe\\openssh-ssh-agent";

/** The child env of the nth recorded subprocess. Fails loudly if none was passed. */
function childEnv(index: number): Record<string, string> {
  const env = calls[index]?.env;
  if (!env) throw new Error(`call ${index} was made WITHOUT an explicit child env`);
  return env;
}

describe("probeAgent picks the right channel for the socket it was given", () => {
  beforeEach(() => {
    setEnv(MARKER, "kept");
  });

  it("SETS SSH_AUTH_SOCK for a Unix socket, on top of a full copy of process.env", () => {
    setPlatform("linux");
    setEnv("SSH_AUTH_SOCK", "/tmp/real-agent.sock");
    execHandler = () => ({ stdout: "256 SHA256:AAA jeff@box (ED25519)" });

    const r = ensureAgent();
    expect(r.reachable).toBe(true);
    expect(r.socket).toBe("/tmp/real-agent.sock");

    const env = childEnv(0);
    expect(env.SSH_AUTH_SOCK).toBe("/tmp/real-agent.sock");
    // Merged on top of process.env, not a fresh object -- ssh-add needs PATH etc.
    expect(env[MARKER]).toBe("kept");
    expect(Object.keys(env).length).toBeGreaterThan(2);
  });

  it("DELETES SSH_AUTH_SOCK for the Windows named pipe, even when the parent has a stale one", () => {
    setPlatform("win32");
    // The exact situation the fall-through exists for: a leftover WSL-style socket
    // that no Windows agent is listening on.
    setEnv("SSH_AUTH_SOCK", "/mnt/wsl/ssh-agent.sock");
    execHandler = (_cmd, _args, env) => {
      if (env && Object.hasOwn(env, "SSH_AUTH_SOCK")) {
        return { fail: true, stderr: "Error connecting to agent: No such file or directory" };
      }
      return { stdout: "256 SHA256:AAA jeff@box (ED25519)" };
    };

    const r = ensureAgent();
    expect(r.reachable).toBe(true);
    expect(r.socket).toBe(NAMED_PIPE);
    expect(r.message).toBe("Windows OpenSSH agent running with 1 key(s) loaded");

    // First probe: the stale socket, passed through as-is.
    expect(childEnv(0).SSH_AUTH_SOCK).toBe("/mnt/wsl/ssh-agent.sock");
    // Second probe: the named pipe, with SSH_AUTH_SOCK removed -- not merely absent
    // from an override map, actually deleted from the inherited copy.
    const pipeEnv = childEnv(1);
    expect(Object.hasOwn(pipeEnv, "SSH_AUTH_SOCK")).toBe(false);
    expect(pipeEnv[MARKER]).toBe("kept");
  });

  it("probes the named pipe on win32 even with NO SSH_AUTH_SOCK at all", () => {
    setPlatform("win32");
    setEnv("SSH_AUTH_SOCK", undefined);
    execHandler = () => ({ stdout: "256 SHA256:AAA jeff@box (ED25519)" });

    const r = ensureAgent();
    expect(r.socket).toBe(NAMED_PIPE);
    expect(calls).toHaveLength(1);
    expect(Object.hasOwn(childEnv(0), "SSH_AUTH_SOCK")).toBe(false);
  });

  it("counts every ssh-add line as a loaded key", () => {
    setPlatform("linux");
    setEnv("SSH_AUTH_SOCK", "/tmp/real-agent.sock");
    execHandler = () => ({ stdout: "256 SHA256:AAA a@box (ED25519)\n3072 SHA256:BBB b@box (RSA)\n" });

    const r = ensureAgent();
    expect(r.keys).toEqual(["256 SHA256:AAA a@box (ED25519)", "3072 SHA256:BBB b@box (RSA)"]);
    expect(r.message).toBe("ssh-agent running with 2 key(s) loaded");
    expect(r.started).toBe(false);
  });

  it("treats 'no identities' as REACHABLE with zero keys and stops looking for another channel", () => {
    // win32 deliberately: a reachable-but-empty agent on the SSH_AUTH_SOCK channel
    // must NOT fall through to the named pipe, or an empty agent would be reported
    // as the Windows one.
    setPlatform("win32");
    setEnv("SSH_AUTH_SOCK", "/tmp/empty-agent.sock");
    execHandler = () => ({ fail: true, stderr: "The agent has no identities." });

    const r = ensureAgent();
    expect(r.reachable).toBe(true);
    expect(r.keys).toEqual([]);
    expect(r.socket).toBe("/tmp/empty-agent.sock");
    expect(r.message).toBe("ssh-agent running but no keys loaded. Use ssh_key_load to add one.");
    expect(calls).toHaveLength(1);
  });

  it("reports the Windows remedy -- and spawns NO ssh-agent -- when no channel answers", () => {
    setPlatform("win32");
    setEnv("SSH_AUTH_SOCK", "/mnt/wsl/ssh-agent.sock");
    execHandler = () => ({ fail: true, stderr: "Error connecting to agent: No such file or directory" });

    const r = ensureAgent();
    expect(r.running).toBe(false);
    expect(r.reachable).toBe(false);
    expect(r.message).toContain("Windows OpenSSH agent not running");
    expect(r.message).toContain("Start-Service ssh-agent");
    // The `ssh-agent -s` spawn is skipped on win32 on purpose: it would orphan a
    // process whose socket the rest of the stack cannot reach.
    expect(calls.some((c) => c.cmd === "ssh-agent")).toBe(false);
  });
});

// ===========================================================================
// GAP -- ensureAgent's Unix spawn path and killStartedAgent.
//
// index.ts calls killStartedAgent() on BOTH the signal path and the exit path
// specifically so a server run that spawned its own agent does not leave a
// daemon behind. Nothing verified that the pid is captured in the first place,
// nor that kill is actually issued for it.
// ===========================================================================

describe("ensureAgent spawns an agent on Unix and killStartedAgent reaps it", () => {
  const SOCK = "/tmp/ssh-abc123/agent.4242";
  const AGENT_OUT =
    `SSH_AUTH_SOCK=${SOCK}; export SSH_AUTH_SOCK;\n` +
    "SSH_AGENT_PID=4242; export SSH_AGENT_PID;\n" +
    "echo Agent pid 4242;";

  /** Pids handed to process.kill while the fake below is installed. */
  const killed: number[] = [];
  let killError: Error | null = null;
  let realKill: typeof process.kill;

  beforeEach(() => {
    setPlatform("linux");
    setEnv("SSH_AUTH_SOCK", undefined);
    setEnv("SSH_AGENT_PID", undefined);
    killed.length = 0;
    killError = null;
    realKill = process.kill;
    process.kill = ((pid: number) => {
      killed.push(pid);
      if (killError) throw killError;
      return true;
    }) as typeof process.kill;
  });

  afterEach(() => {
    // Drain the module-level pid while the fake is still installed, so no test can
    // leak a recorded pid into a real process.kill.
    killStartedAgent();
    process.kill = realKill;
  });

  /** `ssh-agent -s` answers with `out`; everything else fails. */
  function agentSpawns(out: FakeRun): void {
    execHandler = (cmd, args) => {
      if (cmd === "ssh-agent" && args[0] === "-s") return out;
      return { fail: true, stderr: "Could not open a connection to your authentication agent." };
    };
  }

  it("parses SSH_AUTH_SOCK and SSH_AGENT_PID out of the Bourne-shell output", () => {
    agentSpawns({ stdout: AGENT_OUT });

    const r = ensureAgent();
    expect(r.started).toBe(true);
    expect(r.running).toBe(true);
    expect(r.reachable).toBe(true);
    expect(r.socket).toBe(SOCK);
    expect(r.env).toEqual({ SSH_AUTH_SOCK: SOCK, SSH_AGENT_PID: "4242" });
    expect(r.keys).toEqual([]);
    expect(r.message).toContain("Started new ssh-agent scoped to the ssh-mcp server process.");
  });

  it("exports the spawned agent into process.env so later ssh-add calls reach it", () => {
    agentSpawns({ stdout: AGENT_OUT });
    ensureAgent();
    expect(process.env.SSH_AUTH_SOCK).toBe(SOCK);
    expect(process.env.SSH_AGENT_PID).toBe("4242");
  });

  it("does not probe an agent at all when SSH_AUTH_SOCK is unset -- it goes straight to the spawn", () => {
    agentSpawns({ stdout: AGENT_OUT });
    ensureAgent();
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ cmd: "ssh-agent", args: ["-s"] });
  });

  it("falls through to the spawn when a SET SSH_AUTH_SOCK turns out to be dead", () => {
    setEnv("SSH_AUTH_SOCK", "/tmp/stale.sock");
    agentSpawns({ stdout: AGENT_OUT });

    const r = ensureAgent();
    expect(r.started).toBe(true);
    expect(r.socket).toBe(SOCK);
    expect(calls.map((c) => c.cmd)).toEqual(["ssh-add", "ssh-agent"]);
  });

  it("kills exactly the pid it recorded, once", () => {
    agentSpawns({ stdout: AGENT_OUT });
    ensureAgent();

    killStartedAgent();
    expect(killed).toEqual([4242]);

    // index.ts calls this from both the signal handler and the exit handler, so the
    // second call must be a no-op rather than a second kill (or a kill of a pid the
    // OS has since recycled).
    killStartedAgent();
    expect(killed).toEqual([4242]);
  });

  it("swallows a kill against an already-dead pid and still clears it", () => {
    agentSpawns({ stdout: AGENT_OUT });
    ensureAgent();
    killError = Object.assign(new Error("kill ESRCH"), { code: "ESRCH" });

    expect(() => killStartedAgent()).not.toThrow();
    expect(killed).toEqual([4242]);

    // The pid is cleared even though the kill threw, so shutdown does not retry it.
    killError = null;
    killStartedAgent();
    expect(killed).toEqual([4242]);
  });

  it("kills nothing when no agent was ever spawned", () => {
    killStartedAgent();
    expect(killed).toEqual([]);
  });

  it("records NO pid when ssh-agent printed a socket but no SSH_AGENT_PID", () => {
    agentSpawns({ stdout: `SSH_AUTH_SOCK=${SOCK}; export SSH_AUTH_SOCK;` });

    const r = ensureAgent();
    expect(r.started).toBe(true);
    expect(r.env).toEqual({ SSH_AUTH_SOCK: SOCK, SSH_AGENT_PID: undefined });
    expect(process.env.SSH_AGENT_PID).toBeUndefined();

    killStartedAgent();
    expect(killed).toEqual([]);
  });

  it("reports the manual remedy when ssh-agent -s fails, and records no pid", () => {
    agentSpawns({ fail: true, stderr: "ssh-agent: command not found" });

    const r = ensureAgent();
    expect(r.running).toBe(false);
    expect(r.reachable).toBe(false);
    expect(r.started).toBe(false);
    expect(r.message).toBe('Could not start ssh-agent. Run manually: eval "$(ssh-agent -s)"');

    killStartedAgent();
    expect(killed).toEqual([]);
  });

  it("treats a zero-exit ssh-agent that printed no socket as a failure, and captures no pid", () => {
    // The pid capture is nested INSIDE the socket branch: no socket means no
    // startedAgentPid, even though SSH_AGENT_PID is right there in the output.
    agentSpawns({ stdout: "SSH_AGENT_PID=4242; export SSH_AGENT_PID;" });

    const r = ensureAgent();
    expect(r.started).toBe(false);
    expect(r.message).toBe('Could not start ssh-agent. Run manually: eval "$(ssh-agent -s)"');
    expect(process.env.SSH_AGENT_PID).toBeUndefined();

    killStartedAgent();
    expect(killed).toEqual([]);
  });
});

// ===========================================================================
// GAP -- checkSshAgent's two platform-exclusive branches.
//
// The Windows named-pipe branch and the non-win32 "SSH_AUTH_SOCK is not set"
// error can never both run on one machine, so exactly one of them is dead code
// on whatever box runs this suite. process.platform is controlled explicitly so
// BOTH execute here.
// ===========================================================================

describe("checkSshAgent -- both platform branches", () => {
  describe("win32 with no SSH_AUTH_SOCK (the named-pipe branch)", () => {
    beforeEach(() => {
      setPlatform("win32");
      setEnv("SSH_AUTH_SOCK", undefined);
    });

    it("reports the agent's key list on a successful ssh-add", () => {
      execHandler = () => ({ stdout: "256 SHA256:AAA jeff@box (ED25519)" });
      const r = checkSshAgent();
      expect(r.status).toBe("ok");
      expect(r.message).toBe("Windows OpenSSH agent running with keys:\n256 SHA256:AAA jeff@box (ED25519)");
    });

    it("warns (not errors) when the agent answers 'The agent has no identities' on a NON-zero exit", () => {
      execHandler = () => ({ fail: true, stderr: "The agent has no identities." });
      const r = checkSshAgent();
      expect(r.status).toBe("warning");
      expect(r.message).toBe("Windows OpenSSH agent is running but has no keys loaded. Run: ssh-add <key-path>");
    });

    it("also accepts the short 'no identities' spelling", () => {
      execHandler = () => ({ fail: true, stderr: "no identities" });
      expect(checkSshAgent().status).toBe("warning");
    });

    it("errors with the Windows service remedy when ssh-add cannot reach any agent", () => {
      execHandler = () => ({ fail: true, stderr: "Error connecting to agent: No such file or directory" });
      const r = checkSshAgent();
      expect(r.status).toBe("error");
      expect(r.message).toBe(
        "Windows OpenSSH Authentication Agent is not running. Start it: Get-Service ssh-agent | Set-Service -StartupType Automatic; Start-Service ssh-agent",
      );
    });

    it("checks the exit code BEFORE 'no identities', unlike the generic branch (see bugsFound)", () => {
      // A build that reports an empty agent on a ZERO exit is reported "ok" here,
      // with the empty-agent notice pasted in where the key list belongs. The
      // generic branch below calls the same output a warning. Pinned to document
      // the divergence, not to bless it.
      execHandler = () => ({ stdout: "The agent has no identities." });
      const r = checkSshAgent();
      expect(r.status).toBe("ok");
      expect(r.message).toBe("Windows OpenSSH agent running with keys:\nThe agent has no identities.");
    });

    it("is gated on SSH_AUTH_SOCK being UNSET -- with one set, win32 takes the generic path", () => {
      setEnv("SSH_AUTH_SOCK", "/tmp/from-git-bash.sock");
      execHandler = () => ({ fail: true, stderr: "Could not open a connection to your authentication agent." });
      const r = checkSshAgent();
      expect(r.status).toBe("error");
      expect(r.message).toContain('SSH_AUTH_SOCK is set to "/tmp/from-git-bash.sock"');
      expect(r.message).not.toContain("Windows OpenSSH Authentication Agent");
    });
  });

  describe("non-win32 with no SSH_AUTH_SOCK", () => {
    beforeEach(() => {
      setPlatform("linux");
      setEnv("SSH_AUTH_SOCK", undefined);
    });

    it("errors without spawning anything at all", () => {
      execHandler = () => ({ stdout: "should never run" });
      const r = checkSshAgent();
      expect(r.status).toBe("error");
      expect(r.message).toBe("SSH_AUTH_SOCK is not set. ssh-agent is not running or not exported to this shell.");
      expect(calls).toHaveLength(0);
    });

    it("calls a zero-exit 'no identities' a WARNING here -- the mirror of the win32 wart above", () => {
      setEnv("SSH_AUTH_SOCK", "/tmp/agent.sock");
      execHandler = () => ({ stdout: "The agent has no identities." });
      const r = checkSshAgent();
      expect(r.status).toBe("warning");
      expect(r.message).toBe("ssh-agent is running but has no keys loaded. Run: ssh-add <key-path>");
    });
  });
});

// ===========================================================================
// GAP -- probeSshConnection's argv.
//
// A dropped `-p` makes ssh_test probe port 22 while reporting success for
// :2222 -- a false green on the exact check an operator runs BEFORE trusting a
// non-standard-port host.
// ===========================================================================

describe("probeSshConnection builds the ssh argv it claims to", () => {
  const expectedArgs = (host: string, port: string) => [
    "-o",
    "ConnectTimeout=5",
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=no",
    "-p",
    port,
    "--",
    host,
    "echo",
    "SSH_OK",
  ];

  it("passes the requested port through as `-p <port>`", () => {
    execHandler = () => ({ stdout: "SSH_OK" });
    const r = probeSshConnection("box.example.test", 2222);
    expect(r.outcome).toBe("ok");
    expect(calls).toHaveLength(1);
    expect(calls[0].cmd).toBe("ssh");
    expect(calls[0].args).toEqual(expectedArgs("box.example.test", "2222"));
  });

  it("spells the default port explicitly rather than omitting -p", () => {
    execHandler = () => ({ stdout: "SSH_OK" });
    probeSshConnection("box.example.test", 22);
    expect(calls[0].args).toEqual(expectedArgs("box.example.test", "22"));
  });

  it("puts `--` immediately before the host so nothing after it is read as a flag", () => {
    execHandler = () => ({ stdout: "SSH_OK" });
    probeSshConnection("box.example.test", 22);
    const args = calls[0].args;
    expect(args[args.indexOf("--") + 1]).toBe("box.example.test");
  });

  it("reports elapsed wall time for the invocation", () => {
    execHandler = () => ({ stdout: "SSH_OK" });
    const r = probeSshConnection("box.example.test", 22);
    expect(typeof r.elapsedMs).toBe("number");
    expect(r.elapsedMs).toBeGreaterThanOrEqual(0);
  });

  it("does NOT report ok on a zero exit that never echoed SSH_OK", () => {
    execHandler = () => ({ stdout: "Welcome to Ubuntu" });
    const r = probeSshConnection("box.example.test", 22);
    expect(r.outcome).toBe("unknown");
    expect(r.output).toBe("Welcome to Ubuntu");
  });

  it("carries the port into ssh_test's probe, not just into its message", () => {
    execHandler = () => ({ stdout: "SSH_OK" });
    const r = testConnection("box.example.test", 2222);
    expect(r.status).toBe("ok");
    expect(r.message).toContain("box.example.test:2222");
    expect(calls[0].args).toEqual(expectedArgs("box.example.test", "2222"));
  });

  it("carries the port into the diagnose() connectivity check too", () => {
    execHandler = () => ({ stdout: "SSH_OK" });
    const r = checkConnectivity("box.example.test", 2222);
    expect(r.status).toBe("ok");
    expect(calls[0].args).toEqual(expectedArgs("box.example.test", "2222"));
  });

  it("uses port 22 when the diagnose() check is called without one", () => {
    execHandler = () => ({ stdout: "SSH_OK" });
    checkConnectivity("box.example.test");
    expect(calls[0].args).toEqual(expectedArgs("box.example.test", "22"));
  });
});

// ===========================================================================
// GAP -- checkSshKeys on a fresh machine, and how it differs from the
// listSshKeys scan of the same directory.
// ===========================================================================

describe("checkSshKeys on a fresh machine", () => {
  const NO_KEYS = 'No SSH private keys found in ~/.ssh/. Generate one: ssh-keygen -t ed25519 -C "your@email.com"';

  it("tells the operator to create ~/.ssh when the directory does not exist", () => {
    sshDir = { kind: "missing" };
    const r = checkSshKeys();
    expect(r.status).toBe("error");
    expect(r.message).toBe("~/.ssh directory does not exist. Run: mkdir -p ~/.ssh && chmod 700 ~/.ssh");
  });

  it("tells the operator to generate a key when the directory exists but is empty", () => {
    sshDir = { kind: "files", files: {} };
    const r = checkSshKeys();
    expect(r.status).toBe("error");
    expect(r.message).toBe(NO_KEYS);
  });

  it("still reports 'no keys' when the directory holds only non-key files", () => {
    sshDir = {
      kind: "files",
      files: { known_hosts: "host ssh-ed25519 AAA", config: "Host *\n  User jeff", environment: "FOO=bar" },
    };
    expect(checkSshKeys().message).toBe(NO_KEYS);
  });

  it("still reports 'no keys' when the directory holds only a PUBLIC key", () => {
    sshDir = { kind: "files", files: { "id_ed25519.pub": "ssh-ed25519 AAAAC3 jeff@box" } };
    expect(checkSshKeys().message).toBe(NO_KEYS);
  });

  it("finds a default-named key by EXISTENCE alone, without reading it", () => {
    // The keyTypes loop is a pure existsSync check -- a zero-byte id_ed25519 counts.
    sshDir = { kind: "files", files: { id_ed25519: "" } };
    const r = checkSshKeys();
    expect(r.status).toBe("ok");
    expect(r.message).toBe("Found SSH keys: id_ed25519");
  });

  it("finds a non-default key only when its CONTENT looks like a private key", () => {
    sshDir = { kind: "files", files: { work_key: OPENSSH_PRIV, notes_txt: "just a note" } };
    const r = checkSshKeys();
    expect(r.status).toBe("ok");
    expect(r.message).toBe("Found SSH keys: work_key");
  });

  it("lists the default keys first, then the content-detected ones", () => {
    sshDir = { kind: "files", files: { work_key: OPENSSH_PRIV, id_rsa: "", id_ed25519: "" } };
    expect(checkSshKeys().message).toBe("Found SSH keys: id_ed25519, id_rsa, work_key");
  });

  it("falls back to the default-name check when readdir fails", () => {
    sshDir = { kind: "unreadable", error: new Error("EACCES: permission denied, scandir"), files: { id_ed25519: "" } };
    const r = checkSshKeys();
    expect(r.status).toBe("ok");
    expect(r.message).toBe("Found SSH keys: id_ed25519");
  });

  it("reports 'no keys' when readdir fails and no default-named key exists either", () => {
    sshDir = { kind: "unreadable", error: new Error("ENOTDIR: not a directory, scandir"), files: {} };
    expect(checkSshKeys().message).toBe(NO_KEYS);
  });

  it("counts a DOTFILE private key that listSshKeys deliberately skips (see bugsFound)", () => {
    // checkSshKeys filters only *.pub and SSH_NON_KEY_FILES; listSshKeys also skips
    // anything starting with ".". The two scanners disagree about this one file.
    sshDir = { kind: "files", files: { ".hidden_key": OPENSSH_PRIV } };
    expect(checkSshKeys().message).toBe("Found SSH keys: .hidden_key");

    scanWith({ agent: { stdout: "The agent has no identities." } });
    expect(listSshKeysDetailed().keys).toEqual([]);
  });
});

describe("listSshKeysDetailed distinguishes an empty ~/.ssh from an unusable one", () => {
  it("returns status 'no-dir' without probing the agent at all", () => {
    sshDir = { kind: "missing" };
    execHandler = () => ({ stdout: "should never run" });
    const r = listSshKeysDetailed();
    expect(r.status).toBe("no-dir");
    expect(r.dir).toBe(join(homedir(), ".ssh"));
    expect(r.keys).toEqual([]);
    expect(calls).toHaveLength(0);
  });

  it("returns status 'unreadable' with the errno reason when readdir throws", () => {
    sshDir = {
      kind: "unreadable",
      error: new Error("EACCES: permission denied, scandir '/home/jeff/.ssh'"),
      files: {},
    };
    scanWith({ agent: { stdout: "The agent has no identities." } });
    const r = listSshKeysDetailed();
    expect(r.status).toBe("unreadable");
    expect(r.keys).toEqual([]);
    expect(r.status === "unreadable" && r.reason).toContain("EACCES: permission denied");
  });

  it("returns status 'ok' with an empty list when the directory holds no keys", () => {
    sshDir = { kind: "files", files: { known_hosts: "host ssh-ed25519 AAA" } };
    scanWith({ agent: { stdout: "The agent has no identities." } });
    const r = listSshKeysDetailed();
    expect(r.status).toBe("ok");
    expect(r.keys).toEqual([]);
  });
});
