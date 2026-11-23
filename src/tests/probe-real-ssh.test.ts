import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { Worker } from "node:worker_threads";
import { utils } from "ssh2";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { classifySshProbe, probeSshArgs, runArgs } from "../diagnose.js";

// ---------------------------------------------------------------------------
// The probe against a REAL ssh client.
//
// Every other probe test fakes execFileSync and checks argv strings. That cannot
// show what the real client does with `UserKnownHostsFile=/dev/null <pins...>` --
// whether the accepted key really lands in the null device, whether the pins stay
// byte-identical, whether some build creates a file called NUL -- nor that real
// OpenSSH wording classifies the way classifySshProbe assumes.
//
// SAFETY: the probe's production argv names ~/.ssh/known_hosts, and OpenSSH expands
// `~` from the passwd entry, not $HOME, so it can never be pointed at a scratch home.
// The argv here comes from the SAME probeSshArgs production uses, with only the pin
// files swapped for temp-dir copies. The developer's real known_hosts is snapshotted
// and checked as a backstop, never written.
//
// The ssh2 Server runs in a worker thread because runArgs is execFileSync: it blocks
// this thread for the whole ssh run, so a server on this thread could never answer.
// ---------------------------------------------------------------------------

/** Skip reason: the real client is the whole point, so no ssh on PATH means no test. */
const hasSsh = spawnSync("ssh", ["-V"], { stdio: "ignore", windowsHide: true }).status === 0;

const HOST_KEY = utils.generateKeyPairSync("ed25519");
const OTHER_KEY = utils.generateKeyPairSync("ed25519");
const ssh2Path = createRequire(import.meta.url).resolve("ssh2");

// Rejects every auth attempt: the probe needs a host key exchange, not a login.
const SERVER_SRC = `
const { parentPort, workerData } = require("node:worker_threads");
const { Server } = require(workerData.ssh2Path);
const server = new Server({ hostKeys: [workerData.hostKey] }, (client) => {
  client.on("error", () => {});
  client.on("authentication", (ctx) => ctx.reject(["publickey"]));
});
server.listen(0, "127.0.0.1", () => parentPort.postMessage(server.address().port));
`;

const REAL_KNOWN_HOSTS = join(homedir(), ".ssh", "known_hosts");
const snapshot = (p: string): string | null => (existsSync(p) ? readFileSync(p, "latin1") : null);
const nulEntries = (): string[] => readdirSync(process.cwd()).filter((n) => n.toLowerCase() === "nul");

describe.skipIf(!hasSsh)(
  `probeSshArgs against a real ssh client${hasSsh ? "" : " (skipped: no `ssh` on PATH)"}`,
  () => {
    let worker: Worker;
    let port: number;
    let realKnownHostsBefore: string | null;
    let nulBefore: string[];
    let dir: string;
    let pinA: string;
    let pinB: string;

    beforeAll(async () => {
      realKnownHostsBefore = snapshot(REAL_KNOWN_HOSTS);
      nulBefore = nulEntries();
      worker = new Worker(SERVER_SRC, { eval: true, workerData: { ssh2Path, hostKey: HOST_KEY.private } });
      port = await new Promise<number>((resolve, reject) => {
        worker.once("message", resolve);
        worker.once("error", reject);
      });
    });

    afterAll(async () => {
      await worker?.terminate();
      // Backstop: the real file was never in the argv, so it must be exactly as found.
      expect(snapshot(REAL_KNOWN_HOSTS)).toBe(realKnownHostsBefore);
    });

    beforeEach(() => {
      dir = mkdtempSync(join(tmpdir(), "ssh-mcp-probe-"));
      // Forward slashes: the list is whitespace-separated and both ssh builds take C:/...
      pinA = join(dir, "known_hosts").replace(/\\/g, "/");
      pinB = join(dir, "known_hosts2").replace(/\\/g, "/");
      return () => rmSync(dir, { recursive: true, force: true });
    });

    const entry = (pub: string) => `[127.0.0.1]:${port} ${pub}\n`;
    const probe = (strict: boolean) => {
      const { ok, stdout } = runArgs("ssh", probeSshArgs("127.0.0.1", port, [pinA, pinB], strict));
      return { ok, stdout, outcome: classifySshProbe(ok, stdout) };
    };

    it("discards an accepted unknown key into the first-listed /dev/null and leaves every pin file untouched", () => {
      // pinA exists with an unrelated entry; pinB does not exist at all.
      const unrelated = "unrelated.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIUnrelatedUnrelatedUnrelatedUnrelated00\n";
      writeFileSync(pinA, unrelated);

      const r = probe(false);

      // accept-new took the key and went on to auth, which the server refuses.
      expect(r.outcome, r.stdout).toBe("permission-denied");
      expect(readFileSync(pinA, "latin1")).toBe(unrelated);
      expect(readFileSync(pinA, "latin1")).not.toContain(`[127.0.0.1]:${port}`);
      expect(existsSync(pinB)).toBe(false);
      // MSYS ssh writes a relative `NUL` file when given NUL instead of /dev/null.
      expect(nulEntries()).toEqual(nulBefore);
    });

    it("strict mode refuses an unpinned host as host-key-unknown on real OpenSSH wording", () => {
      const r = probe(true);
      expect(r.ok).toBe(false);
      expect(r.stdout).toMatch(/host key is known for/);
      expect(r.outcome, r.stdout).toBe("host-key-unknown");
      expect(existsSync(pinA)).toBe(false);
      expect(existsSync(pinB)).toBe(false);
    });

    it.each([
      ["strict", true],
      ["accept-new", false],
    ])("a pinned-then-changed key is host-key-mismatch (%s) and the pin is not rewritten", (_label, strict) => {
      const stale = entry(OTHER_KEY.public);
      writeFileSync(pinB, stale); // the LAST listed file: every pin file is read, not just the first

      const r = probe(strict);

      expect(r.ok).toBe(false);
      expect(r.outcome, r.stdout).toBe("host-key-mismatch");
      expect(readFileSync(pinB, "latin1")).toBe(stale);
      expect(existsSync(pinA)).toBe(false);
    });

    it("a correctly pinned key passes the host-key check (strict) and reaches auth", () => {
      const pinned = entry(HOST_KEY.public);
      writeFileSync(pinA, pinned);

      const r = probe(true);

      expect(r.outcome, r.stdout).toBe("permission-denied");
      expect(readFileSync(pinA, "latin1")).toBe(pinned);
    });
  },
);

describe("runArgs against a real child that outlives its timeout", () => {
  it("reports the kill as a timeout the probe classifier recognises", () => {
    const start = Date.now();
    const r = runArgs(process.execPath, ["-e", "setTimeout(() => {}, 60000)"], { timeoutMs: 300 });

    expect(Date.now() - start).toBeLessThan(5000);
    expect(r.ok).toBe(false);
    expect(r.stdout).toContain("timed out after 0.3s and was killed");
    expect(classifySshProbe(false, r.stdout)).toBe("timed-out");
  });
});
