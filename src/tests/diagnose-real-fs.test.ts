import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanPrivateKeyFiles } from "../diagnose.js";

// ---------------------------------------------------------------------------
// scanPrivateKeyFiles against a REAL directory.
//
// The other scan tests mock node:fs, whose openSync ignores the flags argument, so
// they cannot see whether the open is O_NONBLOCK. A FIFO left in ~/.ssh (a control
// path, a forwarding socket's sibling) would block a plain O_RDONLY open until some
// writer appeared -- hanging ssh_diagnose and ssh_key_list.
//
// A blocked openSync blocks this whole thread, so a vitest timeout could never fire.
// Instead a separate process opens the FIFO for writing after WRITER_DELAY_MS, which
// is what would release a blocked reader: a non-blocking scan returns long before that,
// a blocking one returns only after it, and the elapsed time tells them apart.
// ---------------------------------------------------------------------------

const KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n";
const WRITER_DELAY_MS = 2000;

/** Skip reason: POSIX FIFOs need mkfifo and a non-Windows kernel. */
const hasFifo =
  process.platform !== "win32" && spawnSync("mkfifo", ["--help"], { stdio: "ignore" }).error === undefined;

describe.skipIf(!hasFifo)("scanPrivateKeyFiles on a real directory (skipped: needs POSIX mkfifo, not win32)", () => {
  let dir: string | undefined;
  let writer: ChildProcess | undefined;

  afterEach(() => {
    writer?.kill("SIGKILL");
    writer = undefined;
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = undefined;
  });

  it("skips a FIFO without blocking and returns only the regular key file", () => {
    dir = mkdtempSync(join(tmpdir(), "ssh-mcp-scan-"));
    writeFileSync(join(dir, "id_ed25519"), KEY);
    writeFileSync(join(dir, ".hidden_key"), KEY); // dotfile: skipped by name
    writeFileSync(join(dir, "id_ed25519.pub"), "ssh-ed25519 AAAA test\n");
    writeFileSync(join(dir, "notes.txt"), "not a key\n");
    mkdirSync(join(dir, "subdir"));
    const fifo = join(dir, "control-fifo");
    expect(spawnSync("mkfifo", [fifo]).status).toBe(0);

    writer = spawn(
      process.execPath,
      ["-e", `setTimeout(() => require("node:fs").openSync(${JSON.stringify(fifo)}, "w"), ${WRITER_DELAY_MS})`],
      { stdio: "ignore" },
    );

    const start = Date.now();
    const found = scanPrivateKeyFiles(dir);
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(WRITER_DELAY_MS / 2);
    expect(found.map((c) => c.name)).toEqual(["id_ed25519"]);
    expect(found[0].content).toBe(KEY);
    expect(found[0].path).toBe(join(dir, "id_ed25519"));
  });
});
