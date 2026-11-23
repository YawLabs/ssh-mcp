import { homedir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { downloadFile, expandTilde, uploadFile } from "../ssh.js";

// Fake SFTP wrapper that captures the local path passed to fastPut / fastGet.
function makeFakeSftp() {
  const calls = { fastPut: [] as string[], fastGet: [] as string[] };
  const sftp = {
    // uploadFile/downloadFile pass an options object ({ step }) before the callback,
    // so the callback is always the LAST argument.
    fastPut: vi.fn((localPath: string, _remotePath: string, ...rest: unknown[]) => {
      calls.fastPut.push(localPath);
      (rest[rest.length - 1] as (err: null) => void)(null);
    }),
    fastGet: vi.fn((_remotePath: string, localPath: string, ...rest: unknown[]) => {
      calls.fastGet.push(localPath);
      (rest[rest.length - 1] as (err: null) => void)(null);
    }),
    end: vi.fn(),
  };
  return { sftp, calls };
}

// Minimal fake Client whose sftp() method immediately hands back our stub.
function makeFakeClient(sftp: ReturnType<typeof makeFakeSftp>["sftp"]) {
  return {
    sftp: (cb: (err: null, sftp: unknown) => void) => cb(null, sftp),
  } as unknown as import("ssh2").Client;
}

describe("uploadFile tilde expansion in localPath", () => {
  it("expands ~ to the home directory", async () => {
    const { sftp, calls } = makeFakeSftp();
    await uploadFile(makeFakeClient(sftp), "~/.config/app.conf", "/remote/app.conf");
    expect(calls.fastPut[0]).toBe(join(homedir(), ".config/app.conf"));
  });

  it("leaves absolute paths unchanged", async () => {
    const { sftp, calls } = makeFakeSftp();
    await uploadFile(makeFakeClient(sftp), "/tmp/file.txt", "/remote/file.txt");
    expect(calls.fastPut[0]).toBe("/tmp/file.txt");
  });

  it("handles nested paths under ~", async () => {
    const { sftp, calls } = makeFakeSftp();
    await uploadFile(makeFakeClient(sftp), "~/data/export.csv", "/remote/export.csv");
    expect(calls.fastPut[0]).toBe(join(homedir(), "data/export.csv"));
  });
});

describe("tilde spellings that are NOT the current user's home are left alone", () => {
  // `~alice/...` is another user's home and `~backup.key` is a relative file whose
  // name starts with a tilde. Both used to be joined onto OUR home, producing an
  // ENOENT for a path the caller never named.
  it.each(["~alice/.ssh/id_ed25519", "~backup.key", "~"])("uploadFile keeps %s's meaning", async (p) => {
    const { sftp, calls } = makeFakeSftp();
    await uploadFile(makeFakeClient(sftp), p, "/remote/x");
    expect(calls.fastPut[0]).toBe(p === "~" ? homedir() : p);
  });

  it("downloadFile leaves ~name untouched too", async () => {
    const { sftp, calls } = makeFakeSftp();
    await downloadFile(makeFakeClient(sftp), "/remote/x", "~bob/x");
    expect(calls.fastGet[0]).toBe("~bob/x");
  });
});

describe("expandTilde", () => {
  const HOME = join("/", "home", "me");
  const realPlatform = process.platform;
  afterEach(() => {
    Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
  });

  it("expands ~ and ~/ only", () => {
    expect(expandTilde("~", HOME)).toBe(HOME);
    expect(expandTilde("~/.ssh/id", HOME)).toBe(join(HOME, ".ssh/id"));
    expect(expandTilde("~alice/.ssh/id", HOME)).toBe("~alice/.ssh/id");
    expect(expandTilde("~backup.key", HOME)).toBe("~backup.key");
    expect(expandTilde("/abs/~/x", HOME)).toBe("/abs/~/x");
    expect(expandTilde("rel/path", HOME)).toBe("rel/path");
  });

  it("expands ~\\ on Windows only", () => {
    Object.defineProperty(process, "platform", { value: "win32", configurable: true });
    expect(expandTilde("~\\.ssh\\id", HOME)).toBe(join(HOME, ".ssh\\id"));
    Object.defineProperty(process, "platform", { value: "linux", configurable: true });
    expect(expandTilde("~\\.ssh\\id", HOME)).toBe("~\\.ssh\\id");
  });
});

describe("downloadFile tilde expansion in localPath", () => {
  it("expands ~ to the home directory", async () => {
    const { sftp, calls } = makeFakeSftp();
    await downloadFile(makeFakeClient(sftp), "/remote/backup.sql", "~/backups/backup.sql");
    expect(calls.fastGet[0]).toBe(join(homedir(), "backups/backup.sql"));
  });

  it("leaves absolute paths unchanged", async () => {
    const { sftp, calls } = makeFakeSftp();
    await downloadFile(makeFakeClient(sftp), "/remote/file.txt", "/tmp/file.txt");
    expect(calls.fastGet[0]).toBe("/tmp/file.txt");
  });

  it("handles nested paths under ~", async () => {
    const { sftp, calls } = makeFakeSftp();
    await downloadFile(makeFakeClient(sftp), "/remote/data.json", "~/downloads/data.json");
    expect(calls.fastGet[0]).toBe(join(homedir(), "downloads/data.json"));
  });
});
