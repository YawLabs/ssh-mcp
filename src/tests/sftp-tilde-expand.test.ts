import { homedir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { downloadFile, uploadFile } from "../ssh.js";

// Fake SFTP wrapper that captures the local path passed to fastPut / fastGet.
function makeFakeSftp() {
  const calls = { fastPut: [] as string[], fastGet: [] as string[] };
  const sftp = {
    fastPut: vi.fn((localPath: string, _remotePath: string, cb: (err: null) => void) => {
      calls.fastPut.push(localPath);
      cb(null);
    }),
    fastGet: vi.fn((_remotePath: string, localPath: string, cb: (err: null) => void) => {
      calls.fastGet.push(localPath);
      cb(null);
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
