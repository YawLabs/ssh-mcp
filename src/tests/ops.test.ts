import { describe, expect, it } from "vitest";
import { find } from "../ops.js";

describe("find input validation", () => {
  // These tests verify validation without needing a real SSH connection.
  // find() validates inputs before executing any SSH command.

  it("rejects invalid minsize format", async () => {
    const fakeClient = {} as any;
    await expect(find(fakeClient, { path: "/tmp", minsize: "1M; rm -rf /" })).rejects.toThrow("Invalid minsize format");
  });

  it("rejects invalid maxsize format", async () => {
    const fakeClient = {} as any;
    await expect(find(fakeClient, { path: "/tmp", maxsize: "abc" })).rejects.toThrow("Invalid maxsize format");
  });

  it("rejects maxsize with shell metacharacters", async () => {
    const fakeClient = {} as any;
    await expect(find(fakeClient, { path: "/tmp", maxsize: "10M$(whoami)" })).rejects.toThrow("Invalid maxsize format");
  });

  it("accepts valid size formats", async () => {
    // These would fail at the SSH exec step (no real client), but should pass validation.
    // We just verify they don't throw the validation error.
    const fakeClient = {
      exec: (_cmd: string, cb: (err: Error) => void) => cb(new Error("not connected")),
    } as any;

    const validSizes = ["1k", "100M", "5G", "2T", "10P", "1024"];
    for (const size of validSizes) {
      // Should reject with SSH error, not validation error
      await expect(find(fakeClient, { path: "/tmp", minsize: size })).rejects.not.toThrow("Invalid minsize format");
    }
  });
});
