import { homedir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

vi.mock("node:fs", async () => {
  const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
  return {
    ...actual,
    readFileSync: vi.fn(() => Buffer.from("fake-key-data")),
  };
});

import { readFileSync } from "node:fs";
import { resolveConfig } from "../ssh.js";

describe("resolveConfig tilde expansion in privateKeyPath", () => {
  it("expands ~ to the home directory", () => {
    vi.mocked(readFileSync).mockClear();
    resolveConfig({ host: "example.com", privateKeyPath: "~/.ssh/id_ed25519" });

    const call = vi.mocked(readFileSync).mock.calls[0];
    expect(call[0]).toBe(join(homedir(), ".ssh/id_ed25519"));
  });

  it("leaves absolute paths unchanged", () => {
    vi.mocked(readFileSync).mockClear();
    const absPath = "/home/testuser/.ssh/id_ed25519";
    resolveConfig({ host: "example.com", privateKeyPath: absPath });

    const call = vi.mocked(readFileSync).mock.calls[0];
    expect(call[0]).toBe(absPath);
  });

  it("handles nested paths under ~", () => {
    vi.mocked(readFileSync).mockClear();
    resolveConfig({ host: "example.com", privateKeyPath: "~/keys/work/id_ed25519" });

    const call = vi.mocked(readFileSync).mock.calls[0];
    expect(call[0]).toBe(join(homedir(), "keys/work/id_ed25519"));
  });
});
