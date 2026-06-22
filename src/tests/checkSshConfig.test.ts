import { afterEach, describe, expect, it, vi } from "vitest";

// mockConfig is read by the vi.mock factory below. Set it before each test.
let mockConfig: string | null = null;

vi.mock("node:fs", async () => {
  const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
  return {
    ...actual,
    existsSync: (p: unknown) =>
      String(p).endsWith("config") && String(p).includes(".ssh") ? mockConfig !== null : actual.existsSync(p as string),
    readFileSync: (p: unknown, ...args: unknown[]) =>
      String(p).endsWith("config") && String(p).includes(".ssh") && mockConfig !== null
        ? mockConfig
        : actual.readFileSync(p as string, ...(args as [])),
  };
});

afterEach(() => {
  mockConfig = null;
});

import { checkSshConfig } from "../diagnose.js";

describe("checkSshConfig host block parsing", () => {
  it("captures directives after an empty line within a Host block", () => {
    mockConfig = ["Host myserver", "  User myuser", "", "  Port 2222"].join("\n");

    const result = checkSshConfig("myserver");
    expect(result.status).toBe("ok");
    // Both directives must appear — the empty line must not exit the block.
    expect(result.message).toContain("User myuser");
    expect(result.message).toContain("Port 2222");
  });

  it("does not bleed directives from an unrelated Host block", () => {
    mockConfig = ["Host other", "  User root", "", "Host myserver", "  User myuser"].join("\n");

    const result = checkSshConfig("myserver");
    expect(result.message).toContain("User myuser");
    expect(result.message).not.toContain("User root");
  });

  it("captures wildcard Host * directives that apply to all hosts", () => {
    mockConfig = ["Host *", "  ServerAliveInterval 60", "", "Host myserver", "  User myuser"].join("\n");

    const result = checkSshConfig("myserver");
    expect(result.message).toContain("ServerAliveInterval 60");
    expect(result.message).toContain("User myuser");
  });

  it("returns 'no config entry' when host is not in the file", () => {
    mockConfig = ["Host other", "  User root"].join("\n");

    const result = checkSshConfig("myserver");
    expect(result.status).toBe("ok");
    expect(result.message).toMatch(/no.*config.*entry|defaults/i);
  });
});
