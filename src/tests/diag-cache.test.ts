import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock the cached diagnostic checks while leaving everything else (isValidHostname,
// runArgs, host-specific checks) on its real implementation. The two cached calls
// are checkSshAgent and checkSshKeys; the rest of formatDiagnostics is host-specific
// and not what we're verifying here.
vi.mock("../diagnose.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../diagnose.js")>();
  return {
    ...actual,
    checkSshAgent: vi.fn(() => ({ status: "ok", message: "agent ok" })),
    checkSshKeys: vi.fn(() => ({ status: "ok", message: "keys ok" })),
    // Force host-specific checks to ok too so formatDiagnostics returns "" and
    // the test only depends on call counts.
    checkSshConfig: vi.fn(() => ({ status: "ok", message: "config ok" })),
    checkKnownHosts: vi.fn(() => ({ status: "ok", message: "known ok" })),
  };
});

describe("formatDiagnostics — 2s TTL cache on agent/keys checks", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.resetModules();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("memoizes checkSshAgent and checkSshKeys within the 2s window", async () => {
    // Fresh module instance so the module-level cache state is clean per test.
    const ssh = await import("../ssh.js");
    const diag = await import("../diagnose.js");
    const agentMock = vi.mocked(diag.checkSshAgent);
    const keysMock = vi.mocked(diag.checkSshKeys);
    agentMock.mockClear();
    keysMock.mockClear();

    ssh.formatDiagnostics("example.com");
    ssh.formatDiagnostics("example.com");

    expect(agentMock).toHaveBeenCalledTimes(1);
    expect(keysMock).toHaveBeenCalledTimes(1);
  });

  it("re-runs checkSshAgent and checkSshKeys after the TTL elapses", async () => {
    const ssh = await import("../ssh.js");
    const diag = await import("../diagnose.js");
    const agentMock = vi.mocked(diag.checkSshAgent);
    const keysMock = vi.mocked(diag.checkSshKeys);
    agentMock.mockClear();
    keysMock.mockClear();

    ssh.formatDiagnostics("example.com");
    expect(agentMock).toHaveBeenCalledTimes(1);
    expect(keysMock).toHaveBeenCalledTimes(1);

    // 2s TTL — bump past it and confirm the cache is busted.
    vi.advanceTimersByTime(2001);

    ssh.formatDiagnostics("example.com");
    expect(agentMock).toHaveBeenCalledTimes(2);
    expect(keysMock).toHaveBeenCalledTimes(2);
  });
});
