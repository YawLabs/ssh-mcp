import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ConnectionPool } from "./pool.js";
import { registerTools } from "./tools.js";

// Read version from package.json at runtime so we never lie to MCP clients about
// what they're talking to. package.json is always present in published npm packages
// (the files allow-list does not affect it) and at the repo root in dev.
// Inlined by the single-binary build (build-binary.mjs --define); the runtime
// package.json read crashes the SEA binary (no package.json beside the exe).
// Falls back to reading package.json for the normal ESM/tsup build.
declare const __VERSION__: string;
export const version =
  typeof __VERSION__ !== "undefined"
    ? __VERSION__
    : (
        JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "package.json"), "utf8")) as {
          version: string;
        }
      ).version;

export function createServer(pool?: ConnectionPool): McpServer {
  const server = new McpServer({
    name: "ssh-mcp",
    version,
  });

  registerTools(server, pool);

  return server;
}

export type { DiagnosticReport, DiagnosticResult } from "./diagnose.js";
export {
  checkConnectivity,
  checkKnownHosts,
  checkSshAgent,
  checkSshConfig,
  checkSshKeys,
  diagnose,
} from "./diagnose.js";
export type { AgentResult, ConfigLookupResult, KeyInfo } from "./env.js";
export {
  checkGitSsh,
  configLookup,
  ensureAgent,
  fixKnownHosts,
  listSshKeys,
  loadKey,
  testConnection,
} from "./env.js";
export type { FindOptions, MultiExecHost, MultiExecResult, ServiceStatus } from "./ops.js";
export { find, multiExec, serviceStatus, tail } from "./ops.js";
export { enforcePolicy, isPolicyConfigured } from "./policy.js";
export type { PoolOptions } from "./pool.js";
export { ConnectionPool } from "./pool.js";
export type { ExecResult, FileStats, ResolvedConfig, SSHConfig } from "./ssh.js";
export {
  connect,
  connectRaw,
  connectWithProxy,
  deleteFile,
  downloadFile,
  exec,
  formatDiagnostics,
  listDir,
  makeDir,
  readFile,
  readKnownHostsKeys,
  resolveConfig,
  statFile,
  uploadFile,
  writeFile,
} from "./ssh.js";
export { registerTools } from "./tools.js";
