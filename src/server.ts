import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ConnectionPool } from "./pool.js";
import { registerTools } from "./tools.js";

// Read version from package.json at runtime so we never lie to MCP clients about
// what they're talking to. package.json is always present in published npm packages
// (the files allow-list does not affect it) and at the repo root in dev.
const pkgPath = join(dirname(fileURLToPath(import.meta.url)), "..", "package.json");
const { version } = JSON.parse(readFileSync(pkgPath, "utf8")) as { version: string };

export function createServer(pool?: ConnectionPool): McpServer {
  const server = new McpServer({
    name: "ssh-mcp",
    version,
  });

  registerTools(server, pool);

  return server;
}

export { registerTools } from "./tools.js";
export {
  diagnose,
  checkSshAgent,
  checkSshKeys,
  checkKnownHosts,
  checkConnectivity,
  checkSshConfig,
} from "./diagnose.js";
export type { DiagnosticResult, DiagnosticReport } from "./diagnose.js";
export {
  connect,
  connectRaw,
  connectWithProxy,
  resolveConfig,
  readKnownHostsKeys,
  formatDiagnostics,
  exec,
  readFile,
  writeFile,
  uploadFile,
  downloadFile,
  listDir,
} from "./ssh.js";
export type { SSHConfig, ExecResult, ResolvedConfig } from "./ssh.js";
export { ConnectionPool } from "./pool.js";
export type { PoolOptions } from "./pool.js";
export { multiExec, find, tail, serviceStatus } from "./ops.js";
export type { MultiExecResult, MultiExecHost, FindOptions, ServiceStatus } from "./ops.js";
export {
  ensureAgent,
  listSshKeys,
  loadKey,
  configLookup,
  fixKnownHosts,
  checkGitSsh,
  testConnection,
} from "./env.js";
export type { KeyInfo, AgentResult, ConfigLookupResult } from "./env.js";
