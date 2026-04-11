import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ConnectionPool } from "./pool.js";
import { registerTools } from "./tools.js";

export function createServer(pool?: ConnectionPool): McpServer {
  const server = new McpServer({
    name: "ssh-mcp",
    version: "0.6.0",
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
