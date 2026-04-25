import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ConnectionPool } from "./pool.js";
import { registerTools } from "./tools.js";

export function createServer(pool?: ConnectionPool): McpServer {
  const server = new McpServer({
    name: "ssh-mcp",
    version: "0.7.0",
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
export type { PoolOptions } from "./pool.js";
export { ConnectionPool } from "./pool.js";
export type { ExecResult, ResolvedConfig, SSHConfig } from "./ssh.js";
export {
  connect,
  connectRaw,
  connectWithProxy,
  downloadFile,
  exec,
  formatDiagnostics,
  listDir,
  readFile,
  readKnownHostsKeys,
  resolveConfig,
  uploadFile,
  writeFile,
} from "./ssh.js";
export { registerTools } from "./tools.js";
