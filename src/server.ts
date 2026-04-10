import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerTools } from "./tools.js";

export function createServer(): McpServer {
  const server = new McpServer({
    name: "ssh-mcp",
    version: "0.3.0",
  });

  registerTools(server);

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
export { connect, exec, readFile, writeFile, uploadFile, downloadFile, listDir } from "./ssh.js";
export type { SSHConfig, ExecResult } from "./ssh.js";
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
