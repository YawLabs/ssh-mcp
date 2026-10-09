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

/**
 * Routing guidance sent once, at initialize. Yaw MCP shows it when this server is
 * activated, capped at 2000 UTF-8 bytes, so it stays plain ASCII, well under that, and
 * about these tools only (src/tests/server.test.ts pins both). It must not carry
 * Yaw MCP's own framing markers, which the proxy strips or rejects.
 */
export const SERVER_INSTRUCTIONS = [
  "ssh-mcp runs commands and moves files on remote hosts over SSH, using ~/.ssh/config, the ssh-agent and known_hosts the way the OpenSSH client does.",
  "",
  "- After an auth, connect or host-key failure, run ssh_diagnose on that host before retrying. ssh_test is the quick check; ssh_key_list and ssh_key_load fix a key missing from the agent; ssh_known_hosts_fix replaces a stale host key.",
  "- Prefer the purpose-built tools over ssh_exec: ssh_read_file, ssh_ls, ssh_stat, ssh_find, ssh_tail, ssh_service_status. Use ssh_multi_exec for the same command on several hosts.",
  "- ssh_exec returns the exit code first, then stderr, then stdout. Proxies may cut long results (Yaw MCP keeps about 100 KB), so filter on the remote (grep, head, tail) instead of printing everything. Page a large file with ssh_read_file offset and length.",
  "- The SFTP tools take absolute remote paths (ssh_mkdir also accepts a relative one); ~ is not expanded.",
  "- Host keys: a host already in known_hosts must match. An unknown host is trusted on every connection unless strict mode (SSH_MCP_STRICT_HOSTKEYS=1) is on; add it with ssh_known_hosts_fix first.",
  "- On Windows the agent is the OpenSSH Authentication Agent service pipe; if agent auth fails, ssh_agent_ensure checks that the agent is reachable.",
  "- SSH_MCP_COMMAND_WHITELIST / SSH_MCP_COMMAND_BLACKLIST gate only ssh_exec and ssh_multi_exec, not the SFTP write and delete tools.",
].join("\n");

export function createServer(pool?: ConnectionPool): McpServer {
  const server = new McpServer(
    {
      name: "ssh-mcp",
      version,
    },
    { instructions: SERVER_INSTRUCTIONS },
  );

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
export type { PolicyContext } from "./policy.js";
export { enforcePolicy, isPolicyConfigured } from "./policy.js";
export type { AcquireOptions, PoolOptions } from "./pool.js";
export { ConnectionPool, isPoolFullError, POOL_FULL_ERROR_CODE, PoolFullError } from "./pool.js";
// HostKeyRejection / HostKeyRejectionReason are named by the public ResolvedConfig,
// so a consumer cannot fully type that value without them.
export type {
  ExecResult,
  FileRange,
  FileStats,
  HostKeyRejection,
  HostKeyRejectionReason,
  ResolvedConfig,
  SSHConfig,
} from "./ssh.js";
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
  readFileRange,
  readKnownHostsKeys,
  resolveConfig,
  statFile,
  uploadFile,
  writeFile,
} from "./ssh.js";
export { registerTools } from "./tools.js";
