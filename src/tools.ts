import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { diagnose } from "./diagnose.js";
import { checkGitSsh, configLookup, ensureAgent, fixKnownHosts, listSshKeys, loadKey, testConnection } from "./env.js";
import { find, multiExec, serviceStatus, tail } from "./ops.js";
import { ConnectionPool } from "./pool.js";
import { downloadFile, exec, listDir, readFile, uploadFile, writeFile } from "./ssh.js";

const HostSchema = z.string().describe("SSH hostname or IP address");
const PortSchema = z.number().int().min(1).max(65535).optional().describe("SSH port (default: 22)");
const UsernameSchema = z.string().optional().describe("SSH username (default: current user)");
const KeyPathSchema = z.string().optional().describe("Path to SSH private key");
const PasswordSchema = z
  .string()
  .optional()
  .describe(
    "SSH password. STRONGLY prefer key-based auth (privateKeyPath or ssh-agent). Passwords pass through MCP protocol frames as plaintext and may be logged by the transport or host process.",
  );
const TimeoutSchema = z
  .number()
  .int()
  .positive()
  .optional()
  .describe("Command timeout in milliseconds (default: 30000)");

const connectionParams = {
  host: HostSchema,
  port: PortSchema,
  username: UsernameSchema,
  privateKeyPath: KeyPathSchema,
  password: PasswordSchema,
};

export function registerTools(server: McpServer, pool?: ConnectionPool) {
  const connectionPool = pool ?? new ConnectionPool();

  server.tool(
    "ssh_exec",
    "Execute a command on a remote host via SSH. The command is interpreted by the remote login shell — pipes, redirects, globs, and other shell metacharacters work as expected. Returns stdout, stderr, and exit code.",
    {
      ...connectionParams,
      command: z
        .string()
        .describe("Shell command to execute on the remote host (interpreted by the remote login shell)"),
      timeout: TimeoutSchema,
    },
    async ({ command, timeout, ...conn }) => {
      return connectionPool.withConnection(conn, async (client) => {
        const result = await exec(client, command, timeout || 30000);
        const parts: string[] = [];
        if (result.stdout) parts.push(result.stdout);
        if (result.stderr) parts.push(`[stderr]\n${result.stderr}`);
        parts.push(`[exit code: ${result.code}]`);
        return { content: [{ type: "text", text: parts.join("\n") }] };
      });
    },
  );

  server.tool(
    "ssh_read_file",
    "Read a file from a remote host via SFTP.",
    {
      ...connectionParams,
      path: z.string().describe("Absolute path to the remote file"),
    },
    async ({ path, ...conn }) => {
      return connectionPool.withConnection(conn, async (client) => {
        const content = await readFile(client, path);
        return { content: [{ type: "text", text: content }] };
      });
    },
  );

  server.tool(
    "ssh_write_file",
    "Write content to a file on a remote host via SFTP. Creates or overwrites the file.",
    {
      ...connectionParams,
      path: z.string().describe("Absolute path to the remote file"),
      content: z.string().describe("File content to write"),
    },
    async ({ path, content, ...conn }) => {
      return connectionPool.withConnection(conn, async (client) => {
        await writeFile(client, path, content);
        return { content: [{ type: "text", text: `Wrote ${content.length} bytes to ${path}` }] };
      });
    },
  );

  server.tool(
    "ssh_upload",
    "Upload a local file to a remote host via SFTP.",
    {
      ...connectionParams,
      localPath: z.string().describe("Path to the local file to upload"),
      remotePath: z.string().describe("Absolute path on the remote host"),
    },
    async ({ localPath, remotePath, ...conn }) => {
      return connectionPool.withConnection(conn, async (client) => {
        await uploadFile(client, localPath, remotePath);
        return { content: [{ type: "text", text: `Uploaded ${localPath} → ${remotePath}` }] };
      });
    },
  );

  server.tool(
    "ssh_download",
    "Download a file from a remote host to local filesystem via SFTP.",
    {
      ...connectionParams,
      remotePath: z.string().describe("Absolute path to the remote file"),
      localPath: z.string().describe("Local path to save the downloaded file"),
    },
    async ({ remotePath, localPath, ...conn }) => {
      return connectionPool.withConnection(conn, async (client) => {
        await downloadFile(client, remotePath, localPath);
        return { content: [{ type: "text", text: `Downloaded ${remotePath} → ${localPath}` }] };
      });
    },
  );

  server.tool(
    "ssh_ls",
    "List files in a directory on a remote host via SFTP.",
    {
      ...connectionParams,
      path: z.string().describe("Absolute path to the remote directory"),
    },
    async ({ path, ...conn }) => {
      return connectionPool.withConnection(conn, async (client) => {
        const files = await listDir(client, path);
        return { content: [{ type: "text", text: files.join("\n") }] };
      });
    },
  );

  server.tool(
    "ssh_diagnose",
    "Diagnose SSH connectivity issues. Checks ssh-agent status, loaded keys, known_hosts, SSH config, and attempts a test connection. Use this BEFORE attempting SSH operations if you suspect connectivity issues, or AFTER a failed SSH operation to understand why it failed.",
    {
      host: HostSchema,
      port: PortSchema,
    },
    async ({ host, port }) => {
      const report = diagnose(host, port || 22);

      const lines: string[] = [];
      lines.push(`SSH Diagnostic Report for ${host}:${port || 22}`);
      lines.push(`Overall: ${report.overall.toUpperCase()}`);
      lines.push("");

      for (const check of report.checks) {
        const icon = check.status === "ok" ? "PASS" : check.status === "warning" ? "WARN" : "FAIL";
        lines.push(`[${icon}] ${check.name}`);
        lines.push(`  ${check.message}`);
        lines.push("");
      }

      if (report.suggestions.length > 0) {
        lines.push("Suggested fixes:");
        for (const s of report.suggestions) {
          lines.push(`  - ${s}`);
        }
      }

      return { content: [{ type: "text", text: lines.join("\n") }], isError: report.overall === "error" };
    },
  );

  // --- SSH Environment Management ---

  server.tool(
    "ssh_agent_ensure",
    "Ensure ssh-agent is running and reachable. Starts a new agent if needed and sets environment variables so subsequent SSH operations work. Use this FIRST when SSH operations fail with agent-related errors.",
    {},
    async () => {
      const result = ensureAgent();
      const lines: string[] = [];
      lines.push(result.message);
      if (result.socket) lines.push(`Socket: ${result.socket}`);
      if (result.keys.length > 0) {
        lines.push("Loaded keys:");
        for (const k of result.keys) lines.push(`  ${k}`);
      }
      if (result.env) {
        lines.push("Environment variables set in this session:");
        if (result.env.SSH_AUTH_SOCK) lines.push(`  SSH_AUTH_SOCK=${result.env.SSH_AUTH_SOCK}`);
        if (result.env.SSH_AGENT_PID) lines.push(`  SSH_AGENT_PID=${result.env.SSH_AGENT_PID}`);
      }
      return { content: [{ type: "text", text: lines.join("\n") }], isError: !result.reachable };
    },
  );

  server.tool(
    "ssh_key_list",
    "List all SSH private keys in ~/.ssh/ with their type, fingerprint, and whether they are loaded in the agent. Use this to find which keys are available and which ones need to be loaded.",
    {},
    async () => {
      const keys = listSshKeys();
      if (keys.length === 0) {
        return {
          content: [
            {
              type: "text",
              text: 'No SSH private keys found in ~/.ssh/. Generate one: ssh-keygen -t ed25519 -C "your@email.com"',
            },
          ],
        };
      }

      const lines: string[] = [`Found ${keys.length} SSH key(s):`, ""];
      for (const key of keys) {
        const status = key.loadedInAgent ? "LOADED" : "not loaded";
        lines.push(`${key.name} (${key.type}) [${status}]`);
        lines.push(`  Path: ${key.path}`);
        if (key.fingerprint) lines.push(`  Fingerprint: ${key.fingerprint}`);
        lines.push("");
      }
      return { content: [{ type: "text", text: lines.join("\n") }] };
    },
  );

  server.tool(
    "ssh_key_load",
    "Load an SSH private key into the running agent. Ensures the agent is running first. Use this after ssh_key_list shows a key that is not loaded.",
    {
      keyPath: z.string().describe("Path to the SSH private key to load (e.g. ~/.ssh/id_ed25519)"),
    },
    async ({ keyPath }) => {
      const result = loadKey(keyPath);
      return { content: [{ type: "text", text: result.message }], isError: result.status === "error" };
    },
  );

  server.tool(
    "ssh_config_lookup",
    "Resolve the effective SSH configuration for a host. Shows hostname, user, port, identity files, proxy settings, and all other options from ~/.ssh/config. Use this to understand how SSH will connect to a host.",
    {
      host: HostSchema,
    },
    async ({ host }) => {
      const result = configLookup(host);
      if ("error" in result) {
        return { content: [{ type: "text", text: result.error }], isError: true };
      }

      const lines: string[] = [`SSH config for "${host}":`, ""];
      lines.push(`  Hostname: ${result.hostname}`);
      lines.push(`  User: ${result.user}`);
      lines.push(`  Port: ${result.port}`);
      if (result.identityFile.length > 0) {
        lines.push(`  Identity files: ${result.identityFile.join(", ")}`);
      }
      if (result.proxyJump) lines.push(`  ProxyJump: ${result.proxyJump}`);
      if (result.proxyCommand) lines.push(`  ProxyCommand: ${result.proxyCommand}`);
      return { content: [{ type: "text", text: lines.join("\n") }] };
    },
  );

  server.tool(
    "ssh_known_hosts_fix",
    "Remove a stale host key from known_hosts and re-scan the host to add the current key. Use this when you see 'Host key verification failed' errors, typically after a server has been recreated or reprovisioned.",
    {
      host: HostSchema,
      port: PortSchema,
    },
    async ({ host, port }) => {
      const result = fixKnownHosts(host, port || 22);
      const lines: string[] = [result.message];
      if (result.actions.length > 0) {
        lines.push("");
        lines.push("Actions taken:");
        for (const a of result.actions) lines.push(`  - ${a}`);
      }
      return { content: [{ type: "text", text: lines.join("\n") }], isError: result.status === "error" };
    },
  );

  server.tool(
    "ssh_test",
    "Quick connectivity test to an SSH host. Reports success/failure with timing and actionable error details. Lighter and faster than ssh_diagnose — use this for a quick check before running operations.",
    {
      host: HostSchema,
      port: PortSchema,
    },
    async ({ host, port }) => {
      const result = testConnection(host, port || 22);
      return { content: [{ type: "text", text: result.message }], isError: result.status === "error" };
    },
  );

  server.tool(
    "ssh_git_check",
    "Test Git-over-SSH authentication to a hosting provider (GitHub, GitLab, Bitbucket, etc). Verifies your SSH key is registered and working. Use this when git clone/pull/push fails with SSH errors.",
    {
      host: z.string().optional().describe('Git hosting hostname (default: "github.com")'),
      user: z.string().optional().describe('SSH user for the git host (default: "git")'),
    },
    async ({ host, user }) => {
      const result = checkGitSsh(host || "github.com", user || "git");
      const lines: string[] = [result.message];
      if (result.authenticatedAs) {
        lines.push(`Authenticated as: ${result.authenticatedAs}`);
      }
      return { content: [{ type: "text", text: lines.join("\n") }], isError: result.status === "error" };
    },
  );

  // --- Higher-level operations ---

  server.tool(
    "ssh_multi_exec",
    "Execute a command on multiple remote hosts in parallel. Returns results per host. Use this instead of calling ssh_exec multiple times — it's faster and shows results side by side.",
    {
      hosts: z.array(z.string()).describe("List of SSH hostnames or IPs"),
      command: z.string().describe("Shell command to execute on all hosts"),
      port: PortSchema,
      username: UsernameSchema,
      privateKeyPath: KeyPathSchema,
      password: PasswordSchema,
      timeout: TimeoutSchema,
    },
    async ({ hosts, command, port, username, privateKeyPath, password, timeout }) => {
      const hostConfigs = hosts.map((host) => ({ host, port, username, privateKeyPath, password }));
      const results = await multiExec(connectionPool, hostConfigs, command, timeout || 30000);

      const lines: string[] = [];
      for (const r of results) {
        lines.push(`--- ${r.host} ---`);
        if (r.error) {
          lines.push(`[ERROR] ${r.error}`);
        } else {
          if (r.stdout) lines.push(r.stdout);
          if (r.stderr) lines.push(`[stderr] ${r.stderr}`);
          lines.push(`[exit code: ${r.code}]`);
        }
        lines.push("");
      }
      const hasErrors = results.some((r) => r.error || r.code !== 0);
      return { content: [{ type: "text", text: lines.join("\n") }], isError: hasErrors };
    },
  );

  server.tool(
    "ssh_find",
    "Search for files on a remote host. Wraps the find command with structured parameters so you don't have to construct find syntax manually.",
    {
      ...connectionParams,
      path: z.string().describe("Directory to search in (e.g. /var/log, /home/user)"),
      name: z.string().optional().describe("Filename pattern with wildcards (e.g. '*.log', 'config.*')"),
      type: z.enum(["f", "d", "l"]).optional().describe("File type: f=file, d=directory, l=symlink"),
      maxdepth: z.number().optional().describe("Maximum directory depth to search"),
      minsize: z.string().optional().describe("Minimum file size (e.g. '1M', '100k')"),
      maxsize: z.string().optional().describe("Maximum file size (e.g. '10M', '500k')"),
      timeout: TimeoutSchema,
    },
    async ({ path, name, type, maxdepth, minsize, maxsize, timeout, ...conn }) => {
      return connectionPool.withConnection(conn, async (client) => {
        const files = await find(client, { path, name, type, maxdepth, minsize, maxsize }, timeout || 30000);
        if (files.length === 0) {
          return { content: [{ type: "text", text: "No files found." }] };
        }
        return { content: [{ type: "text", text: `Found ${files.length} result(s):\n${files.join("\n")}` }] };
      });
    },
  );

  server.tool(
    "ssh_tail",
    "Read the last N lines of a file on a remote host, optionally filtering by a grep pattern. Use this for reading log files instead of ssh_exec with manual tail/grep commands.",
    {
      ...connectionParams,
      path: z.string().describe("Absolute path to the file to tail"),
      lines: z.number().optional().describe("Number of lines to read from the end (default: 100)"),
      grep: z.string().optional().describe("Case-insensitive pattern to filter lines"),
      timeout: TimeoutSchema,
    },
    async ({ path, lines, grep, timeout, ...conn }) => {
      return connectionPool.withConnection(conn, async (client) => {
        const output = await tail(client, path, lines || 100, grep, timeout || 30000);
        if (!output.trim()) {
          return {
            content: [
              {
                type: "text",
                text: grep
                  ? `No lines matching "${grep}" in last ${lines || 100} lines.`
                  : "File is empty or does not exist.",
              },
            ],
          };
        }
        return { content: [{ type: "text", text: output }] };
      });
    },
  );

  server.tool(
    "ssh_service_status",
    "Check the status of a systemd service on a remote host. Returns whether it's active, its PID, uptime, and description. Use this instead of ssh_exec with systemctl.",
    {
      ...connectionParams,
      service: z.string().describe("Systemd service name (e.g. nginx, sshd, docker)"),
      timeout: TimeoutSchema,
    },
    async ({ service, timeout, ...conn }) => {
      return connectionPool.withConnection(conn, async (client) => {
        const status = await serviceStatus(client, service, timeout || 30000);
        const lines: string[] = [];
        lines.push(`Service: ${status.name}`);
        lines.push(`Status: ${status.status}`);
        if (status.description) lines.push(`Description: ${status.description}`);
        if (status.pid) lines.push(`PID: ${status.pid}`);
        if (status.since) lines.push(`Since: ${status.since}`);
        lines.push("");
        lines.push(status.raw);
        return { content: [{ type: "text", text: lines.join("\n") }], isError: !status.active };
      });
    },
  );
}
