import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { diagnose } from "./diagnose.js";
import { checkGitSsh, configLookup, ensureAgent, fixKnownHosts, listSshKeys, loadKey, testConnection } from "./env.js";
import { connect, downloadFile, exec, listDir, readFile, uploadFile, writeFile } from "./ssh.js";

const HostSchema = z.string().describe("SSH hostname or IP address");
const PortSchema = z.number().optional().describe("SSH port (default: 22)");
const UsernameSchema = z.string().optional().describe("SSH username (default: current user)");
const KeyPathSchema = z.string().optional().describe("Path to SSH private key");
const PasswordSchema = z.string().optional().describe("SSH password (prefer keys)");
const TimeoutSchema = z.number().optional().describe("Command timeout in milliseconds (default: 30000)");

const connectionParams = {
  host: HostSchema,
  port: PortSchema,
  username: UsernameSchema,
  privateKeyPath: KeyPathSchema,
  password: PasswordSchema,
};

export function registerTools(server: McpServer) {
  server.tool(
    "ssh_exec",
    "Execute a command on a remote host via SSH. Returns stdout, stderr, and exit code.",
    {
      ...connectionParams,
      command: z.string().describe("Shell command to execute on the remote host"),
      timeout: TimeoutSchema,
    },
    async ({ host, port, username, privateKeyPath, password, command, timeout }) => {
      const client = await connect({ host, port, username, privateKeyPath, password });
      try {
        const result = await exec(client, command, timeout || 30000);
        const parts: string[] = [];
        if (result.stdout) parts.push(result.stdout);
        if (result.stderr) parts.push(`[stderr]\n${result.stderr}`);
        parts.push(`[exit code: ${result.code}]`);
        return { content: [{ type: "text", text: parts.join("\n") }] };
      } finally {
        client.end();
      }
    },
  );

  server.tool(
    "ssh_read_file",
    "Read a file from a remote host via SFTP.",
    {
      ...connectionParams,
      path: z.string().describe("Absolute path to the remote file"),
    },
    async ({ host, port, username, privateKeyPath, password, path }) => {
      const client = await connect({ host, port, username, privateKeyPath, password });
      try {
        const content = await readFile(client, path);
        return { content: [{ type: "text", text: content }] };
      } finally {
        client.end();
      }
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
    async ({ host, port, username, privateKeyPath, password, path, content }) => {
      const client = await connect({ host, port, username, privateKeyPath, password });
      try {
        await writeFile(client, path, content);
        return { content: [{ type: "text", text: `Wrote ${content.length} bytes to ${path}` }] };
      } finally {
        client.end();
      }
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
    async ({ host, port, username, privateKeyPath, password, localPath, remotePath }) => {
      const client = await connect({ host, port, username, privateKeyPath, password });
      try {
        await uploadFile(client, localPath, remotePath);
        return { content: [{ type: "text", text: `Uploaded ${localPath} → ${remotePath}` }] };
      } finally {
        client.end();
      }
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
    async ({ host, port, username, privateKeyPath, password, remotePath, localPath }) => {
      const client = await connect({ host, port, username, privateKeyPath, password });
      try {
        await downloadFile(client, remotePath, localPath);
        return { content: [{ type: "text", text: `Downloaded ${remotePath} → ${localPath}` }] };
      } finally {
        client.end();
      }
    },
  );

  server.tool(
    "ssh_ls",
    "List files in a directory on a remote host via SFTP.",
    {
      ...connectionParams,
      path: z.string().describe("Absolute path to the remote directory"),
    },
    async ({ host, port, username, privateKeyPath, password, path }) => {
      const client = await connect({ host, port, username, privateKeyPath, password });
      try {
        const files = await listDir(client, path);
        return { content: [{ type: "text", text: files.join("\n") }] };
      } finally {
        client.end();
      }
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

      return { content: [{ type: "text", text: lines.join("\n") }] };
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
}
