import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { diagnose } from "./diagnose.js";
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
}
