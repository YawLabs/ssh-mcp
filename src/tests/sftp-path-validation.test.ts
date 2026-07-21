import { describe, expect, it } from "vitest";
import { z } from "zod";
import { registerTools } from "../tools.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

// Collect each tool's inputSchema so we can pull out individual field schemas.
function collectTools() {
  const tools: Record<string, z.ZodObject<Record<string, z.ZodTypeAny>>> = {};
  const fakeServer = {
    tool: (name: string, _desc: string, schema: Record<string, z.ZodTypeAny>) => {
      tools[name] = z.object(schema);
    },
  } as unknown as McpServer;
  registerTools(fakeServer);
  return tools;
}

const tools = collectTools();

// Tools that have an SFTP remote path parameter that must be absolute.
// ssh_mkdir is intentionally excluded: its makeDir implementation supports
// relative paths and was designed that way.
const REMOTE_PATH_TOOLS: Array<{ tool: string; param: string }> = [
  { tool: "ssh_read_file", param: "path" },
  { tool: "ssh_write_file", param: "path" },
  { tool: "ssh_ls", param: "path" },
  { tool: "ssh_stat", param: "path" },
  { tool: "ssh_delete", param: "path" },
  { tool: "ssh_upload", param: "remotePath" },
  { tool: "ssh_download", param: "remotePath" },
];

describe("SFTP remote path absolute-path enforcement", () => {
  for (const { tool, param } of REMOTE_PATH_TOOLS) {
    describe(tool, () => {
      function paramSchema() {
        return tools[tool].shape[param];
      }

      it(`rejects a relative path in ${param}`, () => {
        const result = paramSchema().safeParse("relative/path");
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues[0].message).toMatch(/absolute|start with \//i);
        }
      });

      it(`rejects a tilde path in ${param}`, () => {
        const result = paramSchema().safeParse("~/file.txt");
        expect(result.success).toBe(false);
      });

      it(`accepts an absolute path in ${param}`, () => {
        const result = paramSchema().safeParse("/absolute/path/file.txt");
        expect(result.success).toBe(true);
      });
    });
  }
});
