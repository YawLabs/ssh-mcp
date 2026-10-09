import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it } from "vitest";
import { createServer, SERVER_INSTRUCTIONS } from "../server.js";

describe("createServer", () => {
  it("creates an MCP server instance", () => {
    const server = createServer();
    expect(server).toBeDefined();
  });
});

/** Connect a real MCP client to createServer() over an in-memory transport. */
async function connected(): Promise<Client> {
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await createServer().connect(serverSide);
  const client = new Client({ name: "server-test", version: "0.0.0" });
  await client.connect(clientSide);
  return client;
}

describe("initialize instructions", () => {
  // Yaw MCP caps upstream instructions at 2000 UTF-8 bytes and drops the rest, so the
  // ceiling is the real constraint; ASCII keeps byte and character counts equal and
  // survives the proxy's sanitizer unchanged.
  it("stays under the 2000-byte ceiling Yaw MCP enforces", () => {
    expect(Buffer.byteLength(SERVER_INSTRUCTIONS, "utf8")).toBeLessThan(2000);
  });

  it("is plain printable ASCII (newlines allowed)", () => {
    expect(SERVER_INSTRUCTIONS).toMatch(/^[\x20-\x7e\n]+$/);
  });

  it("does not carry Yaw MCP's own framing markers", () => {
    expect(SERVER_INSTRUCTIONS).not.toContain("[yaw-mcp]");
    expect(SERVER_INSTRUCTIONS).not.toMatch(/<<<(BEGIN|END) UPSTREAM SERVER TEXT/);
  });

  it("is sent to the client at initialize", async () => {
    const client = await connected();
    try {
      expect(client.getInstructions()).toBe(SERVER_INSTRUCTIONS);
    } finally {
      await client.close();
    }
  });
});

describe("tool annotations", () => {
  // Yaw MCP picks its example tool as the first no-argument tool that is readOnlyHint,
  // falling back to the first no-argument tool. Without annotations that fallback was
  // ssh_agent_ensure, which can start an ssh-agent.
  it("the first no-argument read-only tool is ssh_key_list, not ssh_agent_ensure", async () => {
    const client = await connected();
    try {
      const { tools } = await client.listTools();
      const needsNoArgs = (t: (typeof tools)[number]) => (t.inputSchema.required ?? []).length === 0;
      const pick = tools.find((t) => needsNoArgs(t) && t.annotations?.readOnlyHint === true);
      expect(pick?.name).toBe("ssh_key_list");
      const agent = tools.find((t) => t.name === "ssh_agent_ensure");
      expect(agent?.annotations?.readOnlyHint).not.toBe(true);
    } finally {
      await client.close();
    }
  });

  it("marks the read-only tools read-only and the destructive SFTP tools destructive", async () => {
    const client = await connected();
    try {
      const { tools } = await client.listTools();
      const byName = new Map(tools.map((t) => [t.name, t.annotations ?? {}]));
      for (const name of [
        "ssh_key_list",
        "ssh_config_lookup",
        "ssh_ls",
        "ssh_stat",
        "ssh_read_file",
        "ssh_diagnose",
        "ssh_find",
        "ssh_tail",
        "ssh_service_status",
      ]) {
        expect(byName.get(name)?.readOnlyHint, name).toBe(true);
      }
      for (const name of ["ssh_key_list", "ssh_config_lookup"]) {
        expect(byName.get(name)?.openWorldHint, name).toBe(false);
      }
      for (const name of ["ssh_delete", "ssh_write_file"]) {
        expect(byName.get(name)?.destructiveHint, name).toBe(true);
        expect(byName.get(name)?.readOnlyHint, name).not.toBe(true);
      }
      for (const name of ["ssh_exec", "ssh_multi_exec", "ssh_agent_ensure", "ssh_key_load", "ssh_known_hosts_fix"]) {
        expect(byName.get(name)?.readOnlyHint, name).not.toBe(true);
      }
    } finally {
      await client.close();
    }
  });
});
