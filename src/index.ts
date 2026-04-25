import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { killStartedAgent } from "./env.js";
import { ConnectionPool } from "./pool.js";
import { createServer } from "./server.js";

async function main() {
  const pool = new ConnectionPool();
  const server = createServer(pool);
  const transport = new StdioServerTransport();

  const shutdown = () => {
    pool.drain();
    killStartedAgent();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  await server.connect(transport);
}

main().catch((err) => {
  console.error("ssh-mcp failed to start:", err);
  process.exit(1);
});
