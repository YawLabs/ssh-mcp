import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { killStartedAgent } from "./env.js";
import { ConnectionPool } from "./pool.js";
import { createServer } from "./server.js";

async function main() {
  const pool = new ConnectionPool();
  const server = createServer(pool);
  const transport = new StdioServerTransport();

  let shuttingDown = false;
  const shutdown = async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    // Order: stop accepting new MCP requests (server.close also closes the
    // transport and any pending requests) -> drain SSH sockets -> wait briefly
    // for TCP FIN frames to flush -> exit. Closing twice or after stdin EOF
    // should not crash the process, so swallow errors here.
    try {
      await server.close();
    } catch {}
    pool.drain();
    killStartedAgent();
    // Give the event loop ~100ms so TCP FIN frames from drain()'d sockets flush
    // before the process exits. Do NOT unref -- the timer must keep the loop
    // alive across the grace window.
    setTimeout(() => process.exit(0), 100);
  };
  process.on("SIGINT", () => {
    shutdown().catch(() => process.exit(1));
  });
  process.on("SIGTERM", () => {
    shutdown().catch(() => process.exit(1));
  });
  // SIGINT/SIGTERM aren't the only way this server dies -- a stdio MCP server
  // normally exits via stdin-EOF / pipe-close, which fires neither signal and so
  // never runs shutdown(). Without a backstop, an ssh-agent we spawned ourselves
  // (env.ts ensureAgent) is orphaned. process.on("exit") fires on every normal
  // termination, including the event loop draining after stdin EOF. The handler
  // must be synchronous (the only contract 'exit' allows); drain() and
  // killStartedAgent() are both idempotent, so re-running after a signal-driven
  // shutdown is harmless.
  process.on("exit", () => {
    pool.drain();
    killStartedAgent();
  });

  await server.connect(transport);
}

main().catch((err) => {
  console.error("ssh-mcp failed to start:", err);
  process.exit(1);
});
