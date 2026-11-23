import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { killStartedAgent } from "./env.js";
import { ConnectionPool } from "./pool.js";
import { createServer, version } from "./server.js";

// Handle --version BEFORE main() (which connects stdio and blocks forever).
//
// Two consumers depend on this, and a change here is only safe if it holds for
// every one of them. Not CI: this repo has no .github/workflows, it releases
// from the workstation via ./release.sh.
//
// 1. bin/ssh-mcp.mjs, in-process path. The launcher can run this module IN-PROCESS
//    (`await import(dist/index.js)` in its runInProcess()) rather than spawning
//    it, so a `ssh-mcp --version` that reached main() would connect a stdio
//    transport and hang instead of printing. The process.exit(0) below is the
//    only thing that ends that invocation, and the launcher is written around
//    it: it flushes its own stderr synchronously first (its errSync()) because
//    this exit truncates a pending async write on Windows TTYs and pipes.
//    runtimePlan() picks this path on a host that is already oam at or above
//    the launcher's floor (ALREADY RUNNING ON OAM in its header), under `auto`
//    and SSH_MCP_RUNTIME=oam alike, and under SSH_MCP_RUNTIME=node on Node.
//    With AUTO_PREFERS_OAM = true, `auto` on a Node host does NOT take it: it
//    goes to "discover" (path 2) and serves in-process on Node only when no
//    usable oam is found or the chosen one fails to launch.
// 2. bin/ssh-mcp.mjs, spawned paths. The discover path's launchChild() call
//    (`oam run <entry> -- ...process.argv.slice(2)`), and
//    `node <entry> ...process.argv.slice(2)` when an oam host hands off to Node
//    (handOffToNode(): SSH_MCP_RUNTIME=node, or a host below the floor with no
//    newer oam to spawn), forward the flag unchanged into a
//    subprocess running this same module, so the answer has to come from here
//    either way.
//
// So: keep this synchronous, keep it above main(), keep the exit, and keep the
// output a bare version on stdout.
if (process.argv[2] === "--version" || process.argv[2] === "version") {
  console.log(version);
  process.exit(0);
}

// How long stdin EOF waits for already-received requests to be answered before
// shutting down anyway. Generous on purpose: a command's `timeout` defaults to
// 30s (and the pool wait is bounded separately by the same value), so this
// covers a defaulted ssh_exec several times over while still ending a hung call.
const EOF_DRAIN_GRACE_MS = 5 * 60_000;

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
  // A stdio MCP server normally ends by the host closing the pipe, which fires
  // neither signal. StdioServerTransport listens only for stdin 'data' and
  // 'error', so EOF alone ends nothing: the process used to linger until the
  // event loop emptied, and pooled SSH sockets are ref'd, so that took up to the
  // idle TTL (60s) for idle connections and the rest of the command for a
  // checked-out one -- live SSH sessions and any self-started agent included.
  // EOF and pipe-close therefore take the same shutdown() path as SIGTERM
  // (shutdown() is guarded, so 'end' followed by 'close' runs it once) -- but
  // NOT immediately. EOF means "no more requests", not "abandon the ones already
  // sent": `printf '<initialize>\n<tools/call>\n' | ssh-mcp` closes stdin right
  // after writing, and server.close() aborts in-flight handlers and drops their
  // responses. So EOF waits for every request already received to be answered
  // (or cancelled by the client), bounded by EOF_DRAIN_GRACE_MS so a hung call
  // cannot keep the process alive forever. SIGINT/SIGTERM still shut down at once.
  //
  // In-flight requests are tracked at the transport boundary: an onmessage set
  // BEFORE server.connect() is chained by the SDK's Protocol.connect (it calls the
  // prior handler first), and Protocol sends every response through
  // transport.send, so wrapping that instance method sees each answer.
  const inFlight = new Set();
  let stdinGone = false;
  const maybeShutdownAfterEof = () => {
    if (!stdinGone || inFlight.size > 0) return;
    // The grace timer below is left running: shutdown() ends in process.exit.
    shutdown().catch(() => process.exit(1));
  };
  transport.onmessage = (message) => {
    if ("method" in message) {
      if ("id" in message) {
        inFlight.add(message.id);
      } else if (message.method === "notifications/cancelled") {
        // A cancelled request gets no response, so stop waiting for it. Mirror
        // Protocol._oncancel exactly: it ignores a falsy requestId (so a cancel
        // of id 0 aborts nothing and that request is still answered).
        const params = message.params;
        if (params && typeof params === "object" && "requestId" in params && params.requestId) {
          inFlight.delete(params.requestId);
          maybeShutdownAfterEof();
        }
      }
    }
  };
  const sendRaw = transport.send.bind(transport);
  transport.send = async (message) => {
    try {
      await sendRaw(message);
    } finally {
      if (!("method" in message) && "id" in message && inFlight.delete(message.id)) {
        maybeShutdownAfterEof();
      }
    }
  };
  const onStdinGone = () => {
    if (stdinGone) return;
    stdinGone = true;
    if (inFlight.size > 0) {
      setTimeout(() => {
        inFlight.clear();
        maybeShutdownAfterEof();
      }, EOF_DRAIN_GRACE_MS);
    }
    maybeShutdownAfterEof();
  };
  process.stdin.once("end", onStdinGone);
  process.stdin.once("close", onStdinGone);
  // Backstop for every other normal termination. The handler must be
  // synchronous (the only contract 'exit' allows); drain() and
  // killStartedAgent() are both idempotent, so re-running after shutdown() is
  // harmless.
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
