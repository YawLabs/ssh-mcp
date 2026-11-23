import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { killStartedAgent } from "./env.js";
import { ConnectionPool } from "./pool.js";
import { createServer, version } from "./server.js";

// Handle --version BEFORE main() (which connects stdio and blocks forever).
//
// Four consumers depend on this, and a change here is only safe if it holds for
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
// 3. A single-file binary. Such a build bundles src/index.ts straight into the
//    executable and does NOT go through bin/ssh-mcp.mjs, so the early exit below
//    is inlined and is what makes the binary terminate on --version at all. A
//    --version that reached main() would attach the transport to whatever stdin
//    the binary inherited and HANG. (This repo has no binary build script wired
//    up right now; the Homebrew/Scoop manifests scripts/update-manifests.mjs
//    generates still point at per-arch binaries, so the invariant stands.)
// 4. scripts/update-manifests.mjs, the formula template's `test do` block -- the generated Homebrew formula's
//    `test do assert_match version.to_s, shell_output("#{bin}/ssh-mcp --version")`.
//    `brew test` runs that against the RELEASED binary, so it fails if this stops
//    printing a bare version to stdout or stops exiting.
//
// So: keep this synchronous, keep it above main(), keep the exit, and keep the
// output a bare version on stdout. (Verified against a built single-file binary:
// `ssh-mcp --version` prints and exits 0 -- argv[2] is still the first user arg
// there.)
if (process.argv[2] === "--version" || process.argv[2] === "version") {
  console.log(version);
  process.exit(0);
}

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
  // (shutdown() is guarded, so 'end' followed by 'close' runs it once).
  const onStdinGone = () => {
    shutdown().catch(() => process.exit(1));
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
