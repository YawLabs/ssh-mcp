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
// 1. bin/ssh-mcp.mjs, Node path. The launcher runs this module IN-PROCESS
//    (`await import(dist/index.js)` in runInProcess, bin/ssh-mcp.mjs:189-202)
//    rather than spawning it, so a `ssh-mcp --version` that reached main() would
//    connect a stdio transport and hang instead of printing. The process.exit(0)
//    below is the only thing that ends that invocation, and the launcher is
//    written around it: it flushes its own stderr synchronously first (errSync,
//    bin/ssh-mcp.mjs:266-269) because this exit truncates a pending async write
//    on Windows TTYs and pipes.
// 2. bin/ssh-mcp.mjs, oam path. `oam run <entry> -- ...process.argv.slice(2)`
//    (bin/ssh-mcp.mjs:302) forwards the flag unchanged into a subprocess running
//    this same module, so the answer has to come from here either way.
// 3. scripts/build-binary.mjs:151 -- the SEA smoke test, `run(outExe,
//    ['--version'])`, execFileSync with stdio:'inherit' (helper at :60-63). This
//    does NOT go through bin/ssh-mcp.mjs: esbuild bundles src/index.ts straight
//    into the binary (:46, :79), so the early exit below is inlined and is what
//    makes the binary terminate at all. Because stdin is inherited, a --version
//    that reached main() would attach the transport to the build shell's stdin
//    and HANG the build. It is darwin-only (it guards the codesign dance), so
//    win32/linux builds run no smoke test and would ship the break silently --
//    caught later by :159-160's printed "Verify with:" hint, or by 4.
// 4. scripts/update-manifests.mjs:144 -- the generated Homebrew formula's
//    `test do assert_match version.to_s, shell_output("#{bin}/ssh-mcp --version")`.
//    `brew test` runs that against the RELEASED binary, so it fails if this stops
//    printing a bare version to stdout or stops exiting.
//
// So: keep this synchronous, keep it above main(), keep the exit, and keep the
// output a bare version on stdout. (Verified against the built binary: `ssh-mcp
// --version` prints and exits 0 -- in a SEA, argv[2] is still the first user arg.)
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
