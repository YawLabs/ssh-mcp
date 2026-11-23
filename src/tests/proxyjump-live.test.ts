import type { AddressInfo } from "node:net";
import { Server, utils } from "ssh2";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { connectWithProxy, exec, type ResolvedConfig } from "../ssh.js";

// Isolate the JUMP hop from the developer's machine. connectWithProxy builds each hop via
// resolveConfig, which runs `ssh -G` (a `Host *` ProxyJump would reroute it), consults
// known_hosts through `ssh-keygen -F` (a bare `127.0.0.1` entry is checked for non-22
// ports too), reads the strict-mode env, and walks the default keys under the home dir (an
// encrypted ~/.ssh/id_ed25519 with no agent fails the hop on POSIX). So: both helpers report
// "unavailable", the home dir is an empty temp dir, and the env is cleared per test.
vi.mock("../diagnose.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../diagnose.js")>();
  return { ...actual, runArgs: () => ({ stdout: "", ok: false }) };
});
vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  const { mkdtempSync } = await import("node:fs");
  const { join } = await import("node:path");
  const home = mkdtempSync(join(actual.tmpdir(), "ssh-mcp-proxyjump-home-"));
  const homedir = () => home;
  return { ...actual, default: { ...actual, homedir }, homedir };
});

beforeEach(() => {
  vi.stubEnv("SSH_MCP_STRICT_HOSTKEYS", "");
  vi.stubEnv("SSH_MCP_STRICT_HOST_KEY", "");
  vi.stubEnv("SSH_AUTH_SOCK", "");
});
afterEach(() => {
  vi.unstubAllEnvs();
});

// ---------------------------------------------------------------------------
// ProxyJump against REAL SSH servers, in process.
//
// Every other ProxyJump assertion in the suite runs against a hand-written fake
// whose forwardOut hands back a bare EventEmitter, so `sock: stream` had never
// been given to a real ssh2 Client and no real server had ever accepted a
// direct-tcpip channel from this code. src/tests/integration.test.ts has a
// Docker-based version of this, but it is SKIPPED without SSH_MCP_INTEGRATION=1
// and a running engine -- so on a normal `npm test` the newest and most-changed
// path in ssh.ts had zero real-protocol coverage.
//
// ssh2 ships a Server, so both hops can be real without Docker, without
// privileges, and without leaving the test process: a full SSH handshake, real
// channel multiplexing, and a real forwarded stream handed to ssh.ts as `sock`.
// That is precisely the seam the fakes could not exercise.
//
// The TARGET only ever accepts connections that arrive through the bastion's
// forwarded channel -- the test never learns a directly-dialable address for it,
// which is what makes a passing jump meaningful rather than incidental.
// ---------------------------------------------------------------------------

const HOST_KEY = utils.generateKeyPairSync("ed25519").private;

/** Anything authenticates: these servers exist to exercise transport, not auth. */
function acceptAnyAuth(client: import("ssh2").Connection): void {
  client.on("authentication", (ctx) => ctx.accept());
}

/**
 * A server that answers `exec` with a fixed line, so a command run over the
 * tunnel proves it reached THIS host rather than the one we tunnelled through.
 */
function startEchoServer(banner: string): Promise<{ port: number; close: () => Promise<void> }> {
  const server = new Server({ hostKeys: [HOST_KEY] }, (client) => {
    acceptAnyAuth(client);
    client.on("ready", () => {
      client.on("session", (accept) => {
        const session = accept();
        session.on("exec", (acceptExec) => {
          const stream = acceptExec();
          stream.write(`${banner}\n`);
          stream.exit(0);
          stream.end();
        });
      });
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const port = (server.address() as AddressInfo).port;
      resolve({
        port,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

/**
 * A bastion that honours `direct-tcpip` by opening a real TCP socket to the
 * requested destination and piping the two together -- exactly what OpenSSH does
 * for a ProxyJump hop. `forwards` records every destination asked for, which is
 * how a test proves the jump was actually used.
 */
function startBastion(
  forwards: { host: string; port: number }[],
): Promise<{ port: number; close: () => Promise<void> }> {
  const server = new Server({ hostKeys: [HOST_KEY] }, (client) => {
    acceptAnyAuth(client);
    client.on("ready", () => {
      client.on("tcpip", async (accept, reject, info) => {
        forwards.push({ host: info.destIP, port: info.destPort });
        const net = await import("node:net");
        const socket = net.connect(info.destPort, info.destIP, () => {
          const channel = accept();
          socket.pipe(channel).pipe(socket);
        });
        socket.on("error", () => reject());
      });
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const port = (server.address() as AddressInfo).port;
      resolve({
        port,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

const baseTarget = (port: number) => ({
  host: "127.0.0.1",
  port,
  username: "tester",
  password: "irrelevant",
  // These servers present a freshly generated host key that is in no known_hosts,
  // which is the documented trust-always default. This pins only the TARGET's
  // verifier; the jump hop gets its own from resolveConfig, which is why the module
  // mocks and env stubs at the top of this file exist.
  hostVerifier: () => true,
});

describe("ProxyJump over real SSH servers (no Docker)", () => {
  it("reaches the target THROUGH the bastion and runs a command there", async () => {
    const forwards: { host: string; port: number }[] = [];
    const target = await startEchoServer("i-am-the-target");
    const bastion = await startBastion(forwards);
    try {
      const resolved: ResolvedConfig = {
        connectConfig: baseTarget(target.port),
        proxyJump: `tester@127.0.0.1:${bastion.port}`,
      };

      const client = await connectWithProxy(resolved);
      try {
        const result = await exec(client, "hostname");
        // The banner comes from the TARGET's exec handler, so this output could
        // only have arrived over the forwarded channel.
        expect(result.stdout.trim()).toBe("i-am-the-target");
        expect(result.code).toBe(0);
      } finally {
        client.end();
      }

      // The bastion was genuinely asked to forward to the target's port -- proof
      // the hop happened rather than the client dialling the target directly.
      expect(forwards).toEqual([{ host: "127.0.0.1", port: target.port }]);
    } finally {
      await bastion.close();
      await target.close();
    }
  });

  it("parses `user@host:port` into a real dial rather than one hostname", async () => {
    // The regression this guards: `ssh -G` emits the ProxyJump value verbatim, and
    // handing `tester@127.0.0.1:<port>` to resolveConfig as a single `host` used to
    // produce hostname "127.0.0.1:<port>" on port 22, which fails before a byte is
    // sent. Here the spec form is the only way the bastion is addressed at all, so
    // a parsing regression cannot pass this test.
    const forwards: { host: string; port: number }[] = [];
    const target = await startEchoServer("reached-via-spec");
    const bastion = await startBastion(forwards);
    try {
      const client = await connectWithProxy({
        connectConfig: baseTarget(target.port),
        proxyJump: `tester@127.0.0.1:${bastion.port}`,
      });
      try {
        expect((await exec(client, "id")).stdout.trim()).toBe("reached-via-spec");
      } finally {
        client.end();
      }
    } finally {
      await bastion.close();
      await target.close();
    }
  });

  it("chains TWO hops in the order the spec lists them", async () => {
    // A comma list is emitted verbatim by `ssh -G` too. Each bastion records what it
    // was asked to reach, so the recorded destinations spell out the actual route.
    const firstForwards: { host: string; port: number }[] = [];
    const secondForwards: { host: string; port: number }[] = [];
    const target = await startEchoServer("end-of-chain");
    const second = await startBastion(secondForwards);
    const first = await startBastion(firstForwards);
    try {
      const client = await connectWithProxy({
        connectConfig: baseTarget(target.port),
        proxyJump: `tester@127.0.0.1:${first.port},tester@127.0.0.1:${second.port}`,
      });
      try {
        expect((await exec(client, "hostname")).stdout.trim()).toBe("end-of-chain");
      } finally {
        client.end();
      }

      // Hop 1 was asked to reach hop 2; hop 2 was asked to reach the target.
      expect(firstForwards).toEqual([{ host: "127.0.0.1", port: second.port }]);
      expect(secondForwards).toEqual([{ host: "127.0.0.1", port: target.port }]);
    } finally {
      await first.close();
      await second.close();
      await target.close();
    }
  });

  it("rejects when the bastion refuses to forward, instead of hanging", async () => {
    // A bastion with forwarding restricted (PermitOpen / AllowTcpForwarding no)
    // rejects the direct-tcpip channel. connectWithProxy must surface that.
    const target = await startEchoServer("unreachable");
    const refusing = new Server({ hostKeys: [HOST_KEY] }, (client) => {
      acceptAnyAuth(client);
      client.on("ready", () => {
        client.on("tcpip", (_accept, reject) => reject());
      });
    });
    const port = await new Promise<number>((resolve) => {
      refusing.listen(0, "127.0.0.1", () => resolve((refusing.address() as AddressInfo).port));
    });
    try {
      await expect(
        connectWithProxy({
          connectConfig: baseTarget(target.port),
          proxyJump: `tester@127.0.0.1:${port}`,
        }),
      ).rejects.toThrow();
    } finally {
      await new Promise<void>((done) => refusing.close(() => done()));
      await target.close();
    }
  });
});
