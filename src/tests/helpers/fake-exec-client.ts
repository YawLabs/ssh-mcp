import { EventEmitter } from "node:events";

/**
 * What a fake exec channel emits, in this order, on a microtask after exec()'s callback
 * has run (so the listeners ssh.ts's exec() attaches are in place first):
 * stdout data, stderr data, then `close(code, signal)`.
 */
export interface FakeExecScript {
  /** One stdout `data` chunk. Emitted before `stdoutChunks`. */
  stdout?: string;
  /** One stderr `data` chunk. Emitted before `stderrChunks`. */
  stderr?: string;
  stdoutChunks?: Buffer[];
  stderrChunks?: Buffer[];
  /** Exit code passed to `close`. Default 0; `null` models a signal-only close. */
  code?: number | null;
  /** Signal name passed to `close` as its second argument. */
  signal?: string;
  /** exec() calls back with this error and no stream. */
  execError?: Error;
  /** The stream never emits anything, so exec() runs to its own timeout. */
  hang?: boolean;
}

export interface FakeExecStream extends EventEmitter {
  stderr: EventEmitter;
}

/**
 * The one stand-in for an ssh2 Client's exec() channel the unit tests share, so a change to
 * exec()'s stream contract is mirrored in one place. `script` may be a function of the
 * command, for a client that answers per command. `lastCommand()` is the most recent command
 * string handed to exec(); `commands` is every one, in order.
 */
export function fakeExecClient(script: FakeExecScript | ((command: string) => FakeExecScript) = {}): {
  client: never;
  lastCommand: () => string | undefined;
  commands: string[];
} {
  const commands: string[] = [];
  const client = {
    exec: (command: string, cb: (err: Error | null, stream: FakeExecStream | null) => void) => {
      commands.push(command);
      const s = typeof script === "function" ? script(command) : script;
      if (s.execError) {
        cb(s.execError, null);
        return;
      }
      const stream = new EventEmitter() as FakeExecStream;
      stream.stderr = new EventEmitter();
      cb(null, stream);
      if (s.hang) return;
      queueMicrotask(() => {
        if (s.stdout) stream.emit("data", Buffer.from(s.stdout));
        for (const c of s.stdoutChunks ?? []) stream.emit("data", c);
        if (s.stderr) stream.stderr.emit("data", Buffer.from(s.stderr));
        for (const c of s.stderrChunks ?? []) stream.stderr.emit("data", c);
        if (s.signal !== undefined) stream.emit("close", s.code === undefined ? 0 : s.code, s.signal);
        else stream.emit("close", s.code === undefined ? 0 : s.code);
      });
    },
  };
  return { client: client as never, lastCommand: () => commands.at(-1), commands };
}
