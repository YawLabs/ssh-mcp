// Command policy enforcement for the agent-facing exec tools.
//
// Policy is configured via two env vars, each a comma-separated list of regex patterns:
//
//   SSH_MCP_COMMAND_WHITELIST -- if set, command MUST match at least one pattern
//   SSH_MCP_COMMAND_BLACKLIST -- if set, command MUST NOT match any pattern
//
// If both are set, the command must pass both checks (whitelist first, then blacklist).
// If neither is set, all commands are allowed -- this is the default and existing behavior.
//
// ============================================================================
// SCOPE LIMIT -- THIS IS NOT WHOLE-SERVER COVERAGE. READ BEFORE CONFIGURING.
// ============================================================================
// Policy is enforced at the MCP tool boundary for exactly TWO tools: ssh_exec
// and ssh_multi_exec. Every other tool runs unchecked. Most importantly, the
// SFTP tools that MUTATE remote state are NOT policy-checked:
//
//   ssh_write_file -- creates/overwrites an arbitrary remote file
//   ssh_upload     -- creates/overwrites an arbitrary remote file
//   ssh_mkdir      -- creates remote directories
//   ssh_delete     -- unlinks a remote file / rmdirs an empty remote directory
//
// Concretely: SSH_MCP_COMMAND_BLACKLIST=^rm does NOT stop ssh_delete, and
// SSH_MCP_COMMAND_WHITELIST=^ls does NOT stop ssh_write_file. Those tools never
// build a shell command string, so a command-shaped regex has nothing to match;
// closing the gap would require a separate path-policy mechanism, which this
// server deliberately does not have. An admin who must prevent remote mutation
// has to stop these tools from being exposed at all (drop them from the client's
// tool allowlist / run a client that gates them), not rely on these two env vars.
//
// The remaining unchecked tools split into TWO groups with DIFFERENT rationales.
// Do not read them as one exemption:
//
//   (a) Structural -- the same reason as the mutation tools above. ssh_ls,
//       ssh_stat, ssh_read_file and ssh_download build NO shell command at all;
//       they are pure SFTP (listDir / statFile / readFile / downloadFile in
//       src/ssh.ts). There is no command string for a regex to match, and so no
//       `^pattern` an admin could add that would make policy apply to them.
//       Caveat on ssh_download: it is non-mutating on the REMOTE only. It
//       creates or overwrites an arbitrary LOCAL file at an agent-chosen
//       `localPath` (the downloadFile call in src/tools.ts), which no command
//       policy sees and no remote-side control can constrain.
//
//   (b) Ergonomic, and much weaker stakes -- ssh_find, ssh_tail and
//       ssh_service_status DO build shell commands (find / tail / systemctl),
//       but from typed parameters rather than free-form agent input. Gating
//       them would force admins to allow `^find `, `^tail `, `^systemctl `
//       just to keep those tools working, defeating the point of a tight
//       whitelist.
//
// Neither rationale justifies the mutation gap above, which is a genuine
// limitation of the current design.
// ============================================================================
//
// Patterns are JS regexes. Use `^` / `$` for full-string matches; otherwise the regex is
// a substring match. Comma is the delimiter, so patterns containing literal commas need
// to express them as `\x2c` or via a character class `[,]`.
//
// Env-prefix interaction: ssh_exec / ssh_multi_exec check policy against the FINAL command
// string, which includes the `KEY='value' ...` prefix built from their `env` parameter. Two
// consequences, both deliberate and load-bearing:
//   - a `^`-anchored whitelist stops matching the moment `env` is used, because the string
//     now starts with the first env-var name. enforcePolicy says so in the rejection when
//     the caller passes `envPrefixApplied` (see PolicyContext below).
//   - a blacklist can trip on metacharacters that are actually inert, because they sit
//     inside a single-quoted env value that the remote shell will never interpret.

/**
 * Compile one env var's comma-separated pattern list.
 *
 * FAIL-CLOSED CONTRACT. A single malformed pattern among several is still skipped with a
 * stderr warning -- a typo in one entry must not disable the sibling entries that DO compile.
 * But if the var is set to something non-empty and NOT ONE pattern compiles, this throws
 * instead of returning an empty list.
 *
 * Why: an empty list is indistinguishable from "this var was never set", and both call sites
 * below treat an empty list as "no policy configured, allow through". So before this guard,
 * `SSH_MCP_COMMAND_WHITELIST="(unclosed"` -- one typo in a single-pattern whitelist -- silently
 * turned the whitelist OFF and allowed every command, and an all-malformed BLACKLIST silently
 * protected nothing. A security control that evaporates on a typo is worse than no control,
 * because the operator believes it is running.
 *
 * The behavior change is deliberate and is the correct direction: such a deployment goes from
 * "everything allowed" to "everything blocked, with an error naming the broken pattern". It
 * also restores the invariant isPolicyConfigured() implies "policy actually enforces
 * something" -- both use the same non-empty-after-trim test on the raw value.
 */
function parsePatterns(raw: string | undefined, envVarName: string): RegExp[] {
  if (!raw) return [];
  const patterns: RegExp[] = [];
  const malformed: string[] = [];
  for (const p of raw.split(",")) {
    // Trim LEADING whitespace only -- handles the "^ls, ^df" comma-then-space style
    // without silently stripping a significant trailing space. Patterns like "^rm "
    // (blocks `rm foo` but not `rmdir`) rely on the trailing space being preserved.
    const cleaned = p.replace(/^\s+/, "");
    if (!cleaned) continue;
    try {
      patterns.push(new RegExp(cleaned));
    } catch {
      // Malformed regex -- log and skip so a typo in one pattern doesn't disable the rest.
      // stderr is the only safe channel for the stdio MCP transport (stdout is JSON-RPC).
      malformed.push(cleaned);
      console.error(`ssh-mcp: ignoring malformed regex in command policy: "${cleaned}"`);
    }
  }

  // Nothing usable came out of a var the operator did set. Refuse to run rather than
  // degrade to "allow everything". A whitespace-only value is treated as unset (same test
  // isPolicyConfigured uses), so it falls through to the normal no-policy path.
  if (patterns.length === 0 && raw.trim() !== "") {
    const detail =
      malformed.length > 0
        ? `Malformed pattern(s): ${malformed.map((m) => `"${m}"`).join(", ")}.`
        : `The value ${JSON.stringify(raw)} contains only separators, so it declares no patterns.`;
    throw new Error(
      `Command blocked -- ssh-mcp command policy is MISCONFIGURED: ${envVarName} is set, but not one usable` +
        ` regex could be compiled from it, so ${envVarName} is NOT IN EFFECT. Every ssh_exec / ssh_multi_exec` +
        ` call is refused until it is fixed (failing closed: a policy that cannot be compiled must not be` +
        ` read as "no policy"). ${detail} Each comma-separated entry must be a valid JavaScript regex --` +
        " note that comma is the delimiter, so a pattern needing a literal comma must write it as" +
        " \\x2c or [,]. Fix or unset the variable to restore service.",
    );
  }

  return patterns;
}

export interface PolicyContext {
  /**
   * True when `command` carries an env-var prefix (`KEY='value' ...`) built from the
   * ssh_exec / ssh_multi_exec `env` parameter. Enforcement is identical either way -- this
   * only adds an explanation to a whitelist rejection, so an operator whose previously
   * working `^`-anchored pattern just started failing can see why.
   */
  envPrefixApplied?: boolean;
}

/**
 * Check a command against the env-configured policy. Throws if blocked.
 *
 * Called from MCP tool handlers (ssh_exec, ssh_multi_exec) -- not from `exec()` itself,
 * so library consumers using the programmatic API don't get policy enforcement (they're
 * outside the MCP trust boundary and write their own gating).
 *
 * See the SCOPE LIMIT block at the top of this file: the SFTP mutation tools are not
 * routed through here at all.
 */
export function enforcePolicy(command: string, context: PolicyContext = {}): void {
  // Compile BOTH lists before testing either. parsePatterns throws on a set-but-uncompilable
  // var (see its contract), and a misconfiguration is the more useful thing to report: an
  // operator whose blacklist is broken should hear that, not "does not match the whitelist".
  const whitelist = parsePatterns(process.env.SSH_MCP_COMMAND_WHITELIST, "SSH_MCP_COMMAND_WHITELIST");
  const blacklist = parsePatterns(process.env.SSH_MCP_COMMAND_BLACKLIST, "SSH_MCP_COMMAND_BLACKLIST");

  if (whitelist.length > 0 && !whitelist.some((r) => r.test(command))) {
    let message = `Command blocked: does not match any pattern in SSH_MCP_COMMAND_WHITELIST. Configured patterns: ${whitelist.map((r) => r.source).join(", ")}`;
    if (context.envPrefixApplied) {
      // The footgun this surfaces: policy is checked against the env-PREFIXED string, so
      // `^ls` rejects `ls` as soon as any env var is passed -- the string now starts with
      // `FOO=`, not `ls`. Enforcement point is deliberate; only the diagnosis was missing.
      message +=
        ". NOTE: an `env` prefix was applied, and policy is checked against the PREFIXED command" +
        " -- the string starts with the first `KEY='value'` assignment, not the command verb," +
        " so a `^`-anchored pattern that matches without `env` stops matching with it." +
        " Either set the variables inside the command string instead of passing `env`, or add a" +
        " pattern that tolerates the prefix (e.g." +
        " `^([A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|\\\\')+ )*ls( |$)`)." +
        " Keep the trailing `( |$)`: without a tail anchor the suggestion is a PREFIX match," +
        " so `^(...)*ls` would also admit `lsof -i` and `ls; <anything>`." +
        " The value group is `(?:'[^']*'|\\\\')+`, not `'[^']*'`: an env VALUE containing an" +
        " apostrophe is emitted by shellQuote in the close-escape-reopen form" +
        " (`O'Brien` -> `'O'\\''Brien'`), which a single `'[^']*'` cannot match -- a suggestion" +
        " built on it would block exactly the calls it claims to allow.";
    }
    throw new Error(message);
  }

  for (const pattern of blacklist) {
    if (pattern.test(command)) {
      throw new Error(`Command blocked by SSH_MCP_COMMAND_BLACKLIST: pattern "${pattern.source}"`);
    }
  }
}

/** Returns true if any policy is currently configured. Used by tool descriptions to surface that. */
export function isPolicyConfigured(): boolean {
  return Boolean(process.env.SSH_MCP_COMMAND_WHITELIST?.trim() || process.env.SSH_MCP_COMMAND_BLACKLIST?.trim());
}
