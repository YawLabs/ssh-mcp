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
// Enforced at the MCP tool boundary (ssh_exec, ssh_multi_exec). Structured higher-level
// tools (ssh_find, ssh_tail, ssh_service_status, SFTP ops) are exempt -- they build
// commands from typed parameters, not free-form agent input, so applying the policy to
// them would mean admins have to allow `^find `, `^tail `, `^systemctl ` just to keep
// those tools working, defeating the point of a tight whitelist.
//
// Patterns are JS regexes. Use `^` / `$` for full-string matches; otherwise the regex is
// a substring match. Comma is the delimiter, so patterns containing literal commas need
// to express them as `\x2c` or via a character class `[,]`.

function parsePatterns(raw: string | undefined): RegExp[] {
  if (!raw) return [];
  const patterns: RegExp[] = [];
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
      console.error(`ssh-mcp: ignoring malformed regex in command policy: "${cleaned}"`);
    }
  }
  return patterns;
}

/**
 * Check a command against the env-configured policy. Throws if blocked.
 *
 * Called from MCP tool handlers (ssh_exec, ssh_multi_exec) -- not from `exec()` itself,
 * so library consumers using the programmatic API don't get policy enforcement (they're
 * outside the MCP trust boundary and write their own gating).
 */
export function enforcePolicy(command: string): void {
  const whitelist = parsePatterns(process.env.SSH_MCP_COMMAND_WHITELIST);
  if (whitelist.length > 0 && !whitelist.some((r) => r.test(command))) {
    throw new Error(
      `Command blocked: does not match any pattern in SSH_MCP_COMMAND_WHITELIST. Configured patterns: ${whitelist.map((r) => r.source).join(", ")}`,
    );
  }

  const blacklist = parsePatterns(process.env.SSH_MCP_COMMAND_BLACKLIST);
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
