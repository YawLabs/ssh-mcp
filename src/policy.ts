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
// THIS IS NOT A SECURITY BOUNDARY. It is a regex over a string that a remote shell will
// interpret: a guard rail against an agent going off-script, not containment of a hostile
// one. Blacklists are best effort: `/bin/rm`, `\rm` and `r''m` all evade `^rm `. A whitelist
// is stronger, but an allowed program can itself run things (`find -exec`, `awk` system(),
// `tar --checkpoint-action`), and an agent that has a shell and the credential by any other
// route is not constrained by anything in this server.
//
// While a whitelist is active, a command that matches it is ALSO refused if it contains
// shell control syntax or starts with a variable assignment (see checkWhitelistedShape).
// SSH_MCP_COMMAND_ALLOW_SHELL_SYNTAX=1 turns that extra check off.
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
// a substring match. Comma is the delimiter, except where it is part of the regex: inside
// a character class (`[,]`), when escaped (`\,`), or in a `{m,n}` quantifier. Any other
// literal comma, including one inside a group, must be written `\,`, `[,]` or `\x2c`.
// A class whose comma might really be a delimiter is refused (see splitPatternList).
//
// Env-prefix interaction: ssh_exec / ssh_multi_exec check policy against the FINAL command
// string, which includes the `KEY='value' ...` prefix built from their `env` parameter.
// Consequences, all deliberate and load-bearing:
//   - a `^`-anchored whitelist stops matching the moment `env` is used, because the string
//     now starts with the first env-var name. enforcePolicy says so in the rejection when
//     the caller passes `envPrefixApplied` (see PolicyContext below).
//   - even a pattern that tolerates the prefix is refused under a whitelist by default,
//     because `env: { LD_PRELOAD: ... }` or `env: { PATH: ... }` changes what an allowed
//     command actually runs.
//   - a blacklist can trip on metacharacters that are actually inert, because they sit
//     inside a single-quoted env value that the remote shell will never interpret.

const ALLOW_SHELL_SYNTAX_VAR = "SSH_MCP_COMMAND_ALLOW_SHELL_SYNTAX";

// Deliberately blind to quoting. The remote login shell is unknown and quoting rules differ
// between shells: `'\''; reboot #'` is a quoted string to sh, but fish reads `\'` inside
// single quotes as an escape and runs `reboot`, and cmd.exe does not treat `'` as a quote at
// all. Parens are included because they are command substitution in fish and PowerShell, and
// `@{` because a PowerShell hash literal runs its values while the argument is evaluated.
const SHELL_CONTROL_SYNTAX = /\$[([{]|@\{|[;&|`<>()\r\n]/;

// `NAME=`, `NAME+=` or `NAME[i]=` at the start of the command: the shell applies it to the
// command that follows, which is how LD_PRELOAD and PATH redirect an allowed program.
const LEADING_ASSIGNMENT = /^\s*[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=/;

// A `{m,n}` or `{m,}` quantifier. `{,n}` is not one in JS (it matches literally), so that
// comma stays a delimiter, as it always has been.
const QUANTIFIER_WITH_COMMA = /\{\d+,\d*\}/y;

// Unescaped in a class after an unescaped comma, these suggest the comma ended an entry and
// the text after it is the next pattern. Punctuation such as `[,;]` or `[, ]` does not.
const PATTERN_TEXT_AFTER_CLASS_COMMA = /[A-Za-z0-9_,[^]/;

/** Why a pattern that `new RegExp` accepted was still refused. */
const LOOSE_QUANTIFIER_NOTE =
  "an unbalanced { ... } (an unclosed or invalid quantifier; write {n,m} or escape the brace as \\{)";

/**
 * True when the pattern holds a `{` that starts like a quantifier (a digit
 * follows) but does not end as a well-formed `{n}` / `{n,}` / `{n,m}`.
 *
 * JS compiles `new RegExp("a{1,2")` -- an unclosed quantifier -- as the
 * LITERAL `a{1,2`, raising no SyntaxError, so the malformed-entry guard below
 * would miss it and the operator's deny would silently not apply while the
 * server reported its policy in effect. Scanning for the shape a typo produces
 * closes that hole. A `{` not followed by a digit is left alone: `a{,3}` and
 * `^a{` are literal text in JS, and patterns that use them are documented and
 * tested as working.
 */
function hasLooseQuantifier(src: string): boolean {
  let inClass = false;
  let i = 0;
  while (i < src.length) {
    const c = src[i] as string;
    if (c === "\\") {
      // Only a `{` DIRECTLY after a single backslash (`\{`) is a guaranteed
      // escaped brace, which can never start a quantifier. `\\{` is an escaped
      // backslash followed by a literal `{` -- V8 reads a `{` that is not a
      // valid quantifier as literal text anyway, so that shape (and any longer
      // backslash run) is skipped as a whole and left to the check below,
      // because treating it as escaped refused `^a\\{1,2$`, a pattern that
      // compiles correctly.
      if (src[i + 1] === "\\" && src[i + 2] !== "\\") {
        i += 2; // exactly one backslash: the next char is escaped
        continue;
      }
      i++; // part of a longer run (or a trailing lone backslash): move on
      continue;
    }
    if (inClass) {
      if (c === "]") inClass = false;
      i++;
    } else if (c === "[") {
      inClass = true;
      i++;
    } else if (c === "{") {
      const rest = src.slice(i);
      const quantifier = /^\{\d+(?:,\d*)?\}/.exec(rest);
      if (quantifier) {
        i += quantifier[0].length;
      } else if (/^\{\d/.test(rest)) {
        return true;
      } else {
        i++;
      }
    } else {
      i++;
    }
  }
  return false;
}

/**
 * Split a pattern list on the commas that are delimiters, leaving alone the commas that
 * belong to a regex: escaped (`\,`), inside a character class (`[,]`), or in a `{m,n}`
 * quantifier.
 *
 * A typo'd `[` puts the scan in class mode until the next `]`, however many entries away,
 * and the merged text is often a VALID regex: `^rm[,^reboot,^mkfs[.]` is one class, and the
 * deny entries inside it would silently stop applying. A class holding an unescaped comma is
 * therefore returned in `ambiguousClasses` when EITHER its content suggests a swallowed
 * separator (an unescaped `[` before the comma, or pattern-like text after it) OR a real
 * top-level entry follows the class -- the class's comma then sits exactly where a delimiter
 * would (`^rm[abc,>],^df` absorbed the `>` entry into the class). The second rule fires only
 * when another entry follows, so a single pattern like `^[a-z,_]+$`, where no comma in the
 * value could be a delimiter, is never refused. A class that never closes needs no check: it
 * fails to compile.
 */
function splitPatternList(raw: string): { entries: string[]; ambiguousClasses: string[] } {
  const entries: string[] = [];
  const ambiguousClasses: string[] = [];
  /** Every index at which a real top-level entry was cut. */
  const topLevelCommas: number[] = [];
  /** Classes that closed: span in the raw string, whether the forward scan's content
   *  heuristic fired, and whether the class held any unescaped comma at all. */
  const classSpans: { start: number; end: number; heuristic: boolean; hasComma: boolean }[] = [];
  let start = 0;
  let inClass = false;
  let classStart = 0;
  let classHasComma = false;
  let classHasBracket = false;
  let classIsAmbiguous = false;
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (c === "\\") {
      i++;
    } else if (inClass) {
      if (c === "]") {
        inClass = false;
        classSpans.push({ start: classStart, end: i, heuristic: classIsAmbiguous, hasComma: classHasComma });
      } else {
        if (classHasComma ? PATTERN_TEXT_AFTER_CLASS_COMMA.test(c) : c === "," && classHasBracket) {
          classIsAmbiguous = true;
        }
        classHasComma ||= c === ",";
        classHasBracket ||= c === "[";
      }
    } else if (c === "[") {
      inClass = true;
      classStart = i;
      classHasComma = false;
      classHasBracket = false;
      classIsAmbiguous = false;
    } else if (c === "{") {
      QUANTIFIER_WITH_COMMA.lastIndex = i;
      const quantifier = QUANTIFIER_WITH_COMMA.exec(raw);
      if (quantifier) i += quantifier[0].length - 1;
    } else if (c === ",") {
      topLevelCommas.push(i);
      entries.push(raw.slice(start, i));
      start = i + 1;
    }
  }
  entries.push(raw.slice(start));
  for (const span of classSpans) {
    // A class with no unescaped comma in it cannot have swallowed a delimiter.
    if (!span.hasComma) continue;
    const anotherEntryFollows = topLevelCommas.some((p) => p > span.end);
    if (span.heuristic || anotherEntryFollows) {
      ambiguousClasses.push(raw.slice(span.start, span.end + 1));
    }
  }
  return { entries, ambiguousClasses };
}

/**
 * Compile one env var's comma-separated pattern list.
 *
 * FAIL-CLOSED CONTRACT. If the var is set to something non-empty and ANY entry fails to
 * compile, or it declares no entry at all, this throws and every gated call is refused.
 *
 * Why every entry and not just "at least one": a dropped deny entry silently stops blocking
 * what the operator listed, and a dropped allow entry means the policy being enforced is not
 * the one that was written. A security control that erodes on a typo is worse than no
 * control, because the operator believes it is running. An empty list is also
 * indistinguishable from "this var was never set", which enforcePolicy reads as "no policy
 * configured, allow through".
 */
function parsePatterns(raw: string | undefined, envVarName: string): RegExp[] {
  if (!raw) return [];
  const patterns: RegExp[] = [];
  const malformed: string[] = [];
  const { entries, ambiguousClasses } = splitPatternList(raw);
  for (const p of entries) {
    // Trim LEADING whitespace only -- handles the "^ls, ^df" comma-then-space style
    // without silently stripping a significant trailing space. Patterns like "^rm "
    // (blocks `rm foo` but not `rmdir`) rely on the trailing space being preserved.
    const cleaned = p.replace(/^\s+/, "");
    if (!cleaned) continue;
    try {
      const re = new RegExp(cleaned);
      if (hasLooseQuantifier(re.source)) malformed.push(`"${cleaned}" (${LOOSE_QUANTIFIER_NOTE})`);
      else patterns.push(re);
    } catch (err) {
      malformed.push(`"${cleaned}" (${err instanceof Error ? err.message : String(err)})`);
    }
  }
  for (const cls of ambiguousClasses) {
    malformed.push(
      `"${cls}" (ambiguous character class: its comma may be separating entries after a "[" that was never closed.` +
        ' If that "[" is a typo, close it or escape it as \\[. If the comma is meant literally, write it as \\,)',
    );
  }

  // Every path out of a var the operator SET must be one of: usable patterns, or a
  // refusal. A blank value ("   ", ",,") used to read as "unset" here while
  // isPolicyConfigured read it as set -- policy then vanished on a stray keystroke
  // while the operator was told one was running, which is the fail-open the
  // malformed-entry guard exists to prevent.
  if (malformed.length > 0 || patterns.length === 0) {
    const detail =
      malformed.length > 0
        ? `Malformed pattern(s): ${malformed.join(", ")}.`
        : raw.trim() === ""
          ? `The value ${JSON.stringify(raw)} is whitespace only, so it declares no patterns.`
          : `The value ${JSON.stringify(raw)} contains only separators, so it declares no patterns.`;
    throw new Error(
      `Command blocked -- ssh-mcp command policy is MISCONFIGURED: ${envVarName} could not be fully compiled,` +
        " so every ssh_exec / ssh_multi_exec call is refused until it is fixed (failing closed: a policy with" +
        ` a broken entry is not the policy you wrote). ${detail} Each comma-separated entry must be a valid` +
        " JavaScript regex. A comma inside [...], in a {m,n} quantifier, or escaped as \\, belongs to the" +
        " pattern; any other comma separates entries, so a literal comma inside a group must be written" +
        " \\, or [,]. Fix or unset the variable to restore service.",
    );
  }

  return patterns;
}

/** Read the opt-out strictly: a value we cannot interpret must not change enforcement silently. */
function shellSyntaxAllowed(): boolean {
  const raw = process.env[ALLOW_SHELL_SYNTAX_VAR] ?? "";
  const value = raw.trim().toLowerCase();
  if (value === "1" || value === "true") return true;
  if (value === "" || value === "0" || value === "false") return false;
  throw new Error(
    `Command blocked -- ssh-mcp command policy is MISCONFIGURED: ${ALLOW_SHELL_SYNTAX_VAR} is set to` +
      ` ${JSON.stringify(raw)}, which is not a recognized value. Set it to 1 or true to opt out of the` +
      " whitelist shell-syntax check, or to 0, false or nothing to keep the check.",
  );
}

/**
 * Extra checks on a command that already matched the whitelist. A pattern like `^ls( |$)`
 * says nothing about the rest of the line, so without this `ls ; reboot` and `ls $(reboot)`
 * pass, and `LD_PRELOAD=/tmp/x.so ls` passes any pattern loose enough to accept it. This
 * narrows what a match can mean; it does not make the match safe, because an allowed program
 * may still run things on its own.
 */
function checkWhitelistedShape(command: string, context: PolicyContext): void {
  const optOut =
    `If this deployment really needs it, an administrator can set ${ALLOW_SHELL_SYNTAX_VAR}=1, which` +
    " returns to pattern-only matching and makes each pattern responsible for the entire command string.";

  if (LEADING_ASSIGNMENT.test(command)) {
    const fix = context.envPrefixApplied
      ? "Remove the `env` parameter from this call."
      : "Remove the assignment and run the command on its own.";
    throw new Error(
      "Command blocked: SSH_MCP_COMMAND_WHITELIST is active and the command starts with an environment" +
        ` variable assignment, which can change what an allowed command runs (LD_PRELOAD, PATH and similar). ${fix} ${optOut}`,
    );
  }

  const control = SHELL_CONTROL_SYNTAX.exec(command);
  if (control) {
    throw new Error(
      "Command blocked: SSH_MCP_COMMAND_WHITELIST is active and the command contains shell control syntax" +
        ` (${JSON.stringify(control[0])}), which can run something the matched pattern never names. Quoting does` +
        " not exempt it, because the remote shell's quoting rules are not known here. Run one plain command" +
        " without ; & | ` $( ${ $[ @{ ( ) < > or a line break, and split a pipeline into separate calls." +
        ` ${optOut}`,
    );
  }
}

export interface PolicyContext {
  /**
   * True when `command` carries an env-var prefix (`KEY='value' ...`) built from the
   * ssh_exec / ssh_multi_exec `env` parameter. Enforcement is identical either way -- this
   * only tailors a whitelist rejection, so an operator whose previously working
   * `^`-anchored pattern just started failing can see why and what to change.
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

  if (whitelist.length > 0) {
    // Read first so a bad opt-out value is reported as misconfiguration on every call.
    const allowShellSyntax = shellSyntaxAllowed();
    if (!whitelist.some((r) => r.test(command))) {
      let message = `Command blocked: does not match any pattern in SSH_MCP_COMMAND_WHITELIST. Configured patterns: ${whitelist.map((r) => r.source).join(", ")}`;
      if (context.envPrefixApplied) {
        // Policy is checked against the env-PREFIXED string, so `^ls` rejects `ls` as soon as
        // any env var is passed. The suggested pattern names the variable and pins the whole
        // line on purpose: the opt-out it needs also turns off the shell-syntax check, and a
        // generic NAME= pattern would admit LD_PRELOAD and PATH. The value group accepts
        // shellQuote's close-escape-reopen form (`O'Brien` -> `'O'\''Brien'`).
        message +=
          ". NOTE: an `env` prefix was applied, and policy is checked against the PREFIXED command" +
          " -- the string starts with the first `KEY='value'` assignment, not the command verb," +
          " so a `^`-anchored pattern that matches without `env` stops matching with it." +
          " Under a whitelist the fix is normally to remove `env` from the call: assignments are refused" +
          " by default because they can change what an allowed command runs. To permit one specific" +
          ` variable, an administrator must set ${ALLOW_SHELL_SYNTAX_VAR}=1 and add a pattern that names it` +
          " and spells out the whole command, e.g." +
          " `^FOO='(?:[^']|'\\\\'')*' ls( [A-Za-z0-9_./:=@%+-]+)*$`." +
          " That opt-out also disables the shell-syntax check, so every whitelist pattern must then be" +
          " anchored at both ends. Do not use a generic variable-name pattern: it would admit LD_PRELOAD" +
          " and PATH.";
      }
      throw new Error(message);
    }
    if (!allowShellSyntax) checkWhitelistedShape(command, context);
  }

  for (const pattern of blacklist) {
    if (pattern.test(command)) {
      throw new Error(`Command blocked by SSH_MCP_COMMAND_BLACKLIST: pattern "${pattern.source}"`);
    }
  }
}

/** Returns true if any policy is currently configured. Exported for library consumers and tests; tool descriptions use static "if configured" text instead.
 *
 * Tests the RAW value, not its trim: a var that is set to whitespace used to report
 * "configured" while enforcePolicy read the same whitespace as unset and allowed
 * everything through. enforcePolicy now fails closed on a blank value, so "set" and
 * "configured" must agree. */
export function isPolicyConfigured(): boolean {
  return Boolean(process.env.SSH_MCP_COMMAND_WHITELIST || process.env.SSH_MCP_COMMAND_BLACKLIST);
}
