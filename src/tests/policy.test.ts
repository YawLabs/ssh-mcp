import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { enforcePolicy, isPolicyConfigured } from "../policy.js";

describe("enforcePolicy", () => {
  beforeEach(() => {
    vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "");
    vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "");
    vi.stubEnv("SSH_MCP_COMMAND_ALLOW_SHELL_SYNTAX", "");
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  describe("default (no env)", () => {
    it("allows any command when no policy is set", () => {
      expect(() => enforcePolicy("ls -la")).not.toThrow();
      expect(() => enforcePolicy("rm -rf /tmp/foo")).not.toThrow();
      expect(() => enforcePolicy("anything; goes")).not.toThrow();
    });

    it("isPolicyConfigured returns false", () => {
      expect(isPolicyConfigured()).toBe(false);
    });
  });

  describe("whitelist only", () => {
    it("allows commands that match a whitelist pattern", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls( .*)?,^df.*,^uptime$");
      expect(() => enforcePolicy("ls")).not.toThrow();
      expect(() => enforcePolicy("ls -la /var/log")).not.toThrow();
      expect(() => enforcePolicy("df -h")).not.toThrow();
      expect(() => enforcePolicy("uptime")).not.toThrow();
    });

    it("blocks commands that match none of the whitelist patterns", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls( .*)?,^df.*");
      expect(() => enforcePolicy("rm -rf /")).toThrow(/does not match any pattern in SSH_MCP_COMMAND_WHITELIST/);
      expect(() => enforcePolicy("cat /etc/passwd")).toThrow(/SSH_MCP_COMMAND_WHITELIST/);
    });

    it("error message includes the configured patterns", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls,^df");
      expect(() => enforcePolicy("rm foo")).toThrow(/Configured patterns: \^ls, \^df/);
    });
  });

  describe("blacklist only", () => {
    it("allows commands that don't match any blacklist pattern", () => {
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "^rm ,^shutdown,^reboot");
      expect(() => enforcePolicy("ls -la")).not.toThrow();
      expect(() => enforcePolicy("df -h")).not.toThrow();
    });

    it("blocks commands that match a blacklist pattern", () => {
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "^rm ,^shutdown");
      expect(() => enforcePolicy("rm -rf /")).toThrow(/SSH_MCP_COMMAND_BLACKLIST/);
      expect(() => enforcePolicy("shutdown now")).toThrow(/SSH_MCP_COMMAND_BLACKLIST/);
    });

    it("error message identifies which pattern matched", () => {
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "^ls,^rm ,^cat ");
      expect(() => enforcePolicy("rm -rf /tmp")).toThrow(/pattern "\^rm "/);
    });

    it("preserves trailing whitespace in patterns (^rm blocks rm but not rmdir)", () => {
      // This was a real bug: trim() stripped the trailing space and ^rm matched rmdir.
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "^rm ");
      expect(() => enforcePolicy("rm -rf /tmp")).toThrow();
      expect(() => enforcePolicy("rmdir /tmp/empty")).not.toThrow();
    });
  });

  describe("both whitelist and blacklist", () => {
    it("requires the command to pass both checks", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls,^find ,^cat ");
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "/etc/shadow");
      // In whitelist, not in blacklist -> allowed
      expect(() => enforcePolicy("ls /var/log")).not.toThrow();
      expect(() => enforcePolicy("cat /var/log/messages")).not.toThrow();
      // In whitelist but ALSO in blacklist -> blocked by blacklist
      expect(() => enforcePolicy("cat /etc/shadow")).toThrow(/SSH_MCP_COMMAND_BLACKLIST/);
      // Not in whitelist -> blocked by whitelist before blacklist even runs
      expect(() => enforcePolicy("rm /etc/shadow")).toThrow(/SSH_MCP_COMMAND_WHITELIST/);
    });
  });

  describe("regex handling", () => {
    it("ignores empty / whitespace entries between commas", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls,,  ,^df");
      expect(() => enforcePolicy("ls")).not.toThrow();
      expect(() => enforcePolicy("df")).not.toThrow();
      expect(() => enforcePolicy("rm")).toThrow();
    });

    it("one malformed whitelist entry refuses every command, even ones a valid sibling allows", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "(unclosed,^df");
      expect(() => enforcePolicy("df -h")).toThrow(/MISCONFIGURED: SSH_MCP_COMMAND_WHITELIST/);
      expect(() => enforcePolicy("df -h")).toThrow(/"\(unclosed"/);
    });

    it("one malformed blacklist entry refuses every command instead of dropping the entry", () => {
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "^rm ,(unclosed");
      expect(() => enforcePolicy("ls")).toThrow(/MISCONFIGURED: SSH_MCP_COMMAND_BLACKLIST/);
      expect(() => enforcePolicy("ls")).toThrow(/Fix or unset the variable/);
    });

    it("patterns without ^/$ are substring matches", () => {
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "passwd");
      expect(() => enforcePolicy("cat /etc/passwd")).toThrow();
      expect(() => enforcePolicy("ls -la")).not.toThrow();
    });
  });

  describe("comma handling in pattern lists", () => {
    it("keeps a comma inside a character class (the documented [,] form)", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^foo[,]bar$");
      expect(() => enforcePolicy("foo,bar")).not.toThrow();
      // Split at the comma this was `^foo[` (dropped) plus a live `]bar$`.
      expect(() => enforcePolicy("reboot # ]bar")).toThrow(/does not match any pattern/);
    });

    it("keeps a comma in a {m,n} quantifier", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^a{1,3}$");
      expect(() => enforcePolicy("aaa")).not.toThrow();
      expect(() => enforcePolicy("aaaa")).toThrow(/does not match any pattern/);
      expect(() => enforcePolicy("3}")).toThrow(/does not match any pattern/);
    });

    it("keeps an open-ended {m,} quantifier and still splits after it", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^a{2,}$,^df$");
      expect(() => enforcePolicy("aaaa")).not.toThrow();
      expect(() => enforcePolicy("df")).not.toThrow();
      expect(() => enforcePolicy("a")).toThrow(/does not match any pattern/);
    });

    it("keeps an escaped comma, and an escaped ] does not end the class", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^a\\,b$,^x[\\],]y$");
      expect(() => enforcePolicy("a,b")).not.toThrow();
      expect(() => enforcePolicy("x,y")).not.toThrow();
      expect(() => enforcePolicy("x]y")).not.toThrow();
    });

    it("an escaped backslash does not escape the delimiter after it", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^a\\\\$,^df$");
      expect(() => enforcePolicy("a\\")).not.toThrow();
      expect(() => enforcePolicy("df")).not.toThrow();
    });

    it("still splits existing lists, including the literal-brace {,n} form", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^a{,^df$, ^uptime$");
      expect(() => enforcePolicy("a{")).not.toThrow();
      expect(() => enforcePolicy("df")).not.toThrow();
      expect(() => enforcePolicy("uptime")).not.toThrow();
    });

    it("an unterminated class fails closed rather than guessing where it ends", () => {
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "^a[b,^rm ");
      expect(() => enforcePolicy("ls")).toThrow(/MISCONFIGURED: SSH_MCP_COMMAND_BLACKLIST/);
    });

    // Each value has an unclosed `[` whose class would otherwise run on to a later `]`, merging
    // the entries between into one valid regex so the deny entries silently stop applying.
    it.each([
      ["a later entry has its own class", "^rm[,^reboot,^mkfs[.]"],
      ["the typo has members before the comma", "^rm[x,^reboot,^mkfs[.]"],
      ["a later entry only ends in ]", "^rm[,^reboot,x]"],
      ["the only later entry escapes its [", "^rm[,reboot\\[1]"],
      ["one plain entry follows", "^rm[,reboot]"],
      ["the [ comes before the comma", "^rm[a[,]"],
      ["the next entry is only an anchor", "^rm[,^]"],
      // Measured: these two compile as ONE pattern (a class that never denies `rm`), and the
      // content heuristic does NOT catch them -- their comma is followed only by shell
      // punctuation. Only the "another entry follows" rule refuses them, so they pin that rule
      // and are why the documented `[,]` form is not accepted in a multi-entry list.
      ["a swallow with letters before the comma", "^rm[abc,>],^df"],
      ["a swallow with only punctuation after the comma", "^rm[,>|],^df"],
    ])("fails closed when a class may have swallowed entries: %s", (_name, value) => {
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", value);
      for (const command of ["reboot now", "mkfs.ext4 /dev/sda", "rm -rf /", "ls"]) {
        expect(() => enforcePolicy(command)).toThrow(/MISCONFIGURED: SSH_MCP_COMMAND_BLACKLIST/);
      }
    });

    it("the same ambiguity in a whitelist fails closed too", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls[,^df,^du[.]");
      expect(() => enforcePolicy("ls")).toThrow(/MISCONFIGURED: SSH_MCP_COMMAND_WHITELIST/);
    });

    it("the ambiguity error names the class and both ways to fix it", () => {
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "^rm[,^reboot,^mkfs[.]");
      expect(() => enforcePolicy("ls")).toThrow(/"\[,\^reboot,\^mkfs\[\.\]"/);
      expect(() => enforcePolicy("ls")).toThrow(/escape it as \\\[/);
      expect(() => enforcePolicy("ls")).toThrow(/write it as \\,/);
    });

    it.each([
      ["^a[,:]b$", "a:b"],
      ["^a[, ]b$", "a b"],
      ["^[^,]+$", "abc"],
      ["^[0-9,]+$", "1,2"],
      ["^[a-z,]+$", "a,b"],
      ["^a[,\\s]b$", "a b"],
      // KNOWN WART (deferred): `^[a-z,_]+$` is refused even as a SINGLE pattern, though no
      // comma in the value could be a delimiter, because `_` after the class comma trips
      // PATTERN_TEXT_AFTER_CLASS_COMMA. Pre-existing; narrowing it needs a classifier
      // redesign, not a row here.
    ])("still accepts the unambiguous class in %j", (pattern, command) => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", pattern);
      expect(() => enforcePolicy(command)).not.toThrow();
    });

    it("refuses an unescaped [,] class as soon as a sibling entry follows, and says so", () => {
      // The `[,]` idiom is fine alone (row above), but in a LIST its comma is
      // indistinguishable from a delimiter, so it is refused -- the error names the class
      // and points at `\,`. The escaped form is accepted in a list. README documents this.
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^foo[,]bar$,^df$");
      expect(() => enforcePolicy("df")).toThrow(/MISCONFIGURED: SSH_MCP_COMMAND_WHITELIST/);
      expect(() => enforcePolicy("df")).toThrow(/ambiguous character class/);
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^foo[\\,]bar$,^df$");
      expect(() => enforcePolicy("foo,bar")).not.toThrow();
      expect(() => enforcePolicy("df")).not.toThrow();
    });

    it("does not refuse an unescaped [,] class that is the only pattern in the list", () => {
      // No comma in the value could be a delimiter, so the single-pattern case is unaffected.
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^foo[,]bar$");
      expect(() => enforcePolicy("foo,bar")).not.toThrow();
    });

    it("an escaped comma keeps working where an unescaped one is ambiguous", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^[a\\,b]$,^df$");
      expect(() => enforcePolicy("b")).not.toThrow();
      expect(() => enforcePolicy(",")).not.toThrow();
      expect(() => enforcePolicy("df")).not.toThrow();
    });

    it("applies to the blacklist too", () => {
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "^foo[,]bar$");
      expect(() => enforcePolicy("foo,bar")).toThrow(/SSH_MCP_COMMAND_BLACKLIST/);
      expect(() => enforcePolicy("x ]bar")).not.toThrow();
    });
  });

  describe("shell syntax under an active whitelist", () => {
    it.each([
      "ls ; rm -rf /",
      "ls $(reboot)",
      "ls `reboot`",
      "ls | sh",
      "ls || reboot",
      "ls && reboot",
      "ls & reboot",
      "ls > /tmp/x",
      "ls < /tmp/x",
      "ls <(reboot)",
      "ls x\nreboot",
      "ls x\r\nreboot",
      `ls $${"{IFS}"}x`,
      "ls $[1+1]",
      "ls (reboot)",
      // A PowerShell hash literal runs its values while the argument is evaluated.
      "ls @{a=New-Item x}",
      "ls -Path:@{a=New-Item x}",
      "ls $PSHOME.@{a=New-Item x}",
      "ls '@{a=New-Item x}'",
    ])("refuses %j even though it matches ^ls( |$)", (command) => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls( |$)");
      expect(() => enforcePolicy(command)).toThrow(/shell control syntax/);
    });

    it("does not trust quoting, because the remote shell's rules are unknown", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls( |$)");
      // Quoted to sh, but fish reads \' inside single quotes as an escape and runs reboot.
      expect(() => enforcePolicy("ls '\\''; reboot #'")).toThrow(/shell control syntax/);
      expect(() => enforcePolicy("ls 'a;b'")).toThrow(/shell control syntax/);
    });

    it.each([
      "LD_PRELOAD=/tmp/x.so ls",
      "PATH=/tmp ls",
      "PATH+=:/tmp ls",
      "  FOO=1 ls",
      "\tFOO=1 ls",
      "A[0]=1 ls",
      "FOO= ls",
    ])("refuses the leading assignment in %j", (command) => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "ls");
      expect(() => enforcePolicy(command)).toThrow(/variable assignment/);
    });

    it("does not refuse braces or @ on their own", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls( |$)");
      for (const command of ["ls {a,b}", "ls user@host", "ls @ {a}"]) {
        expect(() => enforcePolicy(command)).not.toThrow();
      }
    });

    it("still allows plain commands, including = in later arguments", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls( |$)");
      expect(() => enforcePolicy("ls")).not.toThrow();
      expect(() => enforcePolicy("ls -la /var/log")).not.toThrow();
      expect(() => enforcePolicy("ls --color=auto $HOME")).not.toThrow();
    });

    it("the error names the opt-out", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls( |$)");
      expect(() => enforcePolicy("ls ; id")).toThrow(/SSH_MCP_COMMAND_ALLOW_SHELL_SYNTAX=1/);
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "ls");
      expect(() => enforcePolicy("PATH=/tmp ls")).toThrow(/SSH_MCP_COMMAND_ALLOW_SHELL_SYNTAX=1/);
    });

    it("does not apply when only a blacklist is configured", () => {
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "^reboot");
      expect(() => enforcePolicy("FOO=1 ls | wc -l")).not.toThrow();
    });

    it.each(["1", "true", "TRUE", " 1 "])("SSH_MCP_COMMAND_ALLOW_SHELL_SYNTAX=%j opts out", (value) => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "ls");
      vi.stubEnv("SSH_MCP_COMMAND_ALLOW_SHELL_SYNTAX", value);
      expect(() => enforcePolicy("ls | wc -l")).not.toThrow();
      expect(() => enforcePolicy("FOO=1 ls")).not.toThrow();
    });

    it.each(["0", "false", ""])("SSH_MCP_COMMAND_ALLOW_SHELL_SYNTAX=%j keeps the check", (value) => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls( |$)");
      vi.stubEnv("SSH_MCP_COMMAND_ALLOW_SHELL_SYNTAX", value);
      expect(() => enforcePolicy("ls ; id")).toThrow(/shell control syntax/);
    });

    it("an unrecognized opt-out value fails closed and says what to set", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls( |$)");
      vi.stubEnv("SSH_MCP_COMMAND_ALLOW_SHELL_SYNTAX", "yes");
      expect(() => enforcePolicy("ls")).toThrow(/MISCONFIGURED: SSH_MCP_COMMAND_ALLOW_SHELL_SYNTAX/);
      expect(() => enforcePolicy("ls")).toThrow(/Set it to 1 or true/);
    });

    it("refuses the export and env spellings of a leading assignment", () => {
      // `env LD_PRELOAD=... ls` is the same redirection as `LD_PRELOAD=... ls` by another
      // name, and matched a bare `ls` whitelist pattern before this was added.
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "ls");
      for (const command of [
        "env LD_PRELOAD=/tmp/x.so ls",
        "export PATH=/tmp; ls",
        "export FOO=ops ls",
        "  env FOO=1 ls",
      ]) {
        expect(() => enforcePolicy(command)).toThrow(/variable assignment/);
      }
      // A word that merely STARTS with `env`, or `env` as a later argument, is untouched.
      for (const command of ["ls environment", "ls -la env", "ls env x"]) {
        expect(() => enforcePolicy(command)).not.toThrow();
      }
    });

    it("the assignment check only sees the bare `env ` spelling, so other spellings still pass", () => {
      // PINS A LIMIT, not desired behaviour. LEADING_ASSIGNMENT anchors on the literal
      // `env ` keyword, and a whitelist pattern can only match the command if the operator
      // wrote something that admits `env` in the first place. Once they have, every spelling
      // except the bare one carries the redirection through: `/usr/bin/env`, a backslash
      // escape and the `command` builtin all leave the assignment in place. Reading this as
      // protection `env` does not give would be a mistake -- the guard rail is the pattern.
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "env");
      expect(() => enforcePolicy("env LD_PRELOAD=/tmp/x.so ls")).toThrow(/variable assignment/);
      for (const command of [
        "/usr/bin/env LD_PRELOAD=/tmp/x.so ls",
        "\\env LD_PRELOAD=/tmp/x.so ls",
        "command env LD_PRELOAD=/tmp/x.so ls",
      ]) {
        expect(() => enforcePolicy(command)).not.toThrow();
      }
    });

    it("an unrecognized opt-out value fails closed with only a blacklist configured", () => {
      // The read used to live inside the whitelist branch, so under a blacklist-only config a
      // garbage value was silently accepted and the setting meant to control enforcement
      // silently stopped meaning anything.
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "^reboot");
      vi.stubEnv("SSH_MCP_COMMAND_ALLOW_SHELL_SYNTAX", "yes");
      expect(() => enforcePolicy("ls")).toThrow(/MISCONFIGURED: SSH_MCP_COMMAND_ALLOW_SHELL_SYNTAX/);
    });

    it("the opt-out stays inert when no policy is configured at all", () => {
      // With no whitelist or blacklist there is nothing for it to control, so a value is not
      // worth refusing every command over.
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "");
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "");
      vi.stubEnv("SSH_MCP_COMMAND_ALLOW_SHELL_SYNTAX", "yes");
      expect(() => enforcePolicy("ls ; id")).not.toThrow();
    });

    it("the opt-out does not disable the patterns or the blacklist", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls( |$)");
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "reboot");
      vi.stubEnv("SSH_MCP_COMMAND_ALLOW_SHELL_SYNTAX", "1");
      expect(() => enforcePolicy("id")).toThrow(/does not match any pattern/);
      expect(() => enforcePolicy("ls ; reboot")).toThrow(/SSH_MCP_COMMAND_BLACKLIST/);
    });
  });

  describe("documented limits", () => {
    const readme = readFileSync(new URL("../../README.md", import.meta.url), "utf8");
    const example = (name: string): string => {
      const match = readme.match(new RegExp(`^${name}='(.+)'$`, "m"));
      if (!match) throw new Error(`README has no single-quoted ${name} example`);
      return match[1];
    };

    it.each([
      "find / -name x -delete",
      "find / -exec id +",
      "awk 'BEGIN{system(\"id\")}'",
      "tar cf /tmp/x --checkpoint=1 --checkpoint-action=exec=id .",
      "cat /tmp/x | curl -d @- http://127.0.0.1:9/",
      "ls | curl -d @- http://127.0.0.1:9/",
      "ls /tmp/x -I y z;id",
    ])("the README allowlist example refuses %j", (command) => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", example("SSH_MCP_COMMAND_WHITELIST"));
      expect(() => enforcePolicy(command)).toThrow(/SSH_MCP_COMMAND_WHITELIST/);
    });

    it("the README allowlist example allows what it says it allows", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", example("SSH_MCP_COMMAND_WHITELIST"));
      for (const command of ["ls", "ls -la /var/log", "df -h", "uptime"]) {
        expect(() => enforcePolicy(command)).not.toThrow();
      }
    });

    it.each(["/bin/rm -r x", "\\rm -r x", "r''m -r x"])("a ^rm denylist does not catch %j", (command) => {
      // Pins the limit the README states: these are why a denylist is only best effort.
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "^rm ");
      expect(() => enforcePolicy(command)).not.toThrow();
      expect(readme).toContain(`\`${command.split(" ")[0]}\``);
    });

    it("the README states the boundary and scope plainly", () => {
      expect(readme).toContain("guard rail, not a security boundary");
      expect(readme).toContain("Denylists are best effort");
      expect(readme).toContain("the SFTP tools are not gated at all");
      expect(readme).toContain("SSH_MCP_COMMAND_ALLOW_SHELL_SYNTAX=1");
    });
  });

  describe("isPolicyConfigured", () => {
    it("returns true when whitelist is set", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "^ls");
      expect(isPolicyConfigured()).toBe(true);
    });

    it("returns true when blacklist is set", () => {
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "^rm");
      expect(isPolicyConfigured()).toBe(true);
    });

    it("returns true for whitespace-only env values: the var IS set, and enforcePolicy fails closed on it", () => {
      vi.stubEnv("SSH_MCP_COMMAND_WHITELIST", "   ");
      vi.stubEnv("SSH_MCP_COMMAND_BLACKLIST", "");
      expect(isPolicyConfigured()).toBe(true);
    });
  });
});
