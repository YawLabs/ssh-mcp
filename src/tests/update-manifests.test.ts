import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

// scripts/update-manifests.mjs writes package.json's description (and the
// homepage, version and license) into Ruby double-quoted strings in the
// Homebrew formula. These tests pin the escaping that keeps each value a plain
// string (CodeQL js/incomplete-sanitization).
const scriptPath = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "scripts", "update-manifests.mjs");

interface FormulaInput {
  className: string;
  cmd: string;
  description?: string;
  homepage: string;
  version: string;
  license?: string;
  assets: Record<"macArm64" | "macX64" | "linuxX64", { url: string; sha256: string }>;
}

let rubyString: (value: unknown) => string;
let renderFormula: (input: FormulaInput) => string;

beforeAll(async () => {
  // A computed specifier keeps tsc from resolving the untyped .mjs, and
  // importing it must not run the release side effects (gh release download).
  const mod = (await import(pathToFileURL(scriptPath).href)) as {
    rubyString: typeof rubyString;
    renderFormula: typeof renderFormula;
  };
  rubyString = mod.rubyString;
  renderFormula = mod.renderFormula;
});

// Read the body of a Ruby double-quoted literal the way Ruby does, failing on
// anything that would end the string early or interpolate code.
function parseRubyDq(body: string): string {
  let out = "";
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === "\\") {
      const next = body[++i];
      if (next === undefined) throw new Error("dangling backslash escapes the closing quote");
      out += next === "n" ? "\n" : next === "r" ? "\r" : next;
    } else if (c === '"') {
      throw new Error(`unescaped quote at ${i} ends the string early`);
    } else if (c === "#" && /[{@$]/.test(body[i + 1] ?? "")) {
      throw new Error(`unescaped interpolation at ${i}`);
    } else if (c === "\n" || c === "\r") {
      throw new Error(`raw line break at ${i}`);
    } else {
      out += c;
    }
  }
  return out;
}

const asset = (name: string) => ({ url: `https://example.test/${name}`, sha256: "0".repeat(64) });
const baseInput: FormulaInput = {
  className: "SshMcp",
  cmd: "ssh-mcp",
  description: "SSH MCP server",
  homepage: "https://yaw.sh/mcp-servers/ssh-mcp/",
  version: "0.17.1",
  license: "MIT",
  assets: { macArm64: asset("a"), macX64: asset("b"), linuxX64: asset("c") },
};

describe("update-manifests rubyString", () => {
  const cases = [
    "SSH MCP server: run remote commands, transfer files over SFTP, manage ssh-agent keys and known_hosts, and auto-diagnose SSH failures.",
    'He said "hi"',
    "trailing backslash \\",
    'backslash then quote \\"',
    "C:\\path\\to\\thing",
    '#{system("rm -rf ~")}',
    "#@ivar and #$global",
    "C# support, #1 pick",
    "line one\nline two\r\n",
    "",
  ];

  for (const input of cases) {
    it(`round-trips ${JSON.stringify(input)}`, () => {
      expect(parseRubyDq(rubyString(input))).toBe(input);
    });
  }

  it("escapes the backslash before the quote", () => {
    // The old `.replace(/"/g, '\\"')` turned `\"` into `\\"`, which Ruby reads
    // as an escaped backslash followed by a closing quote.
    expect(rubyString('a\\"b')).toBe('a\\\\\\"b');
  });

  it("escapes # only where it starts interpolation", () => {
    // A redundant `\#` is legal Ruby but brew style flags it.
    expect(rubyString("C# support")).toBe("C# support");
    expect(rubyString("#{x} #@y #$z")).toBe("\\#{x} \\#@y \\#$z");
  });

  it("treats null and undefined as empty", () => {
    expect(rubyString(undefined)).toBe("");
    expect(rubyString(null)).toBe("");
  });
});

describe("update-manifests renderFormula", () => {
  const stanza = (formula: string, key: string): string => {
    const m = formula.match(new RegExp(`^  ${key} "(.*)"$`, "m"));
    if (!m) throw new Error(`no one-line ${key} stanza in formula:\n${formula}`);
    return m[1];
  };

  it("routes a hostile description through rubyString", () => {
    const description = 'evil \\" #{system("id")}\nmore';
    const formula = renderFormula({ ...baseInput, description });
    const body = stanza(formula, "desc");
    expect(body).toBe(rubyString(description));
    expect(parseRubyDq(body)).toBe(description);
  });

  it("escapes homepage, version and license too", () => {
    const formula = renderFormula({
      ...baseInput,
      homepage: 'https://x.test/"#{h}',
      version: '1.0"#{v}',
      license: 'MIT"#{l}',
    });
    expect(parseRubyDq(stanza(formula, "homepage"))).toBe('https://x.test/"#{h}');
    expect(parseRubyDq(stanza(formula, "version"))).toBe('1.0"#{v}');
    expect(parseRubyDq(stanza(formula, "license"))).toBe('MIT"#{l}');
  });

  it("keeps the real package's stanzas unchanged", () => {
    const formula = renderFormula(baseInput);
    expect(formula).toContain('  desc "SSH MCP server"\n');
    expect(formula).toContain('  license "MIT"\n');
    expect(formula).toContain('shell_output("#{bin}/ssh-mcp --version")');
  });

  it("uses :cannot_represent for an unlicensed package", () => {
    expect(renderFormula({ ...baseInput, license: "UNLICENSED" })).toContain("  license :cannot_represent\n");
    expect(renderFormula({ ...baseInput, license: undefined })).toContain("  license :cannot_represent\n");
  });

  it("refuses a class name that is not a plain Ruby constant", () => {
    expect(() => renderFormula({ ...baseInput, className: "Ssh; system('id'); class X" })).toThrow(/class name/);
  });
});
