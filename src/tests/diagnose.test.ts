import { describe, expect, it } from "vitest";
import {
  bracketedIpv6Inner,
  checkKnownHosts,
  diagnose,
  INVALID_SSH_HOST_SUGGESTION,
  isInternationalHostname,
  isValidHostname,
  isValidSshHost,
} from "../diagnose.js";

describe("isValidHostname", () => {
  it("accepts standard hostnames", () => {
    expect(isValidHostname("example.com")).toBe(true);
    expect(isValidHostname("my-server")).toBe(true);
    expect(isValidHostname("host.sub.domain.com")).toBe(true);
    expect(isValidHostname("192.168.1.1")).toBe(true);
  });

  it("accepts hostnames with underscores", () => {
    expect(isValidHostname("my_server")).toBe(true);
  });

  it("accepts bracketed IPv6", () => {
    expect(isValidHostname("[::1]")).toBe(true);
    expect(isValidHostname("[2001:db8::1]")).toBe(true);
    expect(isValidHostname("[fe80:0:0:0:0:0:0:1]")).toBe(true);
  });

  it("rejects malformed IPv6", () => {
    expect(isValidHostname("[::1")).toBe(false); // missing closing bracket
    expect(isValidHostname("::1]")).toBe(false); // missing opening bracket
    expect(isValidHostname("[::1]:22")).toBe(false); // port not part of hostname
  });

  it("rejects shell injection attempts", () => {
    expect(isValidHostname("host; rm -rf /")).toBe(false);
    expect(isValidHostname("host$(whoami)")).toBe(false);
    expect(isValidHostname("host`id`")).toBe(false);
    expect(isValidHostname("host | cat /etc/passwd")).toBe(false);
    expect(isValidHostname("")).toBe(false);
  });

  it("rejects hostnames starting with a dash (flag/option injection)", () => {
    // A leading '-' would otherwise reach ssh / ssh-keygen positionally and be
    // parsed as a flag (e.g. -E logfile, -oProxyCommand=...).
    expect(isValidHostname("-E")).toBe(false);
    expect(isValidHostname("-rf")).toBe(false);
    expect(isValidHostname("-oProxyCommand=evil")).toBe(false);
    // Internal hyphens remain valid.
    expect(isValidHostname("my-server")).toBe(true);
  });

  it("rejects hostnames over 253 chars", () => {
    expect(isValidHostname("a".repeat(254))).toBe(false);
  });

  it("accepts hostnames at 253 chars", () => {
    expect(isValidHostname("a".repeat(253))).toBe(true);
  });

  it("rejects bare colons (no longer valid outside brackets)", () => {
    expect(isValidHostname("::1")).toBe(false);
    expect(isValidHostname("host:22")).toBe(false);
  });
});

// The connection path's check (resolveConfig): isValidHostname plus BARE IPv6, which
// ssh2 dials as given and `ssh -G` / parseJumpSpec hand back unbracketed.
describe("isValidSshHost", () => {
  it("accepts everything isValidHostname accepts", () => {
    for (const host of ["example.com", "my_server", "192.168.1.1", "[::1]", "[2001:db8::1]", "a".repeat(253)]) {
      expect(isValidSshHost(host), host).toBe(true);
    }
  });

  it("also accepts a bare IPv6 literal, zone id included", () => {
    for (const host of ["::1", "fe80::1", "2001:db8::1", "::ffff:192.0.2.1", "fe80::1%eth0"]) {
      expect(isValidHostname(host), host).toBe(false); // the narrower check still refuses it
      expect(isValidSshHost(host), host).toBe(true);
    }
  });

  it("refuses option-shaped, port-glued and injection-shaped input", () => {
    for (const host of [
      "-oProxyCommand=x",
      "-E",
      "host:22", // one colon is never IPv6
      ":::", // colons alone are not an address
      "[::1]:22",
      "[::1",
      "user@host",
      "host; reboot",
      "host\nother",
      "",
      "a".repeat(254),
    ]) {
      expect(isValidSshHost(host), host).toBe(false);
    }
  });

  it("refuses a non-string from an untyped caller instead of throwing", () => {
    expect(isValidSshHost(undefined as unknown as string)).toBe(false);
    expect(isValidSshHost(42 as unknown as string)).toBe(false);
  });

  it("its suggestion names every accepted shape, bare IPv6 and zone ids included", () => {
    expect(INVALID_SSH_HOST_SUGGESTION).toContain("ssh_config alias");
    expect(INVALID_SSH_HOST_SUGGESTION).toContain("bare (::1, fe80::1%eth0)");
    expect(INVALID_SSH_HOST_SUGGESTION).toContain("bracketed ([::1], [fe80::1%eth0])");
    expect(INVALID_SSH_HOST_SUGGESTION).toContain("internationalized name such as bücher.de");
    expect(INVALID_SSH_HOST_SUGGESTION).toContain("not starting with a hyphen");
  });

  // Every shape the suggestion advertises must pass the check it accompanies.
  it("accepts a bracketed IPv6 literal with a zone id, which isValidHostname's bracket form refuses", () => {
    for (const host of ["[fe80::1%eth0]", "[fe80::1%25]", "[::ffff:192.0.2.1]"]) {
      expect(isValidHostname(host), host).toBe(false);
      expect(isValidSshHost(host), host).toBe(true);
      expect(bracketedIpv6Inner(host), host).toBe(host.slice(1, -1));
    }
    for (const host of ["[fe80::1%eth0]:22", "[host.example]", "[]", "[fe80::1%eth0", "fe80::1%eth0]"]) {
      expect(isValidSshHost(host), host).toBe(false);
      expect(bracketedIpv6Inner(host), host).toBeNull();
    }
  });

  it("accepts an internationalized hostname, as OpenSSH and the old direct dial did", () => {
    for (const host of ["bücher.de", "BÜCHER.de", "münchen.example", "例え.jp", "bü_x.de"]) {
      expect(isValidHostname(host), host).toBe(false);
      expect(isInternationalHostname(host), host).toBe(true);
      expect(isValidSshHost(host), host).toBe(true);
    }
  });

  it("refuses an internationalized host carrying anything isValidHostname would refuse", () => {
    for (const host of [
      "-bücher.de", // option-shaped; punycode would hide the '-' (xn---bcher-kva.de)
      "­-bücher.de", // a soft hyphen IDNA maps to nothing, which would leave a leading '-'
      "bücher.de:22", // port
      "jeff@bücher.de", // login
      "bü%41.de", // domainToASCII would percent-decode it
      "bü cher.de", // ASCII space
      "bü　cher.de", // ideographic space
      "bü​cher.de", // zero-width space, which IDNA maps to nothing
      "bü‮cher.de", // bidi override
      "bü\ncher.de",
      "bücher.de;reboot",
      "ü".repeat(300), // over 253 once punycoded
      "ｂü：ｃｈｅｒ．ｄｅ", // a full-width colon maps to ':'
    ]) {
      expect(isInternationalHostname(host), JSON.stringify(host)).toBe(false);
      expect(isValidSshHost(host), JSON.stringify(host)).toBe(false);
    }
    // All-ASCII input is isValidHostname's job, not this one's.
    expect(isInternationalHostname("example.com")).toBe(false);
  });
});

// Only pure cases live here -- each returns before any subprocess or filesystem
// read, so none depends on the machine, its agent, its ~/.ssh or the network. The
// checks that do shell out are covered with a faked subprocess and a faked ~/.ssh in
// env-diagnose-coverage.test.ts.

describe("checkKnownHosts", () => {
  it("returns error for invalid hostname", () => {
    const result = checkKnownHosts("host; rm -rf /");
    expect(result.status).toBe("error");
    expect(result.message).toMatch(/Invalid hostname/);
  });
});

describe("diagnose", () => {
  it("rejects invalid hostname early", () => {
    const report = diagnose("host; rm -rf /");
    expect(report.overall).toBe("error");
    expect(report.checks[0].name).toBe("Input Validation");
  });
});
