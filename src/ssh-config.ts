// Pure parser for `ssh -G <host>` output. Two callers wrap this:
//   - resolveFromSshConfig in ssh.ts (uses identityFiles + a few fields for ConnectConfig)
//   - configLookup in env.ts (exposes the full keymap as a tool result)
//
// Both walked the same lines and split on the first space; this collapses that
// duplication into one place. Consumer-specific filters (e.g. dropping
// `proxyjump=none`, `proxycommand=none` to undefined) stay AT THE CALL SITES so
// this helper has no opinion about which keys matter.
export function parseSshConfigOutput(stdout: string): {
  all: Record<string, string>;
  identityFiles: string[];
} {
  const all: Record<string, string> = {};
  const identityFiles: string[] = [];

  for (const line of stdout.split("\n")) {
    const spaceIdx = line.indexOf(" ");
    if (spaceIdx > 0) {
      const key = line.substring(0, spaceIdx);
      const value = line.substring(spaceIdx + 1);
      if (key === "identityfile") {
        identityFiles.push(value);
      } else {
        all[key] = value;
      }
    }
  }

  return { all, identityFiles };
}
