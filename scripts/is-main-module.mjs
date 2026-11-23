/**
 * Is the module at `moduleUrl` the one Node was asked to run?
 *
 * Shared by every script in scripts/ that guards its side effects on being run
 * directly, so the guard cannot drift between them again: there used to be three
 * implementations, and check-compliance.mjs kept the plain resolve() compare that
 * check-oam-floor.mjs had already been fixed away from.
 *
 * Node realpaths the main module's URL (unless --preserve-symlinks-main) but
 * leaves argv[1] as typed, so from a junctioned or symlinked checkout a plain
 * resolve() of the two differs: main() is skipped and the script exits 0 having
 * done nothing, a silence that reads as a pass in release.sh. Both sides are
 * realpath'd, falling back to resolve() when a path cannot be.
 */

import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function isMainModule(argv1, moduleUrl) {
  if (!argv1) return false;
  const real = (p) => {
    try {
      return realpathSync(p);
    } catch {
      return resolve(p);
    }
  };
  return real(argv1) === real(fileURLToPath(moduleUrl));
}
