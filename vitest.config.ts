import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    testTimeout: 30000,
    // Cap workers: this suite spawns real subprocesses (node launcher, cli
    // lifecycle), and vitest's default = cores-1 left no headroom for them on a
    // shared box -- worst when several sessions run suites at once (the load
    // pattern behind release.sh's flaky test gate). 4 matches the cap ctxlint
    // and typed already use.
    maxWorkers: 4,
  },
});
