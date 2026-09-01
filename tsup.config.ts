import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: { index: "src/index.ts" },
    format: ["esm"],
    dts: false,
    clean: true,
    target: "node18",
    banner: { js: "#!/usr/bin/env node" },
  },
  {
    entry: { server: "src/server.ts" },
    format: ["esm"],
    // Declarations come from `tsc -p tsconfig.build.json` in the build script,
    // not from tsup: the rollup-plugin-dts it inlines predates TypeScript 7 and
    // crashes on it, and tsup 8.5.1 is the latest release. See tsconfig.build.json.
    dts: false,
    clean: false,
    target: "node18",
  },
]);
