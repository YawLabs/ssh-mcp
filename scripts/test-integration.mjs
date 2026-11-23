#!/usr/bin/env node
/**
 * `npm run test:integration`: bring the Docker fixture up, run the integration
 * suite against it, always tear it down, and exit with the SUITE's status.
 *
 * This used to be an inline shell chain in package.json:
 *   up ... && SSH_MCP_INTEGRATION=1 vitest run ...; docker compose ... down
 * Two defects. Its exit status was that of `down`, so a failing suite exited 0.
 * And npm runs scripts through cmd.exe on Windows by default, where neither the
 * `VAR=1 cmd` prefix nor the `;` separator means anything. A node script has
 * neither problem: the variable is set in the child's env, and the status is
 * chosen explicitly.
 *
 * Requires Docker. Usage: node scripts/test-integration.mjs
 */

import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isMainModule } from "./is-main-module.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const COMPOSE = ["compose", "-f", join("test", "docker", "docker-compose.yml")];
const VITEST = join(REPO_ROOT, "node_modules", "vitest", "vitest.mjs");

/** Run one command with inherited stdio; its exit status, 1 when it could not start or died on a signal. */
function defaultRun(cmd, args, extraEnv = {}) {
  const r = spawnSync(cmd, args, { cwd: REPO_ROOT, stdio: "inherit", env: { ...process.env, ...extraEnv } });
  if (r.error) console.error(`test:integration: could not run ${cmd} (${r.error.message})`);
  return typeof r.status === "number" ? r.status : 1;
}

/**
 * The whole sequence, with the runner injected so it is testable without Docker.
 * Returns the status to exit with: the fixture's when it would not come up,
 * otherwise the suite's. `down` runs in both cases (a failed `up --wait` can
 * leave containers behind) and its own status never replaces the suite's.
 */
export function runIntegration(run = defaultRun) {
  const up = run("docker", [...COMPOSE, "up", "-d", "--build", "--wait"]);
  if (up !== 0) {
    run("docker", [...COMPOSE, "down"]);
    return up;
  }
  let status = 1;
  try {
    status = run(process.execPath, [VITEST, "run", "src/tests/integration.test.ts"], { SSH_MCP_INTEGRATION: "1" });
  } finally {
    run("docker", [...COMPOSE, "down"]);
  }
  return status;
}

if (isMainModule(process.argv[1], import.meta.url)) {
  process.exit(runIntegration());
}
