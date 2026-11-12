// Runs the registry Worker locally for development: the production bundle (dist/worker.js) in workerd through
// Miniflare, R2 and the analysis queue simulated, Hyperdrive pointing at Postgres. Nothing here persists:
// the database is a fresh copy of the migrated schema and R2 lives in memory.
//
//   bun run registry                       # http://127.0.0.1:4873/, proxying registry.npmjs.org
//   APM_UPSTREAM=off bun run registry      # no npm proxy
//
// Postgres comes from APM_TEST_DATABASE_URL, or a throwaway local cluster (initdb under /usr/lib/postgresql).
import { randomBytes } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname } from "node:path";
import { Miniflare } from "miniflare";
import { buildWorker } from "../packages/registry/scripts/build.ts";
import { COMPATIBILITY_DATE, COMPATIBILITY_FLAGS } from "../packages/registry/scripts/compat.ts";
import { freshDatabase } from "../tests/acceptance/postgres.ts";

const port = Number(process.env.APM_PORT ?? 4873);
const url = `http://127.0.0.1:${port}/`;
const [database, script] = await Promise.all([freshDatabase(), buildWorker("worker", mkdtempSync(`${tmpdir()}/apm-dev-`))]);

const bindings = new Map([
  ["APM_REGISTRY_URL", url],
  ["APM_PUBLIC_URL", process.env.APM_PUBLIC_URL ?? url],
  ["APM_UPSTREAM", process.env.APM_UPSTREAM ?? "https://registry.npmjs.org/"],
  ["APM_LEGACY_AUTH", process.env.APM_LEGACY_AUTH ?? "0"],
  ["APM_NAME_POLICY", process.env.APM_NAME_POLICY ?? "scoped"],
  ["APM_AUTH_SECRET", process.env.APM_AUTH_SECRET ?? randomBytes(32).toString("base64url")],
]);

for (const key of ["APM_GITHUB_CLIENT_ID", "APM_GITHUB_CLIENT_SECRET", "APM_VERCEL_CLIENT_ID", "APM_VERCEL_CLIENT_SECRET"]) {
  const value = process.env[key];

  if (value) bindings.set(key, value);
}

const mf = new Miniflare({
  modules: [{ type: "ESModule", path: script }],
  modulesRoot: dirname(script),
  compatibilityDate: COMPATIBILITY_DATE,
  compatibilityFlags: [...COMPATIBILITY_FLAGS],
  bindings: Object.fromEntries(bindings),
  r2Buckets: ["BLOBS"],
  queueProducers: { ANALYSIS_QUEUE: { queueName: "apm-analysis" } },
  queueConsumers: { "apm-analysis": { maxBatchTimeout: 1 } },
  hyperdrives: { HYPERDRIVE: database.url },
  host: "127.0.0.1",
  port,
});

await mf.ready;

process.stdout.write(`apm registry listening on ${url} (upstream ${bindings.get("APM_UPSTREAM")}, names ${bindings.get("APM_NAME_POLICY")})\n`);

const stop = async (): Promise<void> => {
  await mf.dispose();
  await database.drop();
  process.exit(0);
};

process.on("SIGINT", () => void stop());

process.on("SIGTERM", () => void stop());
