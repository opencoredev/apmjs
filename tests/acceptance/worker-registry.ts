// Runs the registry the way Cloudflare does: the bundled Worker (packages/registry/dist/worker-test.js, which
// wraps the production entry) in workerd through Miniflare, with R2, the analysis Queue and Hyperdrive simulated
// locally, Hyperdrive pointing at a real Postgres 18 (postgres.ts). A small proxy in front stamps the test's clock on each request.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { Miniflare } from "miniflare";
import { Client } from "pg";
import { z } from "zod";
import { buildWorker } from "../../packages/registry/scripts/build.ts";
import { COMPATIBILITY_DATE, COMPATIBILITY_FLAGS } from "../../packages/registry/scripts/compat.ts";
import { freshDatabase } from "./postgres.ts";

export type WorkerRegistryOptions = {
  now?: () => number;
  /** The wall clock authenticator codes are checked against. */
  totpNow?: () => number;
  upstream?: string;
  upstreamTtlMs?: number;
  legacyAuth: boolean;
  namePolicy: "scoped" | "open";
  authSecret: string;
  github?: { clientId: string; clientSecret: string; endpoints: { authorize: string; token: string; user: string; emails: string } };
  /** Worker variables to set or override, as the deploy would. */
  env?: Readonly<Record<string, string>>;
};

export type WorkerRegistry = {
  url: string;
  stop: () => Promise<void>;
  mint: (input: { user: string; scope: "publish" | "stage" }) => Promise<string>;
  /** The blob store (R2) as the Worker sees it: list keys, overwrite one. */
  blobs: { keys: () => Promise<string[]>; put: (key: string, bytes: Uint8Array | string) => Promise<void> };
  /** Runs one SQL statement against this registry's database and returns its rows. */
  query: (text: string, params?: readonly unknown[]) => Promise<unknown[]>;
  /** Runs the cron's sweep (matured revokes, expired staged versions) at the test clock. */
  sweep: () => Promise<void>;
  /** Puts npm's packument for `url` in the shared Cache API as another isolate would have, sent at `fetchedAt` (null: no time). */
  seedUpstreamCache: (input: { url: string; packument: string; fetchedAt: number | null }) => Promise<void>;
  /** The registry's Postgres, for tests that hold a lock or change rows from another connection. */
  databaseUrl: string;
  /** Runs the analysis queue's consumer on one job, as the queue would deliver it; says whether it acked or asked for a retry. */
  analysisJob: (job: { name: string; version: string }) => Promise<"ack" | "retry">;
};

const CONTROL = randomBytes(24).toString("hex");
const BlobKeys = z.object({ keys: z.array(z.string()) });
const Minted = z.object({ token: z.string() });
const JobOutcome = z.object({ outcome: z.enum(["ack", "retry"]) });
let bundle: Promise<string> | null = null;
let counter = 0;

function buildBundle(): Promise<string> {
  const dir = mkdtempSync(join(tmpdir(), "apm-worker-"));
  process.on("exit", () => rmSync(dir, { recursive: true, force: true }));

  return buildWorker("worker-test", dir);
}

export async function startWorkerRegistry(opts: WorkerRegistryOptions): Promise<WorkerRegistry> {
  bundle ??= buildBundle();
  const [database, script] = await Promise.all([freshDatabase(), bundle]);

  const queue = `apm-analysis-${++counter}`;

  // The proxy comes first: its address is the registry's public URL, which the Worker needs at start.
  let target = "";

  const proxy = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    maxRequestBodySize: 128 * 1024 * 1024,
    async fetch(req) {
      const u = new URL(req.url);
      const headers = new Headers(req.headers);
      headers.set("x-apm-test-control", CONTROL);
      headers.set("x-apm-test-now", String(opts.now ? opts.now() : Date.now()));

      if (opts.totpNow) headers.set("x-apm-test-totp-now", String(opts.totpNow()));
      const body = req.method === "GET" || req.method === "HEAD" ? undefined : await req.arrayBuffer();
      const res = await fetch(`${target}${u.pathname.slice(1)}${u.search}`, { method: req.method, headers, body, redirect: "manual", decompress: false });

      return new Response(res.body, { status: res.status, statusText: res.statusText, headers: res.headers });
    },
  });

  const url = proxy.url.toString();

  const vars = new Map([
    ["APM_REGISTRY_URL", url],
    ["APM_PUBLIC_URL", url],
    ["APM_UPSTREAM", opts.upstream ?? "off"],
    ["APM_LEGACY_AUTH", opts.legacyAuth ? "1" : "0"],
    ["APM_NAME_POLICY", opts.namePolicy],
    ["APM_AUTH_SECRET", opts.authSecret],
    ["TEST_CONTROL_SECRET", CONTROL],
  ]);

  if (opts.upstreamTtlMs !== undefined) vars.set("APM_UPSTREAM_TTL_MS", String(opts.upstreamTtlMs));

  for (const [key, value] of Object.entries(opts.env ?? {})) vars.set(key, value);

  if (opts.github) {
    vars.set("APM_GITHUB_CLIENT_ID", opts.github.clientId);
    vars.set("APM_GITHUB_CLIENT_SECRET", opts.github.clientSecret);
    vars.set("APM_GITHUB_ENDPOINTS", JSON.stringify(opts.github.endpoints));
  }

  const mf = new Miniflare({
    modules: [{ type: "ESModule", path: script }],
    modulesRoot: dirname(script),
    compatibilityDate: COMPATIBILITY_DATE,
    compatibilityFlags: [...COMPATIBILITY_FLAGS],
    bindings: Object.fromEntries(vars),
    r2Buckets: ["BLOBS"],
    queueProducers: { ANALYSIS_QUEUE: { queueName: queue } },
    queueConsumers: { [queue]: { maxBatchTimeout: 1, maxBatchSize: 10 } },
    hyperdrives: { HYPERDRIVE: database.url },
    host: "127.0.0.1",
    port: 0,
  });

  target = (await mf.ready).toString();

  return {
    url,
    stop: async () => {
      await proxy.stop(true);
      await mf.dispose();
      await database.drop();
    },
    blobs: {
      keys: async () => {
        const res = await fetch(`${target}__test/blobs`, { headers: { "x-apm-test-control": CONTROL } });
        const body = BlobKeys.safeParse(await res.json());

        if (!body.success) throw new Error(`blob list failed: ${res.status}`);

        return body.data.keys;
      },
      put: async (key, bytes) => {
        const res = await fetch(`${target}__test/blobs/${encodeURIComponent(key)}`, { method: "PUT", headers: { "x-apm-test-control": CONTROL }, body: bytes });

        if (res.status !== 200) throw new Error(`blob put failed: ${res.status}`);
      },
    },
    query: async (text, params = []) => {
      const c = new Client({ connectionString: database.url });
      await c.connect();

      try {
        return (await c.query(text, [...params])).rows;
      } finally {
        await c.end();
      }
    },
    sweep: async () => {
      const res = await fetch(`${target}__test/sweep`, {
        method: "POST",
        headers: { "x-apm-test-control": CONTROL, "x-apm-test-now": String(opts.now ? opts.now() : Date.now()) },
      });

      if (res.status !== 200) throw new Error(`sweep failed: ${res.status}`);
    },
    seedUpstreamCache: async (input) => {
      const res = await fetch(`${target}__test/upstream-cache`, { method: "POST", headers: { "content-type": "application/json", "x-apm-test-control": CONTROL }, body: JSON.stringify(input) });

      if (res.status !== 200) throw new Error(`upstream cache seed failed: ${res.status}`);
    },
    databaseUrl: database.url,
    analysisJob: async (job) => {
      const res = await fetch(`${target}__test/analysis-job`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-apm-test-control": CONTROL },
        body: JSON.stringify(job),
      });

      const body = JobOutcome.safeParse(await res.json());

      if (res.status !== 200 || !body.success) throw new Error(`analysis job failed: ${res.status}`);

      return body.data.outcome;
    },
    mint: async ({ user, scope }) => {
      const res = await fetch(`${target}__test/mint`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-apm-test-control": CONTROL, "x-apm-test-now": String(opts.now ? opts.now() : Date.now()) },
        body: JSON.stringify({ user, scope }),
      });

      const text = await res.text();
      const body = Minted.safeParse(JSON.parse(text));

      if (res.status !== 200 || !body.success) throw new Error(`mint failed: ${res.status} ${text}`);

      return body.data.token;
    },
  };
}
