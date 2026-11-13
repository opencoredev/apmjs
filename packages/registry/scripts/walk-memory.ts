// Runs GET /-/apm/v1/resolve for a few real packages through the real walk, against a stand-in for npm that serves
// saved packuments, and prints what each request held at most (its lease's peak) and how many dependencies the walk
// checked. Saved packuments are read from APM_PACKUMENTS (~/.cache/apm-packuments) first, then from
// APM_WALK_PACKUMENTS (~/.cache/apm-packuments-walk), where a packument neither has is saved the first time it is
// fetched from registry.npmjs.org, so later runs read no network.
//
//   bun packages/registry/scripts/walk-memory.ts [name ...]
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { Effect, Layer, Option } from "effect";
import { z } from "zod";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis } from "../src/analysis.ts";
import { resolveResponse, ResolveWait, scanResponse } from "../src/apm.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { RegistryConfig } from "../src/config.ts";
import { Store } from "../src/db.ts";
import { MemoryPool, RequestMemory } from "../src/memory.ts";
import { Upstream } from "../src/upstream.ts";

const MiB = 1024 * 1024;

// a week on, so no version in these trees is inside its cooldown and every resolve walks its whole tree
const LATER = Date.now() + 7 * 86_400_000;

const SAVED = process.env.APM_PACKUMENTS ?? join(homedir(), ".cache", "apm-packuments");
const FETCHED = process.env.APM_WALK_PACKUMENTS ?? join(homedir(), ".cache", "apm-packuments-walk");
const NAMES = process.argv.slice(2).length > 0 ? process.argv.slice(2) : ["next", "react", "typescript", "vite", "@types/node", "aws-sdk"];

const fileOf = (dir: string, name: string): string => join(dir, `${name.replace("/", "_").replace("@", "_")}.json`);
const savedOf = (name: string): string => join(SAVED, `${name.startsWith("@") ? `_${name.slice(1).replace("/", "_")}` : name}.json`);

/** The packument of `name`, saved or fetched once; null when npm has none. */
async function packument(name: string): Promise<Response> {
  for (const f of [savedOf(name), fileOf(FETCHED, name)]) if (existsSync(f)) return new Response(Bun.file(f), { headers: { "content-type": "application/json" } });
  const res = await fetch(`https://registry.npmjs.org/${name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name)}`, { headers: { accept: "application/json" } });

  if (res.status !== 200) return new Response(await res.text(), { status: res.status });
  const text = await res.text();
  mkdirSync(FETCHED, { recursive: true });
  writeFileSync(fileOf(FETCHED, name), text);

  return new Response(text, { headers: { "content-type": "application/json" } });
}

const npm = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: (req) => packument(decodeURIComponent(new URL(req.url).pathname.slice(1))) });

const Answer = z.object({
  tree: z
    .object({
      unchecked: z.number(),
      packages: z.array(z.object({ name: z.string(), version: z.string() })),
      uncheckedDeps: z.array(z.object({ dependency: z.string(), reason: z.string() })),
    })
    .optional(),
  version: z.string().nullish(),
});

const noBlobs = Layer.succeed(
  Blobs,
  Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }),
);

const db = await freshDatabase();

const ScanAnswer = z.object({ unchecked: z.array(z.object({ reason: z.string() })) });

try {
  for (const name of NAMES) {
    // a pool of its own each, so one package's cache entries never help the next; the second pass finds what the
    // first left in the isolate cache, as a busy isolate would
    const pool = new MemoryPool();
    const settings = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: npm.url.href, legacyAuth: false, namePolicy: "open", admins: [] } as const;
    const base = Layer.mergeAll(Store.postgres(db.url), Clock.fixed({ now: LATER, wallNow: LATER }), Analysis.none, noBlobs, Layer.succeed(RegistryConfig, settings), Layer.succeed(ResolveWait, { maxMs: 0, pollMs: 1 }));
    const layers = Layer.provideMerge(Upstream.layer(npm.url.href, 60_000, null), base);

    for (const pass of ["cold", "warm"] as const) {
      const request = pool.request();
      const url = new URL(`http://registry.test/-/apm/v1/resolve?name=${encodeURIComponent(name)}&range=latest`);
      const started = performance.now();
      const program = Effect.flatMap(resolveResponse(url), (res) => Effect.promise(async () => ({ status: res.status, body: Answer.parse(await res.json()) })));
      const out = await Effect.runPromise(program.pipe(Effect.provideService(RequestMemory, request), Effect.provide(layers), Effect.scoped));
      const tree = out.body.tree;
      const ms = Math.round(performance.now() - started);
      const held = request.taken;
      request.release();

      // the Bun scanner's question about the same tree: the root and every package the walk checked
      const scanRequest = pool.request();
      const packages = [...(out.body.version ? [{ name, version: out.body.version }] : []), ...(tree?.packages ?? [])];
      const req = new Request("http://registry.test/-/apm/v1/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ packages }) });
      const scan = await Effect.runPromise(Effect.flatMap(scanResponse(req, { kind: "anon" }), (res) => Effect.promise(async () => ScanAnswer.parse(await res.json()))).pipe(Effect.provideService(RequestMemory, scanRequest), Effect.provide(layers), Effect.scoped));
      scanRequest.release();
      const fit = (reasons: readonly string[]): number => reasons.filter((r) => r.includes("did not fit")).length;

      const line = {
        name,
        pass,
        version: out.body.version ?? null,
        status: out.status,
        checked: tree?.packages.length ?? 0,
        unchecked: tree?.unchecked ?? 0,
        overBudget: fit(tree?.uncheckedDeps.map((d) => d.reason) ?? []),
        requestPeakMiB: Number((request.peakTaken / MiB).toFixed(1)),
        heldAtAnswerMiB: Number((held / MiB).toFixed(2)),
        scanPeakMiB: Number((scanRequest.peakTaken / MiB).toFixed(1)),
        scanOverBudget: fit(scan.unchecked.map((u) => u.reason)),
        poolPeakMiB: Number((pool.peakCharged / MiB).toFixed(1)),
        ms,
      };

      process.stdout.write(`${JSON.stringify(line)}\n`);
    }
  }
} finally {
  await npm.stop(true);
  await db.drop();
}
