import { afterAll, beforeAll, test } from "bun:test";
import { Effect, Layer, Option } from "effect";
import { Client } from "pg";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis } from "../src/analysis.ts";
import { apmRoute } from "../src/apm.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { RegistryConfig } from "../src/config.ts";
import { Store } from "../src/db.ts";
import { MemoryPool, RequestMemory } from "../src/memory.ts";

const POOL = new MemoryPool();
const NOW = Date.parse("2026-11-12T00:00:00Z");
let db: Awaited<ReturnType<typeof freshDatabase>>;
beforeAll(async () => {
  db = await freshDatabase();
  const c = new Client({ connectionString: db.url });
  await c.connect();
  await c.query(`INSERT INTO users (name, password_hash, email, created_at) VALUES ('u', 'x', 'u@example.test', 0)`);
  for (const n of ["p", "@s/q"]) {
    await c.query(`INSERT INTO packages (name, created_at, modified_at, dist_tags) VALUES ($1, 0, 0, '{"latest":"1.0.0"}'::jsonb)`, [n]);
    await c.query(`INSERT INTO versions (package, version, manifest, shasum, integrity, size, tarball_key, published_at, published_by) VALUES ($1,'1.0.0',$2::jsonb,$3,'sha1-x',10,'k',$4,'u')`, [n, JSON.stringify({ name: n, version: "1.0.0" }), "0".repeat(40), 0]);
  }
  await c.end();
});
afterAll(async () => {
  await db.drop();
});

const noBlobs = Layer.succeed(Blobs, Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }));
async function get(path: string, method = "GET", body?: string) {
  const settings = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: null, legacyAuth: false, namePolicy: "open", admins: [] } as const;
  const layers = Layer.mergeAll(Store.postgres(db.url), Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, noBlobs, Layer.succeed(RegistryConfig, settings), RequestMemory.layer(POOL));
  const req = new Request("http://registry.test" + path, { method, body, headers: body ? { "content-type": "application/json" } : {} });
  try {
    const res = await Effect.runPromise(apmRoute(req, new URL(req.url), { kind: "anon" } as never).pipe(Effect.provide(layers), Effect.scoped));
    return res ? `${res.status} cc=${res.headers.get("cache-control")} vary=${res.headers.get("vary")} ${(await res.text()).slice(0, 100)}` : "null";
  } catch (e) {
    return "THROW " + String(e).slice(0, 150);
  }
}
const big = "a".repeat(100000);
test("probe", async () => {
  const paths = [
    "/-/apm/v1/resolve", "/-/apm/v1/resolve?name=", "/-/apm/v1/resolve?name=p&range=" + big, "/-/apm/v1/resolve?name=" + big,
    "/-/apm/v1/resolve?name=p&range=%zz", "/-/apm/v1/resolve?name=%40s%2fq", "/-/apm/v1/resolve?name=@s/q", "/-/apm/v1/resolve?name=p&wait=-1", "/-/apm/v1/resolve?name=p&wait=1e999", "/-/apm/v1/resolve?name=p&wait=NaN",
    "/-/apm/v1/resolve?name=p&floor=Infinity", "/-/apm/v1/resolve?name=p&floor=1e999", "/-/apm/v1/resolve?name=p&cooldown=1e999d", "/-/apm/v1/resolve?name=p&cooldown=99999999999999999999",
    "/-/apm/v1/resolve?name=p&installed=" + "x,".repeat(1000), "/-/apm/v1/resolve?name=p&installed=a@", "/-/apm/v1/resolve?name=p&installed=@s/q@1.0.0,p@?", "/-/apm/v1/resolve?name=p&os=x&cpu=y", "/-/apm/v1/resolve?name=p&range=%00",
    "/-/apm/v1/resolve?name=constructor", "/-/apm/v1/resolve?name=__proto__", "/-/apm/v1/resolve?name=p&range=latest&strict=yes", "/-/apm/v1/resolve?name=p&range=>=1%20<2||", "/-/apm/v1/resolve?name=p&range=" + "1.x||".repeat(5000),
    "/-/apm/v1/names", "/-/apm/v1/names?q=" + big, "/-/apm/v1/names?q=%40s%2fq", "/-/apm/v1/names?q=%zz", "/-/apm/v1/names?q=p&part=constructor", "/-/apm/v1/names?q=@", "/-/apm/v1/names?q=@/x&user=a", "/-/apm/v1/names?q=p&user=" + big, "/-/apm/v1/names?q=p&user=a%2Fb",
    "/-/apm/v1/recent?limit=abc", "/-/apm/v1/recent?limit=-5", "/-/apm/v1/recent?limit=1e999", "/-/apm/v1/recent-packages?limit=0", "/-/apm/v1/recent-packages?limit=201", "/-/apm/v1/recent-packages?limit=1.5", "/-/apm/v1/recent-packages?limit=",
    "/-/apm/v1/popular-scores", "/-/apm/v1/popular-scores?names=" + big, "/-/apm/v1/popular-scores?names=p,@s/q,%zz,,", "/-/apm/v1/popular-scores?names=" + Array.from({ length: 25 }, (_, i) => "n" + i).join(","), "/-/apm/v1/popular-scores?names=%00,p",
    "/-/apm/v1/packages/p", "/-/apm/v1/packages/%40s%2fq", "/-/apm/v1/packages/%40s", "/-/apm/v1/packages/%zz", "/-/apm/v1/packages/p/versions/1.0.0", "/-/apm/v1/packages/p/versions/%zz", "/-/apm/v1/packages/p/versions/" + big, "/-/apm/v1/packages/p/events", "/-/apm/v1/packages/" + big,
    "/-/apm/v1/score/p", "/-/apm/v1/score/p/latest", "/-/apm/v1/score/p/%zz", "/-/apm/v1/score/%40s%2fq/1.0.0", "/-/apm/v1/score/p/" + big, "/-/apm/v1/score/", "/-/apm/v1/score/p/1.0.0/extra",
  ];
  for (const p of paths) console.log(p.slice(0, 90).padEnd(92), await get(p));
  for (const [p, b] of [["scan", "{}"], ["scan", "not json"], ["scan", '{"packages":[]}'], ["scan", '{"packages":[{"name":"p","version":"1.0.0"}]}'], ["scan", '{"packages":[null]}'], ["scan", '{"packages":[{"name":1,"version":2}]}'], ["scan", '{"packages":"x"}'], ["audit", "{}"], ["audit", "[]"], ["audit", "null"], ["yank", "{}"], ["revoke", "null"], ["incident", "x"], ["owners", "{}"]] as const) {
    console.log(`POST ${p} ${b}`.padEnd(92), await get("/-/apm/v1/" + p, "POST", b));
  }
});
