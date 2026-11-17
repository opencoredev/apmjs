// The work one GET /-/apm/v1/resolve?name=next&range=latest does, counted, for the resolve-speed climb. npm is a
// local stand-in serving the packuments of next's whole tree saved under APM_PACKUMENTS and APM_WALK_PACKUMENTS (no
// network: a packument neither has fails the run), with an ETag on each and a 304 for a matching If-None-Match, as
// registry.npmjs.org answers. The store is a real Postgres.
//
// 1. setup: a cold resolve on a fresh database, then every package the base resolver checked is given a stored
//    analysis (the @next/swc-* binaries are stored as too large, as production has them), so later resolves have
//    nothing pending.
// 2. scored: a new isolate (a fresh memory pool) ten minutes later, then the same isolate five seconds after that.
//    The score adds, for those two: packument MB npm sent, 0.2 a database statement and 0.05 an npm request, about
//    what each costs in production next to the others (17 s for next's 118 MB; ~30 ms a Hyperdrive round trip).
//    Lower is better.
// 3. guards: npm publishes a new patch of each recorded dependency in turn, then cannot answer for each in turn,
//    then answers again (all of them on every run: re-check of 3366a36, finding 5). Every answer (the setup's, the two scored ones and these) must equal,
//    exactly, what the base resolver (c6775ba, before the climb) answered in the same state: a cold resolve on a
//    fresh database with the same analyses, the same clock and the same npm. Those answers were recorded once by
//    running this file on c6775ba with BENCH_RECORD=1, and are kept below as hashes (EXPECTED), with the analyses
//    seeded. On 3aacc2a the answers were compared with the changed resolver itself, so a walk that skipped a
//    package passed (review of 3aacc2a, finding 7). Every request must stay inside REQUEST_METADATA_WEIGHT with
//    nothing over budget.
//
//   bun packages/registry/scripts/resolve-bench.ts                      # next; prints counts, last line the score
//   BENCH_ROOT=vite bun packages/registry/scripts/resolve-bench.ts
//   BENCH_RECORD=1 bun packages/registry/scripts/resolve-bench.ts       # on c6775ba only: prints EXPECTED's entry
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { Effect, Layer } from "effect";
import { z } from "zod";
import { analyze } from "@apm/core";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis } from "../src/analysis.ts";
import { OVER_BUDGET_TEXT, REQUEST_METADATA_WEIGHT, resolveResponse, ResolveWait } from "../src/apm.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { RegistryConfig } from "../src/config.ts";
import { Store } from "../src/db.ts";
import { digestLabel, digestOf } from "../src/digest.ts";
import { MemoryPool, RequestMemory, type Lease } from "../src/memory.ts";
import { Timing, type TimingApi } from "../src/timing.ts";
import { Upstream } from "../src/upstream.ts";
import { Option } from "effect";

const MiB = 1024 * 1024;
const MINUTE = 60_000;
const ROOT = process.env.BENCH_ROOT ?? "next";
const SAVED = process.env.APM_PACKUMENTS ?? join(homedir(), ".cache", "apm-packuments");
const FETCHED = process.env.APM_WALK_PACKUMENTS ?? join(homedir(), ".cache", "apm-packuments-walk");

const fileOf = (dir: string, name: string): string => join(dir, `${name.replace("/", "_").replace("@", "_")}.json`);
const savedOf = (name: string): string => join(SAVED, `${name.startsWith("@") ? `_${name.slice(1).replace("/", "_")}` : name}.json`);

/** npm's state: saved texts, a few replaced (a new publish) or failing (an outage). */
const replaced = new Map<string, string>();
const failing = new Set<string>();
const texts = new Map<string, string | null>();
const counts = { requests: 0, ok: 0, notModified: 0, bytes: 0, failed: 0 };

function savedText(name: string): string | null {
  const known = texts.get(name);

  if (known !== undefined) return known;
  const file = [savedOf(name), fileOf(FETCHED, name)].find((f) => existsSync(f));
  const text = file === undefined ? null : readFileSync(file, "utf8");
  texts.set(name, text);

  return text;
}

const etagOf = (text: string): string => `"${createHash("md5").update(text).digest("hex")}"`;

const npm = Bun.serve({
  port: 0,
  hostname: "127.0.0.1",
  fetch: (req) => {
    const name = decodeURIComponent(new URL(req.url).pathname.slice(1));
    counts.requests++;

    if (failing.has(name)) {
      counts.failed++;

      return new Response("unavailable", { status: 503 });
    }

    const text = replaced.get(name) ?? savedText(name);

    if (text === null) {
      // only names npm really has no package for may be missing; anything else means the fixtures are incomplete
      console.error(`resolve-bench: no saved packument for ${name}`);
      process.exit(2);
    }

    const etag = etagOf(text);

    if (req.headers.get("if-none-match") === etag) {
      counts.notModified++;

      return new Response(null, { status: 304, headers: { etag } });
    }

    counts.ok++;
    counts.bytes += Buffer.byteLength(text);

    return new Response(text, { headers: { "content-type": "application/json", etag, "cache-control": "public, max-age=300" } });
  },
});

const noBlobs = Layer.succeed(
  Blobs,
  Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }),
);

const Answer = z
  .object({
    version: z.string().nullish(),
    tree: z
      .object({
        unchecked: z.number(),
        packages: z.array(z.object({ name: z.string(), version: z.string() })),
        uncheckedDeps: z.array(z.object({ dependency: z.string(), reason: z.string() })),
      })
      .loose()
      .optional(),
  })
  .loose();

const JsonValue = z.json();

type Json = z.infer<typeof JsonValue>;

const JsonObject = z.record(z.string(), JsonValue);

/** A value with every array's members in a fixed order, so two answers that list the same things compare equal. */
function canonical(v: Json): Json {
  if (Array.isArray(v)) return v.map(canonical).toSorted((a, b) => (JSON.stringify(a) < JSON.stringify(b) ? -1 : 1));
  const o = JsonObject.safeParse(v);

  if (o.success) return Object.fromEntries(Object.entries(o.data).toSorted(([a], [b]) => (a < b ? -1 : 1)).map(([k, x]) => [k, canonical(x)]));

  return v;
}

/** An answer's text in canonical form. */
const canonicalText = (text: string): string => JSON.stringify(canonical(JsonValue.parse(JSON.parse(text))));

type Run = { status: number; body: z.infer<typeof Answer>; text: string; ms: number; db: number; dbMs: number; npmRequests: number; npmBytes: number; notModified: number; peak: number };

async function resolveOnce(input: { dbUrl: string; pool: MemoryPool; now: number }): Promise<Run> {
  const settings = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: npm.url.href, legacyAuth: false, namePolicy: "open", admins: [] } as const;
  const timing: TimingApi = Timing.make();
  const entries = new Map<string, { ms: number; count: number }>();

  const recording: TimingApi = {
    add: (metric, ms) => {
      timing.add(metric, ms);
      const e = entries.get(metric) ?? { ms: 0, count: 0 };
      entries.set(metric, { ms: e.ms + ms, count: e.count + 1 });
    },
    header: timing.header,
    expose: timing.expose,
    exposed: timing.exposed,
  };

  const base = Layer.mergeAll(
    Store.postgres(input.dbUrl).pipe(Layer.provide(Layer.succeed(Timing, recording))),
    Clock.fixed({ now: input.now, wallNow: input.now }),
    Analysis.none,
    noBlobs,
    Layer.succeed(RegistryConfig, settings),
    Layer.succeed(ResolveWait, { maxMs: 0, pollMs: 1 }),
    Layer.succeed(Timing, recording),
  );

  const layers = Layer.provideMerge(Upstream.layer(npm.url.href, 60_000, null), base);
  const request: Lease = input.pool.request();
  const before = { ...counts };
  const started = performance.now();
  const url = new URL(`http://registry.test/-/apm/v1/resolve?name=${encodeURIComponent(ROOT)}&range=latest`);
  const program = Effect.flatMap(resolveResponse(url), (res) => Effect.promise(async () => ({ status: res.status, text: await res.text() })));
  const out = await Effect.runPromise(program.pipe(Effect.provideService(RequestMemory, request), Effect.provide(layers), Effect.scoped));
  const ms = performance.now() - started;
  const peak = request.peakTaken;
  request.release();
  const db = entries.get("db") ?? { ms: 0, count: 0 };

  return {
    status: out.status,
    text: out.text,
    body: Answer.parse(JSON.parse(out.text)),
    ms,
    db: db.count,
    dbMs: db.ms,
    npmRequests: counts.requests - before.requests,
    npmBytes: counts.bytes - before.bytes,
    notModified: counts.notModified - before.notModified,
    peak,
  };
}

const problems: string[] = [];

function checkBudget(label: string, r: Run): void {
  if (r.peak > REQUEST_METADATA_WEIGHT) problems.push(`${label}: the request held ${(r.peak / MiB).toFixed(1)} MiB, past ${REQUEST_METADATA_WEIGHT / MiB} MiB`);
  const over = r.body.tree?.uncheckedDeps.filter((d) => d.reason === OVER_BUDGET_TEXT) ?? [];

  if (over.length > 0) problems.push(`${label}: ${over.length} dependencies over budget`);
}

function line(label: string, r: Run): void {
  process.stdout.write(
    `${JSON.stringify({ run: label, status: r.status, version: r.body.version ?? null, checked: r.body.tree?.packages.length ?? 0, unchecked: r.body.tree?.unchecked ?? 0, ms: Math.round(r.ms), db: r.db, dbMs: Math.round(r.dbMs), npm: r.npmRequests, npm304: r.notModified, npmMB: Number((r.npmBytes / 1e6).toFixed(2)), peakMiB: Number((r.peak / MiB).toFixed(1)) })}\n`,
  );
}

/** An analysis the setup stores: scored, or decided too large to score. */
type Seeded = { name: string; version: string; kind: "scored" | "too-large"; digest: string | null };

/**
 * What the base resolver (c6775ba) answered, by root: the analyses seeded after the setup, and for each scenario the
 * sha256 of its status and canonical answer. Recorded with BENCH_RECORD=1 on c6775ba; never edited by hand.
 */
type Recorded = { seeded: Seeded[]; answers: Record<string, string> };

const RECORDED = {
  next: {
    seeded: [
      { "name": "next", "version": "16.4.6", "kind": "scored", "digest": "sha512-4192626216992c9328d8aa64406408c2f99defd595b0059e608539e786bc77bcc0ad2dec8bf211cb7941355febb58844ef4a0bc1d2d884f0172cfc7c1f0730b4" },
      { "name": "postcss", "version": "8.5.23", "kind": "scored", "digest": "sha512-839d39f3acebe1b666c0589395f94cbbc1346c34dbe48e607abb60c002a6b1d5254d022166dba7cd4943d564b3c1c5563e8015a6cac0eaf95f083ee85ef47082" },
      { "name": "@next/env", "version": "16.4.6", "kind": "scored", "digest": "sha512-4ae9c18c9eadfa806d79c4b77538dd56e32152880fe700ffbeb18be4456e418335892e0ee6294be751e4889dec3e33334478820a1bebe1d6da4896d1ec5de5c4" },
      { "name": "styled-jsx", "version": "5.1.6", "kind": "scored", "digest": "sha512-a925720d378ca2d76f418a0758b346c111491c2fa2f99bdd051628b0e1600be5a0d6fc787eb376fd11bf340ed262aaaf28d2dfdfd3f62d2440da9bba9f45d864" },
      { "name": "@swc/helpers", "version": "0.5.23", "kind": "scored", "digest": "sha512-e654ac30e4d751178f8250dfbee01052a9067a4f47836924b0e61acb69b4f9747ef9bd8d5982ffe2c5b2baf54122cf282a725ac64762f7085a2ffb2a375dda7f" },
      { "name": "caniuse-lite", "version": "1.0.30001826", "kind": "scored", "digest": "sha512-c1307ef6d21b2eba3f0425f02ee355d667871382fd752e9d02b303c2061f3413cc61272a0a51f21ae9e1902483b4785effaf57974b0794a801559f9f36c62d58" },
      { "name": "baseline-browser-mapping", "version": "2.11.37", "kind": "scored", "digest": "sha512-418a61faf7eeae66b184dc22f45a6b7e6b644f9731d8a7a0f05cd9d2f9e33bcba4b1c2326d5c9918c17076594a1a54c8eaac94f1c938dce33d51787e20526285" },
      { "name": "sharp", "version": "0.35.5", "kind": "scored", "digest": "sha512-6309f83a7cc6ba4a7b08332ba74f11439d182a6bb01b8edbad980854f4ef05a6807d095197282b46a4abc5d0a22fd33e2e5ccb06227af0847542abf31f28c2ee" },
      { "name": "@next/swc-darwin-x64", "version": "16.4.6", "kind": "too-large", "digest": null },
      { "name": "@next/swc-darwin-arm64", "version": "16.4.6", "kind": "too-large", "digest": null },
      { "name": "@next/swc-linux-x64-gnu", "version": "16.4.6", "kind": "too-large", "digest": null },
      { "name": "@next/swc-linux-x64-musl", "version": "16.4.6", "kind": "too-large", "digest": null },
      { "name": "@next/swc-win32-x64-msvc", "version": "16.4.6", "kind": "too-large", "digest": null },
      { "name": "@next/swc-linux-arm64-gnu", "version": "16.4.6", "kind": "too-large", "digest": null },
      { "name": "@next/swc-linux-arm64-musl", "version": "16.4.6", "kind": "too-large", "digest": null },
      { "name": "@next/swc-win32-arm64-msvc", "version": "16.4.6", "kind": "too-large", "digest": null },
      { "name": "react", "version": "19.3.1", "kind": "scored", "digest": "sha512-40d85676dee7ae05565901b9f10b86b004778efdc76dee266f8bf3ef0d9cb271dabdc89926075ad423cd6a5745e9e571bfdd2e7778d45e92a51cbebd80edfccb" },
      { "name": "react-dom", "version": "19.3.1", "kind": "scored", "digest": "sha512-6346c0473e77961102d4d302012b34fe3f9f681ff3aaddd1f21a6f8357bcfbad59549e142f451d0b87016d77d931c22e86b7e07882d32def9978109abd03ed29" },
      { "name": "nanoid", "version": "3.3.20", "kind": "scored", "digest": "sha512-b8a760d86dc63422909fd6f260ea716c6aab4f67c63b9291b7927ff1bde9a24f2b4faab119617a871332262118b407fe155c98b83f6145a0ea5f9b8f15827865" },
      { "name": "picocolors", "version": "1.1.1", "kind": "scored", "digest": "sha512-c5c787dac9e1b5be4cf658aa0ec984c39ea57b7efa993664117fe311bfd1c4d1727a036e97b78db250973fd1438ff2dcbb45fc284c8c71e3f69eda5a1eb0c454" },
      { "name": "source-map-js", "version": "1.2.2", "kind": "scored", "digest": "sha512-2868fff18e37c77e5a6550edb7e27898ad61a0b18750b3187d290e0c93508cd0c2de85b53ea3e8c4cc28d292d4b1633f5041b338dfcdc5e1f2c047cd5cd3f757" },
      { "name": "client-only", "version": "0.0.1", "kind": "scored", "digest": "sha512-215dcebb48d233366b777a59e3c9cb913f4303b020d699cfcda8908695bb73745b72aab3bf3cd5bbe2fc81fa8ca7ff08336310b528aa682c6badc7eef08f2b30" },
      { "name": "tslib", "version": "2.9.1", "kind": "scored", "digest": "sha512-6b8531f552ae20c1ec392ec435b12aea12b66466084f6ed1b65d04e1e0fd2aac3184a89078c644ffdc5bdc8758c166923b220140b1318508170d3628882c6758" },
      { "name": "semver", "version": "7.8.6", "kind": "scored", "digest": "sha512-f65a52494e0c972de6aedaeec0bb3578b2bafa0cdbcea78117044d8c88c4fbd2ee0e959d61cb6b4254377a3d489608bb8249e9b134673e82cff03a421ea1c827" },
      { "name": "@img/colour", "version": "1.1.0", "kind": "scored", "digest": "sha512-4ddefaabb8f9ee8fed2d57604bbe3a7180117d2cb193c8847d1c5ec0bf61e0e3336216d6e1301ca69974993e1ecaa5dd761e8bfe3c2833be66a3b8b16bfa4279" },
      { "name": "detect-libc", "version": "2.1.2", "kind": "scored", "digest": "sha512-06d8f604e38ef37a375b21f9f5ef0c817b3111055c6ab9143a9118aee6c1d2eaf09cdd74c90dfae2bb22072535d67665a966199b4e62fe87fb8a8e26ce2841b5" },
      { "name": "@img/sharp-linux-arm", "version": "0.35.5", "kind": "scored", "digest": "sha512-2c46972b659d5d52b9ca4730d1bb96c8f32c98b2cbdafa472c3eb2acd496f891842f70593c0e2da4a37a89a31ce00c534c0a1a5ffb14d6b38be7595c233e3c65" },
      { "name": "@img/sharp-linux-x64", "version": "0.35.5", "kind": "scored", "digest": "sha512-4b116d2d378922784003d43cdfa92ec76bd935e381404c7ae7caaf6dba1949caf4c08011ca6dc8706996ecaa550f9b1b560d0e8f2fae74541d6b2608672a0da2" },
      { "name": "@img/sharp-win32-x64", "version": "0.35.5", "kind": "scored", "digest": "sha512-c7be9e1f4bc488795c310bbc63c21e9e7b5a002b5d7694fa5b4c265ed5ab9ca727288ecc1390dd82a8400fa48458e125d6fdb30ef9190e1140f4a9d4470a5faa" },
      { "name": "@img/sharp-darwin-x64", "version": "0.35.5", "kind": "scored", "digest": "sha512-f81476e794610e5a72814a4e73f25db759d3e834375c6fc4468e706dc74e7f9437db474ab4f08a3cb4752c9b3d5465d168c6bc975b946b4b6408d397880c5953" },
      { "name": "@img/sharp-win32-ia32", "version": "0.35.5", "kind": "scored", "digest": "sha512-e599bcd8ba01738de78703726d9946ed8d4a3bffd986c9f7d3a7d0976f593ae4ad1cb193a370562fcdeaddcce75f4a68c5200cb982f53a7fc11c1c6405e2abe8" },
      { "name": "@img/sharp-linux-arm64", "version": "0.35.5", "kind": "scored", "digest": "sha512-2d8571e494ec38cd820739b1ade87e9e5eb8ff71fa5dbd3d8922e49ea1f8ef3d93d83145c437852cfe72e1d2707ba1fbb864251cfc8412d22aca8dc362c47075" },
      { "name": "@img/sharp-linux-ppc64", "version": "0.35.5", "kind": "scored", "digest": "sha512-415c4002af1ebd5448f626b6bea830ae65ae727e437eff89756ce3ef9a43f289872cf48fedff29db43bc8f1ce309cb8211010eb583995265f5864899d2475ebc" },
      { "name": "@img/sharp-linux-s390x", "version": "0.35.5", "kind": "scored", "digest": "sha512-5196ac4ce162633a2d4ec18e0aee3605f5333fa4eee83a3ff78ee2466d51b0b2af965971c06727e11376ecb89b19671e8b1e18f8f9b0de3b274dc0902205a3a8" },
      { "name": "@img/sharp-win32-arm64", "version": "0.35.5", "kind": "scored", "digest": "sha512-5f8b7b83eed90390ca6e50811171a352aa9e9a3e2f73320d1bfe6f885c002fc878377a987b28f0742bd12c78b811d39423ed99ed4165a7554cfa9fc0b84b66e9" },
      { "name": "@img/sharp-darwin-arm64", "version": "0.35.5", "kind": "scored", "digest": "sha512-411525150d16c6f756caaa86fd6b48de2ba97c3e6b0739821d749d3ec63dd6c02d56d4e8ed0e1c6facce71c67782a12a92bd1fd40b357a12ea984a43b117fe96" },
      { "name": "@img/sharp-linux-riscv64", "version": "0.35.5", "kind": "scored", "digest": "sha512-2ed76b79782e69abca3833c87f327891f7f1ed436dd689b0b4ad2b721e0405b6d24d73e7c5699849ac9774b270d1f27343dee41edd602ffca1e2dbd4fa70b245" },
      { "name": "@img/sharp-linuxmusl-x64", "version": "0.35.5", "kind": "scored", "digest": "sha512-e0a3a986a074df91eb55da8b65f0a0333cc446b4249333b04619783809113b560295d6da163c925cc68ae77e0ca3457e2e776794993eb1b5322de53450bc83d4" },
      { "name": "@img/sharp-freebsd-wasm32", "version": "0.35.5", "kind": "scored", "digest": "sha512-63fcfdd67119e2e2015f95f79df4e8be353d94734a1586cbda5a4708b54d99740ad3754866f5c106dd0ac5b3c6a7649d19217eda6414e1efa141a58eb7cea203" },
      { "name": "@img/sharp-linuxmusl-arm64", "version": "0.35.5", "kind": "scored", "digest": "sha512-f476cc725988d7394d90546cdf3f7f781b438df0f4b0696b5f5cfa6f5ab09a2158e449432e1e010b42cf05d569ef3d435c588a9487339dff9996cb99ccbc50aa" },
      { "name": "@img/sharp-libvips-linux-arm", "version": "1.3.4", "kind": "scored", "digest": "sha512-2e646d4ec387baf336fb094ed836f7eddc7932266107416f4ae9dc8b0e3c62374e919cfd2808916e6f2e8de30e03520daa67a2e4d6a91716042b50f565289d9b" },
      { "name": "@img/sharp-libvips-linux-x64", "version": "1.3.4", "kind": "scored", "digest": "sha512-189fff4925db9f04837acd36ba60779c324b15c433c3c6b5f15f1fca1aabead579d79b4e10c7489a38f18f502869f311cf9e85dcf1e07ed9e3d5010a494d7393" },
      { "name": "@img/sharp-libvips-darwin-x64", "version": "1.3.4", "kind": "scored", "digest": "sha512-891d8e287f34ca2d14f9d529972877ff176916fa6ce98902c2c5de9c8271ab1475bfda3ec6d29319b4bd1fb729b3ed95c6373c0758fdea9ef93664c68c886da5" },
      { "name": "@img/sharp-libvips-linux-arm64", "version": "1.3.4", "kind": "scored", "digest": "sha512-6377605ffea513642141bf86c72d166717e0f4c126fc90636a66694b622494fef1210a0a378873026eca70c546b5a543b779de13d38a042eef01fa2703f2ebd4" },
      { "name": "@img/sharp-libvips-linux-ppc64", "version": "1.3.4", "kind": "scored", "digest": "sha512-2dee9ba01f136a2d0d8acfa02312292b1ebc50355522a751f138a7e587f5cf62c92502c326f08346a46efa30b6a82a03f9e2289a89e63b0078b26051c5f56961" },
      { "name": "@img/sharp-libvips-linux-s390x", "version": "1.3.4", "kind": "scored", "digest": "sha512-adafe607a32290448350eed883e322f796c505bf46b0e6d446e8673afdceaa49e319ef6c66b1bcb427bdab4c52206aed2e0be0c3480a9c559c2b86e54a040eb9" },
      { "name": "@img/sharp-libvips-darwin-arm64", "version": "1.3.4", "kind": "scored", "digest": "sha512-e51f3d9c162245d5254962713e13be195b5a5f35d2c4a9d1bbfc6a327dca4c0dcbf4407d3b2fcff8d9f67f6be584fb94772fd9bac6f60daadbc93a4609f103bb" },
      { "name": "@img/sharp-webcontainers-wasm32", "version": "0.35.5", "kind": "scored", "digest": "sha512-85f845fc59a84324d4900d1b20a14eb70e77e8141278131ee8117a4325a5acfc53ef9e3e4c52da67bb0a2937efbccd322602a06984f09c508867f1ae0f0e5250" },
      { "name": "@img/sharp-libvips-linux-riscv64", "version": "1.3.4", "kind": "scored", "digest": "sha512-6879242041cf45d4047a024ddb430b986b71603f51db042bdc2c2975d9eee7e60a32de94cdac7b4bd879829653a3cc32ac6b994a57d0eb739ebcbe664f2382ed" },
      { "name": "@img/sharp-libvips-linuxmusl-x64", "version": "1.3.4", "kind": "scored", "digest": "sha512-eb35ca784fe9dfd2350260377091b7e5ec8118da8d75d2e75178e1c019ec1a314f5aa7f954a903044a9a1243c3a1312d931c22dafbfc4dcaf6983c8fe12a3b16" },
      { "name": "@img/sharp-libvips-linuxmusl-arm64", "version": "1.3.4", "kind": "scored", "digest": "sha512-86fba5170b6351c6a0b22b3a041c47c061705a83598e062650b195ad97327cd6e303c84a20b6d1c46835e7fef0e470f25c75d4a2cfe3e9b6805aa9c2c90d8358" },
      { "name": "scheduler", "version": "0.28.0", "kind": "scored", "digest": "sha512-8eea2b7c2988908c3cb53fa9e415d29ba3c98d017fc9c11898acb3511088b7f45a64884bf8fba56d0f58bb6cf51dd3890dda834e5c40d7ec4a0661d726c73303" },
      { "name": "@img/sharp-wasm32", "version": "0.35.5", "kind": "scored", "digest": "sha512-3edb206b5b2ee2d431f8b2c5d44092f54ea7cf9926ad72a8e9755bb51e3c29edd9471c6069606eec80ed11ed6aba8f218aea709ba585ab15655da49fec820d19" },
      { "name": "@emnapi/runtime", "version": "1.11.3", "kind": "scored", "digest": "sha512-5f3e13a72922ed7caba5b50ad6347502174075a5f2861638959de778ba1d9a1a6e59fcb63c040de41e3ab00894e2588e5c62e41f2a67fea53e8ef7d64826182c" },
    ],
    answers: {
      "after-outage": "f8275e43420a1fbf3db4870dd9be62863cb1c2d6bf56d9c5e8c4b8af94eccb3d",
      "new-isolate": "f8275e43420a1fbf3db4870dd9be62863cb1c2d6bf56d9c5e8c4b8af94eccb3d",
      "outage @img/colour": "1f1e16a19010d5d167dbd081b9c9de1c120bf7adcd61f8c59a83630e0c1cd117",
      "outage detect-libc": "5513a801910d7593dc9ff930d37d42fe70cf2b759f304ddffeaacd405da45e2d",
      "outage nanoid": "08234f9ca01ca5c51a3cf48edbe8af3ed2f6b28148daeb3e4ebb4c26a4494568",
      "outage picocolors": "bb3474e2ba2cf56755993678a02868c6909cf1b94f942f91dfd6d485ed22d127",
      "outage semver": "b4c4349f2cf1638adc907f787d77619f799bc7435275c8699ed90714c080e8e5",
      "outage source-map-js": "51a2c8bda414499a919347bf4898bcd7c5830e7fa3ed0f002c583ef5b009c7c4",
      "outage tslib": "acaaa71aa96be93b6cb63a659caa4a81d54e737eadaa92363a45d86ead5636fd",
      "published @img/colour": "d7d77e35278126a4d9dd22ecfc37018957c30e2c2f3de973beb1e69dfcaef16e",
      "published detect-libc": "c1ef7a168ba0a86057cc34c10fb38e234bd74e8346870addd0b99cc44ede23c5",
      "published nanoid": "31845c90667dc84d28850a1067088b370e2b43c50fb7846c9c3d1a9b8d36f563",
      "published picocolors": "bc8e97ea794b195e5fb2c1cbd7303a0eac5536064bf73ed921a25a4280cc185d",
      "published semver": "31a018dcf791101423851808d3bb1b883adfe57f5769ff9bc75f34864d8cc0e1",
      "published source-map-js": "057784ccc07564f35f32c48830d73100d3b44eaa78be4d6d930db28f971709a9",
      "published tslib": "7666f516c52bbc553d86f0ed7acfb301bbfe9a91006c05a769c54e71b05ec53c",
      "same-isolate": "f8275e43420a1fbf3db4870dd9be62863cb1c2d6bf56d9c5e8c4b8af94eccb3d",
      "setup": "fd3e19f1ab9ebaa6f8d5e5d8713f5407433fb740fda2b45fa44949436c16d966",
    },
  },
  vite: {
    seeded: [
      { "name": "vite", "version": "8.3.8", "kind": "scored", "digest": "sha512-2f33a7de1f6b1bfd2f84b757ad5e3227840503d784a2a0a5f98c7e90625deda07dc3a9df3605472926302cf6541ebcf86466beb7e9178d5f62b6f7070cb428b8" },
      { "name": "postcss", "version": "8.5.32", "kind": "scored", "digest": "sha512-2c994a08201414a3ae6718a951d630d4dcc821312c3dc832386f4b92f449bee2a3fdb4736ee458d00457bcbd29586a6c66f9fc8e4bbe2cc7a9d9e534b1e1e9f2" },
      { "name": "rolldown", "version": "1.2.19", "kind": "scored", "digest": "sha512-408895d49f5dd29ccde2379e4c7e2c8cfcb4019e9c032d9c1b41317a8135f94f11be3fa1477818928931d186de50d1a566a890249daeb5c1137b4a0a5f0cecb8" },
      { "name": "picomatch", "version": "4.0.7", "kind": "scored", "digest": "sha512-a9c26ef3c436216a89b030f9dbd24a31dc069bf76f2275b81ef427470887f49b62849bf318eb1c0ed1c4df1d6904a794393cac43c91598b9c9da426eef285c18" },
      { "name": "tinyglobby", "version": "0.2.17", "kind": "scored", "digest": "sha512-c1747f758a5ca8a99f5a911d66388a24ec023459dd0f40cc9eb5bf7188d51adb449017d581c2c51e836b963e3b9a339589cf72c8dbbae5a96c805e0d4324dada" },
      { "name": "lightningcss", "version": "1.33.0", "kind": "scored", "digest": "sha512-5a4503ae88ee26cd3192019fdae756c5adf21814713edc54901efd8ba68264b46073b3ccf1f65ef53a2c7cf0dcbc4a5065bb850129c762644b04b51b98b38820" },
      { "name": "fsevents", "version": "2.3.3", "kind": "scored", "digest": "sha512-e71a037d7f9f2fb7da0139da82658fa5b16dc21fd1efb5a630caaa1c64bae42defbc1d181eb805f81d58999df8e35b4c8f99fade4d36d765cda09c339617df43" },
      { "name": "nanoid", "version": "3.3.20", "kind": "scored", "digest": "sha512-b8a760d86dc63422909fd6f260ea716c6aab4f67c63b9291b7927ff1bde9a24f2b4faab119617a871332262118b407fe155c98b83f6145a0ea5f9b8f15827865" },
      { "name": "picocolors", "version": "1.1.1", "kind": "scored", "digest": "sha512-c5c787dac9e1b5be4cf658aa0ec984c39ea57b7efa993664117fe311bfd1c4d1727a036e97b78db250973fd1438ff2dcbb45fc284c8c71e3f69eda5a1eb0c454" },
      { "name": "source-map-js", "version": "1.2.2", "kind": "scored", "digest": "sha512-2868fff18e37c77e5a6550edb7e27898ad61a0b18750b3187d290e0c93508cd0c2de85b53ea3e8c4cc28d292d4b1633f5041b338dfcdc5e1f2c047cd5cd3f757" },
      { "name": "@oxc-project/types", "version": "0.156.0", "kind": "scored", "digest": "sha512-d43bb2838f1374935dca1101f179f52f7e9b4fd3efe8652d94a8c7c4ecacf3191a17fad0ab75c913e6c0bab48afc0808cf998616c6fbedc9fd3dbdb4f9609273" },
      { "name": "@rolldown/pluginutils", "version": "1.1.1", "kind": "scored", "digest": "sha512-825148243bcb343b49853f6aacc1562cf6ef4beb24c60b782f42bc122d98b6784fcac0099ec23b9f2c522712a3e000de297d0e2e30b89ed464c292cea12debc0" },
      { "name": "@rolldown/binding-darwin-x64", "version": "1.2.19", "kind": "scored", "digest": "sha512-ce8f04b124b0319098fdef9f46719a5f4d981a0bc90f4caf84d8bff61a463c0d8c27d645f1d3c2c3be5419fa48e8ea50fe6c91fdd2189a8811bea8990f44eb5e" },
      { "name": "@rolldown/binding-freebsd-x64", "version": "1.2.19", "kind": "scored", "digest": "sha512-3bc21200e7c8d678fb02e04f777d05485e3bcfb7fb973964e69a105468228a4bd0b86101158bd6f248be5049d3f9824f9cd1a34339f7d38925b783bd15413b98" },
      { "name": "@rolldown/binding-wasm32-wasi", "version": "1.2.19", "kind": "scored", "digest": "sha512-ec41feb243ac979aa95a72b4bf36a68091613afd5cc31429b319bcb48f3cdcaf5fbabe5cdbba7cabcedfcc43ba05b04f69b036ffeb3fcd1eb7fe92dcd77ee23a" },
      { "name": "@rolldown/binding-darwin-arm64", "version": "1.2.19", "kind": "scored", "digest": "sha512-5e8300da9c022864d0cd48cf82d47091e747e1699785d20f293ea5ea83b17753d46cda1d188e837017a480dec40bfffec77a5f0585ffa8bd60366640aa2bf0e6" },
      { "name": "@rolldown/binding-android-arm64", "version": "1.2.19", "kind": "scored", "digest": "sha512-84ea266eb4c9faccedd9c884cd2ee8080efc94c3c1805e54310582248c8d7e7ac8ec62e5f0762816a0a7a4bda070f39a5ccaabc86094e44c5d40ac830dc0bec8" },
      { "name": "@rolldown/binding-linux-x64-gnu", "version": "1.2.19", "kind": "scored", "digest": "sha512-ae6ef9ffd0e41ca794d969c0f30e17f785866202e50c21427e4402fb86e0b952660bf8ef0d1bf607edb02ce621c84d1f56ebfbfff0a4937f4ea0eb9fc82bbbe9" },
      { "name": "@rolldown/binding-linux-x64-musl", "version": "1.2.19", "kind": "scored", "digest": "sha512-8ab87fe3e89814ce06033a65b8312b823cfcf5b8fa343b6aa8c006ffa3b52c6dfc11ddcda7279bcc2a5c54d9055bcba1cbeff7fc1a1c52f9d70d1df709759ef4" },
      { "name": "@rolldown/binding-win32-x64-msvc", "version": "1.2.19", "kind": "scored", "digest": "sha512-cbfb2a45173a77b8440b33857399f72d27aa72d988a7d98c8d8d4aab8b35e2e2cf77f2d9e33ee2d73ad6e9f32da7698f7ae4080b87ba50b31cc10ccca26a906a" },
      { "name": "@rolldown/binding-linux-arm64-gnu", "version": "1.2.19", "kind": "scored", "digest": "sha512-a66fdaa453019d26c56f73ba9c6e691ced62a87859ae31831448d29bea2df49d7b5d73ef1fd2fdd32e61fa381f1c213e41d96cbf2f2a284714e152b18230febc" },
      { "name": "@rolldown/binding-linux-ppc64-gnu", "version": "1.2.19", "kind": "scored", "digest": "sha512-234c700f9ee33ffdc0efee543d98a7db0f18ed71c4984339ceaa5864e710e39325356ead5095338b2995df246beeb2f8bf0c9f11c46c464b02e1aeca734f29e5" },
      { "name": "@rolldown/binding-linux-s390x-gnu", "version": "1.2.19", "kind": "scored", "digest": "sha512-06bb441d3db848d5e3f47897ab2facfe45e24a2406b7a10a08f525462ac0a088a85712869db5c150491b6404807a2ee2649074fd89e6fb424fd34229c7b0274b" },
      { "name": "@rolldown/binding-android-arm-eabi", "version": "1.2.19", "kind": "scored", "digest": "sha512-7be11b7b4593fbdb5b5e634a3c8882f18ad6007630ba0de6ea2e29deb6461ae95f66b8b58ed2381ec953f8e66715ffce207a30585ef50d3947c1704fd92880ec" },
      { "name": "@rolldown/binding-linux-arm64-musl", "version": "1.2.19", "kind": "scored", "digest": "sha512-2b54a6429dc51627219fca2aacd230bc5a19e7072f8c2ee0a01ce968c36f2dff4565cf9007f42f2e69e92598000061e20fdf34b4ff056599d79362bde2bbe5c6" },
      { "name": "@rolldown/binding-win32-arm64-msvc", "version": "1.2.19", "kind": "scored", "digest": "sha512-dd0d5883543bb44bc15a865fe6b16f1bf18a6503e0c1faeefa9e3005a8c37c9141b344870a92fef9d7d38d6f60c8029dd53ed9a4862f75a51ac7b3dafc884555" },
      { "name": "@rolldown/binding-openharmony-arm64", "version": "1.2.19", "kind": "scored", "digest": "sha512-f8a59358da0fb7e09f4aaf780a271e5aedf23c4f90ce4686fa984fcb3f46eb4b6664bc1f424700e007a4b1a7f3bc9030e29be0d6671de5ad53914a95bf4b3824" },
      { "name": "@rolldown/binding-linux-arm-gnueabihf", "version": "1.2.19", "kind": "scored", "digest": "sha512-fe56026dae4d3b4caae12d2318c1fc41306d92f431a178e8416cc5e41716a7d32307d8f15510f51900cda1f9158dc3a3df40d6ca12c837fe0e7bad092b368e37" },
      { "name": "fdir", "version": "6.5.0", "kind": "scored", "digest": "sha512-b486d8b596ee70eb340511aa3c992c84951874bf920c7edd54cf208f2f84469dd60148cb105244fb4da46a7c87b708d63a7c2b298062c0098cd29e242c90275e" },
      { "name": "detect-libc", "version": "2.1.2", "kind": "scored", "digest": "sha512-06d8f604e38ef37a375b21f9f5ef0c817b3111055c6ab9143a9118aee6c1d2eaf09cdd74c90dfae2bb22072535d67665a966199b4e62fe87fb8a8e26ce2841b5" },
      { "name": "lightningcss-darwin-x64", "version": "1.33.0", "kind": "scored", "digest": "sha512-67950f031ceb8e558d3721b2ea2eb9709cf3be02790f74fac0cbecfa05a963d77ba9184036bc6a029e8b871220661584c35f117c94c6711c63b8b201afe9bc5d" },
      { "name": "lightningcss-linux-x64-gnu", "version": "1.33.0", "kind": "scored", "digest": "sha512-6abf89bbb2e670dd09a381692f88691726f0346f7fdc0fc1af9296da7da3c8e0e0dcc1195da0d800375e9a8352f810cd7cc80abf29492e3e12e6dc9101cb6e02" },
      { "name": "lightningcss-win32-x64-msvc", "version": "1.33.0", "kind": "scored", "digest": "sha512-3a5108083c7f5e5d05a92a786ebcbccc59c2bc6a628371a5e200aabaf6301eea892840b5fa7f4d8039e216fa871a632fd5992a0c9ac3a8a292ca44c35fe7a1b8" },
      { "name": "lightningcss-win32-arm64-msvc", "version": "1.33.0", "kind": "scored", "digest": "sha512-d4af8c3df2d2155a69873a5d6df92195693ac01ad339b0734b64fa75bd743cd399811f46a15b005b3c0dcae8546186d3a76de3fb846b9dc7ee8d9e2e0335efc0" },
      { "name": "lightningcss-darwin-arm64", "version": "1.33.0", "kind": "scored", "digest": "sha512-49c89acfc79e9cd4ca9fd6f7b7bfb1af48a94e9f58c4a418e27a704379ab46e2f404054704bc99c687e168a04056dce6b5167fcd3ca8d3fb68e01d6e586fc38e" },
      { "name": "lightningcss-linux-arm64-gnu", "version": "1.33.0", "kind": "scored", "digest": "sha512-8f6bff8ad9b2e0794dc6573abe829762006a362d0d8362d2860e33ec6b9fa4482cd393fedacb815728bd23a607ab9ba8545c7d1138a7dde08484b5725c64272a" },
      { "name": "lightningcss-linux-arm-gnueabihf", "version": "1.33.0", "kind": "scored", "digest": "sha512-37b15505eea24b6e0c94ce91ff84414f11a14217991aceed890f54df652d17be4dccfe50ef158f46a2c108ac65450464deb6358c220f2f3c7b5b33a1b942112d" },
      { "name": "lightningcss-linux-arm64-musl", "version": "1.33.0", "kind": "scored", "digest": "sha512-ca23b944e32e6108176c2eb4ca3654e4261215918a5cbd071404d7b7d987267d7ecd6e79a02b4c23d35f7158582cc1432fb815ee804fa27fc498c3068363afb5" },
      { "name": "lightningcss-linux-x64-musl", "version": "1.33.0", "kind": "scored", "digest": "sha512-4588986e4a24c34b6b7caaaacdf179e658229f010fac3dce2437d3b89cc5b3530aea21670de9dacf57ea2cbb57e084c6dce92d2505ce7936b0d5ac2b0409593f" },
      { "name": "lightningcss-freebsd-x64", "version": "1.33.0", "kind": "scored", "digest": "sha512-41033f4e2fe141a8c9c0263e4625ae099f6c76d23f5d093b9c32b9bc2f2491dc22c5ecce94382f0f1efe453f908cae857054f8329b2ea019c7228fcedd2b5146" },
      { "name": "lightningcss-android-arm64", "version": "1.33.0", "kind": "scored", "digest": "sha512-804a514da94a768b29e016fca96b5cda23a013949e2079694b5ba9f5b16adb003262197551d4ce6d88877bdf3310cf5242f4a8a906752100f424da60dcc979a6" },
      { "name": "@emnapi/core", "version": "2.0.0-beta.2", "kind": "scored", "digest": "sha512-333095a16b5c8383e6d81de37b998cbd832f8f732604ac3e7d4eef6ec25cf7f893f22a7afde6081e8fc3b26fe6afec2c1c1e92132243bb1074f58cbaafff3ee0" },
      { "name": "@emnapi/runtime", "version": "2.0.0-beta.2", "kind": "scored", "digest": "sha512-25cad23f33ef66e359bc9a8f4c5f45c36e4b6ce27c6afcc556569fda0ae61f80a4bb4a063f8eed460a8f65a75c7e3dd8a1930790556709815b40cf08fa2e5013" },
      { "name": "@napi-rs/wasm-runtime", "version": "1.2.6", "kind": "scored", "digest": "sha512-991c83984c3dfdf0835c219f2f5b1b808c3f1942b43d5c515b863080f37ad45dcb43e7d2ca80456ab255ce01b2845ea447311067415e8c3aa6e162d749ea909b" },
      { "name": "tslib", "version": "2.9.1", "kind": "scored", "digest": "sha512-6b8531f552ae20c1ec392ec435b12aea12b66466084f6ed1b65d04e1e0fd2aac3184a89078c644ffdc5bdc8758c166923b220140b1318508170d3628882c6758" },
      { "name": "@emnapi/wasi-threads", "version": "2.2.0", "kind": "scored", "digest": "sha512-24fece607dfc43bfa9c9301ed78ada6472d020aec10ca6ddc238be5e2de971dffa424258407dd25f8c2ee84a651ab1895917a9a0dcde75f9b41b707d6787bd47" },
      { "name": "@tybys/wasm-util", "version": "0.10.4", "kind": "scored", "digest": "sha512-5b77388118a0152d13fcc6b8a88605dc60c07390107476f5c8be739c94f566fd58683f4a8adc7ae7ac018efaf5f6a6e2a2c9994fc9560cce4110cca752a5fae4" },
    ],
    answers: {
      "after-outage": "5cfefa8d21a1774e5d08ca42b313179812c1c7d452ac3ca5074cd1677bdf963f",
      "new-isolate": "5cfefa8d21a1774e5d08ca42b313179812c1c7d452ac3ca5074cd1677bdf963f",
      "outage detect-libc": "cfe1968a7e9ef69689ccec38724ed9108fa3039aa16d69bf4ca2d45d476c6403",
      "outage nanoid": "0b7f5067504d695f3f5ce03528d43b6c467993c67b409999546e2b00637fb925",
      "outage picocolors": "53e25eb08196fd6ca3f2f62a2d90b5c48db17f54b92e213e9f8b7fb31ae2dd32",
      "outage source-map-js": "223c06d6d92d6cb18d59b29cd3128bee88e794078ec4a1264daeff5d5dd81e4f",
      "outage tslib": "307ebff10520c7552cec94fe2faec4b23e7e883afb7bbd25159a48f9e7a7a93b",
      "published detect-libc": "c2e3c0af8f93a10528e04028eb62fff1a22abbe2cfc4829ad92e08be2ed1b268",
      "published nanoid": "ea3d6966ba91945e2f6f935edc71f9c37cb99afd03fe18cf8ec65db799dcc91c",
      "published picocolors": "77c9fc8ef4b53e33f3dcd60a049d59aaafda61c805af7b2e1b3a51b952495ea6",
      "published source-map-js": "202263007ab1804a75feeb48ee0887d90b9f02bedff762b2d32476c7ceb0936b",
      "published tslib": "87befda521683114ecb51924435ed1122198e8779de36c5fe8ec1de40e064f70",
      "same-isolate": "5cfefa8d21a1774e5d08ca42b313179812c1c7d452ac3ca5074cd1677bdf963f",
      "setup": "b6ce7c660bf6cb8cbd33050a789ca001b7f15494aa3bdc07a099b7b53154d8f0",
    },
  },
} satisfies Record<string, Recorded>;

const EXPECTED: ReadonlyMap<string, Recorded> = new Map(Object.entries(RECORDED));

const RECORD = process.env.BENCH_RECORD === "1";
const live = await freshDatabase();
const truthDbs: Awaited<ReturnType<typeof freshDatabase>>[] = [];
const seeded: Seeded[] = [];

async function seed(dbUrl: string): Promise<void> {
  const settings = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: npm.url.href, legacyAuth: false, namePolicy: "open", admins: [] } as const;
  const layers = Layer.mergeAll(Store.postgres(dbUrl), Layer.succeed(RegistryConfig, settings));
  const encoder = new TextEncoder();

  const program = Effect.gen(function* () {
    const store = yield* Store;

    for (const s of seeded) {
      if (s.kind === "too-large") yield* store.setUnscorable({ name: s.name, version: s.version, unscorable: { reason: "too-large", detail: "tarball over the limit" }, digest: null, at: 1 });
      else if (s.digest !== null) {
        const manifest = { name: s.name, version: s.version, main: "index.js", license: "MIT" };
        const file = (path: string, text: string) => ({ path, size: text.length, mode: 0o644, data: encoder.encode(text) });
        const analysis = analyze({ name: s.name, manifest, files: [file("package.json", JSON.stringify(manifest)), file("index.js", "module.exports = 1;\n")], publisher: "u", previousPublishers: [] });
        yield* store.setUpstreamAnalysis({ name: s.name, version: s.version, digest: s.digest, analysis, at: 1 });
      }
    }
  });

  await Effect.runPromise(program.pipe(Effect.provide(layers), Effect.scoped));
}

/** The digest label of a saved packument's version, as the registry keys its analysis. */
function digestFor(name: string, version: string): string | null {
  const text = replaced.get(name) ?? savedText(name);

  if (text === null) return null;
  const doc = z.object({ versions: z.record(z.string(), z.object({ dist: z.object({ integrity: z.string().optional(), shasum: z.string().optional() }).loose() }).loose()) }).loose().parse(JSON.parse(text));
  const dist = doc.versions[version]?.dist;
  const d = dist ? digestOf({ integrity: dist.integrity ?? "", shasum: dist.shasum ?? "" }) : null;

  return d ? digestLabel(d) : null;
}

/** An answer as EXPECTED keeps it: the sha256 of its status and canonical text. */
const answerHash = (r: Run): string => createHash("sha256").update(`${r.status}\n${canonicalText(r.text)}`).digest("hex");

/** What a cold resolve on a fresh database with the seeded analyses answers at `now`, against npm as it is now. */
async function cold(now: number, seeds: boolean): Promise<Run> {
  const db = await freshDatabase();
  truthDbs.push(db);

  if (seeds) await seed(db.url);
  const saved = { ...counts };
  const r = await resolveOnce({ dbUrl: db.url, pool: new MemoryPool(), now });
  Object.assign(counts, saved);

  return r;
}

/** `name`'s packument with a patch release of `version` on top (a copy of it, so its tree is the same): its number. */
function publish(name: string, version: string, at: number): string {
  const doc = z.object({ versions: z.record(z.string(), z.record(z.string(), z.unknown())), time: z.record(z.string(), z.string()), "dist-tags": z.record(z.string(), z.string()) }).loose().parse(JSON.parse(savedText(name) ?? "{}"));
  const [major, minor, patch] = version.split(".").map(Number);
  const bumped = `${major}.${minor}.${(patch ?? 0) + 1000}`;
  const copy = doc.versions[version] ?? {};
  doc.versions[bumped] = { ...copy, version: bumped };
  doc.time[bumped] = new Date(at).toISOString();
  doc["dist-tags"].latest = bumped;
  replaced.set(name, JSON.stringify(doc));

  return bumped;
}

/** The dependencies the publish and outage scenarios may pick: those next's tree asks for with a caret range. */
const CARET = new Set(["tslib", "picocolors", "source-map-js", "nanoid", "detect-libc", "semver", "@img/colour"]);

const t0 = Date.parse("2026-11-20T00:00:00Z");
const AT = { setup: t0, fresh: t0 + 10 * MINUTE, warm: t0 + 10 * MINUTE + 5_000, published: t0 + 20 * MINUTE, outage: t0 + 30 * MINUTE, back: t0 + 40 * MINUTE } as const;

let score = Number.NaN;

/** The climb's check: the scenarios above against the recorded answers; sets the score. */
async function check(): Promise<void> {
  const expected = EXPECTED.get(ROOT);

  if (expected === undefined) {
    problems.push(`no recorded answers for ${ROOT}; record them on c6775ba with BENCH_RECORD=1`);

    return;
  }

  /** The answer `r` must be the base resolver's for `key`. */
  const same = (key: string, r: Run): void => {
    const want = expected.answers[key];

    if (want === undefined) problems.push(`${key}: no recorded answer`);
    else if (answerHash(r) !== want) {
      problems.push(`${key}: the answer differs from the base resolver's (status ${r.status})`);
      process.stderr.write(`--- ${key} got\n${r.text.slice(0, 4000)}\n`);
    }
  };

  const setup = await resolveOnce({ dbUrl: live.url, pool: new MemoryPool(), now: AT.setup });
  line("setup", setup);
  checkBudget("setup", setup);
  same("setup", setup);
  seeded.push(...expected.seeded);
  await seed(live.url);

  // a new isolate ten minutes on, then the same isolate a moment later: the score
  const isolate = new MemoryPool();
  const fresh = await resolveOnce({ dbUrl: live.url, pool: isolate, now: AT.fresh });
  line("new-isolate", fresh);
  const warm = await resolveOnce({ dbUrl: live.url, pool: isolate, now: AT.warm });
  line("same-isolate", warm);
  checkBudget("new-isolate", fresh);
  checkBudget("same-isolate", warm);

  if (ROOT === "next" && (fresh.body.tree?.packages.length ?? 0) < 50) problems.push(`new-isolate: only ${fresh.body.tree?.packages.length ?? 0} packages checked`);
  same("new-isolate", fresh);
  same("same-isolate", warm);
  score = [fresh, warm].reduce((n, r) => n + r.npmBytes / 1e6 + 0.2 * r.db + 0.05 * r.npmRequests, 0);

  // npm publishes a patch of each recorded dependency in turn, then cannot answer for each in turn, then answers
  // again: every recorded guard on every run, so a regression that touches one dependency only is not missed by a
  // random pick (re-check of 3366a36, finding 5)
  const recorded = (prefix: string) => Object.keys(expected.answers).flatMap((k) => (k.startsWith(prefix) ? [k.slice(prefix.length)] : [])).toSorted();
  const versionOf = (name: string) => expected.seeded.find((p) => p.name === name)?.version;
  const targets = recorded("published ");
  const outages = recorded("outage ");

  if (targets.length === 0) problems.push("no recorded publish scenario");

  if (outages.length === 0) problems.push("no recorded outage scenario");

  for (const target of targets) {
    const targetVersion = versionOf(target);

    if (targetVersion === undefined) {
      problems.push(`published ${target}: no seeded version`);
      continue;
    }

    const bumped = publish(target, targetVersion, AT.published - 9 * MINUTE);
    const published = await resolveOnce({ dbUrl: live.url, pool: new MemoryPool(), now: AT.published });
    line(`published ${target}@${bumped}`, published);
    checkBudget(`published ${target}`, published);
    same(`published ${target}`, published);
    replaced.delete(target);
  }

  for (const down of outages) {
    failing.add(down);
    const outage = await resolveOnce({ dbUrl: live.url, pool: new MemoryPool(), now: AT.outage });
    line(`outage ${down}`, outage);
    checkBudget(`outage ${down}`, outage);
    same(`outage ${down}`, outage);
    failing.delete(down);
  }

  const back = await resolveOnce({ dbUrl: live.url, pool: new MemoryPool(), now: AT.back });
  line("after-outage", back);
  checkBudget("after-outage", back);
  same("after-outage", back);
}


try {
  if (RECORD) {
    // the base resolver's answers in every state the check may put npm in
    const answers: Record<string, string> = {};
    const setup = await cold(AT.setup, false);
    answers.setup = answerHash(setup);

    for (const p of [...(setup.body.version ? [{ name: ROOT, version: setup.body.version }] : []), ...(setup.body.tree?.packages ?? [])]) {
      const tooLarge = p.name.startsWith("@next/swc-");
      seeded.push({ name: p.name, version: p.version, kind: tooLarge ? "too-large" : "scored", digest: tooLarge ? null : digestFor(p.name, p.version) });
    }

    answers["new-isolate"] = answerHash(await cold(AT.fresh, true));
    answers["same-isolate"] = answerHash(await cold(AT.warm, true));
    answers["after-outage"] = answerHash(await cold(AT.back, true));
    const all = (setup.body.tree?.packages ?? []).filter((p) => /^\d+\.\d+\.\d+$/.test(p.version));
    const caret = all.filter((p) => CARET.has(p.name));

    for (const p of caret.length > 0 ? caret : all) {
      publish(p.name, p.version, AT.published - 9 * MINUTE);
      answers[`published ${p.name}`] = answerHash(await cold(AT.published, true));
      replaced.delete(p.name);
      failing.add(p.name);
      answers[`outage ${p.name}`] = answerHash(await cold(AT.outage, true));
      failing.delete(p.name);
    }

    process.stdout.write(`EXPECTED[${JSON.stringify(ROOT)}] = ${JSON.stringify({ seeded, answers })}\n`);

  } else await check();
} finally {
  await npm.stop(true);
  await live.drop();

  for (const db of truthDbs) await db.drop();
}

for (const p of problems) process.stderr.write(`resolve-bench: ${p}\n`);

if (problems.length > 0) process.exit(1);

process.stdout.write(`${score.toFixed(2)}\n`);
