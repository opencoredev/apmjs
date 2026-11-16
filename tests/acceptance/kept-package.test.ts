// A package page reads an upstream package's kept summary (migration 0020, kept-package.ts) instead of npm's whole
// packument. Every read a summary answers must come out byte for byte as npm's packument would answer it, past the
// summary's version window too. A summary must never offer or show the source of a version npm no longer lists, must answer as the code
// did before summaries were kept whenever npm cannot confirm it, must be checked against npm once it is five minutes
// old (the HEAD answer too), and must never answer for a package published on apm. A package apm never scored gets
// none. Runs the bundled Worker against a local npm that answers as registry.npmjs.org does (ETags, HEAD, 304, version
// documents).
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { z } from "zod";
import { getJson, pkgTgz, putPublish, startRegistry, type Registry } from "./harness";

const MINUTE = 60_000;
let clock = Date.parse("2026-10-01T00:00:00Z");
let reg: Registry;

/** What npm lists: name -> versions (in publish order) and latest; a package with no latest tag has `latest: null`. */
const listed = new Map<string, { versions: string[]; latest: string | null }>();

/** "<name>@<version>" -> what npm now says of its tarball: moved to another URL (same bytes), or another shasum. */
const changedDist = new Map<string, { moved?: boolean; shasum?: string }>();

/** `down`: every packument, HEAD and version document answers a 500; `failing`: those of these packages do. */
let down = false;
const failing = new Set<string>();

/** Packages whose version documents npm fails: "error" answers a 500, "hang" answers only after HANG_MS. */
const versionDocFault = new Map<string, "error" | "hang">();
const HANG_MS = 4_000;

/** Version documents asked for, per package, whatever npm answered. */
const versionDocRequests = new Map<string, number>();

/** Whole packuments npm sent with a body, and HEADs of packuments, per package. */
const packumentReads = new Map<string, number>();
const packumentHeads = new Map<string, number>();

const tgz = (name: string, version: string) => pkgTgz({ name, version, main: "index.js", license: "MIT" }, { "index.js": `module.exports = "${version}";\n`, "README.md": `# ${name} ${version}\n` });

function versionDoc(name: string, v: string, base: string) {
  const bytes = tgz(name, v);
  const changed = changedDist.get(`${name}@${v}`);
  const tarball = changed?.moved ? `${base}moved/${name}/-/${name}-${v}.tgz` : `${base}${name}/-/${name}-${v}.tgz`;
  const dist = { tarball, integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`, shasum: changed?.shasum ?? createHash("sha1").update(bytes).digest("hex") };

  return { name, version: v, main: "index.js", license: "MIT", repository: { type: "git", url: "git+https://github.com/example/kp.git" }, homepage: "https://example.com/kp", dist };
}

function packument(name: string, base: string): string | null {
  const pkg = listed.get(name);

  if (!pkg) return null;
  const versions = Object.fromEntries(pkg.versions.map((v) => [v, versionDoc(name, v, base)]));
  const time = Object.fromEntries(pkg.versions.map((v, i) => [v, new Date(Date.parse("2026-01-01T00:00:00Z") + i * 60 * MINUTE).toISOString()]));

  const distTags = pkg.latest === null ? {} : { latest: pkg.latest };

  return JSON.stringify({ name, description: `${name} does things`, readme: `# ${name}\n\nThe readme.`, maintainers: [{ name: "kp-owner" }], "dist-tags": distTags, versions, time });
}

const npm = Bun.serve({
  port: 0,
  hostname: "127.0.0.1",
  async fetch(req): Promise<Response> {
    const path = decodeURIComponent(new URL(req.url).pathname.slice(1));
    const tarball = /^(moved\/)?([^/]+)\/-\/[^/]+-(\d+\.\d+\.\d+)\.tgz$/.exec(path);

    if (tarball) {
      const [, moved, tName = "", tVersion = ""] = tarball;

      // a moved tarball is only at its new URL
      if (Boolean(changedDist.get(`${tName}@${tVersion}`)?.moved) !== (moved !== undefined)) return new Response("Not found", { status: 404 });

      return new Response(tgz(tName, tVersion));
    }

    const [name = "", version] = path.split("/");

    if (down || failing.has(name)) return new Response("down", { status: 500 });

    if (version !== undefined) {
      versionDocRequests.set(name, (versionDocRequests.get(name) ?? 0) + 1);
      const fault = versionDocFault.get(name);

      if (fault === "error") return new Response("rate limited", { status: 500 });

      if (fault === "hang") await Bun.sleep(HANG_MS);
    }

    const pkg = listed.get(name);
    let text: string | null = null;

    if (version === undefined) text = packument(name, npm.url.href);
    else if (pkg?.versions.includes(version)) text = JSON.stringify(versionDoc(name, version, npm.url.href));

    if (text === null) return Response.json({ error: "Not found" }, { status: 404 });
    const etag = `"${createHash("sha1").update(text).digest("hex")}"`;
    const headers = { "content-type": "application/json", etag };

    if (req.method === "HEAD") {
      if (version === undefined) packumentHeads.set(name, (packumentHeads.get(name) ?? 0) + 1);

      return new Response(null, { headers });
    }

    if (req.headers.get("if-none-match") === etag) return new Response(null, { status: 304, headers });

    if (version === undefined) packumentReads.set(name, (packumentReads.get(name) ?? 0) + 1);

    return new Response(text, { headers });
  },
});

beforeAll(async () => {
  // TTL 0: no isolate or shared copy of a packument or a version document, so every read that is not kept asks npm
  reg = await startRegistry({
    now: () => clock,
    upstream: npm.url.href,
    upstreamTtlMs: 0,
    // the review answer is one of the reads a summary may answer
    review: { serviceTokenHash: createHash("sha256").update("kp-review-service").digest("hex"), admins: [] },
  });
});

afterAll(async () => {
  await reg.stop();
  await npm.stop(true);
});

const Kept = z.array(z.object({ computed_at: z.union([z.string(), z.number()]).transform(Number), summary: z.unknown() }));

async function keptRow(name: string) {
  return Kept.parse(await reg.query("SELECT computed_at, summary FROM kept_packages WHERE package = $1", [name]))[0] ?? null;
}

async function dropRow(name: string): Promise<void> {
  await reg.query("DELETE FROM kept_packages WHERE package = $1", [name]);
}

/** The paths a package page and its file views read for one version. */
const pagePaths = (name: string, version: string) => [
  `-/apm/v1/packages/${name}`,
  `-/apm/v1/packages/${name}/versions/${version}`,
  `-/apm/v1/score/${name}/${version}`,
  `-/apm/v1/review/${name}/${version}`,
  `-/apm/v1/file/${name}/${version}?path=package.json`,
  `-/apm/v1/readme/${name}/${version}`,
];

/** Each answer as sent: its status and its body's text. */
async function answers(paths: readonly string[], before: () => Promise<void> = async () => undefined): Promise<string[]> {
  const out: string[] = [];

  for (const p of paths) {
    await before();
    const res = await fetch(`${reg.url}${p}`);
    out.push(`${res.status} ${p}\n${await res.text()}`);
  }

  return out;
}

/** A package npm lists, viewed once and scored, so it is kept. */
async function keptPackage(name: string, versions: string[]): Promise<void> {
  listed.set(name, { versions, latest: versions.at(-1) ?? null });
  await getJson(`${reg.url}-/apm/v1/packages/${name}`);

  for (const v of versions) expect(await reg.analysisJob({ name, version: v })).toBe("ack");
  await getJson(`${reg.url}-/apm/v1/packages/${name}`);
  expect(await keptRow(name)).not.toBeNull();
}

describe("kept package summaries", () => {
  test("a package apm never scored gets no summary", async () => {
    listed.set("kp-unscored", { versions: ["1.0.0"], latest: "1.0.0" });

    expect((await getJson(`${reg.url}-/apm/v1/packages/kp-unscored`)).status).toBe(200);
    expect(await keptRow("kp-unscored")).toBeNull();
  });

  test("past the version window, a kept summary answers every page read byte for byte as npm's packument does", async () => {
    // 240 versions, so a summary holds only some: 1.0.0 to 1.199.0, then a late 0.5 line of 30, then 1.200.0 to 1.209.0.
    // By number it keeps 1.10.0 and up; by publish time 1.40.0 and up and the 0.5 line; so 1.0.0 to 1.9.0 are left out,
    // and 1.20.0 is kept but published before the publish-time window.
    const name = "kp-wide";
    const versions = [...Array.from({ length: 200 }, (_, i) => `1.${i}.0`), ...Array.from({ length: 30 }, (_, i) => `0.5.${i}`), ...Array.from({ length: 10 }, (_, i) => `1.${200 + i}.0`)];

    listed.set(name, { versions, latest: "1.209.0" });
    await getJson(`${reg.url}-/apm/v1/packages/${name}`);

    // every version the reads name and the one published before each, so no read queues an analysis that could land
    // between the two passes and change a score answer's previous version
    for (const v of ["1.209.0", "1.208.0", "0.5.10", "0.5.9", "1.20.0", "1.19.0", "1.5.0", "1.4.0"]) expect(await reg.analysisJob({ name, version: v })).toBe("ack");
    await getJson(`${reg.url}-/apm/v1/packages/${name}`);
    const Versions = z.object({ versions: z.array(z.object({ version: z.string() })) });

    expect(Versions.parse((await keptRow(name))?.summary).versions.length).toBe(230);

    // the reads a summary answers: the newest versions, the 0.5 line by publish time, 1.20.0 by number
    const covered = [
      `-/apm/v1/packages/${name}`,
      `-/apm/v1/packages/${name}/versions/1.209.0`,
      `-/apm/v1/packages/${name}/versions/0.5.10`,
      `-/apm/v1/packages/${name}/versions/1.20.0`,
      `-/apm/v1/score/${name}`,
      `-/apm/v1/score/${name}/1.209.0`,
      `-/apm/v1/score/${name}/0.5.10`,
      `-/apm/v1/review/${name}/latest`,
      `-/apm/v1/review/${name}/0.5.10`,
      `-/apm/v1/review/${name}/1.20.0`,
      `-/apm/v1/file/${name}/1.209.0?path=package.json`,
      `-/apm/v1/file/${name}/0.5.10?path=index.js`,
      `-/apm/v1/readme/${name}/1.209.0`,
    ];

    // and the ones it cannot: 1.20.0's previous version is outside the publish-time window, and 1.5.0 is not kept
    const uncovered = [`-/apm/v1/score/${name}/1.20.0`, `-/apm/v1/packages/${name}/versions/1.5.0`, `-/apm/v1/review/${name}/1.5.0`, `-/apm/v1/file/${name}/1.5.0?path=package.json`, `-/apm/v1/score/${name}/1.5.0`];
    const reads = () => packumentReads.get(name) ?? 0;
    const before = reads();
    const fromSummary = await answers(covered);

    // none of them read the packument
    expect(reads()).toBe(before);
    const passedOn = await answers(uncovered);

    expect(reads()).toBe(before + uncovered.length);
    // the same reads with no summary at all: the row is gone before each one
    const live = await answers([...covered, ...uncovered], () => dropRow(name));

    expect([...fromSummary, ...passedOn]).toEqual(live);
    expect(live.filter((a) => !a.startsWith("200 "))).toEqual([]);
  });

  test("a version npm removed is answered as npm's packument answers it, never from the summary", async () => {
    await keptPackage("kp-removed", ["1.0.0", "1.1.0", "1.2.0"]);
    // npm takes 1.1.0 down; the summary, a moment old, still lists it
    listed.set("kp-removed", { versions: ["1.0.0", "1.2.0"], latest: "1.2.0" });
    // every read that shows 1.1.0's source or offers it; the package answer's version list may lag up to five minutes
    const paths = pagePaths("kp-removed", "1.1.0").slice(1);
    const kept = await answers(paths);
    const live = await answers(paths, () => dropRow("kp-removed"));

    expect(kept).toEqual(live);
    // every one of them is refused, as without a summary
    expect(kept.every((a) => a.startsWith("404 "))).toBe(true);
  });

  test("a package npm removed is answered as npm's packument answers it, and its summary goes", async () => {
    await keptPackage("kp-gone", ["1.0.0", "1.1.0"]);
    listed.delete("kp-gone");
    // accepted (re-check of 1cbdc6c, finding 4): a summary under five minutes old still tells the HEAD the package
    // exists, so the page renders, while every read below that would show its source asks npm and is refused
    expect((await fetch(`${reg.url}-/apm/v1/packages/kp-gone`, { method: "HEAD" })).status).toBe(200);
    const paths = pagePaths("kp-gone", "1.1.0");
    const kept = await answers(paths);
    const live = await answers(paths, () => dropRow("kp-gone"));

    expect(kept).toEqual(live);
    expect(kept.every((a) => a.startsWith("404 "))).toBe(true);
    expect(await keptRow("kp-gone")).toBeNull();
  });

  test("a package with no latest tag is never answered from its summary", async () => {
    await keptPackage("kp-untagged", ["1.0.0", "1.1.0"]);
    listed.set("kp-untagged", { versions: ["1.0.0", "1.1.0"], latest: null });
    // past five minutes, the changed ETag sends the view to npm, whose answer replaces the summary: no latest tag now
    clock += 6 * MINUTE;
    await getJson(`${reg.url}-/apm/v1/packages/kp-untagged`);
    expect(z.object({ distTags: z.record(z.string(), z.string()) }).parse((await keptRow("kp-untagged"))?.summary).distTags).toEqual({});
    // npm removes the package: no read names a version it would show, so each asks npm, which has none
    listed.delete("kp-untagged");
    const paths = [`-/apm/v1/packages/kp-untagged`, `-/apm/v1/score/kp-untagged`];
    const kept = await answers(paths);

    expect(kept).toEqual(await answers(paths, () => dropRow("kp-untagged")));
    expect(kept.every((a) => a.startsWith("404 "))).toBe(true);
    expect(kept.join("\n")).not.toContain("The readme.");
  });

  test("a version whose tarball URL or shasum npm changed is read from npm, and its summary refreshed", async () => {
    await keptPackage("kp-moved", ["1.0.0", "1.1.0"]);
    const Versions = z.object({ versions: z.array(z.object({ version: z.string(), tarball: z.string(), shasum: z.string() })) });
    const keptVersion = async (v: string) => Versions.parse((await keptRow("kp-moved"))?.summary).versions.find((x) => x.version === v);
    const reads = () => packumentReads.get("kp-moved") ?? 0;

    // the same bytes at a new URL, the old one gone, and no stored copy of the tarball to fall back on
    changedDist.set("kp-moved@1.1.0", { moved: true });

    for (const key of (await reg.blobs.keys()).filter((k) => !k.startsWith("files/"))) await reg.blobs.put(key, "not the tarball");
    const file = [`-/apm/v1/file/kp-moved/1.1.0?path=index.js`];
    const before = reads();
    const kept = await answers(file);

    expect(reads()).toBe(before + 1);
    expect(kept).toEqual(await answers(file, () => dropRow("kp-moved")));
    expect(kept[0]?.startsWith("200 ")).toBe(true);
    expect((await keptVersion("1.1.0"))?.tarball).toContain("/moved/");
    // a shasum npm changed, its sha512 the same: read from npm too
    changedDist.set("kp-moved@1.0.0", { shasum: "0".repeat(40) });
    const score = [`-/apm/v1/score/kp-moved/1.0.0`];
    const at = reads();
    const scored = await answers(score);

    expect(reads()).toBe(at + 1);
    expect(scored).toEqual(await answers(score, () => dropRow("kp-moved")));
    expect((await keptVersion("1.0.0"))?.shasum).toBe("0".repeat(40));
  });

  test("a score answer's previous version is confirmed with npm too", async () => {
    await keptPackage("kp-prev", ["1.0.0", "1.1.0", "1.2.0"]);
    // npm removes 1.1.0, the version 1.2.0's score compares with
    listed.set("kp-prev", { versions: ["1.0.0", "1.2.0"], latest: "1.2.0" });
    const path = [`-/apm/v1/score/kp-prev/1.2.0`];
    const kept = await answers(path);

    expect(kept).toEqual(await answers(path, () => dropRow("kp-prev")));
    const Previous = z.object({ previous: z.object({ version: z.string() }).nullable() });

    expect(Previous.parse(JSON.parse(kept[0]?.split("\n").slice(1).join("\n") ?? "")).previous?.version).toBe("1.0.0");
  });

  test("after npm changed a package, repeated HEADs ask npm once", async () => {
    await keptPackage("kp-heads", ["1.0.0", "1.1.0"]);
    clock += 10 * MINUTE;
    listed.set("kp-heads", { versions: ["1.0.0", "1.1.0", "1.2.0"], latest: "1.2.0" });
    const heads = () => packumentHeads.get("kp-heads") ?? 0;
    const reads = () => packumentReads.get("kp-heads") ?? 0;
    const [h0, r0] = [heads(), reads()];

    for (let i = 0; i < 5; i++) expect((await fetch(`${reg.url}-/apm/v1/packages/kp-heads`, { method: "HEAD" })).status).toBe(200);
    // the first asks npm once, with the summary's ETag, and npm's answer is the changed packument, which replaces the
    // summary (before resolve's kept choices joined it: a HEAD, then the packument); the other four use it
    expect([heads() - h0, reads() - r0]).toEqual([0, 1]);
    expect(z.object({ distTags: z.object({ latest: z.string() }) }).parse((await keptRow("kp-heads"))?.summary).distTags.latest).toBe("1.2.0");
  });

  test("a failed version document is not asked for again for a while: reads go to npm's packument as before", async () => {
    // production's caches, scaled down: a 3 s TTL, so a failure is remembered for 3 s (NPM_FAILURE_MS caps it at 30)
    const ttl = 3_000;
    const reg2 = await startRegistry({ now: () => clock, upstream: npm.url.href, upstreamTtlMs: ttl });

    try {
      const keep = async (name: string) => {
        listed.set(name, { versions: ["1.0.0", "1.1.0"], latest: "1.1.0" });
        await fetch(`${reg2.url}-/apm/v1/packages/${name}`);

        for (const v of ["1.0.0", "1.1.0"]) expect(await reg2.analysisJob({ name, version: v })).toBe("ack");
        await fetch(`${reg2.url}-/apm/v1/packages/${name}`);
        expect(await reg2.query("SELECT 1 FROM kept_packages WHERE package = $1", [name])).toHaveLength(1);
      };

      const read = async (paths: readonly string[], before: () => Promise<void> = async () => undefined) => {
        const out: string[] = [];

        for (const p of paths) {
          await before();
          const res = await fetch(`${reg2.url}${p}`);
          out.push(`${res.status} ${p}\n${await res.text()}`);
        }

        return out;
      };

      for (const [name, fault] of [
        ["kp-doc-error", "error"],
        ["kp-doc-hang", "hang"],
      ] as const) {
        await keep(name);
        // the reads a summary would answer after confirming one version: three routes, one after another
        const paths = [`-/apm/v1/packages/${name}/versions/1.1.0`, `-/apm/v1/file/${name}/1.1.0?path=index.js`, `-/apm/v1/readme/${name}/1.1.0`];
        const requests = () => versionDocRequests.get(name) ?? 0;

        versionDocFault.set(name, fault);
        const before = requests();
        const started = performance.now();
        const kept = await read(paths);
        const took = performance.now() - started;

        // one version document, whatever npm did with it; the other reads went straight to the packument
        expect(requests() - before).toBe(1);

        // a hang costs the 2 s timeout once, not npm's whole stall, and not once per read
        if (fault === "hang") expect(took).toBeLessThan(HANG_MS);
        expect(kept).toEqual(await read(paths, async () => void (await reg2.query("DELETE FROM kept_packages WHERE package = $1", [name]))));
        // the summary comes back once npm can confirm again: kept from the read above, and asked again past the window
        versionDocFault.delete(name);
        await Bun.sleep(ttl + 200);
        const at = requests();

        expect((await fetch(`${reg2.url}${paths[0]}`)).status).toBe(200);
        expect(requests() - at).toBe(1);
      }
    } finally {
      versionDocFault.clear();
      await reg2.stop();
    }
    // two waits past the 3 s window and a 2 s timeout: past bun's default 5 s (re-check 3 of 0abfdbf)
  }, 30_000);

  test("with npm down, every read answers as it did before summaries were kept", async () => {
    await keptPackage("kp-down", ["1.0.0", "1.1.0"]);
    const row = await keptRow("kp-down");
    down = true;

    try {
      const paths = pagePaths("kp-down", "1.1.0");
      const kept = await answers(paths);

      const live = await answers(paths, () => dropRow("kp-down"));

      expect(kept).toEqual(live);
      expect(kept.some((a) => a.startsWith("200 "))).toBe(false);
    } finally {
      down = false;
    }

    // and the sweep leaves the summary as it was
    clock += 30 * MINUTE;
    await reg.query("INSERT INTO kept_packages (package, summary, computed_at, asked_at) VALUES ($1, $2::jsonb, $3, $4)", ["kp-down", JSON.stringify(row?.summary), row?.computed_at, clock]);
    down = true;

    try {
      await reg.sweep();
      expect(await keptRow("kp-down")).toEqual(row);
    } finally {
      down = false;
    }
  });

  test("a summary older than five minutes is checked against npm first, the HEAD answer too", async () => {
    await keptPackage("kp-age", ["1.0.0", "1.1.0"]);
    const reads = () => packumentReads.get("kp-age") ?? 0;
    const head = async () => (await fetch(`${reg.url}-/apm/v1/packages/kp-age`, { method: "HEAD" })).status;
    const before = reads();

    // a fresh summary: the HEAD asks npm nothing
    expect(await head()).toBe(200);
    expect(reads()).toBe(before);
    // two days old and npm changed the package: the HEAD reads it from npm
    clock += 2 * 24 * 60 * MINUTE;
    listed.set("kp-age", { versions: ["1.0.0", "1.1.0", "1.2.0"], latest: "1.2.0" });
    expect(await head()).toBe(200);
    expect(reads()).toBe(before + 1);
    // two days old and npm no longer has it: the HEAD says so, and the summary goes
    await reg.query("UPDATE kept_packages SET computed_at = $1 WHERE package = 'kp-age'", [clock - 2 * 24 * 60 * MINUTE]);
    listed.delete("kp-age");
    expect(await head()).toBe(404);
    expect(await keptRow("kp-age")).toBeNull();
  });

  test("an unchanged packument keeps its summary current without being read again", async () => {
    await keptPackage("kp-same", ["1.0.0", "1.1.0"]);
    const before = packumentReads.get("kp-same") ?? 0;

    clock += 60 * MINUTE;
    expect((await getJson(`${reg.url}-/apm/v1/packages/kp-same`)).status).toBe(200);
    expect(packumentReads.get("kp-same") ?? 0).toBe(before);
    expect((await keptRow("kp-same"))?.computed_at).toBe(clock);
  });

  test("a release on npm shows once the summary is refreshed", async () => {
    await keptPackage("kp-lib", ["1.0.0", "1.1.0", "1.2.0"]);
    listed.set("kp-lib", { versions: ["1.0.0", "1.1.0", "1.2.0", "1.3.0"], latest: "1.3.0" });
    clock += 4 * MINUTE;
    // a four-minute-old summary answers at once and is refreshed after the response
    const Latest = z.object({ latest: z.string() });

    expect(Latest.parse((await getJson(`${reg.url}-/apm/v1/packages/kp-lib`)).body).latest).toBe("1.2.0");
    const deadline = Date.now() + 10_000;

    for (;;) {
      const now = Latest.parse((await getJson(`${reg.url}-/apm/v1/packages/kp-lib`)).body).latest;

      if (now === "1.3.0") break;

      if (Date.now() > deadline) throw new Error("the summary was never refreshed");
      await Bun.sleep(50);
    }
  });

  test("the sweep refreshes a summary asked about, and drops one npm no longer has", async () => {
    listed.set("kp-lib", { versions: ["1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"], latest: "1.4.0" });
    clock += 10 * MINUTE;
    await reg.sweep();
    const Summary = z.object({ distTags: z.object({ latest: z.string() }) });

    expect(Summary.parse((await keptRow("kp-lib"))?.summary).distTags.latest).toBe("1.4.0");
    listed.delete("kp-lib");
    clock += 10 * MINUTE;
    await reg.sweep();
    expect(await keptRow("kp-lib")).toBeNull();
  });

  test("packages npm keeps failing for do not hold the sweep's place", async () => {
    // a batch's worth of summaries npm answers 500 for, all older than the one npm answers for, and no others
    await reg.query("DELETE FROM kept_packages");
    const old = clock - 60 * MINUTE;
    const summary = (name: string) => JSON.stringify({ name, distTags: { latest: "1.0.0" }, description: "", readme: "", maintainers: [], latest: {}, completeSince: null, etag: null, versions: [] });
    const broken = Array.from({ length: 24 }, (_, i) => `kp-broken-${String(i).padStart(2, "0")}`);

    for (const [i, name] of broken.entries()) {
      failing.add(name);
      await reg.query("INSERT INTO kept_packages (package, summary, computed_at, asked_at) VALUES ($1, $2::jsonb, $3, $4)", [name, summary(name), old - 24 + i, clock]);
    }

    listed.set("kp-healthy", { versions: ["1.0.0", "2.0.0"], latest: "2.0.0" });
    await reg.query("INSERT INTO kept_packages (package, summary, computed_at, asked_at) VALUES ($1, $2::jsonb, $3, $4)", ["kp-healthy", summary("kp-healthy"), old, clock]);
    const Summary = z.object({ distTags: z.object({ latest: z.string() }) });
    const latest = async () => Summary.parse((await keptRow("kp-healthy"))?.summary).distTags.latest;

    try {
      // the first sweep takes the 24 older ones and fails on each; the next moves past them
      await reg.sweep();
      expect(await latest()).toBe("1.0.0");
      clock += 10 * MINUTE;
      await reg.sweep();
      expect(await latest()).toBe("2.0.0");
      const Due = z.array(z.object({ failures: z.number(), next_attempt_at: z.union([z.string(), z.number()]).transform(Number) }));
      const due = Due.parse(await reg.query("SELECT failures, next_attempt_at FROM kept_packages WHERE package = $1", [broken[0]]));

      expect(due[0]?.failures).toBe(1);
      expect(due[0]?.next_attempt_at).toBeGreaterThan(clock);
    } finally {
      for (const name of broken) failing.delete(name);
    }
  });

  test("a package published on apm is never answered from a kept summary", async () => {
    const token = await reg.mintToken({ user: "kp-local", scope: "publish" });

    expect((await putPublish(reg, token, { name: "kp-local", version: "1.0.0" })).status).toBe(201);
    // a summary that names another latest, as if npm had kept one for this name
    const summary = { name: "kp-local", distTags: { latest: "9.9.9" }, description: "not this one", readme: "", maintainers: ["someone"], latest: {}, completeSince: null, etag: null, versions: [] };

    await reg.query("INSERT INTO kept_packages (package, summary, computed_at, asked_at) VALUES ($1, $2::jsonb, $3, $3)", ["kp-local", JSON.stringify(summary), clock]);
    const answer = z.object({ source: z.string(), latest: z.string() }).parse((await getJson(`${reg.url}-/apm/v1/packages/kp-local`)).body);

    expect(answer).toEqual({ source: "local", latest: "1.0.0" });
  });
});
