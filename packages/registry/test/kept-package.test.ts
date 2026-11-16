// A kept package summary (kept-package.ts) holds only some of a package's versions, so every read it answers must come
// out as the whole packument would: the package answer's newest versions, a dist-tag's target, an exact version and the
// version published before one. The table is capped however many packages are asked about.
import { describe, expect, test } from "bun:test";
import { Effect } from "effect";
import { Client } from "pg";
import { z } from "zod";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Store, type VersionRecord } from "../src/db.ts";
import { admitted, covers, expand, KEPT_PACKAGE_MAX_BYTES, KEPT_VERSIONS, keptWithoutScore, summarize } from "../src/kept-package.ts";
import { newestFirst } from "../src/semver.ts";
import type { CachedPackage, UpstreamPackage } from "../src/upstream.ts";

const DAY = 24 * 60 * 60_000;

/** A package npm lists: `versions` in publish order, a day apart. */
function cached(versions: readonly string[], tags: Record<string, string>, readme = ""): CachedPackage {
  const records = versions.map(
    (version, seq): Omit<VersionRecord, "score"> => ({
      package: "big",
      version,
      manifest: { name: "big", version, repository: "github:example/big", homepage: "https://example.com", description: "a long manifest" },
      shasum: "1".repeat(40),
      integrity: `sha512-${Buffer.alloc(64, seq % 256).toString("base64")}`,
      size: 0,
      tarball_key: "",
      published_at: seq * DAY,
      seq,
      published_by: `publisher-${seq % 3}`,
      deprecated: seq % 7 === 0 ? "old" : null,
      status: "active",
      status_reason: null,
      status_at: null,
      status_by: null,
    }),
  );

  return {
    name: "big",
    distTags: tags,
    description: "big",
    readme,
    maintainers: ["a"],
    versions: records,
    tarballs: new Map(versions.map((v) => [v, `https://npm.invalid/big/-/big-${v}.tgz`])),
    serveCost: { versionDocs: 0, maxPieceChars: 0 },
    etag: null,
    fetchedAt: Number.NEGATIVE_INFINITY,
    readAt: Number.NEGATIVE_INFINITY,
  };
}

/** 600 versions: 1.0.0 to 1.299.0 published first, then 200 releases of an old 0.9 line, then 2.0.0 to 2.99.0. */
const versions = [...Array.from({ length: 300 }, (_, i) => `1.${i}.0`), ...Array.from({ length: 200 }, (_, i) => `0.9.${i}`), ...Array.from({ length: 100 }, (_, i) => `2.${i}.0`)];
const pkg = cached(versions, { latest: "2.99.0", legacy: "1.5.0", backport: "0.9.199" });

/** previousOf in apm.ts: the last version published at or before `v`, other than `v`. */
function previous(all: readonly { version: string; published_at: number }[], version: string): string | null {
  const v = all.find((x) => x.version === version);

  if (!v) return null;

  return all.filter((x) => x.version !== version && x.published_at <= v.published_at).at(-1)?.version ?? null;
}

describe("a package summary", () => {
  const kept = summarize(pkg);

  test("keeps the newest versions by number and by publish time, and every dist-tag's target", () => {
    expect(kept).not.toBeNull();

    if (!kept) return;
    const held = new Set(kept.versions.map((v) => v.version));

    for (const v of versions.toSorted(newestFirst).slice(0, KEPT_VERSIONS)) expect(held.has(v)).toBe(true);

    for (const v of versions.slice(-KEPT_VERSIONS)) expect(held.has(v)).toBe(true);

    for (const v of Object.values(pkg.distTags)) expect(held.has(v)).toBe(true);
    expect(held.size).toBeLessThan(versions.length);
  });

  test("expands to the package answer's versions, and each kept version as npm listed it", () => {
    if (!kept) throw new Error("not kept");
    const out = expand(kept);
    const shown = (vs: readonly { version: string }[]) => vs.map((v) => v.version).toSorted(newestFirst).slice(0, KEPT_VERSIONS);

    expect(shown(out.versions)).toEqual(shown(pkg.versions));

    for (const v of out.versions) {
      const whole = pkg.versions.find((x) => x.version === v.version);
      const { manifest: _m, ...rest } = v;
      const { manifest: _w, ...wholeRest } = whole ?? v;

      expect(rest).toEqual({ ...wholeRest, tarball_key: rest.tarball_key });
      expect(out.tarballs.get(v.version)).toBe(pkg.tarballs.get(v.version));
    }

    expect(out.versions.find((v) => v.version === "2.99.0")?.manifest).toEqual({ repository: "github:example/big", homepage: "https://example.com" });
  });

  test("answers a version's previous one only when it is the one the whole list has", () => {
    if (!kept) throw new Error("not kept");
    const out = expand(kept);

    for (const v of versions) {
      if (covers(kept, { kind: "history", spec: v })) expect(previous(out.versions, v)).toBe(previous(pkg.versions, v));
    }

    // inside the publish-time window, and the old line outside it
    expect(covers(kept, { kind: "history", spec: "2.50.0" })).toBe(true);
    expect(covers(kept, { kind: "history", spec: "1.5.0" })).toBe(false);
    expect(covers(kept, { kind: "history", spec: undefined })).toBe(true);
  });

  test("answers a spec it holds, a dist-tag it holds, and no version it does not", () => {
    if (!kept) throw new Error("not kept");
    expect(covers(kept, { kind: "spec", spec: "latest" })).toBe(true);
    expect(covers(kept, { kind: "spec", spec: "legacy" })).toBe(true);
    expect(covers(kept, { kind: "spec", spec: "1.6.0" })).toBe(false);
    expect(covers(kept, { kind: "spec", spec: "no-such-tag" })).toBe(false);
    expect(covers(kept, { kind: "version", version: "1.6.0" })).toBe(false);
    expect(covers(kept, { kind: "version", version: "2.0.0" })).toBe(true);
  });

  test("is not kept when it would be larger than the limit", () => {
    expect(summarize(cached(["1.0.0"], { latest: "1.0.0" }, "x".repeat(KEPT_PACKAGE_MAX_BYTES)))).toBeNull();
  });

  test("counts its size in UTF-8 bytes, not characters", () => {
    // 100,000 characters of a 3-byte one: under the limit by length, 300,000 bytes as UTF-8
    const readme = "中".repeat(100_000);

    expect(readme.length).toBeLessThan(KEPT_PACKAGE_MAX_BYTES);
    expect(summarize(cached(["1.0.0"], { latest: "1.0.0" }, readme))).toBeNull();
    // and one that fits in bytes is kept
    expect(summarize(cached(["1.0.0"], { latest: "1.0.0" }, "中".repeat(50_000)))).not.toBeNull();
  });
});

const Count = z.array(z.object({ count: z.union([z.string(), z.number()]).transform(Number) }));

describe("which packages get a summary", () => {
  const TOO_LARGE = { reason: "too-large" as const, detail: "the tarball (43.7 MB) is larger than the 32 MiB apm downloads", digest: null };

  /** `name` as npm lists it with two versions, the newest scored, recorded unscorable, or neither. */
  const analysed = (name: string, latest: "scored" | "unscorable" | "none"): UpstreamPackage => {
    const c = cached(["1.0.0", "2.0.0"], { latest: "2.0.0" });

    const versions = c.versions.map((v): VersionRecord => {
      if (v.version !== "2.0.0" || latest === "none") return { ...v, package: name, score: null };

      return latest === "scored" ? { ...v, package: name, score: { score: 80 } } : { ...v, package: name, score: null, unscorable: TOO_LARGE };
    });

    return { ...c, name, versions };
  };

  test("a scored package does; an unscorable one only when the operator listed it (review of e4f97b2)", () => {
    expect(admitted(analysed("anything", "scored"))).toBe(true);
    expect(admitted(analysed("anything", "none"))).toBe(false);
    // anyone can have apm record any package unscorable: that alone must not take a row
    expect(admitted(analysed("made-to-be-too-large", "unscorable"))).toBe(false);
    expect(admitted(analysed("next", "unscorable"))).toBe(true);
    expect(admitted(analysed("@next/swc-linux-x64-gnu", "unscorable"))).toBe(true);
    // listed, but nothing recorded: not analysed, no row
    expect(admitted(analysed("next", "none"))).toBe(false);
  });

  test("the list matches exact names and prefixes, nothing near them", () => {
    expect(keptWithoutScore("next")).toBe(true);
    expect(keptWithoutScore("@next/swc-win32-arm64-msvc")).toBe(true);

    for (const near of ["next-auth", "nextjs", "@next/env", "@next/swc", "@nextx/swc-linux", "Next"]) expect(keptWithoutScore(near)).toBe(false);
    expect(keptWithoutScore("x", [{ kind: "exact", name: "x" }])).toBe(true);
  });
});

describe("keepPackage", () => {
  test("adds no row past the capacity, and replaces a kept one", async () => {
    const db = await freshDatabase();
    const c = new Client({ connectionString: db.url });

    await c.connect();

    try {
      const run = <A>(effect: Effect.Effect<A, unknown, Store>) => Effect.runPromise(effect.pipe(Effect.provide(Store.postgres(db.url)), Effect.scoped));
      const keep = (name: string, at: number) => run(Effect.flatMap(Store, (s) => s.keepPackage({ name, summary: { name }, at, capacity: 3 })));

      for (const n of ["a", "b", "c", "d"]) await keep(n, 1);
      expect(Count.parse((await c.query("SELECT count(*) FROM kept_packages")).rows)[0]?.count).toBe(3);
      expect((await c.query("SELECT 1 FROM kept_packages WHERE package = 'd'")).rows).toEqual([]);
      await keep("a", 2);
      expect((await c.query("SELECT computed_at FROM kept_packages WHERE package = 'a'")).rows).toEqual([{ computed_at: "2" }]);
    } finally {
      await c.end();
      await db.drop();
    }
  });
});
