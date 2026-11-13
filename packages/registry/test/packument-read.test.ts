// The streaming packument reader (src/packument-read.ts): what it keeps equals JSON.parse of the packument minus the
// fields it drops, however the bytes are split, and a packument past either cap is refused instead of held.
import { describe, expect, test } from "bun:test";
import { z } from "zod";
import { DROPPED_VERSION_FIELDS, readPackument, type JsonValue, type KeptPackument, type PackumentLimits } from "../src/packument-read.ts";

const LIMITS: PackumentLimits = { maxBytes: 10_000_000, maxKeptBytes: 1_000_000 };

function streamOf(text: string, chunk: number): ReadableStream<Uint8Array> {
  const bytes = new TextEncoder().encode(text);
  let at = 0;

  return new ReadableStream({
    pull(c) {
      if (at >= bytes.length) {
        c.close();

        return;
      }

      c.enqueue(bytes.slice(at, at + chunk));
      at += chunk;
    },
  });
}

const Doc = z.record(z.string(), z.json());
const Versions = z.record(z.string(), z.json());
const VersionDoc = z.record(z.string(), z.json());

/** What the reader should keep: JSON.parse of the packument, its top-level fields and versions minus the dropped fields. */
function expected(packument: JsonValue): KeptPackument {
  const top = ["name", "dist-tags", "versions", "time", "description", "readme", "maintainers"];
  const out: Record<string, JsonValue> = Object.fromEntries(Object.entries(Doc.parse(packument)).filter(([k]) => top.includes(k)));
  const versions = Versions.safeParse(out.versions);

  if (versions.success) {
    out.versions = Object.fromEntries(
      Object.entries(versions.data).map(([v, d]) => {
        const doc = VersionDoc.safeParse(d);

        return [v, doc.success ? Object.fromEntries(Object.entries(doc.data).filter(([f]) => !DROPPED_VERSION_FIELDS.has(f))) : d];
      }),
    );
  }

  return out;
}

const PACKUMENT = {
  _id: "pkg",
  _rev: "12-abc",
  name: "pkg",
  "dist-tags": { latest: "1.1.0", next: "2.0.0-beta.1" },
  description: 'a package with "quotes", a \\ backslash, a   separator and é',
  readme: "# pkg\n\n```js\nconst a = { b: [1, 2] };\n```\n",
  maintainers: [{ name: "a", email: "a@example.invalid" }],
  users: { someone: true },
  time: { created: "2020-01-01T00:00:00.000Z", "1.0.0": "2020-01-01T00:00:00.000Z", "1.1.0": "2021-01-01T00:00:00.000Z" },
  versions: {
    "1.0.0": {
      name: "pkg",
      version: "1.0.0",
      dist: { tarball: "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz", shasum: "00", integrity: "sha512-AA==" },
      dependencies: { dep: "^1.0.0" },
      licenseText: "MIT License {[\"x\"]}\n".repeat(50),
      readme: "old readme with } and ] and \\\" in it",
      scripts: { postinstall: "node install.js" },
      _npmUser: { name: "a" },
      deprecated: false,
      n: -1.5e3,
      t: true,
      z: null,
    },
    "1.1.0": { name: "pkg", version: "1.1.0", dist: { tarball: "https://registry.npmjs.org/pkg/-/pkg-1.1.0.tgz" }, bin: { pkg: "cli.js" }, readmeFilename: "README.md", "": "", __proto__x: 1 },
    "2.0.0-beta.1": { name: "pkg", version: "2.0.0-beta.1", dist: { tarball: "x" }, nested: { deep: [[[{ a: "}" }]]] } },
  },
};

describe("readPackument", () => {
  for (const chunk of [1, 3, 64, 1 << 20]) {
    test(`keeps exactly the fields it reads, in chunks of ${chunk} bytes`, async () => {
      const text = JSON.stringify(PACKUMENT, null, chunk % 2 === 0 ? 2 : undefined);
      const r = await readPackument(streamOf(text, chunk), LIMITS);

      expect(r.kind).toBe("ok");

      if (r.kind !== "ok") return;
      expect(r.body).toEqual(expected(PACKUMENT));
      expect(r.bytes).toBe(new TextEncoder().encode(text).length);
      // the license text was read past, never kept
      expect(r.keptBytes).toBeLessThan(text.length - 50 * 20);
    });
  }

  test("a key named __proto__ is an own property, not the prototype", async () => {
    const text = '{"name":"p","versions":{"1.0.0":{"name":"p","version":"1.0.0","__proto__":{"polluted":true},"dist":{"tarball":"t"}}}}';
    const r = await readPackument(streamOf(text, 5), LIMITS);

    expect(r.kind).toBe("ok");

    if (r.kind !== "ok") return;
    // read without a schema: zod rebuilds objects and drops a __proto__ key itself
    const v = Object.values(r.body.versions ?? {})[0];

    expect(Object.getPrototypeOf(v)).toBe(Object.prototype);
    expect(Object.keys(v ?? {})).toContain("__proto__");
    expect("polluted" in {}).toBe(false);
  });

  test("past the read cap it stops reading and says how far it got", async () => {
    const text = JSON.stringify({ name: "big", versions: {}, filler: "x".repeat(5_000) });
    const r = await readPackument(streamOf(text, 1000), { maxBytes: 2_000, maxKeptBytes: 1_000_000 });

    expect(r).toMatchObject({ kind: "too-large", over: "read", limit: 2_000 });
    // it stopped at the first chunk past the cap, not at the end
    expect(r.kind === "too-large" ? r.bytes : 0).toBe(3_000);
  });

  test("a packument that would keep more than the kept cap is refused, though dropped fields do not count", async () => {
    const versions = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`1.0.${i}`, { name: "big", version: `1.0.${i}`, dist: { tarball: "t" }, licenseText: "L".repeat(10_000) }]));
    const text = JSON.stringify({ name: "big", versions });

    // 200 KB of license text, all dropped: well under a 10 KB kept cap
    expect((await readPackument(streamOf(text, 4096), { maxBytes: 1_000_000, maxKeptBytes: 10_000 })).kind).toBe("ok");

    const kept = JSON.stringify({ name: "big", description: "D".repeat(20_000), versions });

    expect(await readPackument(streamOf(kept, 4096), { maxBytes: 1_000_000, maxKeptBytes: 10_000 })).toMatchObject({ kind: "too-large", over: "kept", limit: 10_000 });
  });

  for (const [what, text] of [
    ["an array", "[1,2]"],
    ["a truncated object", '{"name":"p","versions":{"1.0.0":{"name"'],
    ["two objects", '{"name":"p"}{"name":"q"}'],
    ["unbalanced brackets", '{"name":"p","versions":{"1.0.0":{]}}'],
    ["nothing", ""],
  ] as const) {
    test(`${what} is invalid`, async () => {
      expect((await readPackument(streamOf(text, 2), LIMITS)).kind).toBe("invalid");
    });
  }

  test("vite's shape: every version repeating a long licenseText keeps under a tenth of the bytes", async () => {
    const versions = Object.fromEntries(Array.from({ length: 200 }, (_, i) => [`5.${i}.0`, { name: "vite", version: `5.${i}.0`, dist: { tarball: "t", integrity: "sha512-AA==" }, dependencies: { esbuild: "^0.21.3" }, licenseText: "# Vite core license\n".repeat(2_300) }]));
    const text = JSON.stringify({ name: "vite", "dist-tags": { latest: "5.199.0" }, versions });
    const r = await readPackument(streamOf(text, 65_536), LIMITS);

    expect(r.kind).toBe("ok");

    if (r.kind !== "ok") return;
    expect(r.keptBytes / r.bytes).toBeLessThan(0.1);
    expect(r.body).toEqual(expected(JSON.parse(text)));
  });
});
