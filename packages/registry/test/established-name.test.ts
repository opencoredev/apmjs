// npm's record of an upstream package's name reaches its score where the score is worked out (reportFor), so a
// look-alike name npm has listed for years (safer-buffer, which express installs) neither costs points nor holds an
// install, with no stored analysis read again; a new look-alike still holds. The record rides each version record
// through every path a version takes: the packument read, a resolve's kept choices and a page's kept summary.
import { describe, expect, test } from "bun:test";
import { analyze, riskSignalsIn, type TarEntry } from "@apm/core";
import { reportFor } from "../src/apm.ts";
import { KeptChoices, type VersionRecord } from "../src/db.ts";
import { digestLabel, digestOf } from "../src/digest.ts";
import { expand, summarize } from "../src/kept-package.ts";
import { cachedPackage, scoredPackage, type CachedPackage } from "../src/upstream.ts";

const DAY = 24 * 60 * 60_000;
const NOW = Date.UTC(2026, 10, 18);

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

const manifest = { name: "safer-buffer", version: "2.1.2", license: "MIT", main: "safer.js" };

// one edit from safe-buffer: the look-alike rule flags it
const analysis = analyze({ name: "safer-buffer", manifest, files: [entry("package.json", JSON.stringify(manifest)), entry("safer.js", "module.exports = require('buffer');\n")], publisher: "a", previousPublishers: [] });

/** A packument for safer-buffer with versions published `ago` days before NOW, the last one 2.1.2. */
function packument(ago: readonly number[]): CachedPackage {
  const numbers = ago.map((_, i) => (i === ago.length - 1 ? "2.1.2" : `2.0.${i}`));

  const integrity = (i: number): string => `sha512-${Buffer.alloc(64, i + 1).toString("base64")}`;

  const body = {
    name: "safer-buffer",
    "dist-tags": { latest: "2.1.2" },
    versions: Object.fromEntries(numbers.map((v, i) => [v, { name: "safer-buffer", version: v, dist: { tarball: `https://registry.npmjs.org/safer-buffer/-/safer-buffer-${v}.tgz`, integrity: integrity(i) } }])),
    time: Object.fromEntries(numbers.map((v, i) => [v, new Date(NOW - (ago[i] ?? 0) * DAY).toISOString()])),
  };

  const pkg = cachedPackage("safer-buffer", body, { versionDocs: 0, maxPieceChars: 0 }, null);

  if (pkg === null) throw new Error("not a packument");

  return pkg;
}

/** 2.1.2 as the registry scores it, its stored analysis attached the way the store attaches it. */
function latest(pkg: CachedPackage): VersionRecord {
  const v = pkg.versions.find((x) => x.version === "2.1.2");
  const d = v ? digestOf(v) : null;

  if (!v || !d) throw new Error("no 2.1.2");
  const probe = scoredPackage(pkg, { scores: new Map([[`2.1.2 ${digestLabel(d)}`, analysis]]), unscorable: new Map() });

  if (probe.kind !== "found") throw new Error("not found");
  const scored = probe.pkg.versions.find((x) => x.version === "2.1.2");

  if (!scored) throw new Error("not scored");

  return scored;
}

// safer-buffer's own record: 2.0.0 on 2018-03-19 to 2.1.2 on 2018-04-08
const OLD = [3166, 3165, 3160, 3155, 3150, 3149, 3146];

describe("a look-alike name npm has listed for years", () => {
  test("costs nothing and is no risk, read from npm's version times when the score is worked out", () => {
    const r = reportFor(latest(packument(OLD)), NOW, { ignoreRecent: true });

    expect(r?.signals.find((s) => s.id === "typosquat")?.points).toBe(0);
    expect(r && riskSignalsIn(r)).toEqual([]);
    expect(r?.score).toBe(100);
  });

  test("a new look-alike of the same name still holds", () => {
    const r = reportFor(latest(packument([40, 30, 20, 10, 5, 3, 2])), NOW, { ignoreRecent: true });

    expect(r?.signals.find((s) => s.id === "typosquat")?.points).toBe(-20);
    expect(r && riskSignalsIn(r).map((s) => s.id)).toEqual(["typosquat"]);
  });

  test("the record survives a resolve's kept choice and a page's kept summary", () => {
    const pkg = packument(OLD);
    const record = pkg.versions.find((v) => v.version === "2.1.2");

    expect(record?.history).toEqual({ first: NOW - 3166 * DAY, fifth: NOW - 3150 * DAY });
    // upstream_choices stores records as JSON and parses them back with KeptChoices
    const stored = KeptChoices.parse(JSON.parse(JSON.stringify({ distTags: pkg.distTags, lists: {}, records: { "2.1.2": record } })));

    expect(stored.records["2.1.2"]?.history).toEqual(record?.history);
    const kept = summarize(pkg);

    expect(kept && pageRoundTrip(kept)).toEqual(record?.history);
  });
});

/** A page's summary as Postgres keeps it (JSON), expanded back into records: the history its records carry. */
function pageRoundTrip(kept: NonNullable<ReturnType<typeof summarize>>) {
  const back = expand(JSON.parse(JSON.stringify(kept)));

  return back.versions.find((v) => v.version === "2.1.2")?.history;
}
