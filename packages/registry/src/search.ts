// Search over the packages published here: ranking by name, description and keywords, with a withheld version's
// text left out (withheld.ts). Store reads only, so it can be tested against a database without the Worker.
import { Effect } from "effect";
import { editDistance } from "@apm/core";
import { Clock } from "./clock.ts";
import { Store, type PackageRecord, type VersionRecord } from "./db.ts";
import type { StoreError } from "./errors.ts";
import { atTime } from "./lifecycle.ts";
import { packageTextShown } from "./withheld.ts";

export type SearchHit = { pkg: PackageRecord; latest: VersionRecord; rank: number; owners: string[] };

/** The most distinct words of a search that are ranked. */
export const MAX_SEARCH_TERMS = 16;

function bareName(name: string): string {
  return name.startsWith("@") ? name.slice(name.indexOf("/") + 1) : name;
}

function rankOf(pkg: PackageRecord, terms: string[]): number {
  const name = pkg.name;
  const hay = `${name} ${pkg.description} ${pkg.keywords.join(" ")}`.toLowerCase();
  let rank = 0;

  if (terms.length === 0) rank = 1;

  for (const t of terms) {
    if (name === t) rank += 100;
    else if (name.startsWith(t)) rank += 40;
    else if (name.includes(t)) rank += 25;
    else if (pkg.keywords.some((k) => k.toLowerCase() === t)) rank += 15;
    else if (hay.includes(t)) rank += 5;
    // A misspelled name still finds the package: one edit away for short names, two for long ones.
    else if (t.length >= 4 && withinEdits(bareName(name), bareName(t), t.length >= 8 ? 2 : 1)) rank += 10;
  }

  return rank;
}

/**
 * Whether `a` and `b` are at most `max` edits apart. Two strings whose lengths differ by more than `max` never are,
 * and editDistance costs the product of their lengths: a 12 000-character search term took 2 s against 100 packages.
 */
function withinEdits(a: string, b: string, max: number): boolean {
  return Math.abs(a.length - b.length) <= max && editDistance(a, b) <= max;
}

export const searchPackages = (text: string): Effect.Effect<SearchHit[], StoreError, Store | Clock> =>
  Effect.gen(function* () {
    const store = yield* Store;
    const now = yield* (yield* Clock).now;
    const q = text.trim().toLowerCase();
    // ranking costs each term against every package: past MAX_SEARCH_TERMS distinct terms the rest are not ranked, or
    // a query of 500 name-length words took 1.8 s against 100 packages
    const terms = [...new Set(q.split(/\s+/).filter(Boolean))].slice(0, MAX_SEARCH_TERMS);
    // a package with a withheld version is ranked, and shown, by the text its shown versions wrote (withheld.ts)
    // one query for every such package's versions, however many there are: their description and keywords only
    const withheld = yield* store.withheldPackageText();

    const packages = (yield* store.listPackages()).map((pkg): PackageRecord => {
      const versions = withheld.get(pkg.name);

      return versions ? { ...pkg, ...packageTextShown(pkg, versions.map((v) => atTime(v, now))) } : pkg;
    });

    const ranked = packages.flatMap((pkg) => {
      const rank = rankOf(pkg, terms);

      return rank > 0 ? [{ pkg, rank }] : [];
    });

    const names = ranked.map((h) => h.pkg.name);
    const active = (yield* store.activeVersionsOf(names)).map((v) => atTime(v, now)).filter((v) => v.status === "active");
    const owners = yield* store.ownersOf(names);
    const byPackage = new Map<string, VersionRecord[]>();

    for (const v of active) byPackage.set(v.package, [...(byPackage.get(v.package) ?? []), v]);
    const hits: SearchHit[] = [];

    for (const { pkg, rank } of ranked) {
      const live = byPackage.get(pkg.name) ?? [];
      const latest = live.find((v) => v.version === pkg.distTags.latest) ?? live[live.length - 1];

      if (!latest) continue;
      hits.push({ pkg, latest, rank, owners: owners.get(pkg.name) ?? [] });
    }

    hits.sort((a, b) => b.rank - a.rank || a.pkg.name.localeCompare(b.pkg.name));

    return hits;
  });
