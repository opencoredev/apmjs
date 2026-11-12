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
    else if (t.length >= 4 && editDistance(bareName(name), bareName(t)) <= (t.length >= 8 ? 2 : 1)) rank += 10;
  }

  return rank;
}

export const searchPackages = (text: string): Effect.Effect<SearchHit[], StoreError, Store | Clock> =>
  Effect.gen(function* () {
    const store = yield* Store;
    const now = yield* (yield* Clock).now;
    const q = text.trim().toLowerCase();
    const terms = q.split(/\s+/).filter(Boolean);
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
