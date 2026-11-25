// The OSSF feed's reads of one name's advisories (osv.ts advisoriesFor) are bounded: each MAL- id is read once, at most
// MAX_ADVISORIES of them, a few at a time, and none past MAX_ADVISORY_BYTES. What is past a bound is not read, so the
// answer is partial: what was read still withholds its versions, and the answer is not kept, so the next request asks
// again. OSV is a stand-in fetcher; no network and no database.
import { describe, expect, test } from "bun:test";
import { Effect } from "effect";
import { KnownMalicious, MAX_ADVISORIES, MAX_ADVISORY_BYTES, osvFeed, type Advisory } from "../src/osv.ts";

type Stand = { ids: string[]; huge?: ReadonlySet<string> };

/** OSV for one name: the batch answer lists `ids` (in that order, duplicates kept); each advisory names version 1.0.0. */
function standIn(name: string, stand: Stand) {
  const counts = { reads: new Map<string, number>(), inFlight: 0, maxInFlight: 0 };

  // SAFETY: osvFeed calls its fetcher only with a URL string and RequestInit, the call shape this stand-in reads
  const fetcher = (async (input: RequestInfo | URL): Promise<Response> => {
    const path = new URL(String(input)).pathname;
    const read = /\/v1\/vulns\/(.+)$/.exec(path);

    if (!read?.[1]) return Response.json({ results: [{ vulns: stand.ids.map((id) => ({ id, modified: "2026-11-24T00:00:00Z" })) }] });
    const id = decodeURIComponent(read[1]);

    counts.reads.set(id, (counts.reads.get(id) ?? 0) + 1);
    counts.inFlight++;
    counts.maxInFlight = Math.max(counts.maxInFlight, counts.inFlight);

    try {
      await Bun.sleep(5);
      const body = { id, affected: [{ package: { name, ecosystem: "npm" }, versions: ["1.0.0"] }], details: stand.huge?.has(id) === true ? "x".repeat(MAX_ADVISORY_BYTES) : "" };

      return Response.json(body);
    } finally {
      counts.inFlight--;
    }
  }) as typeof fetch;

  const root = `https://osv.test/${crypto.randomUUID()}/`;
  const ask = (): Promise<readonly Advisory[]> => Effect.runPromise(Effect.flatMap(KnownMalicious, (k) => k.advisoriesFor(name)).pipe(Effect.provide(osvFeed(root, fetcher))));

  return { counts, ask };
}

const reads = (counts: { reads: Map<string, number> }): number => [...counts.reads.values()].reduce((a, b) => a + b, 0);

describe("one name's advisory reads are bounded", () => {
  test("an id the answer lists twice is read once, and the answer is complete and kept", async () => {
    const s = standIn("twice-listed", { ids: ["MAL-2026-1", "MAL-2026-1", "MAL-2026-2"] });

    expect((await s.ask()).map((a) => a.id)).toEqual(["MAL-2026-1", "MAL-2026-2"]);
    expect([...s.counts.reads.values()]).toEqual([1, 1]);
    // kept: the next request reads nothing
    expect((await s.ask()).map((a) => a.id)).toEqual(["MAL-2026-1", "MAL-2026-2"]);
    expect(reads(s.counts)).toBe(2);
  });

  test("past MAX_ADVISORIES ids, only that many are read, a few at a time; what was read withholds, and the partial answer is not kept", async () => {
    const ids = Array.from({ length: MAX_ADVISORIES + 36 }, (_, i) => `MAL-2026-${1000 + i}`);
    const s = standIn("many-listed", { ids });
    const first = await s.ask();

    expect(first.map((a) => a.id)).toEqual(ids.slice(0, MAX_ADVISORIES));
    expect(first.every((a) => a.versions.includes("1.0.0"))).toBe(true);
    expect(reads(s.counts)).toBe(MAX_ADVISORIES);
    expect(s.counts.maxInFlight).toBeLessThanOrEqual(8);
    // not kept: the next request asks OSV again
    await s.ask();
    expect(reads(s.counts)).toBe(2 * MAX_ADVISORIES);
  });

  test("an advisory over MAX_ADVISORY_BYTES is not read; the other one still withholds, and the partial answer is not kept", async () => {
    const s = standIn("one-huge", { ids: ["MAL-2026-7", "MAL-2026-8"], huge: new Set(["MAL-2026-8"]) });

    expect((await s.ask()).map((a) => a.id)).toEqual(["MAL-2026-7"]);
    await s.ask();
    expect(s.counts.reads.get("MAL-2026-7")).toBe(2);
  });
});
