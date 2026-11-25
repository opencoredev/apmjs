// The OSSF feed's reads of one name's advisories (osv.ts advisoriesFor) are bounded: each MAL- id is read once, at most
// MAX_ADVISORIES of them across every page, a few at a time, and none past MAX_ADVISORY_BYTES. What is past a bound is
// not read, so the answer is partial: what was read still withholds its versions, and the answer is not kept, so the
// next request asks again. Reads that overlap spend the request's OSV budget once, not once each. OSV is a stand-in
// fetcher; no network and no database.
import { describe, expect, test } from "bun:test";
import { Effect } from "effect";
import { z } from "zod";
import { KnownMalicious, MAX_ADVISORIES, MAX_ADVISORY_BYTES, osvFeed, type Advisory } from "../src/osv.ts";

/** `pages`: the MAL- ids of each page of the name's answer, in order, duplicates kept. */
type Stand = { pages: string[][]; huge?: ReadonlySet<string>; readMs?: number };

const PageQuery = z.object({ queries: z.array(z.object({ page_token: z.string().optional() })) });

/** OSV for one name; each advisory names version 1.0.0. */
function standIn(name: string, stand: Stand) {
  const counts = { reads: new Map<string, number>(), inFlight: 0, maxInFlight: 0 };

  // SAFETY: osvFeed calls its fetcher only with a URL string and RequestInit, the call shape this stand-in reads
  const fetcher = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const path = new URL(String(input)).pathname;
    const read = /\/v1\/vulns\/(.+)$/.exec(path);

    if (!read?.[1]) {
      const page = Number(PageQuery.parse(JSON.parse(String(init?.body))).queries[0]?.page_token ?? "0");
      const next = page + 1 < stand.pages.length ? { next_page_token: String(page + 1) } : {};

      return Response.json({ results: [{ vulns: (stand.pages[page] ?? []).map((id) => ({ id, modified: "2026-11-24T00:00:00Z" })), ...next }] });
    }

    const id = decodeURIComponent(read[1]);

    counts.reads.set(id, (counts.reads.get(id) ?? 0) + 1);
    counts.inFlight++;
    counts.maxInFlight = Math.max(counts.maxInFlight, counts.inFlight);

    try {
      await Bun.sleep(stand.readMs ?? 5);

      return Response.json({ id, affected: [{ package: { name, ecosystem: "npm" }, versions: ["1.0.0"] }], details: stand.huge?.has(id) === true ? "x".repeat(MAX_ADVISORY_BYTES) : "" });
    } finally {
      counts.inFlight--;
    }
  }) as typeof fetch;

  const root = `https://osv.test/${crypto.randomUUID()}/`;
  const ask = (): Promise<readonly Advisory[]> => Effect.runPromise(Effect.flatMap(KnownMalicious, (k) => k.advisoriesFor(name)).pipe(Effect.provide(osvFeed(root, fetcher))));

  return { counts, ask };
}

const reads = (counts: { reads: Map<string, number> }): number => [...counts.reads.values()].reduce((a, b) => a + b, 0);

const idsFrom = (from: number, n: number): string[] => Array.from({ length: n }, (_, i) => `MAL-2026-${from + i}`);

describe("one name's advisory reads are bounded", () => {
  test("an id the answer lists twice is read once, and the answer is complete and kept", async () => {
    const s = standIn("twice-listed", { pages: [["MAL-2026-1", "MAL-2026-1", "MAL-2026-2"]] });

    expect((await s.ask()).map((a) => a.id)).toEqual(["MAL-2026-1", "MAL-2026-2"]);
    expect([...s.counts.reads.values()]).toEqual([1, 1]);
    // kept: the next request reads nothing
    expect((await s.ask()).map((a) => a.id)).toEqual(["MAL-2026-1", "MAL-2026-2"]);
    expect(reads(s.counts)).toBe(2);
  });

  test("past MAX_ADVISORIES ids, only that many are read, a few at a time; what was read withholds, and the partial answer is not kept", async () => {
    const ids = idsFrom(1000, MAX_ADVISORIES + 36);
    const s = standIn("many-listed", { pages: [ids] });
    const first = await s.ask();

    expect(first.map((a) => a.id)).toEqual(ids.slice(0, MAX_ADVISORIES));
    expect(first.every((a) => a.versions.includes("1.0.0"))).toBe(true);
    expect(reads(s.counts)).toBe(MAX_ADVISORIES);
    expect(s.counts.maxInFlight).toBeLessThanOrEqual(8);
    // not kept: the next request asks OSV again
    await s.ask();
    expect(reads(s.counts)).toBe(2 * MAX_ADVISORIES);
  });

  test("MAX_ADVISORIES counts every page: an id a later page repeats is not read again, and the reads stop at the bound", async () => {
    const s = standIn("paged-listed", { pages: [idsFrom(2000, 40), [...idsFrom(2000, 5), ...idsFrom(3000, 40)]] });
    const got = await s.ask();

    expect(reads(s.counts)).toBe(MAX_ADVISORIES);
    expect([...s.counts.reads.values()].every((n) => n === 1)).toBe(true);
    expect(got.map((a) => a.id)).toEqual([...idsFrom(2000, 40), ...idsFrom(3000, MAX_ADVISORIES - 40)]);
  });

  test("an advisory over MAX_ADVISORY_BYTES is not read; the other one still withholds, and the partial answer is not kept", async () => {
    const s = standIn("one-huge", { pages: [["MAL-2026-7", "MAL-2026-8"]], huge: new Set(["MAL-2026-8"]) });

    expect((await s.ask()).map((a) => a.id)).toEqual(["MAL-2026-7"]);
    await s.ask();
    expect(s.counts.reads.get("MAL-2026-7")).toBe(2);
  });

  // Sol on c4a535c: reads that overlap were each charged their whole wait, so two rounds of slow reads spent the budget
  test("reads that overlap spend the budget once: 16 advisories of 650 ms each, two rounds, are all read", async () => {
    const ids = idsFrom(4000, 16);
    const s = standIn("slow-listed", { pages: [ids], readMs: 650 });

    expect((await s.ask()).map((a) => a.id)).toEqual(ids);
    expect(s.counts.maxInFlight).toBe(8);
  });
});
