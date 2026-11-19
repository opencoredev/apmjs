// Which versions a look at a package queues besides `latest` (analysis.ts, versionsToSeed): every version a dist-tag
// names and every one published in the last RECENT_SEED_MS, newest first, at most SEED_PER_PACKAGE, none with a stored
// result and none withheld. tests/acceptance/version-seeding.test.ts drives the page and the cron through it.
import { describe, expect, test } from "bun:test";
import { Effect } from "effect";
import { analyze } from "@apm/core";
import { hasResult, RECENT_SEED_MS, SEED_PER_PACKAGE, versionsToSeed } from "../src/analysis.ts";
import type { VersionRecord } from "../src/db.ts";
import { freshSeedingState, SEED_AGAIN_MS, Seeding, SEEDS_RUNNING_MAX, type SeedInput } from "../src/seeding.ts";

const DAY = 86_400_000;
const NOW = Date.parse("2026-11-18T12:00:00Z");

function version(v: string, ago: number, change: Partial<VersionRecord> = {}): VersionRecord {
  return { package: "pkg", version: v, manifest: {}, shasum: "", integrity: "", size: 0, tarball_key: "", published_at: NOW - ago, seq: 0, published_by: "someone", deprecated: null, status: "active", status_reason: null, status_at: null, status_by: null, score: null, ...change };
}

const scored = analyze({ name: "pkg", manifest: { name: "pkg", version: "1.0.0" }, files: [], publisher: "someone", previousPublishers: [] });

describe("versionsToSeed", () => {
  test("typescript's shape: the nightly line under `next` and the older tagged versions, not latest or an old untagged one", () => {
    const versions = [
      version("3.9.4", 2000 * DAY),
      version("5.0.0", 900 * DAY),
      version("7.0.1-rc", 60 * DAY),
      version("7.0.2", 30 * DAY),
      ...[14, 15, 16, 17, 18].map((d) => version(`7.1.0-dev.202611${d}.1`, (18 - d) * DAY + DAY / 6)),
    ];

    const distTags = { latest: "7.0.2", next: "7.1.0-dev.20261118.1", rc: "7.0.1-rc", dev: "3.9.4" };

    expect(versionsToSeed({ versions, distTags, now: NOW, done: hasResult })).toEqual(["7.1.0-dev.20261118.1", "7.1.0-dev.20261117.1", "7.1.0-dev.20261116.1", "7.1.0-dev.20261115.1", "7.1.0-dev.20261114.1", "7.0.1-rc", "3.9.4"]);
  });

  test("a version with a score, one apm cannot score, and a withheld one are not queued again", () => {
    const versions = [
      version("1.0.0", 1 * DAY, { score: scored }),
      version("1.0.1", 1 * DAY, { unscorable: { reason: "unreadable", detail: "x", digest: null } }),
      version("1.0.2", 1 * DAY, { status: "revoked" }),
      version("1.0.3", 1 * DAY, { status: "revoke-pending" }),
      version("1.0.4", 1 * DAY, { status: "yanked" }),
    ];

    expect(versionsToSeed({ versions, distTags: { latest: "9.9.9" }, now: NOW, done: hasResult })).toEqual(["1.0.4"]);
  });

  test("at most SEED_PER_PACKAGE, newest first; the window's edge counts", () => {
    const versions = Array.from({ length: 20 }, (_, i) => version(`0.0.${i}`, i * 60 * 60_000));

    expect(versionsToSeed({ versions, distTags: {}, now: NOW, done: hasResult })).toEqual(versions.slice(0, SEED_PER_PACKAGE).map((v) => v.version));
    expect(versionsToSeed({ versions: [version("1.0.0", RECENT_SEED_MS), version("1.0.1", RECENT_SEED_MS + 1)], distTags: {}, now: NOW, done: hasResult })).toEqual(["1.0.0"]);
  });
});

// review of 2022f3d, P2: the page awaited its seeding (up to 8 s of database wait or 4 s of queue wait) and nothing
// bounded it across packages. A look now hands its versions over and returns; the work runs after the answer.
describe("a page's seeding runs after the answer, bounded", () => {
  const layerWith = (run: (input: SeedInput) => Promise<void>, opts: { now?: () => number; deadlineMs?: number } = {}) => {
    const kept: Promise<void>[] = [];
    const state = freshSeedingState();
    const layer = Seeding.layer({ background: (w) => void kept.push(w), run, now: opts.now ?? (() => NOW), deadlineMs: opts.deadlineMs, state });
    const look = (name: string, versions: readonly string[]) => Effect.runPromise(Effect.flatMap(Seeding, (s) => s.look({ name, versions })).pipe(Effect.provide(layer)));

    return { kept, look, state };
  };

  test("a look returns at once, whatever its work waits on, and the work is kept alive after it", async () => {
    let release = (): void => undefined;
    const started: string[] = [];

    const { kept, look } = layerWith((input) => {
      started.push(input.name);

      return new Promise<void>((resolve) => (release = resolve));
    });

    // on 2022f3d the answer waited on this: here the look is done before the work is
    expect(await look("typescript", ["7.1.0-dev.20261117.1"])).toBe("seeded");
    expect(started).toEqual(["typescript"]);
    expect(kept.length).toBe(1);
    release();
    await Promise.all(kept);
  });

  test("its work is aborted at its deadline", async () => {
    let aborted = false;
    const { kept, look } = layerWith((input) => new Promise<void>((resolve) => input.signal.addEventListener("abort", () => ((aborted = true), resolve()))), { deadlineMs: 20 });

    await look("next", ["16.5.0-canary.54"]);
    await Promise.all(kept);
    expect(aborted).toBe(true);
  });

  test("at most SEEDS_RUNNING_MAX run at once in an isolate, and a package is seeded once per SEED_AGAIN_MS", async () => {
    let at = NOW;
    const releases: (() => void)[] = [];
    const { kept, look } = layerWith(() => new Promise<void>((resolve) => releases.push(resolve)), { now: () => at });
    const outcomes = [];

    for (let i = 0; i < SEEDS_RUNNING_MAX + 2; i++) outcomes.push(await look(`pkg-${i}`, ["1.0.0"]));

    expect(outcomes).toEqual([...Array.from({ length: SEEDS_RUNNING_MAX }, () => "seeded"), "skipped", "skipped"]);

    for (const r of releases) r();
    await Promise.all(kept);
    // pkg-0 again: within SEED_AGAIN_MS it is left alone, after it it is seeded again
    expect(await look("pkg-0", ["1.0.0"])).toBe("skipped");
    at += SEED_AGAIN_MS + 1;
    expect(await look("pkg-0", ["1.0.0"])).toBe("seeded");

    for (const r of releases) r();
    await Promise.all(kept);
  });

  test("nothing to seed, nothing run", async () => {
    const { kept, look } = layerWith(() => Promise.resolve());

    expect(await look("pkg", [])).toBe("skipped");
    expect(kept).toEqual([]);
  });
});
