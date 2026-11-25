// What the isolate keeps of names' OSV advisories, and the data center's copies of them, under memory budgets (osv.ts:
// keep, answerOf, sharedRead, sharedWrite). From Sol's review of c752a16: a copy the request had no room to read was taken
// for none, so a name OSV could not be asked about was served as unlisted; a name whose advisories did not fit lost its
// newest stamp, so an older answer landing after it undid it; the kept advisories shared npm's cache lease and limit; a
// read past its deadline gave its room back while it still read, and a request answered from kept advisories held no
// charge for them; copies waiting to be written queued without bound. OSV is a stand-in fetcher, the data center's cache
// a stand-in on globalThis.caches; no network and no database.
import { afterEach, describe, expect, setSystemTime, test } from "bun:test";
import { Effect, Fiber, Layer } from "effect";
import { z } from "zod";
import { ISOLATE_POOL, type Lease, RequestMemory } from "../src/memory.ts";
import { KnownMalicious, listedAmong, listedNotice, listedTarballText, maliciousText, NAME_FRESH_MS, osvFeed, type Advisory } from "../src/osv.ts";

const X = "MAL-2026-90001";
const VERSIONS = ["1.0.0", "2.0.0"];

/**
 * OSV for one name: each query answers the ids its `answers` entry gives (shifted, the last kept), each advisory naming
 * `versions` (1.0.0); with `down`, every call is a 503; with `stalled`, an advisory's body never ends.
 */
function osv(name: string) {
  const answers: (() => Promise<string[]>)[] = [];
  const ids: string[] = [];
  const stand = { down: false, answers, ids, queries: 0, versions: ["1.0.0"], stalled: false, cancels: 0 };

  // SAFETY: osvFeed calls its fetcher only with a URL string and RequestInit, the call shape this stand-in reads
  const fetcher = (async (input: string | URL): Promise<Response> => {
    if (stand.down) return new Response("unavailable", { status: 503 });
    const read = /\/v1\/vulns\/(.+)$/.exec(new URL(String(input)).pathname);

    if (read?.[1] !== undefined) {
      const id = decodeURIComponent(read[1]);

      if (!stand.stalled) return Response.json({ id, affected: [{ package: { name, ecosystem: "npm" }, versions: stand.versions }] });

      // a detail whose body starts and never ends
      return new Response(
        new ReadableStream<Uint8Array>({
          start: (c) => c.enqueue(new TextEncoder().encode('{"id":')),
          cancel: () => {
            stand.cancels++;
          },
        }),
      );
    }

    stand.queries++;
    const next = stand.answers.shift();
    const ids = next === undefined ? stand.ids : await next();

    return Response.json({ results: [{ vulns: ids.map((id) => ({ id, modified: "2026-11-24T00:00:00Z" })) }] });
  }) as typeof fetch;

  const root = `https://osv.test/${crypto.randomUUID()}/`;

  const lookup = (lease?: Lease) => Effect.flatMap(KnownMalicious, (k) => k.advisoriesFor(name)).pipe(Effect.provide(Layer.merge(osvFeed(root, fetcher), lease === undefined ? Layer.empty : Layer.succeed(RequestMemory, lease))));
  const ask = (lease?: Lease): Promise<readonly Advisory[]> => Effect.runPromise(lookup(lease));

  return { stand, ask, lookup, copyUrl: `https://osv-cache.apmjs.internal/v2/${encodeURIComponent(`${root} ${name}`)}` };
}

/** The data center's cache, standing in: `copy` answers a read of a URL, after `matchMs`; `put` takes a write. */
function sharedCache(input: { copy: (url: string) => Response | undefined; put?: (url: string, res: Response) => Promise<void>; matchMs?: number }) {
  const cache = {
    match: async (key: Request) => {
      if (input.matchMs !== undefined) await Bun.sleep(input.matchMs);

      return input.copy(key.url);
    },
    put: async (key: Request, res: Response) => input.put?.(key.url, res),
  };

  Object.defineProperty(globalThis, "caches", { value: { default: cache }, configurable: true });
}

afterEach(() => {
  Reflect.deleteProperty(globalThis, "caches");
  setSystemTime();
});

const listed = (name: string, advisories: readonly Advisory[]): string[] => [...listedAmong(name, advisories, VERSIONS).keys()].toSorted();

describe("OSV advisories under memory budgets", () => {
  test("a copy the request has no room to read, or past the read's cap, withholds every version while OSV is down", async () => {
    for (const kind of ["no room", "too large"] as const) {
      const name = kind === "no room" ? "copy-no-room" : "copy-too-large";
      const o = osv(name);
      // older than NAME_FRESH_MS, so OSV is asked after it
      const fetchedAt = Date.now() - NAME_FRESH_MS - 60_000;
      const versions = kind === "too large" ? Array.from({ length: 120_000 }, (_, i) => `1.0.${i}`) : ["1.0.0"];

      sharedCache({ copy: (url) => (url === o.copyUrl ? Response.json({ fetchedAt, advisories: [{ id: X, versions, ranges: [] }] }) : undefined) });
      o.stand.down = true;
      const lease = ISOLATE_POOL.request();

      try {
        if (kind === "no room") expect(lease.take(lease.headroom - 64 * 1024)).toBe(true);
        // on c752a16: [], read as no copy, so served as unlisted
        expect(listed(name, await o.ask(lease))).toEqual(VERSIONS);
      } finally {
        lease.release();
      }
    }

    // a copy read whole is used as ever: only what it names
    const o = osv("copy-read");

    sharedCache({ copy: (url) => (url === o.copyUrl ? Response.json({ fetchedAt: Date.now() - NAME_FRESH_MS - 60_000, advisories: [{ id: X, versions: ["1.0.0"], ranges: [] }] }) : undefined) });
    o.stand.down = true;
    const lease = ISOLATE_POOL.request();

    try {
      expect(listed("copy-read", await o.ask(lease))).toEqual(["1.0.0"]);
    } finally {
      lease.release();
    }
  });

  test("a name whose advisories do not fit keeps its newest answer's order: an older answer landing after it does not undo it", async () => {
    const o = osv("no-fit");
    const gate = Promise.withResolvers<void>();
    const queried = Promise.withResolvers<void>();

    o.stand.answers.push(async () => {
      queried.resolve();
      await gate.promise;

      return [];
    });
    o.stand.ids = [X];
    // the pool has no room left, so nothing the isolate keeps of the name fits
    const hog = ISOLATE_POOL.request(Number.POSITIVE_INFINITY);

    try {
      expect(hog.take(ISOLATE_POOL.unused)).toBe(true);
      const older = o.ask();

      await queried.promise;
      expect(listed("no-fit", await o.ask())).toContain("1.0.0");
      gate.resolve();
      // on c752a16: [], the older empty answer's, as the newer one was not kept
      expect(listed("no-fit", await older)).toContain("1.0.0");
    } finally {
      gate.resolve();
      hog.release();
    }
  });

  test("the advisories the isolate keeps are charged to a lease of their own, never npm's cache", async () => {
    const o = osv("own-lease");

    o.stand.ids = [X];
    const cache = ISOLATE_POOL.cache();
    const before = { cache: cache.taken, pool: ISOLATE_POOL.charged };
    const lease = ISOLATE_POOL.request();

    try {
      expect(listed("own-lease", await o.ask(lease))).toEqual(["1.0.0"]);
    } finally {
      lease.release();
    }

    // on c752a16: charged to the npm cache's lease, whose limit the first to open it set
    expect(cache.taken).toBe(before.cache);
    expect(ISOLATE_POOL.charged).toBeGreaterThan(before.pool);
  });

  test("a request answered from what the isolate keeps holds its charge while it refers to it", async () => {
    const o = osv("held-answer");

    o.stand.ids = [X];
    const first = ISOLATE_POOL.request();

    try {
      await o.ask(first);
    } finally {
      first.release();
    }

    const second = ISOLATE_POOL.request();

    try {
      expect(listed("held-answer", await o.ask(second))).toEqual(["1.0.0"]);
      // fresh: OSV was asked once; on c752a16 the second request held nothing of what it answered with
      expect(o.stand.queries).toBe(1);
      expect(second.taken).toBeGreaterThan(0);
    } finally {
      second.release();
    }
  });

  test("a copy whose read passes its deadline is cancelled, and its room held until the read has ended", async () => {
    const o = osv("stalled-copy");
    let cancels = 0;

    sharedCache({
      copy: (url) =>
        url === o.copyUrl
          ? new Response(
              new ReadableStream<Uint8Array>({
                start: (c) => c.enqueue(new TextEncoder().encode('{"fetchedAt":')),
                cancel: () => {
                  cancels++;
                },
              }),
            )
          : undefined,
    });
    const lease = ISOLATE_POOL.request();

    try {
      // OSV answers: the copy that could not be read stands for nothing then
      expect(await o.ask(lease)).toEqual([]);
      await Bun.sleep(10);
      // on c752a16: 0, the stream left open after its room was given back
      expect(cancels).toBe(1);
      expect(lease.taken).toBe(0);
    } finally {
      lease.release();
    }
  });

  test("copies waiting on a put that has not ended are charged and coalesced: only the newest is written after it", async () => {
    const o = osv("slow-put");

    o.stand.ids = [X];
    const gate = Promise.withResolvers<void>();
    const puts: number[] = [];

    sharedCache({
      copy: () => undefined,
      put: async (_url, res) => {
        puts.push(z.object({ fetchedAt: z.number() }).parse(await res.json()).fetchedAt);

        if (puts.length === 1) await gate.promise;
      },
    });
    const t = Date.now();

    for (const at of [t, t + NAME_FRESH_MS + 1_000, t + 2 * (NAME_FRESH_MS + 1_000)]) {
      setSystemTime(at);
      await o.ask();
    }

    expect(o.stand.queries).toBe(3);
    const waiting = ISOLATE_POOL.charged;

    gate.resolve();
    await Bun.sleep(20);
    expect(puts).toEqual([t, t + 2 * (NAME_FRESH_MS + 1_000)]);
    // the copy being written and the one waiting were charged until written; on c752a16 neither was
    expect(ISOLATE_POOL.charged).toBeLessThan(waiting);
  });

  // Sol on dd47451: a lookup past its deadline was read as no copy
  test("a copy whose lookup passes its deadline withholds every version while OSV is down", async () => {
    const o = osv("late-lookup");

    sharedCache({ copy: (url) => (url === o.copyUrl ? Response.json({ fetchedAt: Date.now() - NAME_FRESH_MS - 60_000, advisories: [{ id: X, versions: ["1.0.0"], ranges: [] }] }) : undefined), matchMs: 300 });
    o.stand.down = true;
    // on dd47451: [], served as unlisted
    expect(listed("late-lookup", await o.ask())).toEqual(VERSIONS);
  });

  // Sol on dd47451: the read's room was given back before what it read was parsed
  test("a copy read keeps its room until what it read is parsed", async () => {
    const o = osv("handoff");

    sharedCache({ copy: (url) => (url === o.copyUrl ? Response.json({ fetchedAt: Date.now() - 1_000, advisories: [{ id: X, versions: ["1.0.0"], ranges: [] }] }) : undefined) });
    const lease = ISOLATE_POOL.request();

    try {
      expect(listed("handoff", await o.ask(lease))).toEqual(["1.0.0"]);
      // the read's room (1 MiB, twice) and the parse at once; on dd47451 only the read's
      expect(lease.peakTaken).toBeGreaterThan(2 * 1024 * 1024);
    } finally {
      lease.release();
    }
  });

  // Sol on dd47451: a hold read as the feed listing the version, linking to no advisory
  test("a version only apm's hold withholds is said not to be checked, never listed by the feed", () => {
    const held = { name: "held-pkg", version: "1.0.0", ids: ["APM-OSV-COPY-UNREAD"] };

    expect(maliciousText(held)).toStartWith("not checked:");
    expect(listedTarballText(held)).not.toContain("osv.dev");
    expect(listedNotice("held-pkg", [{ id: "APM-OSV-COPY-UNREAD", versions: [], ranges: [[{ introduced: "0" }]], every: true }])).toContain("could not check");
    // a real advisory beside it is still cited
    expect(maliciousText({ ...held, ids: [X, "APM-OSV-HELD"] })).toBe(`known malicious: the OSSF malicious-packages feed lists held-pkg@1.0.0 (${X})`);
  });

  // Sol on 18281c9: interrupting the lookup gave an advisory read's room back while its stream stayed open
  test("an advisory read stopped by its lookup's interruption is cancelled, and keeps its room until it has ended", async () => {
    const o = osv("interrupted-read");

    o.stand.ids = [X];
    o.stand.stalled = true;
    const lease = ISOLATE_POOL.request();

    try {
      const fiber = Effect.runFork(o.lookup(lease));

      await Bun.sleep(50);
      await Effect.runPromise(Fiber.interrupt(fiber));
      await Bun.sleep(10);
      // on 18281c9: 0, the stream left open after the room was given back
      expect(o.stand.cancels).toBe(1);
      expect(lease.taken).toBe(0);
    } finally {
      lease.release();
    }
  });

  // Sol on 18281c9: a name that could never fit shed every other name first
  test("a name whose observations could never fit is held alone: other names keep what they name", async () => {
    const kept = osv("kept-small");

    kept.stand.ids = [X];
    expect(listed("kept-small", await kept.ask())).toEqual(["1.0.0"]);
    const huge = osv("never-fits");

    huge.stand.ids = [X];
    // about 150 kB of versions: past the names' 2 MiB once weighed as parsed
    huge.stand.versions = Array.from({ length: 12_000 }, (_, i) => `1.0.${i}`);
    const lease = ISOLATE_POOL.request();

    try {
      expect(listed("never-fits", await huge.ask(lease))).toEqual(VERSIONS);
    } finally {
      lease.release();
    }

    // past NAME_FRESH_MS with OSV down: what was kept of the other name answers
    setSystemTime(Date.now() + NAME_FRESH_MS + 1_000);
    kept.stand.down = true;
    // on 18281c9: both, the other name shed and held whole
    expect(listed("kept-small", await kept.ask())).toEqual(["1.0.0"]);
  });

  // Sol on 18281c9: an advisory withheld unread was cited as the feed listing the version
  test("a version only an advisory withheld unread names is said not to be checked", () => {
    const m = listedAmong("unread-advisory", [{ id: X, versions: [], ranges: [[{ introduced: "0" }]], every: true }], ["1.0.0"]).get("1.0.0");

    expect(m?.ids).toEqual([X]);
    // on 18281c9: "known malicious: the OSSF malicious-packages feed lists ..."
    expect(m === undefined ? "" : maliciousText(m)).toStartWith("not checked:");
    expect(m === undefined ? "" : listedTarballText(m)).not.toContain("osv.dev");
  });
});
