// new-publisher on real npm histories. test/fixtures/publisher-history.json is npm's packument for typescript,
// @typescript/typescript-darwin-arm64 and event-stream (fetched 18 Nov 2026), cut to the versions where the publisher
// changes and each version's name, version, _npmUser and dist, as npm sends them. Each is read the way the registry
// reads npm (readPackument's trimmed profile, then cachedPackage) and its version analysed as the queue does.
//
// What npm records: microsoft1es's first publish of typescript, or of any @typescript/typescript-<platform> package, is
// 7.0.2 (8 Jul 2026); every one of its 128 versions of each is 7.0.2 or later. So 7.0.2 is the release where the
// publishing account changed, which is what the signal is for, and it still fires there; the history it names is the
// accounts, not "upstream" (typescript 0.8.1 has no _npmUser).
import { describe, expect, test } from "bun:test";
import { gzipSync } from "node:zlib";
import { analyze, type AnalyzeInput, type Signal } from "@apm/core";
import { analyzeUpstreamTarball } from "../src/analysis.ts";
import { MemoryPool } from "../src/memory.ts";
import { readPackument } from "../src/packument-read.ts";
import { NO_RECORDED_PUBLISHER, UNRECORDED_PUBLISHER, newestPublishersFirst, recordedPublisher, upstreamPublishers } from "../src/publishers.ts";
import { cachedPackage, scoredPackage, type UpstreamPackage } from "../src/upstream.ts";
import HISTORY from "./fixtures/publisher-history.json";

function tarFile(path: string, text: string): Uint8Array[] {
  const data = new TextEncoder().encode(text);
  const h = new Uint8Array(512);
  const put = (s: string, at: number) => h.set(new TextEncoder().encode(s), at);
  put(path, 0);
  put("0000644\0", 100);
  put(`${data.length.toString(8).padStart(11, "0")}\0`, 124);
  put("        ", 148);
  put("0", 156);
  put("ustar\0", 257);
  let sum = 0;

  for (const b of h) sum += b;
  put(`${sum.toString(8).padStart(6, "0")}\0 `, 148);

  return [h, data, new Uint8Array((512 - (data.length % 512)) % 512)];
}

function tarball(name: string, version: string): Uint8Array {
  const parts = [...tarFile("package/package.json", JSON.stringify({ name, version, license: "MIT", main: "index.js" })), ...tarFile("package/index.js", "module.exports = 1;\n"), new Uint8Array(1024)];
  const tar = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;

  for (const p of parts) {
    tar.set(p, at);
    at += p.length;
  }

  return new Uint8Array(gzipSync(tar));
}

type FixtureName = keyof typeof HISTORY;

/** The fixture's packument for `name`, read as the registry reads one from npm. */
async function upstream(name: FixtureName): Promise<UpstreamPackage> {
  const text = JSON.stringify(HISTORY[name]);
  const body = new ReadableStream<Uint8Array>({ start: (c) => (c.enqueue(new TextEncoder().encode(text)), c.close()) });
  const read = await readPackument(body, { lease: new MemoryPool(Number.POSITIVE_INFINITY).request(Number.POSITIVE_INFINITY) });

  if (read.kind !== "ok") throw new Error(`fixture ${name} did not read: ${read.kind}`);
  const cached = cachedPackage(name, read.body, { versionDocs: read.versionDocs, maxPieceChars: read.maxPieceChars }, null);

  if (cached === null) throw new Error(`fixture ${name} is not a packument`);
  const probe = scoredPackage(cached, { scores: new Map(), unscorable: new Map() });

  if (probe.kind !== "found") throw new Error(`fixture ${name} was not found`);

  return probe.pkg;
}

/** new-publisher as the queue's analysis of `version` finds it, or undefined when it does not fire. */
async function newPublisher(name: FixtureName, version: string): Promise<Signal | undefined> {
  const pkg = await upstream(name);
  const v = pkg.versions.find((x) => x.version === version);

  if (v === undefined) throw new Error(`fixture ${name} has no ${version}`);
  const result = analyzeUpstreamTarball(pkg, v, tarball(name, version), { maxWork: Number.POSITIVE_INFINITY });

  if (result.kind !== "scored") throw new Error(`${name}@${version} was not scored: ${result.kind}`);

  return result.analysis.signals.find((s) => s.id === "new-publisher");
}

describe("new-publisher on npm's typescript history", () => {
  test("7.0.2, microsoft1es's first typescript publish, is flagged, naming the accounts before it newest first and not the 2012 placeholder", async () => {
    const s = await newPublisher("typescript", "7.0.2");

    expect(s?.points).toBe(-10);
    expect(s?.evidence).toEqual(["microsoft1es has not published this package before (previous: typescript-deploys, typescript-bot, typescript)"]);
  });

  test("the history is every earlier version by publish time, prereleases included: microsoft1es's nightlies after 7.0.2 are not flagged", async () => {
    expect(await newPublisher("typescript", "7.1.0-dev.20260710.1")).toBeUndefined();
    expect(await newPublisher("typescript", "7.1.0-dev.20261117.1")).toBeUndefined();
  });

  test("7.0.1-rc, a prerelease, counts as typescript-deploys's history, and typescript-bot's nightlies as its", async () => {
    const pkg = await upstream("typescript");
    const v = pkg.versions.find((x) => x.version === "7.0.2");

    expect(v && upstreamPublishers(pkg.versions, v).previousPublishers).toContain("typescript-deploys");
    expect(await newPublisher("typescript", "6.0.3")).toBeUndefined();
  });

  test("being listed in maintainers is not having published: the maintainers list is not the history", async () => {
    expect(HISTORY.typescript.maintainers.map((m) => m.name)).toContain("microsoft1es");
    expect(await newPublisher("typescript", "7.0.2")).toBeDefined();
  });

  test("a version npm recorded no publisher for (0.8.1) fails closed: flagged as an unknown account, and adds no name to the history", async () => {
    const pkg = await upstream("typescript");
    const old = pkg.versions.find((x) => x.version === "0.8.1");

    expect(old?.published_by).toBe(NO_RECORDED_PUBLISHER);
    expect(old && recordedPublisher(old)).toBeNull();
    expect((await newPublisher("typescript", "0.8.1"))?.evidence).toEqual([`${UNRECORDED_PUBLISHER} has not published this package before (previous: typescript)`]);
    // 0.8.2 follows 0.8.0 (typescript) and 0.8.1 (no record): typescript published before, so it is not new
    expect(await newPublisher("typescript", "0.8.2")).toBeUndefined();
  });
});

describe("new-publisher on a platform package", () => {
  test("@typescript/typescript-darwin-arm64@7.0.2 is flagged: microsoft1es had published no version of it, and only typescript-deploys had", async () => {
    const s = await newPublisher("@typescript/typescript-darwin-arm64", "7.0.2");

    expect(s?.evidence).toEqual(["microsoft1es has not published this package before (previous: typescript-deploys)"]);
  });

  test("its later nightlies by the same account are not", async () => {
    expect(await newPublisher("@typescript/typescript-darwin-arm64", "7.1.0-dev.20261117.1")).toBeUndefined();
  });
});

describe("new-publisher on a takeover (event-stream, 2018)", () => {
  test("right9ctrl's first publish of a package dominictarr published for seven years is flagged", async () => {
    const s = await newPublisher("event-stream", "3.3.5");

    expect(s?.points).toBe(-10);
    expect(s?.evidence).toEqual(["right9ctrl has not published this package before (previous: dominictarr)"]);
  });

  test("a version with no recorded publisher in the history (3.0.0) does not hide the takeover", async () => {
    const pkg = await upstream("event-stream");
    const v = pkg.versions.find((x) => x.version === "3.3.5");

    expect(v && upstreamPublishers(pkg.versions, v).previousPublishers).toEqual(["dominictarr"]);
  });

  test("right9ctrl's later versions are not flagged: the signal marks the first publish of an account", async () => {
    expect(await newPublisher("event-stream", "4.0.1")).toBeUndefined();
  });
});

describe("recordedPublisher", () => {
  test("an account named like the placeholder is still an account when npm recorded it", () => {
    const named = { manifest: { _npmUser: { name: NO_RECORDED_PUBLISHER } }, published_by: NO_RECORDED_PUBLISHER, published_at: 1 };

    expect(recordedPublisher(named)).toBe(NO_RECORDED_PUBLISHER);
    expect(upstreamPublishers([{ ...named, published_by: "alice", manifest: { _npmUser: { name: "alice" } }, published_at: 0 }], named).previousPublishers).toEqual(["alice"]);
  });
});

describe("unknown publishers fail closed (never a higher score than comparing the placeholder as an account)", () => {
  type Row = Parameters<typeof upstreamPublishers>[1];

  const rec = (name: string, at: number): Row => ({ manifest: { _npmUser: { name } }, published_by: name, published_at: at });
  const unrec = (at: number): Row => ({ manifest: {}, published_by: NO_RECORDED_PUBLISHER, published_at: at });

  const flagged = (versions: Row[], v: Row) => {
    const p = upstreamPublishers(versions, v);
    const input: AnalyzeInput = { name: "left-pad", manifest: { name: "left-pad", version: "2.0.0", license: "MIT" }, files: [], ...p };

    return { ...p, signal: analyze(input).signals.find((x) => x.id === "new-publisher") };
  };

  test("a version with no recorded publisher after a named one is flagged and scores as it did", () => {
    const r = flagged([rec("alice", 0), unrec(1)], unrec(1));

    expect(r.signal?.evidence).toEqual([`${UNRECORDED_PUBLISHER} has not published this package before (previous: alice)`]);
    expect(r.signal?.points).toBe(-10);
  });

  // stricter than comparing the placeholder as an account, which matched "upstream" with itself and let this pass
  test("an unrecorded version after a named one and an unrecorded one is still flagged", () => {
    const versions = [rec("alice", 0), unrec(1), unrec(2)];

    expect(flagged(versions, unrec(2)).signal?.evidence).toEqual([`${UNRECORDED_PUBLISHER} has not published this package before (previous: alice)`]);
  });

  test("a named account after versions that name no one is flagged", () => {
    expect(flagged([unrec(0), unrec(1), rec("alice", 2)], rec("alice", 2)).signal?.evidence).toEqual([`alice has not published this package before (previous: ${UNRECORDED_PUBLISHER})`]);
  });

  test("no record before and none now is not flagged (as before: nothing to tell apart), and a first version never is", () => {
    expect(flagged([unrec(0), unrec(1)], unrec(1)).signal).toBeUndefined();
    expect(flagged([rec("alice", 0)], rec("alice", 0)).signal).toBeUndefined();
  });

  test("the label can never equal an npm account name", () => {
    expect(UNRECORDED_PUBLISHER).toContain(" ");
  });
});

describe("new-publisher's evidence", () => {
  const input = (previousPublishers: readonly string[]): AnalyzeInput => ({
    name: "left-pad",
    manifest: { name: "left-pad", version: "2.0.0", license: "MIT" },
    files: [],
    publisher: "mallory",
    previousPublishers,
  });

  test("names at most five earlier publishers, each once, and says how many more", () => {
    const history = newestPublishersFirst(["a", "b", "c", "b", "d", "e", "f", "g"].map((publisher, i) => ({ publisher, at: 100 - i })));
    const s = analyze(input(history)).signals.find((x) => x.id === "new-publisher");

    expect(history).toEqual(["a", "b", "c", "d", "e", "f", "g"]);
    expect(s?.evidence).toEqual(["mallory has not published this package before (previous: a, b, c, d, e and 2 more)"]);
  });

  test("a publisher among the earlier ones is not new, however far back", () => {
    expect(analyze({ ...input(["a", "b", "c", "d", "e", "f", "mallory"]) }).signals.some((x) => x.id === "new-publisher")).toBe(false);
  });
});
