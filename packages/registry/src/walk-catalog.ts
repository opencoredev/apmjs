// What the resolve walk, its root, a scan and the AI review's look at a fetched package keep of each package they
// read: for the versions they pick, the record with a manifest cut down to the fields they read. A packument is held
// whole only while it is read and cut down (Upstream.summaries); what is kept weighs a small part of it (next: 26.6 MiB
// cached; the walk keeps one version of it, the review's look under 1 KiB a version), so the isolate's pool holds the
// tree's summaries, not their packuments.
//
// A summary kept under a lease is reserved before it is built: an upper bound on what it keeps and on what building it
// takes (its JSON text included) is taken first, a version at a time, then settled to the weight it keeps. On 2fbf383
// the weight was taken only after the summary existed, so the pool's peak missed it (review of 2fbf383, finding 3).
import { z } from "zod";
import { WEIGHTS } from "./packument-read.ts";
import type { VersionRecord } from "./db.ts";
import type { Lease } from "./memory.ts";
import type { UpstreamPackage } from "./upstream.ts";

/** What a reader keeps of a package, and what it weighs (an upper bound on its heap, as WEIGHTS). */
export type Summary<S> = { readonly summary: S; readonly weight: number };

/** Where a summary's weight is taken from before it is built: the lease that keeps it. */
export type Reserve = Pick<Lease, "take" | "give">;

/**
 * What a kept version's record holds beside its strings and manifest: the record object and its blob key, as a cached
 * package's record is charged (upstream.ts, RECORD_WEIGHT, measured in workerd at 284 bytes at most).
 */
const RECORD_WEIGHT = 384;

/**
 * What building one version's summary takes beside what it keeps and its JSON text: the schema read of its install
 * scripts and the small arrays that filter them.
 */
const BUILD_WEIGHT = 1024;

/**
 * The manifest fields a summary keeps beside its install scripts: what decides what a version installs and where (the
 * walk reads dependencies, optionalDependencies, peerDependencies and their meta, os and cpu; a withheld version's
 * report names them).
 */
export const SUMMARY_MANIFEST_FIELDS = ["dependencies", "optionalDependencies", "peerDependencies", "peerDependenciesMeta", "os", "cpu"] as const;

/** The manifest fields the AI review's look keeps beside its install scripts (review.ts, hasInstallScript). */
const REVIEW_MANIFEST_FIELDS = ["hasInstallScript"] as const;

/** A package as a walk keeps it: where it was read from, its dist-tags and its versions with summarized manifests. */
export type Catalog = { kind: "local" | "upstream"; name: string; distTags: Record<string, string>; versions: VersionRecord[] };

/** A string's heap, as packument-read charges a kept one: two bytes a character past U+00FF. */
function stringWeight(s: string): number {
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) > 0xff) return WEIGHTS.value + 2 * s.length * WEIGHTS.text;

  return WEIGHTS.value + s.length * WEIGHTS.text;
}

const COLON = 0x3a;
const COMMA = 0x2c;
const OPEN_OBJECT = 0x7b;
const OPEN_ARRAY = 0x5b;

/**
 * An upper bound on the heap the value `json` is the text of holds once parsed (WEIGHTS), as if nothing in it were
 * shared. Every value but the root follows a colon, a comma or a `[`, and every container opens with `{` or `[`, so
 * counting those (inside strings too, which only adds) bounds its nodes: each is charged as a container in a dictionary,
 * each object a hidden class of its own, and the text at two bytes a character.
 */
export function jsonWeight(json: string): number {
  let nodes = 1;
  let objects = 0;

  for (let i = 0; i < json.length; i++) {
    const c = json.charCodeAt(i);

    if (c === COLON || c === COMMA || c === OPEN_ARRAY) nodes++;

    if (c === OPEN_OBJECT) objects++;
  }

  return 2 * json.length * WEIGHTS.text + nodes * (WEIGHTS.container + WEIGHTS.dictKey) + objects * WEIGHTS.hiddenClass;
}

/** What one UTF-16 unit takes in JSON text at most: a quote, a backslash and the short escapes 2, other controls and any surrogate 6. */
function escapedLength(c: number): number {
  if (c === 0x22 || c === 0x5c || c === 0x08 || c === 0x09 || c === 0x0a || c === 0x0c || c === 0x0d) return 2;

  if (c < 0x20 || (c >= 0xd800 && c <= 0xdfff)) return 6;

  return 1;
}

type Manifest = VersionRecord["manifest"];

/** Counts toward a bound on JSON text and on what jsonWeight counts in it, built up without writing the text. */
type JsonCounts = { length: number; nodes: number; objects: number };

/** `s` as a JSON string: its quotes and escapes, and the separators inside it that jsonWeight counts. */
function addString(b: JsonCounts, s: string): void {
  b.length += 2;

  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    b.length += escapedLength(c);

    if (c === COLON || c === COMMA || c === OPEN_ARRAY) b.nodes++;

    if (c === OPEN_OBJECT) b.objects++;
  }
}

/** The longest text JSON.stringify writes for a number (`-1.2345678901234567e-308`), true, false or null. */
const SCALAR_LENGTH = 24;

/** An upper bound on a value's JSON: its length, and jsonWeight of that text. */
export type JsonBound = { weight: number; length: number };

/**
 * An upper bound on jsonWeight(JSON.stringify(values)) for the values `push` puts on the stack, and on that text's
 * length, found without writing it: a colon and a comma counted for every member and a comma for every element (one
 * more than the text has), each scalar at its longest. Iterative, so a deep value cannot overflow the stack. It reads
 * parsed JSON in place, by typeof as JSON.stringify does: parsing it into a schema first would copy what it bounds.
 */
function boundOf(start: (b: JsonCounts, stack: unknown[]) => void): JsonBound {
  const b: JsonCounts = { length: 0, nodes: 1, objects: 0 };
  const stack: unknown[] = [];

  start(b, stack);

  while (stack.length > 0) {
    const v = stack.pop();

    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- JSON.stringify decides what to write by typeof, and so does this bound of it
    if (typeof v === "string") addString(b, v);
    else if (Array.isArray(v)) {
      b.length += 2 + v.length;
      b.nodes += 1 + v.length;

      for (const x of v) stack.push(x);
      // oxlint-disable-next-line anti-slop/no-runtime-typeof -- JSON.stringify decides what to write by typeof, and so does this bound of it
    } else if (typeof v === "object" && v !== null) {
      b.objects++;
      b.length += 2;

      for (const k in v) {
        if (!Object.hasOwn(v, k)) continue;
        // a key and its colon and comma
        addString(b, k);
        b.length += 2;
        b.nodes += 2;
        // oxlint-disable-next-line anti-slop/no-reflect-get -- a member of parsed JSON read in place, as JSON.stringify reads it; copying it to a typed shape is what the bound must not do
        stack.push(Reflect.get(v, k));
      }
    } else b.length += SCALAR_LENGTH;
  }

  return { weight: 2 * b.length * WEIGHTS.text + b.nodes * (WEIGHTS.container + WEIGHTS.dictKey) + b.objects * WEIGHTS.hiddenClass, length: b.length };
}

/** jsonBound of a manifest as if it held only the keys in `only`, as the summary that keeps them does. */
function manifestBound(m: Manifest, only: readonly string[]): JsonBound {
  return boundOf((b, stack) => {
    b.objects++;
    b.length += 2;

    for (const k of only) {
      if (!Object.hasOwn(m, k)) continue;
      addString(b, k);
      b.length += 2;
      b.nodes += 2;
      stack.push(m[k]);
    }
  });
}

/** jsonBound of dist-tags, as the summary's head writes them. */
function tagsBound(tags: Record<string, string>): JsonBound {
  return boundOf((_b, stack) => {
    stack.push(tags);
  });
}

/**
 * An upper bound on jsonWeight(JSON.stringify(m)) and on that text's length, found without writing it; with `only`,
 * as if `m` held only those of its keys.
 */
export function jsonBound(m: Manifest, only: readonly string[] = Object.keys(m)): JsonBound {
  return manifestBound(m, only);
}

/** A value's bounded weight and the JSON text weighing it writes (JSON.stringify), at two bytes a character. */
function withText(bound: JsonBound): number {
  return bound.weight + 2 * bound.length * WEIGHTS.text;
}

/**
 * `build`'s summary with `allowance` taken from `reserve` before it is built, then settled to the weight it keeps:
 * what is over is given back, and a weight past the allowance is taken on top. null, with nothing left taken, when
 * either does not fit.
 */
function reserved<T>(reserve: Reserve, allowance: number, build: () => Summary<T>): Summary<T> | null {
  if (!reserve.take(allowance)) return null;
  const made = build();

  if (made.weight <= allowance) {
    reserve.give(allowance - made.weight);

    return made;
  }

  if (reserve.take(made.weight - allowance)) return made;
  reserve.give(allowance);

  return null;
}

/** The install scripts of a manifest, each kept only when it is text, as the publish guard reads them. */
const InstallScripts = z.object({ preinstall: z.string().optional().catch(undefined), install: z.string().optional().catch(undefined), postinstall: z.string().optional().catch(undefined) });

/** A manifest cut down to `fields` and its install scripts (the fields are shared, not copied). */
function summaryManifest(m: Manifest, fields: readonly string[]): Manifest {
  const out: Manifest = {};

  for (const k of fields) if (m[k] !== undefined) out[k] = m[k];
  const scripts = InstallScripts.safeParse(m.scripts);

  if (scripts.success) {
    const kept = Object.fromEntries(Object.entries(scripts.data).filter(([, v]) => v !== undefined));

    if (Object.keys(kept).length > 0) out.scripts = kept;
  }

  return out;
}

/** What a version record's own strings weigh. */
function recordStrings(v: Omit<VersionRecord, "score">): number {
  let n = 0;

  for (const s of [v.version, v.shasum, v.integrity, v.published_by, v.deprecated, v.status_reason]) if (s !== null) n += stringWeight(s);

  return n;
}

/**
 * A version's record with its manifest summarized, and what it keeps: the record itself (RECORD_WEIGHT), its strings
 * (they outlive the packument they came from once the isolate cache lets it go) and the summary. Its score, read from
 * the database, is shared with the store's answer and not counted here, as the packument it came with never counted it.
 * Uncharged: for what no lease holds (a local package's versions); keptVersion reserves it.
 */
export function summaryVersion(v: VersionRecord, fields: readonly string[] = SUMMARY_MANIFEST_FIELDS): Summary<VersionRecord> {
  const manifest = summaryManifest(v.manifest, fields);

  return { summary: { ...v, manifest }, weight: RECORD_WEIGHT + recordStrings(v) + jsonWeight(JSON.stringify(manifest)) };
}

/**
 * An upper bound, found without building anything, on what summaryVersion keeps of `v` and takes while it builds it:
 * the record, its strings, its cut manifest (bounded as the fields it keeps and all of its scripts) and the JSON text
 * that manifest is weighed by.
 */
export function versionAllowance(v: Omit<VersionRecord, "score">, fields: readonly string[] = SUMMARY_MANIFEST_FIELDS): number {
  return RECORD_WEIGHT + BUILD_WEIGHT + recordStrings(v) + withText(manifestBound(v.manifest, [...fields, "scripts"]));
}

/** summaryVersion, reserved from `reserve` before it is built. null, with nothing taken, when it does not fit. */
export function keptVersion(v: VersionRecord, reserve: Reserve, fields: readonly string[] = SUMMARY_MANIFEST_FIELDS): Summary<VersionRecord> | null {
  return reserved(reserve, versionAllowance(v, fields), () => summaryVersion(v, fields));
}

/** What a summary's head keeps: the record around its versions, its dist-tags and its name. */
function headWeight(name: string, distTags: Record<string, string>): number {
  return WEIGHTS.container + jsonWeight(JSON.stringify(distTags)) + stringWeight(name);
}

/** The head's weight, reserved with the dist-tags' JSON text before that text is written. */
function keptHead(name: string, distTags: Record<string, string>, reserve: Reserve): Summary<null> | null {
  return reserved(reserve, WEIGHTS.container + stringWeight(name) + withText(tagsBound(distTags)), () => ({ summary: null, weight: headWeight(name, distTags) }));
}

/**
 * Each of `versions` kept by `one`, which reserves it before it builds it, so what is taken never falls behind what is
 * built. `head` is the weight already taken for the summary around them. null, with all of it given back, as soon as
 * one does not fit.
 */
function keptVersions<V>(versions: readonly V[], head: number, reserve: Reserve, one: (v: V) => Summary<VersionRecord> | null): Summary<VersionRecord[]> | null {
  const out: VersionRecord[] = [];
  let weight = head;

  for (const v of versions) {
    // its slot in the list is reserved with it
    if (!reserve.take(WEIGHTS.key)) {
      reserve.give(weight);

      return null;
    }

    const made = one(v);

    if (made === null) {
      reserve.give(weight + WEIGHTS.key);

      return null;
    }

    out.push(made.summary);
    weight += WEIGHTS.key + made.weight;
  }

  return { summary: out, weight };
}

/**
 * A package summarized: its dist-tags and `versions` (the few its reader picked from the package), and what the
 * summary weighs. Uncharged: for a local package, whose versions no lease holds; keptSummary reserves it.
 */
export function summarize(input: Catalog): Summary<Catalog> {
  const versions: VersionRecord[] = [];
  let weight = headWeight(input.name, input.distTags);

  for (const v of input.versions) {
    const one = summaryVersion(v);
    versions.push(one.summary);
    weight += WEIGHTS.key + one.weight;
  }

  return { summary: { kind: input.kind, name: input.name, distTags: input.distTags, versions }, weight };
}

/**
 * summarize, reserved from `reserve` as it is built: the head first, then each version before it is cut down, each
 * settled to what it keeps. What stays taken is the summary's weight. null, with nothing taken, when it does not fit.
 */
export function keptSummary(input: Catalog, reserve: Reserve): Summary<Catalog> | null {
  const head = keptHead(input.name, input.distTags, reserve);

  if (head === null) return null;
  const versions = keptVersions(input.versions, head.weight, reserve, (v) => keptVersion(v, reserve));

  return versions === null ? null : { summary: { kind: input.kind, name: input.name, distTags: input.distTags, versions: versions.summary }, weight: versions.weight };
}

/**
 * What the AI review's look at a package npm just sent reads of it (review.ts, considerUpstream): its name, dist-tags
 * and every version's record with only its install scripts, unscored. It runs after the response and may take seconds;
 * handed this, its lease holds under 1 KiB a version (next: 3.2 MiB) instead of the whole package (26.6 MiB), which the
 * isolate cache may then give back while a walk needs the room. Reserved from `reserve` as it is built, a version at
 * a time; null, with nothing taken, when it does not fit.
 */
export function reviewSummary(pkg: Pick<UpstreamPackage, "name" | "distTags"> & { readonly versions: readonly Omit<VersionRecord, "score">[] }, reserve: Reserve): Summary<UpstreamPackage> | null {
  const head = keptHead(pkg.name, pkg.distTags, reserve);

  if (head === null) return null;
  const versions = keptVersions(pkg.versions, head.weight, reserve, (v) => reserved(reserve, versionAllowance(v, REVIEW_MANIFEST_FIELDS), () => summaryVersion({ ...v, score: null }, REVIEW_MANIFEST_FIELDS)));

  if (versions === null) return null;
  const summary: UpstreamPackage = { name: pkg.name, distTags: pkg.distTags, description: "", readme: "", maintainers: [], versions: versions.summary, tarballs: new Map(), serveCost: { versionDocs: 0, maxPieceChars: 0 } };

  return { summary, weight: versions.weight };
}
