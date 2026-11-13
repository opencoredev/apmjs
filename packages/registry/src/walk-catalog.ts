// What the resolve walk, its root and a scan keep of each package they read: its dist-tags and, for each version, its
// record with a manifest cut down to what installing it reads. A packument is held whole only while it is read and cut
// down (Upstream.summaries); the walk keeps the summary, which weighs a small part of it (next: 26.6 MiB cached, a few
// MiB summarized), so a walk over next and its tree holds the tree's summaries, not their packuments.
import { z } from "zod";
import { WEIGHTS } from "./packument-read.ts";
import { RECORD_WEIGHT, type Summary } from "./upstream.ts";
import type { VersionRecord } from "./db.ts";

/**
 * The manifest fields a summary keeps: what decides what a version installs and where (the walk reads dependencies and
 * optionalDependencies, a withheld version's report names them), and its install scripts.
 */
export const SUMMARY_MANIFEST_FIELDS = ["dependencies", "optionalDependencies", "peerDependencies", "peerDependenciesMeta", "os", "cpu"] as const;

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

type Manifest = VersionRecord["manifest"];

/** The install scripts of a manifest, each kept only when it is text, as the publish guard reads them. */
const InstallScripts = z.object({ preinstall: z.string().optional().catch(undefined), install: z.string().optional().catch(undefined), postinstall: z.string().optional().catch(undefined) });

/** A manifest cut down to SUMMARY_MANIFEST_FIELDS and its install scripts (the fields are shared, not copied). */
function summaryManifest(m: Manifest): Manifest {
  const out: Manifest = {};

  for (const k of SUMMARY_MANIFEST_FIELDS) if (m[k] !== undefined) out[k] = m[k];
  const scripts = InstallScripts.safeParse(m.scripts);

  if (scripts.success) {
    const kept = Object.fromEntries(Object.entries(scripts.data).filter(([, v]) => v !== undefined));

    if (Object.keys(kept).length > 0) out.scripts = kept;
  }

  return out;
}

/**
 * A version's record with its manifest summarized, and what it keeps: the record itself (RECORD_WEIGHT), its strings
 * (they outlive the packument they came from once the isolate cache lets it go) and the summary. Its score, read from
 * the database, is shared with the store's answer and not counted here, as the packument it came with never counted it.
 */
export function summaryVersion(v: VersionRecord): Summary<VersionRecord> {
  const manifest = summaryManifest(v.manifest);
  const strings = [v.version, v.shasum, v.integrity, v.published_by, v.deprecated, v.status_reason].reduce((n, s) => n + (s === null ? 0 : stringWeight(s)), 0);

  return { summary: { ...v, manifest }, weight: RECORD_WEIGHT + strings + jsonWeight(JSON.stringify(manifest)) };
}

/**
 * A package summarized: its dist-tags and `versions` (the few its reader picked from the package), and what the
 * summary weighs.
 */
export function summarize(input: Catalog): Summary<Catalog> {
  const versions: VersionRecord[] = [];
  let weight = WEIGHTS.container + jsonWeight(JSON.stringify(input.distTags)) + stringWeight(input.name);

  for (const v of input.versions) {
    const one = summaryVersion(v);
    versions.push(one.summary);
    weight += WEIGHTS.key + one.weight;
  }

  return { summary: { kind: input.kind, name: input.name, distTags: input.distTags, versions }, weight };
}
