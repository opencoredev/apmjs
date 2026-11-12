// What a revoked version's answers may say. Its files, excerpts and readme answer 410 (files.ts). Its review, score and
// package answers are rebuilt from an allowlist: paths, line numbers, rule ids, kinds, a reviewer's sentence and the
// revoke's reason. Nothing is cut out of a string, because the package's own text can sit anywhere in one (a script name
// with a colon, a nested `npm run`, a shell wrapper). A field this file does not name is not sent.
import {
  NOT_CHECKED,
  READING_LIMITS,
  dependencySpecs,
  describeDependency,
  isRegistryDependency,
  isValidPackageName,
  uncheckableReason,
  type DependencySpec,
  type DismissedEvidence,
  type Facts,
  type Signal,
  type SkippedFile,
} from "@apm/core";
import { z } from "zod";
import type { VersionRecord } from "./db.ts";

/** A revoked version, or one whose revoke is pending: its source is not shown anywhere. */
export function isWithheld(status: string): boolean {
  return status === "revoked" || status === "revoke-pending";
}

/** What a withheld version's score says per signal: the rule, its points, and no evidence but the revoke's reason. */
export type WithheldSignal = Pick<Signal, "id" | "label" | "points" | "confidence" | "evidence">;

/**
 * One signal of a withheld version. Evidence lines quote the package (a code line, a script, a gyp command), so they
 * all go; the `revoked` signal's one line is the revoke's reason, which is the registry's own text, and stays.
 */
export function withheldSignal(s: Signal): WithheldSignal {
  return { id: s.id, label: s.label, points: s.points, confidence: s.confidence, evidence: s.id === "revoked" ? [...s.evidence] : [] };
}

/** How a withheld version's answer names a file: a numbered reference ("file 2"), since a path is the publisher's text. */
export type FileRef = (path: string) => string;

/** A reference for each path an answer names: sorted, numbered from 1, the same for one path throughout the answer. */
export function fileReferences(paths: readonly string[]): FileRef {
  const refs = new Map([...new Set(paths)].toSorted().map((p, i) => [p, `file ${i + 1}`]));

  return (path) => refs.get(path) ?? "file";
}

/** A withheld version's dismissed items: the signal, line and the reviewer's reason; the quoted evidence goes. */
export function withheldDismissals(list: readonly DismissedEvidence[], ref: FileRef): DismissedEvidence[] {
  return list.map((d) => ({ signal: d.signal, file: ref(d.file), line: d.line, reason: d.reason, at: d.at, evidence: [] }));
}

/** The files a withheld version's score did not read: each by reference, with its size and why it was not read. */
export function withheldSkipped(list: readonly SkippedFile[], ref: FileRef): SkippedFile[] {
  return list.map((k) => ({ path: ref(k.path), size: k.size, reason: k.reason }));
}

/** The package row fields that say whose readme it is. */
type ReadmeOwner = { readme: string; readme_version: string | null };

/** The readme an answer may show, and the version whose publish wrote it (null when unknown or hidden). */
export type ShownReadme = { text: string; version: string | null };

/**
 * The package's readme, or "" when the version whose publish wrote it is withheld. A publish without a readme keeps the
 * previous text, so the owner is the recorded `readme_version`, not the newest publish. When the owner is unknown (a
 * row from before migration 0008, or npm's packument for an upstream package) the readme is hidden while any version
 * is withheld.
 */
export function readmeShown(pkg: ReadmeOwner, versions: readonly { version: string; status: string }[]): ShownReadme {
  if (pkg.readme === "") return { text: "", version: null };

  if (pkg.readme_version === null) return versions.some((v) => isWithheld(v.status)) ? { text: "", version: null } : { text: pkg.readme, version: null };
  const owner = versions.find((v) => v.version === pkg.readme_version);

  // an owner that is gone or withheld takes its readme with it
  return owner && !isWithheld(owner.status) ? { text: pkg.readme, version: owner.version } : { text: "", version: null };
}

/**
 * A withheld version's facts. All but the license are enums, booleans and counts; the license is the manifest's own
 * string, so it goes.
 */
export function withheldFacts(f: Facts): Facts {
  return { ...f, license: null };
}

// what the stored not-checked entries look like where they carry numbers worth keeping (packages/core/src/score.ts and
// checkDependencies in apm.ts write them)
const UNREAD = /^(\d+) file\(s\) not analyzed: the package is larger than the (\d+(?:\.\d+)?) MB one analysis reads$/;
const MORE_DEPENDENCIES = /^dependency (\d+) more dependencies: apm checks the first (\d+) at publish$/;

/**
 * What a withheld version's review finding says in place of the model's sentence, which can quote the package
 * (review.ts). A finding names no category apm could word it from, so it is this one sentence; its severity stays in
 * its own field.
 */
export const WITHHELD_ISSUE = "Finding withheld with this version";

/** How a withheld version's answers refer to a dependency whose manifest key is not a valid npm name. */
export const INVALID_DEPENDENCY = "a dependency with an invalid name";

/**
 * A dependency's manifest key, when it is a name npm would accept. A URL, git or file dependency's key is not checked
 * at publish, so it can be any text the publisher wrote; one that is not a valid name is not repeated.
 */
function dependencyLabel(key: string): string {
  return isValidPackageName(key) ? key : INVALID_DEPENDENCY;
}

/** Why a dependency was not checked, in fixed words by its kind: never its spec, which is the publisher's text. */
function dependencyLimit(d: DependencySpec): string {
  if (isRegistryDependency(d)) return "apm could not check it at publish";

  return d.kind === "invalid" ? "neither a version range, a dist-tag nor a source apm knows" : uncheckableReason(d);
}

/**
 * A withheld version's not-checked list, rebuilt from fixed wording and structured fields: the general limits, each
 * reading limit without its file list, the unread-file count, and each dependency apm could not check by its manifest
 * name and kind. A stored entry can quote a dependency spec (a URL, a git path, a tag), so none is passed through.
 */
export function withheldLimitations(notChecked: readonly string[], manifest: VersionRecord["manifest"]): string[] {
  const out = [...NOT_CHECKED];

  for (const note of READING_LIMITS) if (notChecked.some((n) => n.startsWith(`${note} (`))) out.push(`${note} (files not named while this version is withheld)`);

  for (const n of notChecked) {
    const unread = UNREAD.exec(n);

    if (unread) out.push(`${unread[1]} file(s) not analyzed: the package is larger than the ${unread[2]} MB one analysis reads`);
  }

  const deps = notChecked.filter((n) => n.startsWith("dependency "));
  let named = 0;

  for (const d of dependencySpecs(manifest)) {
    const said = [`dependency ${describeDependency(d)}:`, ...(isRegistryDependency(d) ? [`dependency ${d.name}@`] : [])];

    if (!deps.some((n) => said.some((p) => n.startsWith(p)))) continue;
    named++;
    out.push(`dependency ${dependencyLabel(d.key)}: ${dependencyLimit(d)}`);
  }

  for (const n of deps) {
    const more = MORE_DEPENDENCIES.exec(n);

    if (more) {
      named++;
      out.push(`dependency ${more[1]} more dependencies: apm checks the first ${more[2]} at publish`);
    }
  }

  if (deps.length > named) out.push(`dependency ${deps.length - named} more: not named while this version is withheld`);

  return [...new Set(out)];
}

/** What a package's row says from its publishes' manifests. */
export type PackageText = { description: string; keywords: string[] };

/** A version, as far as the package text it wrote goes: `published_at` then `seq` is publish order, as in the database. */
type TextSource = Pick<VersionRecord, "status" | "published_at" | "seq" | "manifest">;

/** What a publish writes to the row, read the way publish reads it: a string description, the string keywords. */
const ManifestText = z.object({
  description: z.string().optional().catch(undefined),
  keywords: z
    .array(z.string().nullable().catch(null))
    .transform((ks) => ks.filter((k) => k !== null))
    .optional()
    .catch(undefined),
});

/**
 * The package's description and keywords as an answer may show them. Each publish that sets one overwrites the row, so
 * a withheld publish's text can sit there. While any version is withheld, each field is what the row would say had
 * the withheld publishes never happened: the newest shown version that set it, or empty.
 */
export function packageTextShown(pkg: PackageText, versions: readonly TextSource[]): PackageText {
  if (!versions.some((v) => isWithheld(v.status))) return { description: pkg.description, keywords: pkg.keywords };

  const shown = versions
    .filter((v) => !isWithheld(v.status))
    .toSorted((a, b) => b.published_at - a.published_at || b.seq - a.seq)
    .map((v) => ManifestText.parse(v.manifest));

  const description = shown.find((t) => t.description !== undefined)?.description ?? "";
  const keywords = shown.find((t) => t.keywords !== undefined)?.keywords ?? [];

  return { description, keywords };
}

/**
 * What an event about a withheld version keeps in its detail, by kind: which version, the people and times that make
 * it an audit record, and the words a person wrote about the action itself (a revoke's, yank's or restore's reason, a
 * reviewer's dismissal reason). Text that came with the package goes: a deprecation message, a dist-tag name, a file
 * path. A kind not named here keeps only its version.
 */
const EVENT_KEEPS = new Map([
  ["publish", ["version", "approvedBy", "stagedAt"]],
  ["yank", ["version", "reason"]],
  ["unyank", ["version"]],
  ["revoke", ["version", "reason", "confirms"]],
  ["revoke-pending", ["version", "reason", "finalAt", "dependents"]],
  ["restore", ["version", "reason", "from"]],
  ["deprecate", ["version"]],
  ["undeprecate", ["version"]],
  ["dist-tag", ["version"]],
  ["evidence-dismissed", ["version", "digest", "scorer", "signal", "line", "reason"]],
  ["evidence-restored", ["version", "digest", "scorer", "signal", "line", "reason", "dismissal"]],
]);

/** An event's detail: a JSON object, read for the version it names; every other field is the event kind's own. */
export const StoredEventDetail = z.looseObject({ version: z.string().nullish().catch(null) });

export type StoredEventDetail = z.infer<typeof StoredEventDetail>;

/**
 * An event's detail as an answer may show it: as stored, unless it names a version in `withheld`; then only the fields
 * EVENT_KEEPS names for its kind, with `withheld: true`.
 */
export function eventDetailShown(input: { kind: string; detail: StoredEventDetail; withheld: ReadonlySet<string> }): StoredEventDetail {
  const { kind, detail, withheld } = input;
  const version = detail.version ?? null;

  if (version === null || !withheld.has(version)) return detail;
  const shown: StoredEventDetail = { version, withheld: true };

  for (const k of EVENT_KEEPS.get(kind) ?? ["version"]) if (k in detail) shown[k] = detail[k];

  return shown;
}
