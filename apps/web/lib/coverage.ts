// How much of a version apm read, as the registry sends it with a score (apm-score-v11), and the words every page uses
// for a version apm did not read in full. Not server-only: the score components render it.
import { z } from "zod";
import { formatSize } from "./format";

/**
 * How much of the version apm read (apm-score-v11; earlier scorers and registries send none). A version apm did not
 * read in full scores only what was read, so the page leads with "Not fully checked", never the number alone.
 */
export const Coverage = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("complete") }),
  z.object({ kind: z.literal("partial"), omittedFiles: z.number(), omittedBytes: z.number(), reasons: z.array(z.string()), notes: z.array(z.string()).default([]) }),
]);

export type Coverage = z.infer<typeof Coverage>;

/** A folder of files apm did not read (packages/core omittedFolders): "." is the package's top level. */
export const OmittedFolder = z.object({ path: z.string(), files: z.number(), bytes: z.number() });

export type OmittedFolder = z.infer<typeof OmittedFolder>;

/**
 * The grade the registry gives a version apm did not read in full (apm-score-v11). It stays "P" on the wire for agents
 * and the CLI; no page shows the letter.
 */
export const PARTIAL_GRADE = "P";

/** Whether a grade is the one for a version apm did not read in full. */
export function isNotAllRead(grade: string | null | undefined): boolean {
  return grade === PARTIAL_GRADE;
}

/** The words beside the number wherever a version apm did not read in full is scored: "98 · not all read". */
export const NOT_ALL_READ = "not all read";

/** "98/100 on the files apm read": the score of a version apm did not read in full. */
export function scoreOnWhatWasRead(score: number): string {
  return `${score}/100 on the files apm read`;
}

/** "2,656 files" */
export function filesText(n: number): string {
  return `${n.toLocaleString("en-US")} file${n === 1 ? "" : "s"}`;
}

/** The size one file may be for apm to read it (packages/core MAX_ANALYZED_FILE_BYTES, 32 MiB), as the page says it. */
const FILE_LIMIT = "32 MB";

/** A folder as the page names it: its path, or the top level. */
function folderName(path: string): string {
  return path === "." ? "the top folder" : path;
}

/** The folders worth naming: the biggest, and any other holding at least a twentieth of the bytes not read. */
export function namedFolders(folders: readonly OmittedFolder[], omittedBytes: number): OmittedFolder[] {
  return folders.filter((f, i) => i === 0 || f.bytes * 20 >= omittedBytes);
}

/**
 * Where the skipped files are: "Most of them are in dist/compiled (762 files, 58.2 MB) and dist/esm (1,305 files,
 * 7.4 MB)." "All" when the folders named hold every one, "Most" when they hold more than half the files and more than
 * half the bytes not read, else "Some of them are" (folders apm does not name may hold more, re-check of 5212041); one
 * file is "It is in".
 */
export function foldersSentence(folders: readonly OmittedFolder[], omitted: { files: number; bytes: number }): string {
  const parts = folders.map((f) => `${folderName(f.path)} (${filesText(f.files)}, ${formatSize(f.bytes)})`);
  const last = parts.at(-1) ?? "";
  const list = parts.length <= 1 ? last : `${parts.slice(0, -1).join(", ")} and ${last}`;
  const files = folders.reduce((n, f) => n + f.files, 0);
  const bytes = folders.reduce((n, f) => n + f.bytes, 0);

  if (omitted.files === 1) return `It is in ${folders[0] ? folderName(folders[0].path) : "the package"}.`;

  if (files >= omitted.files) return `All of them are in ${list}.`;

  return `${files * 2 > omitted.files && bytes * 2 > omitted.bytes ? "Most of them are" : "Some of them are"} in ${list}.`;
}

/**
 * What apm skipped and why, in two sentences: "next is 183.4 MB unpacked, more than apm reads of one package, so apm
 * skipped 2,656 files (70.6 MB). Nothing in them was checked." Each file was over the size of one file apm reads,
 * past the amount apm reads of one package, or (some of each) both. Sizes as the facts panel gives them (formatSize).
 */
export function skippedSentence(input: { coverage: Extract<Coverage, { kind: "partial" }>; name: string; unpackedSize: number | null }): string {
  const { coverage } = input;
  const one = coverage.omittedFiles === 1;
  const skipped = `${filesText(coverage.omittedFiles)} (${formatSize(coverage.omittedBytes)})`;
  const checked = ` Nothing in ${one ? "it" : "them"} was checked.`;
  const tooLarge = coverage.reasons.includes("too-large");
  const overBudget = coverage.reasons.includes("over-budget");

  if (tooLarge && !overBudget) return `apm skipped ${skipped}: ${one ? "it is" : "each is"} over ${FILE_LIMIT}, the largest file apm reads.${checked}`;

  if (tooLarge) return `apm skipped ${skipped}: some are over ${FILE_LIMIT}, the largest file apm reads, and the rest are past the amount apm reads of one package.${checked}`;

  if (input.unpackedSize !== null) return `${input.name} is ${formatSize(input.unpackedSize)} unpacked, more than apm reads of one package, so apm skipped ${skipped}.${checked}`;

  return `apm skipped ${skipped}, past the amount apm reads of one package.${checked}`;
}

/**
 * What skipped files alone do to an install through apm (a revoked or held version is refused for its own reason,
 * review of c93d72e finding 2) (registry warnings.ts scoreWarning and
 * apm.ts policyBlock): the default mode installs it with a warning, strict mode and the ~safe view refuse it. The
 * page sets the flag in code type itself; this is the Markdown.
 */
export const NOT_ALL_READ_INSTALLS = "The skipped files alone don't stop an install through apm: it installs with a warning that not every file was checked. Strict mode (`--strict`) refuses it.";

/** NOT_ALL_READ_INSTALLS around the flag, for the page to set `--strict` as code. */
export const NOT_ALL_READ_INSTALLS_PARTS = { before: "The skipped files alone don't stop an install through apm: it installs with a warning that not every file was checked. Strict mode (", flag: "--strict", after: ") refuses it." } as const;
