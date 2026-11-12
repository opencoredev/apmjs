// Builds the text the model reads for one version: the diff from the previous version when there is
// one, otherwise the files, with new-file line numbers so findings can cite `file:line`, capped to a
// token budget. Also records what the model could not read, which the website shows next to the result.
import type { TarEntry } from "@apm/core";
import { diffLines, type Hunk } from "./diff.ts";
import { isReviewable, kindOf, linesOf, MAX_DECODED_BYTES, ordered, textOf } from "./files.ts";
import { dependencyNamesOf, installScripts, type PackageFiles } from "./manifest.ts";

/** Content budget in estimated tokens. The system prompt and header add about 1,000 on top. */
export const DEFAULT_BUDGET_TOKENS = 16_000;

/** Conservative characters per token for code; minified code tokenizes worse than prose. */
export const CHARS_PER_TOKEN = 3.2;
const MAX_LINE_CHARS = 2_000;

/** One file may take at most this share of the budget... */
const MAX_FILE_SHARE = 0.5;

/** ...and a changed file this share, so one rebuilt bundle cannot crowd out the others. */
const DIFF_FILE_SHARE = 0.3;

/** Below this many characters left, a file is not started. */
const MIN_BLOCK_CHARS = 400;

export type NotReadReason = "budget" | "partial" | "binary" | "too-large";

/** Something the model did not see. Dependencies are never read: only this package's own files are. */
export type NotRead = { kind: "file"; path: string; reason: NotReadReason } | { kind: "dependency"; name: string };

export type Coverage = {
  mode: "diff" | "files";
  previousVersion: string | null;
  /** Reviewable files in scope: changed or added ones in a diff, all code and data otherwise (package.json included). */
  filesInScope: number;
  /** Of those, how many the model saw in full. */
  filesRead: number;
};

export type ReviewInput = {
  name: string;
  version: string;
  coverage: Coverage;
  text: string;
  estTokens: number;
  /** Paths shown in full. */
  read: string[];
  notRead: NotRead[];
};

function clip(line: string): string {
  return line.length > MAX_LINE_CHARS ? `${line.slice(0, MAX_LINE_CHARS)} …[line cut, ${line.length - MAX_LINE_CHARS} more chars]` : line;
}

function numbered(lines: readonly string[]): string {
  return lines.map((l, i) => `${String(i + 1).padStart(5)}  ${clip(l)}`).join("\n");
}

function renderHunks(hunks: readonly Hunk[]): string {
  return hunks
    .map((h) => [`@@ new line ${h.newStart} @@`, ...h.lines.map((l) => `${l.newLine === null ? "     " : String(l.newLine).padStart(5)} ${l.kind} ${clip(l.text)}`)].join("\n"))
    .join("\n");
}

class Budget {
  private used = 0;
  readonly parts: string[] = [];
  readonly read: string[] = [];
  readonly partial: string[] = [];
  readonly omitted: string[] = [];

  constructor(readonly maxChars: number) {}

  get left(): number {
    return this.maxChars - this.used;
  }

  /** Adds a block; when it does not fit, adds as many whole lines as fit and records the file as partly read. */
  add(input: { path: string | null; header: string; body: string; share: number }): void {
    const cap = Math.min(this.left, Math.floor(this.maxChars * input.share));

    if (cap < MIN_BLOCK_CHARS) {
      if (input.path !== null) this.omitted.push(input.path);

      return;
    }

    let body = input.body;
    let whole = true;

    if (input.header.length + body.length + 2 > cap) {
      const lines = body.split("\n");
      const kept: string[] = [];
      let n = input.header.length + 80;

      for (const l of lines) {
        if (n + l.length + 1 > cap) break;
        kept.push(l);
        n += l.length + 1;
      }

      body = `${kept.join("\n")}\n…[${lines.length - kept.length} more lines not shown: budget]`;
      whole = false;
    }

    const block = `${input.header}\n${body}\n`;
    this.parts.push(block);
    this.used += block.length;

    if (input.path === null) return;

    if (whole) this.read.push(input.path);
    else this.partial.push(input.path);
  }

  skip(path: string): void {
    this.omitted.push(path);
  }
}

function header(input: { name: string; version: string; previous: string | null; pkg: PackageFiles; extra: readonly string[] }): string {
  const scripts = installScripts(input.pkg.manifest);
  const scriptText = scripts.length > 0 ? scripts.map((s) => `${s.key}: ${s.command}`).join(" | ") : "none";
  const versionText = input.previous === null ? " (no previous version available: full review)" : ` (previous version: ${input.previous})`;

  return [
    `Package: ${input.name}@${input.version}${versionText}`,
    `Files: ${input.pkg.files.length}, unpacked bytes: ${input.pkg.files.reduce((n, f) => n + f.size, 0)}`,
    `Install-time scripts: ${scriptText}`,
    ...input.extra,
  ].join("\n");
}

function notReadOf(b: Budget, input: { binaries: readonly TarEntry[]; tooLarge: readonly string[]; pkg: PackageFiles }): NotRead[] {
  const files: NotRead[] = [
    ...b.omitted.map((path): NotRead => ({ kind: "file", path, reason: "budget" })),
    ...b.partial.map((path): NotRead => ({ kind: "file", path, reason: "partial" })),
    ...input.tooLarge.map((path): NotRead => ({ kind: "file", path, reason: "too-large" })),
    ...input.binaries.map((f): NotRead => ({ kind: "file", path: f.path, reason: "binary" })),
  ];

  const deps = dependencyNamesOf(input.pkg.manifest).map((name): NotRead => ({ kind: "dependency", name }));

  return [...files, ...deps];
}

function finish(input: { name: string; version: string; previous: string | null; pkg: PackageFiles; b: Budget; extra: readonly string[]; inScope: number; binaries: readonly TarEntry[]; tooLarge: readonly string[] }): ReviewInput {
  const { b } = input;
  const extra = b.omitted.length > 0 ? [...input.extra, `Not shown (budget): ${b.omitted.length} files`] : input.extra;
  const text = `${header({ name: input.name, version: input.version, previous: input.previous, pkg: input.pkg, extra })}\n\n${b.parts.join("\n")}`;
  const read = b.read.filter((p, i) => b.read.indexOf(p) === i);

  return {
    name: input.name,
    version: input.version,
    coverage: { mode: input.previous === null ? "files" : "diff", previousVersion: input.previous, filesInScope: input.inScope, filesRead: read.length },
    text,
    estTokens: Math.ceil(text.length / CHARS_PER_TOKEN),
    read,
    notRead: notReadOf(b, { binaries: input.binaries, tooLarge: input.tooLarge, pkg: input.pkg }),
  };
}

export type BuildOptions = { budgetTokens?: number };

/** A first publish, or a version whose previous one is not available: the files themselves. */
export function buildFilesInput(input: { name: string; version: string; pkg: PackageFiles } & BuildOptions): ReviewInput {
  const { pkg } = input;
  const b = new Budget(Math.floor((input.budgetTokens ?? DEFAULT_BUDGET_TOKENS) * CHARS_PER_TOKEN));
  const all = pkg.files.map((f) => `${f.path} (${f.size} bytes)`);
  const listing = all.length > 200 ? [...all.slice(0, 200), `…and ${all.length - 200} more files`] : all;

  b.add({ path: null, header: "=== FILE LIST ===", body: listing.join("\n"), share: 0.1 });
  const pj = pkg.files.find((f) => f.path === "package.json");

  if (pj) b.add({ path: "package.json", header: "=== FILE package.json ===", body: numbered(linesOf(textOf(pj))), share: 0.25 });
  const tooLarge: string[] = [];

  for (const f of ordered(pkg.manifest, pkg.files, pkg.files)) {
    if (f.data.length > MAX_DECODED_BYTES) tooLarge.push(f.path);
    else if (b.left < MIN_BLOCK_CHARS) b.skip(f.path);
    else b.add({ path: f.path, header: `=== FILE ${f.path} ===`, body: numbered(linesOf(textOf(f))), share: MAX_FILE_SHARE });
  }

  const inScope = pkg.files.filter((f) => f.path === "package.json" || isReviewable(f)).length;
  const binaries = pkg.files.filter((f) => kindOf(f) === "binary");

  return finish({ name: input.name, version: input.version, previous: null, pkg, b, extra: [], inScope, binaries, tooLarge });
}

function sameBytes(a: TarEntry, b: TarEntry): boolean {
  return a.size === b.size && Buffer.compare(Buffer.from(a.data), Buffer.from(b.data)) === 0;
}

function listed(label: string, items: readonly string[], max: number): string {
  return `${label} (${items.length}): ${items.slice(0, max).join(", ")}${items.length > max ? " …" : ""}`;
}

/** An update: package.json in full plus line diffs of added and changed files, numbered as in the new version. */
export function buildDiffInput(input: { name: string; version: string; previousVersion: string; pkg: PackageFiles; prev: PackageFiles } & BuildOptions): ReviewInput {
  const { pkg, prev } = input;
  const b = new Budget(Math.floor((input.budgetTokens ?? DEFAULT_BUDGET_TOKENS) * CHARS_PER_TOKEN));
  const before = new Map(prev.files.map((f) => [f.path, f]));
  const after = new Set(pkg.files.map((f) => f.path));
  const added = pkg.files.filter((f) => !before.has(f.path));
  const removed = prev.files.filter((f) => !after.has(f.path));

  const changed = pkg.files.filter((f) => {
    const o = before.get(f.path);

    return o !== undefined && !sameBytes(o, f);
  });

  const summary = [
    listed("Added files", added.map((f) => `${f.path} (${f.size} bytes)`), 60),
    listed("Removed files", removed.map((f) => f.path), 30),
    listed("Changed files", changed.map((f) => f.path), 60),
  ];

  const pj = pkg.files.find((f) => f.path === "package.json");
  const pjOld = before.get("package.json");
  const pjChanged = pj !== undefined && (pjOld === undefined || !sameBytes(pjOld, pj));

  if (pj) {
    const l = linesOf(textOf(pj));

    b.add({ path: "package.json", header: "=== FILE package.json (full, new version) ===", body: numbered(l), share: 0.25 });

    if (pjOld && pjChanged) {
      const h = diffLines(linesOf(textOf(pjOld)), l);

      if (h.length > 0) b.add({ path: null, header: "=== DIFF package.json ===", body: renderHunks(h), share: 0.15 });
    }
  }

  const isAdded = new Set(added.map((f) => f.path));
  const tooLarge: string[] = [];

  for (const f of ordered(pkg.manifest, pkg.files, [...added, ...changed], (x) => isAdded.has(x.path))) {
    const old = before.get(f.path);

    if (f.data.length > MAX_DECODED_BYTES || (old && old.data.length > MAX_DECODED_BYTES)) {
      tooLarge.push(f.path);
      continue;
    }

    if (b.left < MIN_BLOCK_CHARS) {
      b.skip(f.path);
      continue;
    }

    const l = linesOf(textOf(f));

    if (!old) {
      b.add({ path: f.path, header: `=== NEW FILE ${f.path} ===`, body: numbered(l), share: MAX_FILE_SHARE });
      continue;
    }

    const h = diffLines(linesOf(textOf(old)), l);

    // only line endings or trailing bytes changed: nothing to show, nothing hidden
    if (h.length === 0) b.read.push(f.path);
    else b.add({ path: f.path, header: `=== DIFF ${f.path} ===`, body: renderHunks(h), share: DIFF_FILE_SHARE });
  }

  const touched = [...added, ...changed];
  const inScope = touched.filter((f) => f.path === "package.json" || isReviewable(f)).length;
  const binaries = touched.filter((f) => kindOf(f) === "binary");
  const read = pjChanged ? b.read : b.read.filter((p) => p !== "package.json");
  const partial = pjChanged ? b.partial : b.partial.filter((p) => p !== "package.json");

  b.read.splice(0, b.read.length, ...read);
  b.partial.splice(0, b.partial.length, ...partial);

  return finish({ name: input.name, version: input.version, previous: input.previousVersion, pkg, b, extra: summary, inScope, binaries, tooLarge });
}

/** The diff when the previous version is known, else the files. */
export function buildReviewInput(input: { name: string; version: string; pkg: PackageFiles; previous: { version: string; pkg: PackageFiles } | null } & BuildOptions): ReviewInput {
  const budgetTokens = input.budgetTokens ?? DEFAULT_BUDGET_TOKENS;

  if (input.previous === null) return buildFilesInput({ name: input.name, version: input.version, pkg: input.pkg, budgetTokens });

  return buildDiffInput({ name: input.name, version: input.version, previousVersion: input.previous.version, pkg: input.pkg, prev: input.previous.pkg, budgetTokens });
}
