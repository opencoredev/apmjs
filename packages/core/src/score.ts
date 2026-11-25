// apm-score: a per-version safety score. Pure functions, tarball and history in, report out.
// 100 means nothing risky was found. Every deduction is a named signal with evidence.
// Popularity is deliberately not an input: it is gameable and says nothing about compromise.
// What the analysis reads and what it cannot catch is written up in docs/SCORE.md.
import { MAX_SCAN_TEMP_BYTES, withKeepLimit } from "./kept.ts";
import { z } from "zod";
import { dependencySpecs, isRegistryDependency } from "./deps.ts";
import { entryPoints, targetFiles } from "./entries.ts";
import { boundedManifest, MANIFEST_LIMITS, measureManifest } from "./manifest.ts";
import { MAX_ANALYZED_FILE_BYTES, MAX_SCANNED_BYTES, SKIP_REASONS, type SkippedFile } from "./limits.ts";
import { charge, chargeText, inPhase, MAX_ANALYSIS_WORK, Meter, MeterExhausted, PHASE_NAMES, withMeter, type Phase } from "./meter.ts";
import { isEstablishedName, typoConflicts, type NameHistory } from "./names.ts";
import { commandWords, commandWordsWithin, expandHooks, gypCommands, isInlineDownload, otherScripts, type ExpandedHook, type HookKind, type ShellWords } from "./scripts.ts";
import { importsOf, joinStrings, langOf, scanFile, scanText, type Confidence, type Lang, type ExecutedCode, type FlowFinding, type Hidden, type Imports, type TextFinding } from "./source.ts";
import { scanTextRules } from "./textrules.ts";
import { keptBytes, MAX_KEPT_VIEW_BYTES, scanBinaryImports, scanBinaryText, type BinaryTextScan } from "./binary-text.ts";
import { hasDataMagic, isExecutable, NATIVE_NAME, nativeBefore, readAsTextBefore } from "./executable.ts";
import { ambiguousPaths, MemoryRefused, type HoldRule, type LookAt, type StreamMemory, type TarEntry } from "./tarball.ts";
import { CAPABILITY_IDS, declarationOf, matchesPattern, type CapabilityId, type Declaration } from "./declare.ts";
import { factsOf as readFacts, RISK_FACT_KINDS, secretFamily, type Fact } from "./facts.ts";
import { boundOf, PRECISION_BOUNDS, type Bound, type Exports, type Label, type Sink } from "./flow.ts";
import { CrossFile, MAX_CROSS_FILE_STEPS } from "./xfile.ts";

export { CAPABILITY_IDS, declarationOf, type CapabilityId, type Declaration } from "./declare.ts";

export { isInlineDownload } from "./scripts.ts";

export const SIGNAL_IDS = [
  "install-script",
  "shell-exec",
  "network",
  "credential-access",
  "eval",
  "obfuscated",
  "binary",
  "new-publisher",
  "no-license",
  "typosquat",
  "install-download",
  "risky-dependency",
  "new-dependency",
  "incomplete",
  "recent",
  "deprecated",
  "yanked",
  "revoked",
  "git-install-script",
  "dynamic-require",
  "unanalyzed-files",
  // apm-score-v10's risk signals; the code signals above (shell-exec, network, eval, binary, credential-access) are
  // capabilities since v10, and stay here so analyses stored by earlier scorers still read
  "install-network",
  "install-shell",
  "install-eval",
  "credential-read",
  "credential-mention",
  "encoded-data",
  "exfiltration",
  "capture-endpoint",
  "remote-shell",
  "runs-decoded-code",
  "suspicious-combination",
  "undeclared-capability",
] as const;

export type SignalId = (typeof SIGNAL_IDS)[number];

/**
 * v2 lists the files it could not read. v3 reads every file, follows install-script indirection and decodes cheap
 * encodings. v4 matches code rules against code only (not comments, regex literals or ordinary strings) and marks
 * what it could not see used as `possible`, for fewer points. v5 parses JavaScript and TypeScript with real parsers,
 * reads calls, aliases and evaluated strings from the tree, and confirms what a string holds only by its role. v6
 * resolves names by lexical scope, reads members of local objects (getters, Proxy traps, writes), follows every
 * operand that can be a callee and arguments through apply, bind and spreads, reads a file with no tree token by
 * token, and reads every file an exports or imports pattern exposes. v7 starts every parsed file from what v3 read in
 * its code (comments and regex literals left out) and lets the tree remove a finding only where it proves the token
 * harmless; a limit, a value it cannot follow or syntax it does not model leaves v3's finding standing. v8 keeps only
 * the proofs that rest on how code is read (comments, regex bodies, erased types, JSON). v9 keeps none: v3's rules read
 * all text, in every file v3 reads and every file v8 reads, and the tree can only add findings and choose citations.
 * v10 changes what costs points: what a package can do (network, environment, filesystem, processes, dynamic code,
 * native code, install scripts) is listed as a capability for nothing, each with v9's evidence, and points go to what
 * malware does (install-time network and processes, credential files read, the environment sent out, capture
 * endpoints, remote shells, obfuscation, look-alike names) and to capabilities a package's own declaration leaves out.
 * v11 separates what apm read from what it found: files left unread only for their size or the byte budget cost no
 * points (they cost -61 as `incomplete` and -20 as `unanalyzed-files` before) and are stated as the analysis's
 * `coverage`; a partial reading is graded "P", never a letter that reads as a pass. Every other reason an analysis is
 * `incomplete` (the work meter, a parser limit, code run from strings past what apm follows, a re-run that read less
 * after the platform stopped the runs before it) costs what it did. A file's flow reading that stopped at its work
 * allowance or its stack, in code that runs, or the cross-file reading at its budget, is `incomplete` (as it always
 * was), whose evidence names the stop. No signal id is added past v11's list (SIGNAL_IDS), so a report this scorer
 * writes parses under every apm-score-v11 parser.
 */
export const SCORER = "apm-score-v11";

/**
 * Every scorer name a stored analysis may carry. apm-score-v12 is here before any build writes it, so a build that
 * writes it can be rolled back to this one without its reports failing to parse (production-parser.test.ts).
 */
export const PARSED_SCORERS = ["apm-score-v1", "apm-score-v2", "apm-score-v3", "apm-score-v4", "apm-score-v5", "apm-score-v6", "apm-score-v7", "apm-score-v8", "apm-score-v9", "apm-score-v10", SCORER, "apm-score-v12"] as const;

const SignalSchema = z.object({
  id: z.enum(SIGNAL_IDS),
  label: z.string(),
  points: z.number(),
  evidence: z.array(z.string()),
  // analyses before v4 asserted every signal
  confidence: z.enum(["confirmed", "possible"]).default("confirmed"),
  /** Evidence past the five shown, so a reviewer's dismissal can tell when none is left. */
  more: z.array(z.string()).optional(),
  /** Evidence past `evidence` and `more`, counted, not kept. */
  uncounted: z.number().optional(),
  /**
   * Every source the signal's evidence cites (see `citedSource`), including evidence past `more`. Set only when
   * evidence was counted and not kept, so no file the analysis cited is lost to the display cap.
   */
  sources: z.array(z.string()).optional(),
  /** A confirmed signal's possible evidence: what the signal falls back to when every confirmed item is dismissed. */
  fallback: z.array(z.string()).optional(),
});

/** One evidence item an apm reviewer dismissed (see `applyDismissals`), shown struck through with the reason. */
const DismissedSchema = z.object({
  signal: z.enum(SIGNAL_IDS),
  file: z.string(),
  line: z.number(),
  evidence: z.array(z.string()),
  reason: z.string(),
  at: z.number(),
});

const FactsSchema = z.object({
  moduleFormat: z.enum(["esm", "cjs", "dual"]),
  types: z.enum(["bundled", "none"]),
  installScripts: z.boolean(),
  hasBin: z.boolean(),
  license: z.string().nullable(),
  fileCount: z.number(),
  unpackedSize: z.number(),
  dependencyCount: z.number(),
});

const SkippedSchema = z.object({ path: z.string(), size: z.number(), reason: z.enum(SKIP_REASONS) });

/**
 * Why files went unread, for `coverage`: "too-large", one over the size a file may be (MAX_ANALYZED_FILE_BYTES);
 * "over-budget", past the bytes one analysis reads (a tarball read as a stream holds only its budget of them);
 * "stopped", the analysis stopped before it read what it had (the work meter, a package.json past what apm reads, a
 * run that failed), so nothing it holds was read.
 */
export const COVERAGE_REASONS = ["too-large", "over-budget", "stopped"] as const;

/**
 * How much of the version apm read (apm-score-v11). Complete: every file the analysis would read was read. Partial:
 * `omittedFiles` files of `omittedBytes` were not, for `reasons`; `notes` say what else limited the reading (the import
 * graph of a tarball read as a stream). A partial reading is not a finding: size and budget omissions cost no points,
 * and installs check coverage apart from the score (registry warnings.ts, apm.ts policyBlock).
 */
const CoverageSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("complete") }),
  z.object({ kind: z.literal("partial"), omittedFiles: z.number(), omittedBytes: z.number(), reasons: z.array(z.enum(COVERAGE_REASONS)), notes: z.array(z.string()).default([]) }),
]);

/**
 * A capability (apm-score-v10): something the package can do, shown with its evidence and never scored on its own.
 * `status` compares it with the package's declaration: `declared` and `undeclared` when the package declares
 * capabilities, `not-declared` when it declares none, `unused` for a declared capability apm saw no use of. `basis`
 * says what the evidence rests on: a call or load the parsed program showed (or a command, a file, a script), only
 * text matches, or only possible evidence.
 */
const CapabilitySchema = z.object({
  id: z.enum(CAPABILITY_IDS),
  label: z.string(),
  status: z.enum(["declared", "undeclared", "not-declared", "unused"]),
  basis: z.enum(["code", "text", "possible", "none"]),
  /** What the declaration says for this capability, as written. */
  declared: z.string().optional(),
  evidence: z.array(z.string()),
  more: z.array(z.string()).optional(),
  uncounted: z.number().optional(),
  sources: z.array(z.string()).optional(),
  /** For `env`: the variable names read (`*` for a name built at runtime). */
  names: z.array(z.string()).optional(),
  /** Names read that a declared list does not cover. Shown, not scored. */
  outside: z.array(z.string()).optional(),
});

/**
 * What a static read of the tarball cannot see, in plain words. Shown with every score; docs/SCORE.md explains each.
 * The website shows this list as written and folds the per-file reading limits (LIMIT_NOTES in js.ts) into one line.
 */
export const NOT_CHECKED: readonly string[] = [
  "runtime behavior: what the code does when it runs, such as downloading or unpacking more code, or deleting files",
  "code hidden by a custom encoding, compression or encryption",
  "the code of its dependencies, beyond their own scores",
  "where the code sends what it sends: a request to an API and one to an attacker look the same, so network use alone, or one named token sent in a request, costs nothing",
  "native binaries and WebAssembly: listed, not read",
  "whether the publisher's machine or CI was compromised",
];

const AnalysisSchema = z.object({
  scorer: z.enum(PARSED_SCORERS),
  signals: z.array(SignalSchema),
  facts: FactsSchema,
  notChecked: z.array(z.string()).default([...NOT_CHECKED]),
  skipped: z.array(SkippedSchema).default([]),
  /** Evidence an apm reviewer dismissed for these exact bytes and this scorer; the score leaves it out. */
  dismissed: z.array(DismissedSchema).optional(),
  /** What the package can do (apm-score-v10); empty for earlier scorers. */
  capabilities: z.array(CapabilitySchema).default([]),
  /** Whether the package declares its capabilities, and what apm could not use in the declaration. */
  declaration: z.object({ kind: z.enum(["none", "declared"]), notes: z.array(z.string()) }).optional(),
  /** How much of the version apm read (apm-score-v11); absent from analyses earlier scorers stored. */
  coverage: CoverageSchema.optional(),
});

export type Signal = z.infer<typeof SignalSchema>;

export type Facts = z.infer<typeof FactsSchema>;

export type ModuleFormat = Facts["moduleFormat"];

export type Analysis = z.infer<typeof AnalysisSchema>;

export type Coverage = z.infer<typeof CoverageSchema>;

/** The partial coverage of an analysis, or null when it read everything it would (or an earlier scorer stored none). */
export function partialCoverage(a: Pick<Analysis, "coverage">): Extract<Coverage, { kind: "partial" }> | null {
  return a.coverage?.kind === "partial" ? a.coverage : null;
}

/** "2,656 files (74.0 MB) not read", the words every surface uses for a partial reading. */
export function coverageText(c: Extract<Coverage, { kind: "partial" }>): string {
  // an analysis that stopped left nothing it can count: it read no file it could vouch for
  if (c.reasons.includes("stopped")) return "its analysis stopped before it finished, so nothing in it was cleared";

  return `${c.omittedFiles.toLocaleString("en-US")} file${c.omittedFiles === 1 ? "" : "s"} (${(c.omittedBytes / 1_000_000).toFixed(1)} MB) not read`;
}

/** A folder of files apm did not read, for saying where they are: its path ("." for the package's top level), how many files and bytes. */
export type OmittedFolder = { path: string; files: number; bytes: number };

/** How many folders a summary of unread files names. */
export const OMITTED_FOLDERS_SHOWN = 3;

/**
 * Folder names common to npm packages' build output and layout. A skipped file's folder is named publicly only when
 * every part of it (at most two) is one of these: a publisher's own folder name can hold anything, a secret included,
 * and a version's summary can be public while its tarball is not (confirmed malicious, unpublished upstream).
 */
export const KNOWN_FOLDERS: ReadonlySet<string> = new Set([
  "dist", "lib", "build", "out", "es", "esm", "cjs", "umd", "mjs", "compiled", "bundle", "bundles", "vendor", "src", "bin",
  "types", "typings", "prebuilds", "native", "assets", "static", "public", "docs", "doc", "test", "tests", "__tests__",
  "fixtures", "examples", "locales", "locale", "i18n", "fonts", "images", "img", "wasm", "node_modules", "server", "client",
  "browser", "node", "cli", "core", "runtime", "modules", "scripts", "styles", "css", "icons", "data", "generated",
  "release", "binding", "bindings", "napi", "legacy", "experimental", "shared", "internal", "plugins", "templates",
]);

/** A skipped file's folder as shown: "." for the package root, its first two parts when all are known, else null. */
export function folderLabel(path: string): string | null {
  const parts = path.split("/").slice(0, -1).slice(0, 2);

  if (parts.length === 0) return ".";

  return parts.every((p) => KNOWN_FOLDERS.has(p)) ? parts.join("/") : null;
}

/**
 * The folders that hold the most unread bytes, biggest first, at most OMITTED_FOLDERS_SHOWN: each file counts under its
 * first two folders (`dist/compiled/webpack/bundle5.js` under `dist/compiled`), a file at the top level under ".".
 * Each path counts once, whichever walk skipped it.
 */
export function omittedFolders(skipped: readonly { path: string; size: number }[]): OmittedFolder[] {
  const byPath = new Map(skipped.map((s) => [s.path, s.size]));
  const folders = new Map<string, OmittedFolder>();

  for (const [path, size] of byPath) {
    const key = folderLabel(path);

    // a folder the publisher named freely is never repeated (review of c93d72e, finding 1): it is only counted
    if (key === null) continue;
    const f = folders.get(key) ?? { path: key, files: 0, bytes: 0 };
    folders.set(key, { path: key, files: f.files + 1, bytes: f.bytes + size });
  }

  return [...folders.values()].toSorted((a, b) => b.bytes - a.bytes || a.path.localeCompare(b.path)).slice(0, OMITTED_FOLDERS_SHOWN);
}

export type DismissedEvidence = z.infer<typeof DismissedSchema>;

export type Capability = z.infer<typeof CapabilitySchema>;

/** A to F by score; "P" for a partial reading (apm-score-v11), whatever its score: a partial reading is not graded. */
export type Grade = "A" | "B" | "C" | "D" | "F" | "P";

export type ScoreReport = Analysis & { score: number; grade: Grade };

export const SCORE_FLOOR = 40;
export const COOLDOWN_MS = 24 * 60 * 60 * 1000;

/**
 * Signals that make an install verdict review-first wherever they cost points, whatever the score (docs/AGENTS.md,
 * "Risk signals"). The website and the CLI each keep a copy (apps/web/lib/agent/verdict.ts, packages/cli/src/explain.ts)
 * that their tests hold equal to this one; the registry reads it to list dependencies with a risk.
 */
export const RISK_SIGNALS = ["remote-shell", "capture-endpoint", "exfiltration", "credential-read", "install-download", "install-network", "runs-decoded-code", "obfuscated", "suspicious-combination", "typosquat"] as const;

/**
 * Signals scorers before apm-score-v10 gave a risk's meaning that v10 split up: v9's `credential-access` is v10's
 * credential-read and exfiltration (and credential-mention, for a name alone). An analysis an earlier scorer stored
 * keeps its ids until it is analysed again, so these count as risks in it. The other v9 code signals (shell-exec,
 * network, eval, binary) are capabilities, as v10 reads them, and `obfuscated` is in RISK_SIGNALS already.
 */
export const LEGACY_RISK_SIGNALS = ["credential-access"] as const;

/** Signals that say apm did not read or finish everything: an install verdict holds every analysis with one. */
export const GAP_SIGNALS = ["incomplete", "unanalyzed-files"] as const;

/** Risk signals about the name rather than the code: they count unless the name is an established one. */
export const NAME_RISK_SIGNALS = ["typosquat"] as const;

/**
 * Dependency names the look-alike rule flags that are long-established packages in their own right, each checked by
 * hand: safer-buffer (express installs it; one edit from safe-buffer, published by a Node.js core contributor since
 * 2018). Only as a dependency, never as the name an install asks for, and only the name signal. Add to it only with
 * the package's own record checked; the website's and the CLI's verdicts keep copies their tests hold equal.
 */
export const ESTABLISHED_DEPENDENCY_NAMES = ["safer-buffer"] as const;

/**
 * The risk signals in a report that cost points: RISK_SIGNALS (less NAME_RISK_SIGNALS for a dependency whose name is
 * in ESTABLISHED_DEPENDENCY_NAMES), and LEGACY_RISK_SIGNALS in an earlier scorer's analysis.
 */
export function riskSignalsIn(report: { scorer?: string; signals: readonly { id: string; points: number }[] }, of: { kind: "version" } | { kind: "dependency"; name: string } = { kind: "version" }): { id: string; points: number }[] {
  // apm-score-v10 split v9's credential-access, and every scorer since keeps v10's ids
  const split: readonly string[] = ["apm-score-v10", SCORER, "apm-score-v12"];
  const legacy = report.scorer === undefined || !split.includes(report.scorer);
  const exempt = of.kind === "dependency" && ESTABLISHED_DEPENDENCY_NAMES.some((n) => n === of.name);
  const counts = (id: string): boolean => (RISK_SIGNALS.some((r) => r === id) && !(exempt && NAME_RISK_SIGNALS.some((n) => n === id))) || (legacy && LEGACY_RISK_SIGNALS.some((r) => r === id));

  return report.signals.filter((s) => s.points < 0 && counts(s.id));
}

/**
 * The one reason a reading may leave something unread and still install (docs/AGENTS.md): whole files left unread for
 * their size or the bytes one analysis reads (COVERAGE_REASONS less "stopped"). A short allowlist on purpose: anything
 * not on it holds the install.
 */
export const BENIGN_OMISSIONS = ["too-large", "over-budget"] as const;

/**
 * How much of a version apm read, as the install verdict and the grade read it (fail-closed):
 * - complete: the analysis left nothing unread and has no GAP_SIGNALS. An earlier scorer that stored no coverage
 *   counted every file it left unread as a gap signal, so one with none read all of it; the current scorer always
 *   states coverage, and an analysis of its own without it is incomplete.
 * - partial: the current scorer recorded that it left whole files unread, every reason for which is on
 *   BENIGN_OMISSIONS, and nothing else is unfinished (no GAP_SIGNALS). Graded "P"; installs with a note.
 * - incomplete: anything else, an empty or unknown list of reasons included. The install verdict holds it. `why` says
 *   which: `signal`, the analysis has `incomplete`; `legacy-gap`, an earlier scorer's `unanalyzed-files` (files it
 *   left unread, which it counted as a gap); `no-coverage`, the current scorer's analysis with no coverage record;
 *   `coverage`, partial coverage that is not the allowlisted kind (a reason off BENIGN_OMISSIONS, none at all, or
 *   another scorer's).
 */
export type Reading =
  | { kind: "complete" }
  | { kind: "partial"; coverage: Extract<Coverage, { kind: "partial" }> }
  | { kind: "incomplete"; why: "signal" | "legacy-gap" | "no-coverage" } | { kind: "incomplete"; why: "coverage"; coverage: Extract<Coverage, { kind: "partial" }> };

/**
 * The scorers that always state coverage and grade a partial reading "P": apm-score-v11 and every one since. A package
 * published on apm keeps the analysis made at its publish, so a v11 reading of one keeps reading as v11 wrote it.
 */
export const COVERAGE_SCORERS = [SCORER, "apm-score-v12"] as const;

function statesCoverage(scorer: Analysis["scorer"]): boolean {
  return COVERAGE_SCORERS.some((s) => s === scorer);
}

export function readingOf(a: Pick<Analysis, "scorer" | "signals" | "coverage">): Reading {
  if (a.signals.some((s) => s.id === "incomplete")) return { kind: "incomplete", why: "signal" };

  if (a.signals.some((s) => GAP_SIGNALS.some((g) => g === s.id))) return { kind: "incomplete", why: "legacy-gap" };
  const c = a.coverage;

  if (c === undefined) return statesCoverage(a.scorer) ? { kind: "incomplete", why: "no-coverage" } : { kind: "complete" };

  if (c.kind === "complete") return c;
  const benign = c.reasons.length > 0 && c.reasons.every((r) => BENIGN_OMISSIONS.some((b) => b === r));

  return statesCoverage(a.scorer) && benign ? { kind: "partial", coverage: c } : { kind: "incomplete", why: "coverage", coverage: c };
}

/**
 * What each signal costs (apm-score-v10). docs/SCORE.md gives the reason for each weight. The code signals v9 scored
 * (shell-exec, network, eval, binary, credential-access) keep their v9 points here only so a stored v9 analysis reads
 * the same; v10 never raises them, it lists those as capabilities.
 */
export const POINTS: Record<SignalId, number> = {
  // install time: what runs on `npm install`, by what it does there
  "install-script": -10,
  "install-network": -25,
  "install-shell": -15,
  "install-eval": -15,
  "install-download": -40,
  "git-install-script": -10,
  // what stealers and droppers do
  "credential-read": -30,
  exfiltration: -35,
  "capture-endpoint": -50,
  "remote-shell": -50,
  "runs-decoded-code": -25,
  obfuscated: -20,
  "suspicious-combination": -15,
  // weak evidence: text that only names a credential, data that only looks encoded
  "credential-mention": -3,
  "encoded-data": -2,
  // who and what
  typosquat: -20,
  "new-publisher": -10,
  "risky-dependency": -30,
  "new-dependency": -5,
  // a declaring package's first undeclared capability; each further one costs UNDECLARED_MORE, to UNDECLARED_MAX
  "undeclared-capability": -10,
  // status
  deprecated: -5,
  yanked: -10,
  revoked: -100,
  // an analysis that did not read every file that runs can never pass the floor on its own
  incomplete: -(100 - SCORE_FLOOR + 1),
  "unanalyzed-files": -20,
  // informational: age is handled by the cooldown; plugin loaders compute requires honestly; a license is not a risk
  recent: 0,
  "dynamic-require": 0,
  "no-license": 0,
  // apm-score-v9 and earlier only (capabilities since v10)
  "shell-exec": -15,
  network: -10,
  eval: -10,
  binary: -5,
  "credential-access": -25,
};

/**
 * What a flow the parser confirmed costs on its own, whatever else the package does: code or a command it downloaded
 * and runs (`remote-shell`), or the whole environment, a credential file's contents or three families of tokens sent in
 * a request (`exfiltration`). Enough to refuse alone. When only a character window suggests the same thing, the signal
 * keeps its table points (`POINTS`).
 */
export const CONFIRMED_FLOW_POINTS = -(100 - SCORE_FLOOR + 1);

/** `credential-mention` when the name sits next to a file read that apm did not see it reach. */
export const MENTION_NEAR_READ_POINTS = -10;

const UNDECLARED_MORE = -5;
const UNDECLARED_MAX = -20;

/** Each unusual combination past the first adds this, to COMBINATION_MAX. */
const COMBINATION_MORE = -10;
const COMBINATION_MAX = -30;

/** Signals whose evidence a text rule can only suspect, and what each costs then: a third or so of the confirmed points. */
type CodeSignalId = "shell-exec" | "network" | "credential-access" | "eval" | "obfuscated" | "credential-read" | "credential-mention" | "encoded-data";

export const POSSIBLE_POINTS: Record<CodeSignalId, number> = {
  "shell-exec": -5,
  network: -3,
  "credential-access": -8,
  eval: -3,
  obfuscated: -7,
  "credential-read": -10,
  "credential-mention": -1,
  "encoded-data": -1,
};

const POSSIBLE_LABELS: Record<CodeSignalId, string> = {
  "shell-exec": "Possible shell use: names a shell command or child_process, but apm did not see one started",
  network: "Possible network use: names a request or download, but apm did not see one made",
  "credential-access": "Possible credential access: names a credential file or token, but apm did not see it read",
  eval: "Possible eval: keeps a way to run code built at runtime, but apm did not see it used",
  obfuscated: "Possibly obfuscated: holds encoded or assembled text that apm did not see run",
  "credential-read": "Possible credential read: names a credential file near a read, but apm did not see it read",
  "credential-mention": "Possibly names a credential file or token variable",
  "encoded-data": "Possibly holds encoded data",
};

/**
 * A confirmed v9 code signal whose every piece of evidence is a text match (no call or load the parsed program showed)
 * says what was found, not what the code does. The points are the same: v3's rules count the match.
 */
const TEXT_LABELS: Partial<Record<CodeSignalId, string>> = {
  "shell-exec": "Mentions a shell command or child_process; apm did not see one started",
  network: "Mentions a network call (fetch, http, a socket); apm did not see a request made",
  "credential-access": "Mentions a credential file (.npmrc, .ssh) or secret variable; apm did not see one read",
  eval: "Mentions a way to run code built at runtime (eval, Function, vm); apm did not see it called",
  obfuscated: "Holds encoded or escaped text (base64, \\x runs, _0x names); apm did not see it run",
};

export function isCodeSignal(id: SignalId): id is CodeSignalId {
  return id in POSSIBLE_POINTS;
}

const LABELS: Record<SignalId, string> = {
  "install-script": "Runs a script at install time (preinstall, install or postinstall)",
  "shell-exec": "Starts shell commands or child processes, or loads child_process",
  network: "Uses the network: fetch, http, sockets, or a module that makes requests",
  "credential-access": "Reads credential files or secret environment variables",
  eval: "Evaluates code built at runtime (eval, Function, vm)",
  obfuscated: "Obfuscated: obfuscator output, or dangerous names hidden by joining or encoding strings",
  binary: "Ships compiled binaries that cannot be reviewed as source",
  "new-publisher": "Published by an account that never published this package before",
  "no-license": "No license declared",
  typosquat: "Name looks like a popular package's",
  "install-download": "Install script downloads or runs code inline (curl | sh, npx, node -e with network)",
  "risky-dependency": "Depends on a package that scores below the floor",
  "new-dependency": "Adds dependencies the previous version did not have",
  incomplete: "Some code that runs was too large to analyze, so this version is unverified",
  recent: "Published less than 24 hours ago; most malicious versions are caught within hours",
  deprecated: "Deprecated by its maintainer",
  yanked: "Yanked: hidden from new installs by its maintainer",
  revoked: "Revoked: pulled as malicious or compromised",
  "git-install-script": "Runs shell or network commands when installed from git (prepare, prepack)",
  "dynamic-require": "Loads code by a name built at runtime, so apm could not tell which file runs",
  "unanalyzed-files": "Some files were not analyzed: the package is larger than the analysis reads",
  "install-network": "Uses the network at install time",
  "install-shell": "Starts processes at install time",
  "install-eval": "Runs code built at runtime at install time",
  "credential-read": "Reads credential files (.npmrc, .ssh, cloud credentials, browser profiles)",
  "credential-mention": "Names a credential file or token variable; apm did not see a credential file read",
  "encoded-data": "Holds long encoded data (base64 or \\x runs) that decodes to no readable text",
  exfiltration: "Collects the environment, secrets or machine details and uses the network in the same code",
  "capture-endpoint": "Sends to a data-capture endpoint (a request bin, a webhook with its key, a raw tunnel)",
  "remote-shell": "Opens a remote shell, or downloads code and runs it",
  "runs-decoded-code": "Runs code it decoded or assembled from strings, or keeps a network, process or credential call inside a string it runs",
  "suspicious-combination": "Combines capabilities the way malware does",
  "undeclared-capability": "Uses a capability its own package.json declaration leaves out",
};

/** What each capability is, in the words the version page and the CLI use. */
export const CAPABILITY_LABELS: Record<CapabilityId, string> = {
  network: "Network: makes requests or opens sockets",
  env: "Environment variables: reads process.env",
  filesystem: "Filesystem: loads fs to read or write files",
  shell: "Processes and shell: starts commands or loads child_process",
  eval: "Dynamic code: eval, Function, vm or a Worker from a string",
  native: "Native code: ships compiled binaries or builds an addon",
  install: "Install scripts: runs code when the package is installed",
};

/** Files that run by name: node, bun, deno, shells, PowerShell and Python. */
const CODE_EXT = /\.(?:[cm]?[jt]sx?|sh|bash|ps1|py|cmd|bat)$/i;

/**
 * Files that never run by their name: docs, types, source maps, JSON, styles and markup. They are read
 * when code reaches them by a path apm can resolve; otherwise they are left out, or every README with
 * `curl ... | sh` in its install instructions would read as a dropper.
 */
const NOT_CODE = /(?:^|\/)(?:readme|changelog|changes|history|license|licence|copying|authors|contributors|notice|security|code_of_conduct)(?:\.(?!(?:[\w.-]*\.)?(?:[cm]?[jt]sx?|sh|bash|ps1|py|cmd|bat)$)[\w.-]*)?$|\.(?:md|markdown|mdx|txt|rst|adoc|d\.[cm]?ts|map|json|jsonc|json5|ya?ml|toml|css|scss|sass|less|styl|html?|svg|xml|csv|tsv|lock|flow)$/i;

/**
 * Executables and native modules, listed as `binary` and not read as code: a native name, or an ELF or Mach-O file
 * whose structure parses (executable.ts). A magic number alone is not enough: `cf fa ed fe`, a newline and shell
 * commands is a script `sh` runs (review of 1978ee3, P1). A file something runs through an interpreter is read as
 * source whatever this says (`invokedFiles`). Before apm-score-v12 the magic was joined with `<<` into a signed 32-bit
 * number, so no Mach-O matched and a 24 MB macOS executable was read as JavaScript until the platform stopped the run.
 */
function isBinary(e: TarEntry): boolean {
  return NATIVE_NAME.test(e.path) || isExecutable(e.data, e.size);
}

/**
 * A file node loads as JavaScript (an entry point, a file code requires) that is native code all the same: a `.node`
 * addon, which node opens as one, or an executable by its structure, which is not JavaScript node could run. Any other
 * native name (`index.so`) holding JavaScript runs as JavaScript, so it is read.
 */
function isNativeEntry(e: TarEntry): boolean {
  return e.path.endsWith(".node") || isExecutable(e.data, e.size);
}

/**
 * Files something runs through an interpreter or executes by path: every file a package.json script names (a lifecycle
 * hook or any other script), and every `bin` target (npm links it, and a shell runs one the kernel will not load as a
 * script). Each is read as source whatever its bytes, and still listed as native code when it is an executable: an
 * interpreter reads the bytes as text even when a valid header comes first. Commands found in code add theirs as the
 * walk finds them (analyze).
 */
function invokedFiles(manifest: AnalyzeInput["manifest"], byPath: ReadonlyMap<string, TarEntry>, hooks: readonly ExpandedHook[]): Set<string> {
  const out = new Set<string>();

  const take = (word: string): void => {
    const f = resolveIn(byPath, word);

    if (f && f.path !== "package.json") out.add(f.path);
  };

  const commands = [...hooks.flatMap((h) => h.commands.map((c) => c.text)), ...Object.values(otherScripts(manifest, hooks))];

  for (const c of commands) for (const w of [...scriptTargets(c), ...commandWords(c)]) take(w);

  for (const e of entryPoints(manifest)) if (e.field.startsWith("bin")) take(e.path);

  return out;
}

/** Images, fonts, archives and WebAssembly, recognised by their first bytes. JavaScript cannot start with these. */
function isBinaryData(e: TarEntry): boolean {
  return hasDataMagic(e.data);
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function hasTypesCondition(v: unknown): boolean {
  if (!isRecord(v)) return false;

  return Object.entries(v).some(([k, val]) => k === "types" || hasTypesCondition(val));
}

function hasCondition(v: unknown, cond: string): boolean {
  if (!isRecord(v)) return false;

  return Object.entries(v).some(([k, val]) => k === cond || hasCondition(val, cond));
}

export function moduleFormatOf(manifest: Record<string, unknown>): ModuleFormat {
  const exp = manifest.exports;

  if (hasCondition(exp, "import") && hasCondition(exp, "require")) return "dual";

  if (manifest.type === "module") return "esm";

  if (typeof manifest.module === "string" && typeof manifest.main === "string") return "dual";

  return "cjs";
}

const INSTALL_SCRIPTS = ["preinstall", "install", "postinstall"] as const;

export function installScriptsOf(manifest: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  const scripts = manifest.scripts;

  if (!isRecord(scripts)) return out;

  for (const k of INSTALL_SCRIPTS) {
    const v = scripts[k];

    if (typeof v === "string" && v.trim()) out[k] = v;
  }

  return out;
}

export function factsOf(manifest: Record<string, unknown>, files: readonly TarEntry[]): Facts {
  const deps = isRecord(manifest.dependencies) ? Object.keys(manifest.dependencies).length : 0;
  const typesField = typeof manifest.types === "string" || typeof manifest.typings === "string";
  const dts = files.some((f) => f.path.endsWith(".d.ts") || f.path.endsWith(".d.mts") || f.path.endsWith(".d.cts"));

  return {
    moduleFormat: moduleFormatOf(manifest),
    types: typesField || hasTypesCondition(manifest.exports) || dts ? "bundled" : "none",
    installScripts: Object.keys(installScriptsOf(manifest)).length > 0 || files.some((f) => f.path === "binding.gyp"),
    hasBin: typeof manifest.bin === "string" || isRecord(manifest.bin),
    license: typeof manifest.license === "string" && manifest.license.trim() ? manifest.license : null,
    fileCount: files.length,
    unpackedSize: files.reduce((n, f) => n + f.size, 0),
    dependencyCount: deps,
  };
}

/** Marks evidence cited from a test file: shipped, so it is read, but nothing an installer runs loads it as a rule. */
export const IN_TEST_FILE = " (in a test file)";

/** Test files: under a test directory, or named `*.test.*` or `*.spec.*`. */
export function isTestPath(path: string): boolean {
  return /(?:^|\/)(?:__tests__|__mocks__|tests?|spec)\//i.test(path) || /\.(?:test|spec)\.[cm]?[jt]sx?$/i.test(path);
}

/** The evidence a signal shows, and what it keeps past that for a reviewer's dismissal. */
const SHOWN_EVIDENCE = 5;
const KEPT_EVIDENCE = 100;

/** Whether a piece of evidence is a text match only, not a call or load the parsed program showed (any scorer's wording). */
export function isTextEvidence(e: string): boolean {
  return e.includes(TEXT_MATCH_MARK);
}

function labelOf(id: SignalId, confidence: Confidence, evidence: readonly string[]): string {
  if (!isCodeSignal(id)) return LABELS[id];

  if (confidence === "possible") return POSSIBLE_LABELS[id];
  const text = TEXT_LABELS[id];

  return text !== undefined && evidence.length > 0 && evidence.every(isTextEvidence) ? text : LABELS[id];
}

/** Past the shown evidence: what is kept for a reviewer's dismissal, and how many more were not kept. */
function keepRest(out: Signal, sorted: readonly string[]): Signal {
  if (sorted.length > SHOWN_EVIDENCE) out.more = sorted.slice(SHOWN_EVIDENCE, KEPT_EVIDENCE);

  if (sorted.length > KEPT_EVIDENCE) {
    out.uncounted = sorted.length - KEPT_EVIDENCE;
    // the display cap drops evidence; the sources it cites are kept, so every cited file stays on record
    out.sources = [...new Set(sorted.map(citedSource))];
  }

  return out;
}

function signal(id: SignalId, all: string[], confidence: Confidence = "confirmed", fallback: readonly string[] = []): Signal {
  // what the package itself ships is cited before what only its tests do
  const sorted = [...all].sort((a, b) => Number(a.includes(IN_TEST_FILE)) - Number(b.includes(IN_TEST_FILE)));
  const evidence = sorted.slice(0, SHOWN_EVIDENCE);
  const label = labelOf(id, confidence, sorted);

  if (confidence === "possible" && isCodeSignal(id)) return keepRest({ id, label, points: POSSIBLE_POINTS[id], evidence, confidence }, sorted);
  const out = keepRest({ id, label, points: POINTS[id], evidence, confidence: "confirmed" }, sorted);

  if (isCodeSignal(id) && fallback.length > 0) out.fallback = fallback.slice(0, SHOWN_EVIDENCE);

  return out;
}

/**
 * The files lifecycle commands run: for install hooks every path a command names (as apm-score-v3 read them), for git
 * hooks (prepare, prepack, postpack) only what a command runs (`runTargets`), since a build's paths are mostly operands
 * (`rimraf ./dist`, `tsc -p ./tsconfig.json`).
 */
function installRunsOf(commands: readonly { text: string; kind: HookKind }[], byPath: ReadonlyMap<string, TarEntry>, targets: (cmd: string) => string[] = scriptTargetsBefore): string[] {
  const out = new Set<string>();

  for (const c of commands) {
    for (const w of c.kind === "install" ? [...targets(c.text), ...commandWords(c.text), ...runTargets(c.text, targets)] : runTargets(c.text, targets)) {
      const f = resolveIn(byPath, w);

      if (f && f.path !== "package.json") out.add(f.path);
    }
  }

  return [...out];
}

/**
 * What a command runs: a script after an interpreter (`scriptTargets`), the program a command segment starts with
 * (`./install.sh`, `FOO=1 ./bin/setup`), and modules `node -e`, `--require` and `--import` load.
 */
export function runTargets(cmd: string, targets: (cmd: string) => string[] = scriptTargets): string[] {
  const out = [...targets(cmd)];

  for (const segment of cmd.split(/[;&|()]+/)) {
    const first = segment.trim().replace(/^(?:[A-Za-z_]\w*=\S*\s+)+/, "").split(/\s+/)[0] ?? "";

    if (/^\.{0,2}\/[\w@./-]+$/.test(first)) out.push(first);
  }

  for (const m of cmd.matchAll(/\b(?:require|import)\s*\(\s*\\?['"]([^'"\\]+)\\?['"]|(?:--require|-r|--import|--loader)[\s=]+['"]?([\w@./-]+)/g)) {
    const p = m[1] ?? m[2];

    if (p && /^\.{0,2}\//.test(p)) out.push(p);
  }

  return out;
}

/**
 * Paths a command runs after an interpreter, as production (274d284) read them: node, bun, `deno run`, sh, bash, zsh, tsx
 * and ts-node. Production's walk, its reading plan, its floor and its install roots take a command's scripts from this
 * alone (round 17 review of b287849, P1: with python3 recognised, `postinstall: python3 lib/loader` put lib/loader
 * first, its require made the package's own `python3` file JavaScript before it was read, and the facts in its comment
 * went: 0 (F), review-first, became 87, install). The second layer reads what scriptTargets adds.
 */
export function scriptTargetsBefore(cmd: string): string[] {
  return scriptTargetsBeforeWithin(cmd, Number.POSITIVE_INFINITY).words;
}

/** scriptTargetsBefore, `max` at most, and cut past that. */
function scriptTargetsBeforeWithin(cmd: string, max: number): ShellWords {
  return targetsWithin(cmd, max, /(?:^|[;&|]\s*|\s)(?:node|bun|deno run|sh|bash|zsh|tsx|ts-node)\s+(?:-[\w-]+\s+)*((?:\.{0,2}\/)?[\w@./-]+)/g);
}

/**
 * Paths a command runs after an interpreter: `node setup`, `sh ./install.sh`, `bun x.ts`, `python3 x`, `. ./env.sh`. Only
 * the second layer reads these (scriptTargetsBefore is production's).
 */
export function scriptTargets(cmd: string): string[] {
  return scriptTargetsWithin(cmd, Number.POSITIVE_INFINITY).words;
}

/** scriptTargets, `max` at most, and cut past that: what the rest runs is not known (round 13 review of d594415, P2). */
function scriptTargetsWithin(cmd: string, max: number): ShellWords {
  return targetsWithin(cmd, max, /(?:^|[;&|]\s*|\s)(?:node|bun|deno run|sh|bash|zsh|dash|ksh|tsx|ts-node|python3?|perl|ruby|source|\.)\s+(?:-[\w-]+\s+)*((?:\.{0,2}\/)?[\w@./-]+)/g);
}

function targetsWithin(cmd: string, max: number, re: RegExp): ShellWords {
  const words: string[] = [];

  for (const m of cmd.matchAll(re)) {
    if (!m[1] || m[1].startsWith("-")) continue;

    if (words.length >= max) return { kind: "cut", words };
    words.push(m[1]);
  }

  return { kind: "complete", words };
}

/**
 * Entry points, most direct first, from the same collector the publish check uses: `paths` named one at a time, and
 * `files` that a subpath pattern (`"./*": "./docs/*.txt"`) or folder mapping exposes, matched against the tarball.
 */
type DeclaredEntries = { paths: string[]; files: string[] };

function declaredEntries(manifest: Record<string, unknown>, all: readonly string[]): DeclaredEntries {
  const paths: string[] = [];
  const files = new Set<string>();
  // a target named many times (1,600 conditions all naming "./lib/") is matched against the files once
  const targets = new Set<string>();

  for (const e of entryPoints(manifest)) {
    charge("score", 1);

    if (targets.has(e.path)) continue;
    targets.add(e.path);
    const t = targetFiles(e.path, all);

    // the set holds each file once, so it never grows past the tarball's file list; every insertion is charged
    if (t.kind === "files") {
      for (const f of t.files) {
        charge("score", 1);
        files.add(f);
      }
    } else if (t.path.startsWith(".") || /^[\w@]/.test(t.path)) paths.push(t.path);
  }

  return { paths, files: [...files] };
}

/** Files node reads as data, not code, whatever exposes them: JSON, type declarations and native modules. */
const NEVER_RUN = /(?:^|\/)package\.json$|\.(?:json|d\.[cm]?ts|node)$/i;

function dirOf(p: string): string {
  const i = p.lastIndexOf("/");

  return i >= 0 ? p.slice(0, i) : "";
}

function joinPath(dir: string, rel: string): string {
  const parts = dir ? dir.split("/") : [];

  for (const seg of rel.split("/")) {
    if (seg === "" || seg === ".") continue;

    if (seg === "..") parts.pop();
    else parts.push(seg);
  }

  return parts.join("/");
}

/**
 * `rel` from `dir` inside the package, or null when it is absolute or climbs out of the package's folder: a target the
 * package's own files cannot account for, which a walk that only adds what it reads leaves alone.
 */
function insidePackage(dir: string, rel: string): string | null {
  if (rel.startsWith("/")) return null;
  const parts = dir ? dir.split("/") : [];

  for (const seg of rel.split("/")) {
    if (seg === "" || seg === ".") continue;

    if (seg === "..") {
      if (parts.length === 0) return null;
      parts.pop();
    } else parts.push(seg);
  }

  return parts.join("/");
}

/**
 * Every file a command's `word` may name, run from `from`: beside it, and from the package's folder, where npm runs
 * scripts (a shell keeps whatever folder it was started in, so both are plausible). Each that exists, once.
 */
function candidatesOf(byPath: ReadonlyMap<string, TarEntry>, from: string, word: string): TarEntry[] {
  const out = new Map<string, TarEntry>();

  for (const p of [insidePackage(dirOf(from), word), insidePackage("", word)]) {
    const f = p === null ? undefined : resolveIn(byPath, p);

    if (f) out.set(f.path, f);
  }

  return [...out.values()];
}

/** The file node would load for `raw`: exact, then each extension it tries, then a directory index. */
const PROBES = ["", ".js", ".cjs", ".mjs", ".json", ".node", ".ts", ".cts", ".mts", "/index.js", "/index.cjs", "/index.mjs", "/index.json", "/index.node", "/index.ts"];

function resolveIn(byPath: ReadonlyMap<string, TarEntry>, raw: string): TarEntry | undefined {
  const p = joinPath("", raw);

  for (const ext of PROBES) {
    const f = byPath.get(`${p}${ext}`);

    if (f) return f;
  }

  return undefined;
}

function isShellScript(f: Pick<TarEntry, "path">, text: string): boolean {
  return /\.(?:sh|bash|zsh|ps1|cmd|bat)$/i.test(f.path) || /^#!.*\b(?:ba|z|da)?sh\b/.test(text) || (!/\.[^/]+$/.test(f.path) && !/^#!.*\b(?:node|bun|deno)\b/.test(text));
}

export type DependencyRisk = { name: string; version: string; score: number };

/** How many earlier publishers new-publisher's evidence names before saying how many more there are. */
const PUBLISHERS_NAMED = 5;

/** `names` as new-publisher's evidence lists them: each once, in the order given, the first PUBLISHERS_NAMED by name. */
function publisherList(names: readonly string[]): string {
  const unique = [...new Set(names)];
  const shown = unique.slice(0, PUBLISHERS_NAMED).join(", ");

  return unique.length > PUBLISHERS_NAMED ? `${shown} and ${unique.length - PUBLISHERS_NAMED} more` : shown;
}

export type AnalyzeInput = {
  name: string;
  manifest: Record<string, unknown>;
  files: readonly TarEntry[];
  publisher: string;
  /** Every account that published a version of this package before this one, most recent first (new-publisher names the first few). */
  previousPublishers: readonly string[];
  /** Dependencies (resolved) whose own score is below the floor. */
  riskyDependencies?: readonly DependencyRisk[];
  /** Dependency names absent from the previous version; empty for a first release. */
  addedDependencies?: readonly string[];
  /** Dependencies apm could not score (git, URL, missing): listed under "not checked". */
  uncheckedDependencies?: readonly string[];
  /** How many bytes of file content one analysis reads. Defaults to MAX_SCANNED_BYTES. */
  maxScannedBytes?: number;
  /** Steps the flow analysis across files may take, carved out of the meter. Defaults to MAX_CROSS_FILE_STEPS. */
  maxCrossFileSteps?: number;
  /** What binaries' plain views may keep while the walks run (binary-text.ts keptBytes). Defaults to MAX_KEPT_VIEW_BYTES. */
  maxKeptViewBytes?: number;
  /**
   * The work meter this analysis charges (meter.ts). A caller that unpacked the tarball under it passes it on, so the
   * unpack and the analysis share one bound. Without one, the analysis gets a meter of `maxWork` units.
   */
  meter?: Meter;
  /** Units of work one analysis may spend when no `meter` is given. Defaults to MAX_ANALYSIS_WORK. */
  maxWork?: number;
  /**
   * Limits the caller hit before this analysis ran, each said as evidence of `incomplete`: the registry re-runs an
   * analysis the platform stopped on a smaller budget, and says so, since the reading it can afford is not the whole.
   */
  incompleteBecause?: readonly string[];
  /**
   * Entries of `files` whose `data` is only their first bytes (tarball.ts's HEAD_BYTES): a tarball too large to hold,
   * read as a stream that kept these out (planReading). A walk that reaches one reports it skipped, as it reports a file
   * past the byte budget, and never reads the head as if it were the file. Empty, or left out, for a tarball read whole.
   */
  notHeld?: ReadonlySet<TarEntry>;
  /**
   * Paths of `files` a streamed read holds only for the second layer (planLayers' `extra`): production's walk counts
   * them not held, as production's plan left them, and only the second layer reads them.
   */
  extraHeld?: ReadonlySet<string>;
  /**
   * Why a streamed read's plan stopped for its resources where production's went on (FirstPass.stopped): the analysis
   * is incomplete for it and scores 0, since the files it holds may not be the ones production's plan held.
   */
  stoppedBecause?: readonly string[];
  /** What else limited the reading, said in `coverage` when it is partial (a streamed read's cut import graph). */
  coverageNotes?: readonly string[];
};

/** What each dependency installs: the registry name behind an npm: alias, the key for anything else. */
export function dependencyNames(manifest: Record<string, unknown>): string[] {
  return [...new Set(dependencySpecs(manifest).map((d) => (isRegistryDependency(d) ? d.name : d.key)))];
}

/**
 * What a piece of evidence rests on, in the order it is cited: a call or load the parsed program showed (or a fact,
 * such as an install script), a text match in code or a string, or a text match in a comment, a regex body, a type or
 * a JSON file.
 */
type Cited = "tree" | "text" | "hidden";

const CITED_RANK: Record<Cited, number> = { tree: 0, text: 1, hidden: 2 };

const CITED_BY_RANK: readonly Cited[] = ["tree", "text", "hidden"];

function citedAs(f: TextFinding): Cited {
  if (f.tree === true) return "tree";

  return f.hidden ? "hidden" : "text";
}

type Found = {
  /** Records evidence; a signal is confirmed once any of its evidence is, and then shows only confirmed evidence. */
  add: (id: SignalId, ev: string, confidence?: Confidence, cited?: Cited) => void;
  has: (id: SignalId) => boolean;
  get: (id: SignalId) => { evidence: string[]; confidence: Confidence; possible: string[] } | undefined;
  /** Every confirmed piece of evidence, with what it rests on. */
  confirmed: (id: SignalId) => { evidence: string; cited: Cited }[];
  /** A copy to add to, leaving this one as it is (its lists are copied; the evidence strings are shared). */
  clone: () => Found;
};

function collector(seed?: { found: ReadonlyMap<SignalId, { confirmed: string[]; possible: string[]; has: Set<string> }>; rank: ReadonlyMap<string, number> }): Found {
  const found = new Map<SignalId, { confirmed: string[]; possible: string[]; has: Set<string> }>([...(seed?.found ?? [])].map(([id, e]) => [id, { confirmed: [...e.confirmed], possible: [...e.possible], has: new Set(e.has) }]));
  const rank = new Map<string, number>(seed?.rank ?? []);
  // the call or load a parsed program showed comes before a text match, and a text match in code before one in a
  // comment, a regex or a type, so the shown evidence cites the most direct line

  const ranked = (list: readonly string[]): string[] => {
    charge("score", list.length * Math.max(1, Math.ceil(Math.log2(list.length + 1))));

    return [...list].sort((a, b) => (rank.get(a) ?? 0) - (rank.get(b) ?? 0));
  };

  return {
    add(id, ev, confidence = "confirmed", cited = "tree") {
      chargeText("score", ev.length, 3);
      const entry = found.get(id) ?? { confirmed: [], possible: [], has: new Set() };
      const list = entry[confidence];
      const key = `${confidence}\u0000${ev}`;

      rank.set(ev, Math.min(rank.get(ev) ?? CITED_RANK[cited], CITED_RANK[cited]));

      // a set, not a search of the list: a file can give thousands of pieces of evidence
      if (!entry.has.has(key)) {
        entry.has.add(key);
        list.push(ev);
      }

      found.set(id, entry);
    },
    has: (id) => found.has(id),
    confirmed: (id) => (found.get(id)?.confirmed ?? []).map((evidence) => ({ evidence, cited: CITED_BY_RANK[rank.get(evidence) ?? 0] ?? "tree" })),
    get: (id) => {
      const entry = found.get(id);

      if (!entry) return undefined;

      const possible = ranked(entry.possible);

      return entry.confirmed.length > 0 ? { evidence: ranked(entry.confirmed), confidence: "confirmed", possible } : { evidence: possible, confidence: "possible", possible: [] };
    },
    clone: () => {
      charge("score", [...found.values()].reduce((n, e) => n + e.confirmed.length + e.possible.length, 0));

      return collector({ found, rank });
    },
  };
}

/**
 * What a confirmed finding only a text rule made says after its snippet, so a reader can tell it from a call or load
 * the parsed program showed: a text match, and where it sits when that is text the program does not run as written.
 * Every one counts, wherever it sits: `String(fn)`, `re.source` and a file reading its own source give comments,
 * regex bodies and types back at runtime, to run or to use as data.
 */
export const TEXT_MATCH = " (text match)";

export const HIDDEN_NOTES: Record<Hidden, string> = {
  comment: " (text match in a comment)",
  regex: " (text match in a regex)",
  type: " (text match in a TypeScript type)",
  json: " (text match in a JSON file)",
};

/** What every scorer's text-match note starts with (v8 wrote "(text match: counted unless …)"). */
const TEXT_MATCH_MARK = " (text match";

function describeFinding(where: string, f: TextFinding): string {
  const how = f.how === "as written" ? "" : ` (${f.how})`;
  const why = f.confidence === "possible" ? ` [possible: ${f.why}]` : "";
  const text = f.confidence === "confirmed" && f.tree !== true ? (f.hidden ? HIDDEN_NOTES[f.hidden] : TEXT_MATCH) : "";

  return `${where}:${f.line}: ${f.snippet}${how}${text}${isTestPath(where) ? IN_TEST_FILE : ""}${why}`;
}

function depNames(manifest: AnalyzeInput["manifest"], fields: readonly string[]): Set<string> {
  return new Set(fields.flatMap((f) => (isRecord(manifest[f]) ? Object.keys(manifest[f]) : [])));
}

/**
 * Signals from the lifecycle scripts: what runs at install, at a git install, and on the publisher's machine. Returns
 * the evidence it cited from commands that run at install, so the risk signals can tell install-time use apart.
 */
function analyzeHooks(found: Found, manifest: AnalyzeInput["manifest"], hooks: readonly ExpandedHook[]): Set<string> {
  const atInstall = new Set<string>();
  const installed = depNames(manifest, ["dependencies", "optionalDependencies", "peerDependencies"]);
  // a git install also installs devDependencies before it runs prepare
  const gitInstalled = depNames(manifest, ["dependencies", "optionalDependencies", "peerDependencies", "devDependencies"]);

  for (const h of hooks) {
    const own = h.commands[0]?.text ?? "";

    if (h.kind === "install") found.add("install-script", `package.json scripts.${h.hook}: ${own.slice(0, 80)}`);
    let risky = false;

    for (const c of h.commands) {
      const label = `package.json ${c.from}: ${c.text.slice(0, 80)}`;

      if (h.kind !== "publish" && isInlineDownload(c.text, { viaEval: c.viaEval, localBins: h.kind === "git" ? gitInstalled : installed })) {
        found.add("install-download", label);
        risky = true;
      }

      for (const f of scanText(c.text, "plain")) {
        const ev = `${label}${f.how === "as written" ? "" : ` (${f.how})`}`;
        found.add(f.id, ev, f.confidence);

        // a git install runs prepare on the installing machine too: its commands count as install-time
        if (h.kind !== "publish") atInstall.add(ev);
        risky = true;
      }
    }

    if (h.kind === "git" && risky) found.add("git-install-script", `package.json scripts.${h.hook}: ${own.slice(0, 80)} (npm runs it when this package is installed from git)`);
  }

  // scripts no hook reaches never run on an installer's machine; only what they would do to one is reported
  for (const [k, cmd] of Object.entries(otherScripts(manifest, hooks))) {
    for (const f of scanText(cmd, "plain")) if (f.id === "credential-access" || f.id === "obfuscated") found.add(f.id, `package.json scripts.${k}: ${cmd.slice(0, 80)}`, f.confidence);
  }

  return atInstall;
}

/** What the v3 walk needs from `analyze`, and what the walk there read whole (with v3's import pattern for each file). */
type V3Walk = {
  files: readonly TarEntry[];
  byPath: ReadonlyMap<string, TarEntry>;
  manifest: AnalyzeInput["manifest"];
  installCommands: readonly { text: string }[];
  gyp: TarEntry | undefined;
  budget: number;
  /** Entries the text rules already read whole, each with v3's imports of it when they were worked out. */
  readWhole: ReadonlyMap<TarEntry, Imports | null>;
  /** `file:line` of each computed load already reported. */
  dynamicAt: ReadonlySet<string>;
  add: Found["add"];
  /** Called with the text of each file this walk reads that the first walk did not. */
  read: (f: TarEntry, text: string) => void;
  notHeld: ReadonlySet<TarEntry>;
  /** Files something runs as a script or executes (invokedFiles and code's commands): read whatever their bytes. */
  invoked: ReadonlySet<string>;
  /** Files the first walk read whole through their views: read whole, as `readWhole`'s are, and their imports read again by `viewImports`. */
  viewed: ReadonlySet<TarEntry>;
  /** The imports of a file the first walk read through its views, read again from its production view. */
  viewImports: (f: TarEntry) => Imports;
};

/**
 * A file a streamed read did not hold, reached by a walk: skipped as the walk skips a file it has no room for. One over
 * MAX_ANALYZED_FILE_BYTES is too large, as it would be read whole; any other is past the budget, which for a streamed
 * read is what it held (planReading). Its size is the entry's, since its `data` is only its first bytes.
 */
function skipNotHeld(f: TarEntry, reached: boolean, skipped: SkippedFile[], unanalyzed: SkippedFile[]): void {
  if (f.size > MAX_ANALYZED_FILE_BYTES) skipped.push({ path: f.path, size: f.size, reason: "too-large" });
  else (reached ? skipped : unanalyzed).push({ path: f.path, size: f.size, reason: "over-budget" });
}

/** What coverage says when a streamed read could not read the tarball's own package.json. */
export const MANIFEST_NOT_READ = "the tarball's own package.json was not read, so the registry's copy of its manifest was used in its place";

/** Files the analysis reads whole by name, outside its walks, when they are there: they are always held first. */
const READ_BY_NAME = ["package.json", "binding.gyp", "Makefile", "makefile", "GNUmakefile", "CMakeLists.txt"] as const;

/**
 * The relative paths a file loads by apm-score-v3's import pattern: what the analysis's walk follows from a file it
 * reaches (with the parser's own imports, which find the same literal paths), for a reading plan made before the file
 * is held. Charges the installed meter for the text pass.
 */
/** A file's paths for a reading plan: production's (v3's pattern), and what a shell script runs, which only the second layer follows. */
export type PlanPaths = { paths: string[]; shell: ShellWords };

export function importPaths(bytes: Uint8Array, path?: string): PlanPaths {
  chargeText("text", bytes.length, 3);
  const text = new TextDecoder().decode(bytes);
  const paths = importsOf(joinStrings(text).text).paths;

  // a shell script runs what its commands name, sourced files too: the second layer reads those, and its plan holds
  // them from what production's plan leaves of the budget (planLayers); a walk cut at its bound stops the plan (round 13
  // review of d594415, P2)
  if (path === undefined || !isShellScript({ path }, text)) return { paths, shell: { kind: "complete", words: [] } };

  return { paths, shell: shellWords(text) };
}

/**
 * What a streamed read's first pass may hold (the files read by name and the code it holds while it has room, together),
 * may gather to look at (one file, and every file it looks at), may keep of the import graph (characters of paths, and
 * paths), and the memory it charges what it keeps to.
 */
export type FirstPassLimits = { holdBytes: number; lookFileBytes: number; lookTotalBytes: number; importBytes?: number; importEdges?: number; memory?: StreamMemory };

/** Characters of import paths the first pass keeps, all files together: next 16.4.6's 80 MB of code import 0.4 million. */
export const IMPORT_GRAPH_BYTES = 4 * 1024 * 1024;

/** Import paths the first pass keeps, all files together: next 16.4.6's are 9,340. */
export const IMPORT_GRAPH_EDGES = 200_000;

/** Of `holdBytes`, what code the first pass holds leaves free for the files read by name, which may come after it. */
export const NAMED_HEADROOM = 1024 * 1024;

/** Bytes charged for each kept import path beside its characters, and for each file's list. */
const IMPORT_PATH_BYTES = 32;
const IMPORT_LIST_BYTES = 64;

/**
 * The first pass's rule and its look, the import paths of each file it looked at (which fill as it reads), and whether
 * it stopped keeping them at its allowance: a plan made from a cut graph may miss what the rest load.
 */
export type FirstPass = {
  hold: HoldRule;
  look: LookAt;
  /** Production's (274d284) import graph: the paths v3's pattern finds, kept and cut as production's first pass kept them. */
  imports: Map<string, readonly string[]>;
  /** What shell scripts run, which only the second layer follows (planLayers), kept apart within the same limits. */
  shellRuns: Map<string, readonly string[]>;
  readonly importsCut: boolean;
  /**
   * Why the graph stopped for its resources where production's went on (a file's joining past a reading's temporary
   * budget, a script's words past their bound, what scripts run past the graph's limits), or null: the analysis then
   * scores 0 (stoppedBecause), since the plan may hold other files than production's did.
   */
  readonly stopped: string | null;
};

/**
 * The first pass of a streamed read. It holds package.json whenever apm reads a manifest that large at all (4 MB of
 * text, MANIFEST_LIMITS), whatever `holdBytes` is: the plan and the analysis need the tarball's own. It holds the other
 * files the analysis reads by name (binding.gyp, the Makefiles) and, while it has room, code files, all within one
 * `holdBytes`: code leaves NAMED_HEADROOM of it free, so
 * code that came first does not crowd out a package.json that comes last. It looks at every file the analysis's walk
 * could follow imports from (not a doc, type, map or data file, not a native binary by name) for the paths it imports,
 * one file at a time, each let go once read, until it has looked at `lookTotalBytes` or kept `importBytes` characters
 * or `importEdges` paths of the graph; past that it keeps none (`importsCut`). Every path it keeps, and the text it
 * decodes while it reads one, is charged to `memory` first (MemoryRefused when it has no room). When the plan made from
 * it (planReading) wants only files this pass holds, no second pass is needed. A file whose imports it did not keep has
 * none in the plan, so the plan may miss what it loads; `analyze` then reports that as not read.
 */
export function firstPass(limits: FirstPassLimits): FirstPass {
  const imports = new Map<string, readonly string[]>();
  const named = new Set<string>(READ_BY_NAME);
  const memory = limits.memory ?? { take: () => true, give: () => undefined };
  const maxChars = limits.importBytes ?? IMPORT_GRAPH_BYTES;
  const maxEdges = limits.importEdges ?? IMPORT_GRAPH_EDGES;
  const codeRoom = limits.holdBytes - Math.min(NAMED_HEADROOM, limits.holdBytes / 4);
  let looked = 0;
  let heldBytes = 0;
  let chars = 0;
  let edges = 0;
  let cut = false;
  const shellRuns = new Map<string, readonly string[]>();
  let shellChars = 0;
  let shellEdges = 0;
  let stopped: string | null = null;

  const hold: HoldRule = ({ path, size }) => {
    // the manifest the analysis and the plan read: held whenever apm would read it at all, outside the file budget (a
    // budget of one byte still reads the tarball's own package.json, never the registry's copy in its place)
    if (path === "package.json" && size <= MANIFEST_LIMITS.chars) return "hold";

    if (named.has(path) && heldBytes + size <= limits.holdBytes) {
      heldBytes += size;

      return "hold";
    }

    if (NOT_CODE.test(path) || NEVER_RUN.test(path) || /\.(?:node|exe|dll|so|dylib)$/.test(path) || size > limits.lookFileBytes) return "head";

    if (heldBytes + size <= codeRoom) {
      heldBytes += size;
      looked += size;

      return "hold";
    }

    if (cut || looked + size > limits.lookTotalBytes) return "head";
    looked += size;

    return "look";
  };

  const look: LookAt = (file, bytes) => {
    // production's (274d284) look, exactly: not a doc, type, map or data file, not what it took for native code (a
    // native name, ELF's magic); a Mach-O, which its check never matched, has its imports read as production's had
    if (cut || NOT_CODE.test(file.path) || NEVER_RUN.test(file.path) || !readAsTextBefore(file.path, bytes)) return;
    // the decoded text and the joined text it is read from, two bytes a character at most, while it is read
    const reading = 4 * bytes.length;

    if (!memory.take(reading)) throw new MemoryRefused(`no memory to read ${file.path}'s imports`);
    let paths: string[];
    let runs: string[];

    try {
      // a path is copied out of the text it was matched in: V8 keeps a whole file's text alive behind a slice of it. The
      // lists the joining builds are held to a reading's temporary budget (kept.ts) (round 11: a held Mach-O of a million
      // joined literals, read for its imports as production read it, reached 83.8 MiB live; production ended its isolate)
      // once the plan has stopped, what scripts run is not read: only production's paths are, as production's pass read
      // them, so the second layer's work stops spending the stream's meter (round 17 review of b287849, P1)
      const read = withKeepLimit(Number.POSITIVE_INFINITY, MAX_SCAN_TEMP_BYTES, () => importPaths(bytes, stopped === null ? file.path : undefined));

      // its joining stopped where production's went on: production's graph is not known past here, so the graph is cut
      // and the plan stopped for its resources
      if (read.stopped) {
        cut = true;
        stopped ??= `${file.path}: apm stopped reading the paths it loads at what one reading may hold, so the files read were not chosen as production chose them`;

        return;
      }

      paths = read.value.paths.map((p) => decoder.decode(encoder.encode(p)));
      runs = read.value.shell.words.map((p) => decoder.decode(encoder.encode(p)));

      // a script's walk cut at its bound: what it runs is not all known (round 13 review of d594415, P2)
      if (read.value.shell.kind === "cut") stopped ??= `${file.path}: apm read the first ${MAX_SHELL_TOKENS.toLocaleString("en-US")} words of this script's commands and stopped, so what the rest runs was not followed`;
    } finally {
      memory.give(reading);
    }

    // production's graph, kept and cut by production's limits, whatever scripts run besides
    const more = paths.reduce((n, p) => n + p.length, 0);

    if (paths.length > 0) {
      if (chars + more > maxChars || edges + paths.length > maxEdges) {
        cut = true;

        return;
      }

      if (!memory.take(IMPORT_LIST_BYTES + paths.length * IMPORT_PATH_BYTES + 2 * more)) throw new MemoryRefused(`no memory to keep ${file.path}'s imports`);
      chars += more;
      edges += paths.length;
      imports.set(file.path, paths);
    }

    // what scripts run, on limits of their own: past them the plan stopped for its resources
    const ran = runs.reduce((n, p) => n + p.length, 0);

    if (runs.length === 0 || stopped !== null) return;

    if (shellChars + ran > maxChars || shellEdges + runs.length > maxEdges) {
      stopped = `${file.path}: what the package's shell scripts run is past what apm keeps of them, so the files read were not chosen as they would be`;

      return;
    }

    if (!memory.take(IMPORT_LIST_BYTES + runs.length * IMPORT_PATH_BYTES + 2 * ran)) throw new MemoryRefused(`no memory to keep what ${file.path} runs`);
    shellChars += ran;
    shellEdges += runs.length;
    shellRuns.set(file.path, runs);
  };

  return {
    hold,
    look,
    imports,
    shellRuns,
    get importsCut() {
      return cut;
    },
    get stopped() {
      return stopped;
    },
  };
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** A streamed read's plan (planLayers): production's, and what the second layer holds besides. */
export type ReadingPlan = { production: Set<string>; extra: Set<string> };

/**
 * Which files of a tarball too large to hold a streamed read keeps whole, at most `budget` bytes of them, in two layers.
 * `production` is production's (274d284) plan, exactly: the files `analyze` reads by name, then what install hooks run,
 * binding.gyp and the declared entries, then every file those reach through `imports` (production's graph, beside the
 * file), then every other file that could be code, code extensions first, passing over a file that does not fit for the
 * next, and never holding what production never read (a native name, ELF's magic, data, one over
 * MAX_ANALYZED_FILE_BYTES). `extra` is what the second layer reads besides, held from what production's plan left of the
 * budget: what scripts and bin run, whatever their first bytes (invokedFiles), and what those and every held file reach,
 * beside the file or from the package's folder, through `imports` and what shell scripts run (`shellRuns`). Production's
 * walk counts an `extra` file as not held (AnalyzeInput.extraHeld), so it reads what production's read, and the second
 * layer cannot crowd out a file production held (round 16 review of c272202). `files` may hold only each file's first
 * bytes: only paths, sizes and those are read.
 */
export function planLayers(input: { manifest: AnalyzeInput["manifest"]; files: readonly TarEntry[]; imports: ReadonlyMap<string, readonly string[]>; shellRuns?: ReadonlyMap<string, readonly string[]>; budget: number }): ReadingPlan {
  const { files, imports, budget } = input;
  const byPath = new Map(files.map((f) => [f.path, f]));
  const held = new Set<string>();
  const extra = new Set<string>();
  let total = 0;

  charge("score", files.length * 4);

  const take = (f: TarEntry): void => {
    if (held.has(f.path) || !readAsTextBefore(f.path, f.data) || f.size > MAX_ANALYZED_FILE_BYTES || total + f.size > budget) return;
    held.add(f.path);
    total += f.size;
  };

  for (const name of READ_BY_NAME) {
    const f = byPath.get(name);

    if (f) take(f);
  }

  // a manifest past what apm reads is not read here either: `analyze` reads nothing of the version then
  if (measureManifest(input.manifest).kind !== "ok") return { production: held, extra };
  const manifest = input.manifest;
  const first: string[] = [];
  const hooks = expandHooks(manifest);

  // what only the shell reading reaches (HookCommand.added) is not production's: the second layer holds it (invokedFiles)
  // from what production's plan leaves of the budget
  for (const c of hooks.flatMap((h) => (h.kind === "publish" ? [] : h.commands.filter((x) => !x.added)))) {
    for (const w of [...scriptTargetsBefore(c.text), ...commandWords(c.text)]) {
      const f = resolveIn(byPath, w);

      if (f && f.path !== "package.json") first.push(f.path);
    }
  }

  if (byPath.has("binding.gyp")) first.push("binding.gyp");
  const entries = declaredEntries(manifest, files.map((f) => f.path));

  for (const p of entries.paths) {
    const f = resolveIn(byPath, p);

    if (f && !/\.d\.[cm]?ts$/.test(f.path)) first.push(f.path);
  }

  for (const p of entries.files) if (!NEVER_RUN.test(p)) first.push(p);

  const seen = new Set<string>();
  const reachable = new Set<string>(first);
  const queue = [...reachable];

  // the walk: each file it reaches, then what that file loads; files read outside it load nothing it follows
  for (let qi = 0; qi < queue.length; qi++) {
    const path = queue[qi] ?? "";
    const f = byPath.get(path);

    if (!f || seen.has(path)) continue;
    seen.add(path);
    take(f);

    for (const spec of imports.get(path) ?? []) {
      charge("score", 1);
      const target = resolveIn(byPath, joinPath(dirOf(path), spec));

      if (target && !seen.has(target.path) && !reachable.has(target.path)) {
        reachable.add(target.path);
        queue.push(target.path);
      }
    }
  }

  const rest = files.filter((f) => !seen.has(f.path) && !NOT_CODE.test(f.path)).sort((a, b) => Number(!CODE_EXT.test(a.path)) - Number(!CODE_EXT.test(b.path)));

  for (const f of rest) take(f);

  // the second layer's, from what is left: what scripts and bin run first, then what everything held reaches
  const invoked = invokedFiles(manifest, byPath, hooks);

  const takeExtra = (f: TarEntry): void => {
    if (held.has(f.path) || extra.has(f.path) || (!invoked.has(f.path) && !readAsTextBefore(f.path, f.data)) || f.size > MAX_ANALYZED_FILE_BYTES || total + f.size > budget) return;
    extra.add(f.path);
    total += f.size;
  };

  const shellRuns = input.shellRuns ?? new Map<string, readonly string[]>();
  const seenX = new Set<string>();
  const queueX = [...invoked, ...held];

  for (let qi = 0; qi < queueX.length; qi++) {
    const path = queueX[qi] ?? "";
    const f = byPath.get(path);

    if (!f || seenX.has(path)) continue;
    seenX.add(path);
    takeExtra(f);

    if (!held.has(path) && !extra.has(path)) continue;

    for (const spec of [...(imports.get(path) ?? []), ...(shellRuns.get(path) ?? [])]) {
      charge("score", 1);

      // beside the file, or from the package's folder, where npm runs a script's commands (as `analyze` resolves them)
      for (const target of candidatesOf(byPath, path, spec)) if (!seenX.has(target.path)) queueX.push(target.path);
    }
  }

  return { production: held, extra };
}

/** Every file a streamed read holds (planLayers): production's plan and the second layer's. */
export function planReading(input: Parameters<typeof planLayers>[0]): Set<string> {
  const plan = planLayers(input);

  return new Set([...plan.production, ...plan.extra]);
}

/** What the v3 walk could not read: run code too large or past the budget, and other files past the budget. */
type V3Skips = { skipped: SkippedFile[]; unanalyzed: SkippedFile[] };

/**
 * The floor, by construction: apm-score-v3's own walk over the tarball (`analyze` in `test/v3/score.ts`), with its
 * order, its byte budget and its reach: install targets, binding.gyp, declared entries (not `imports`, which v3 did
 * not read), every file v3's import pattern reaches from those, then every other file that could be code. Each file
 * is read whole by the text rules, which hold every pattern of v3's and run every pass it ran, so every finding v3
 * makes in a file is made here, confirmed; a file `analyze` already read whole is not read twice. Computed loads are
 * reported for reached files as v3 reported them, and what did not fit is reported as v3 reported it.
 */
function readLikeV3(w: V3Walk): V3Skips {
  const { byPath, add } = w;
  const installTargets = new Set<string>();
  const first: string[] = [];

  for (const c of w.installCommands) {
    for (const word of [...scriptTargetsBefore(c.text), ...commandWords(c.text)]) {
      const f = resolveIn(byPath, word);

      if (f && f.path !== "package.json") {
        installTargets.add(f.path);
        first.push(f.path);
      }
    }
  }

  if (w.gyp) first.push(w.gyp.path);

  const entryPaths = new Set<string>();

  for (const e of entryPoints(w.manifest)) {
    charge("score", 1);

    if (e.field.startsWith("imports") || !(e.path.startsWith(".") || /^[\w@]/.test(e.path)) || entryPaths.has(e.path)) continue;
    entryPaths.add(e.path);
    const f = resolveIn(byPath, e.path);

    // type declarations listed under exports never run
    if (f && !/\.d\.[cm]?ts$/.test(f.path)) first.push(f.path);
  }

  const reachable = new Set<string>(first);
  const queue = [...reachable];
  const seen = new Set<string>();
  const skipped: SkippedFile[] = [];
  const unanalyzed: SkippedFile[] = [];
  let scanned = 0;
  let qi = 0;

  const readFile = (f: TarEntry, reached: boolean): void => {
    const asSource = w.invoked.has(f.path);
    // production's (274d284) reader, as in analyzeFile: a native name or ELF's magic is binary and not read, nor is data;
    // a Mach-O is read as the text production read (round 16 review of c272202)
    const native = nativeBefore(f.path, f.data);

    if (native || isBinary(f)) add("binary", f.path);

    if (!asSource && (native || hasDataMagic(f.data))) return;

    if (w.notHeld.has(f)) {
      skipNotHeld(f, reached, skipped, unanalyzed);

      return;
    }

    if (f.data.length > MAX_ANALYZED_FILE_BYTES) {
      skipped.push({ path: f.path, size: f.data.length, reason: "too-large" });

      return;
    }

    if (scanned + f.data.length > w.budget) {
      (reached ? skipped : unanalyzed).push({ path: f.path, size: f.data.length, reason: "over-budget" });

      return;
    }

    scanned += f.data.length;
    // keyed by the entry, not its path: only these bytes' own read can stand in for reading them. One read through its
    // views was read whole too, as production read it whole as text; its imports are read again from the view below
    const viewed = w.viewed.has(f);
    const known = viewed ? null : w.readWhole.get(f);

    // decoding the bytes, and what this walk reads of a file the first walk did not read whole
    chargeText("text", f.data.length, known === undefined ? TEXT_PASSES_PER_FILE : 1);
    let text: string | null = null;
    const textOf = (): string => (text ??= new TextDecoder().decode(f.data));

    if (known === undefined) {
      for (const finding of scanTextRules(textOf())) add(finding.id, describeFinding(f.path, finding), "confirmed", citedAs(finding));
      w.read(f, textOf());
    }

    if (installTargets.has(f.path) && isShellScript(f, textOf()) && isInlineDownload(textOf())) add("install-download", `${f.path}: run by an install script and downloads code`);

    if (!reached) return;
    const imports = viewed ? w.viewImports(f) : (known ?? importsOf(joinStrings(textOf()).text));

    // v3's pattern takes any require(…) or import(…) whose argument is not a literal for a computed load
    for (const d of imports.dynamic) if (!w.dynamicAt.has(`${f.path}:${d.line}`)) add("dynamic-require", `${f.path}:${d.line}: ${d.snippet}${TEXT_MATCH}`);

    for (const spec of imports.paths) {
      const target = resolveIn(byPath, joinPath(dirOf(f.path), spec));

      if (target && !seen.has(target.path) && !reachable.has(target.path)) {
        reachable.add(target.path);
        queue.push(target.path);
      }
    }
  };

  const drain = (): void => {
    for (; qi < queue.length; qi++) {
      const f = byPath.get(queue[qi] ?? "");

      if (!f || seen.has(f.path)) continue;
      seen.add(f.path);
      readFile(f, true);
    }
  };

  drain();

  const rest = w.files.filter((f) => !seen.has(f.path) && !NOT_CODE.test(f.path)).sort((a, b) => Number(!CODE_EXT.test(a.path)) - Number(!CODE_EXT.test(b.path)));

  for (const f of rest) {
    seen.add(f.path);
    readFile(f, false);
    // anything the second pass reaches by a resolvable path is read too, even with a non-code name
    drain();
  }

  for (const f of w.files) if (!seen.has(f.path) && (nativeBefore(f.path, f.data) || isBinary(f))) add("binary", f.path);

  return { skipped, unanalyzed };
}

/**
 * A file list `analyze` refuses: a path that appears more than once (after dropping `.` and empty segments) or
 * escapes the package folder. Different tools would extract different bytes for it, so no score can speak for it.
 * The registry refuses such a tarball at publish by the same rule (`ambiguousPaths`).
 */
export class AmbiguousPathsError extends Error {
  override readonly name = "AmbiguousPathsError";
  readonly paths: readonly string[];

  constructor(paths: readonly string[]) {
    super(`duplicate or escaping paths: ${paths.slice(0, 5).join(", ")}${paths.length > 5 ? ` and ${paths.length - 5} more` : ""}`);
    this.paths = paths;
  }
}

/**
 * Static analysis of one version. Run once at publish; stored with the version. Throws AmbiguousPathsError when two
 * files share a path or a path escapes the package folder.
 */
export function analyze(input: AnalyzeInput): Analysis {
  const meter = input.meter ?? new Meter(input.maxWork ?? MAX_ANALYSIS_WORK);
  let read: Analysis;

  try {
    read = withMeter(meter, () => {
      // before anything that recurses into package.json (zod, JSON.stringify, the format check) reads it
      const reading = measureManifest(input.manifest);

      return reading.kind === "ok" ? analyzeMetered(input) : manifestOverAnalysis({ name: input.name, manifest: input.manifest, files: input.files, text: reading.text, because: input.incompleteBecause });
    });
  } catch (e) {
    if (!(e instanceof MeterExhausted)) throw e;

    return unfinishedAnalysis({ name: input.name, manifest: input.manifest, files: input.files, phase: e.phase, limit: e.limit, because: input.incompleteBecause });
  }

  // a throw some step swallowed still left the meter spent: what came back is not a finished reading
  const spentIn = meter.exhausted;

  return spentIn === null ? read : unfinishedAnalysis({ name: input.name, manifest: input.manifest, files: input.files, phase: spentIn, limit: meter.limit, because: input.incompleteBecause });
}

/** What `unfinishedAnalysis` needs: the version, where its meter ran out, and limits the caller hit before. */
export type Unfinished = { name: string; manifest: AnalyzeInput["manifest"]; files: readonly TarEntry[]; phase: Phase; limit: number; because?: readonly string[] | undefined };

/** The `incomplete` evidence for a meter that ran out in `phase`. */
export function meterEvidence(phase: Phase, limit: number): string {
  return `analysis work limit: apm stopped reading this version while ${PHASE_NAMES[phase]}, at the ${limit.toLocaleString("en-US")} units one analysis may spend, so nothing it holds was cleared`;
}

/**
 * The analysis of a version whose meter ran out: `incomplete`, naming the phase, and nothing that reads as a pass. What
 * the reading found before it stopped is not reported, since half a reading cannot be weighed; the score is below the
 * floor on `incomplete` alone. It charges nothing, so it can be built on a spent meter.
 */
export function unfinishedAnalysis(u: Unfinished): Analysis {
  // a reading stopped for its resources scores 0, as one stopped at what a binary's text may hold does (assess): this
  // analysis reads more than production's (274d284) and spends more of the meter, so it can run out where production's
  // finished below 39, and what it did not read could cost more than `incomplete`'s 61 points (round 16 review of
  // c272202: a package production scored 35 (F), complete, scored 39 here, stopped)
  return incompleteAnalysis({ manifest: u.manifest, files: u.files, evidence: [meterEvidence(u.phase, u.limit), ...(u.because ?? [])], notChecked: `everything past the analysis work limit (${PHASE_NAMES[u.phase]})`, stopped: true });
}

/** What `manifestOverAnalysis` needs: the version, which limit its package.json is past, and limits hit before. */
export type ManifestOver = { name: string; manifest: AnalyzeInput["manifest"]; files: readonly TarEntry[]; text: string; because?: readonly string[] | undefined };

/**
 * The analysis of a version whose package.json is past MANIFEST_LIMITS: `incomplete`, and nothing read past the
 * check that found it, so no recursive reader ever sees it. Charges nothing.
 */
export function manifestOverAnalysis(u: ManifestOver): Analysis {
  return incompleteAnalysis({ manifest: u.manifest, files: u.files, evidence: [`${u.text}, past what apm reads, so apm did not read this version and nothing it holds was cleared`, ...(u.because ?? [])], notChecked: "everything in this version: its package.json is past what apm reads" });
}

/**
 * The analysis of a version whose run failed with an error before it finished, after the retries the registry allows:
 * `incomplete`, naming the error's class only (its message may quote the package). Charges nothing.
 */
export function failedAnalysis(u: { manifest: AnalyzeInput["manifest"]; files: readonly TarEntry[]; errorClass: string; attempts: number }): Analysis {
  return incompleteAnalysis({
    manifest: u.manifest,
    files: u.files,
    evidence: [`analysis failed: ${u.attempts} runs of it ended with ${u.errorClass} before finishing, so nothing this version holds was cleared`],
    notChecked: "everything in this version: its analysis failed before it finished",
  });
}

/** `incomplete` and nothing that reads as a pass. Reads package.json only within MANIFEST_LIMITS (boundedManifest). */
function incompleteAnalysis(u: { manifest: AnalyzeInput["manifest"]; files: readonly TarEntry[]; evidence: string[]; notChecked: string; stopped?: boolean }): Analysis {
  const unfinished = signal("incomplete", u.evidence);

  if (u.stopped === true) unfinished.points = -100;

  return {
    scorer: SCORER,
    signals: [unfinished],
    facts: factsOf(boundedManifest(u.manifest), u.files),
    notChecked: [...NOT_CHECKED, u.notChecked],
    skipped: [],
    capabilities: [],
    declaration: { kind: "none", notes: [] },
    // nothing it holds was read: the reading stopped, which `incomplete` costs as before
    coverage: { kind: "partial", omittedFiles: u.files.length, omittedBytes: u.files.reduce((n, f) => n + f.size, 0), reasons: ["stopped"], notes: [] },
  };
}

/**
 * Linear passes the analysis makes over each file's text outside the parser and the text rules (which charge their
 * own): decoding the bytes, choosing the language, the facts, v3's imports and the joined text they are read from.
 */
const TEXT_PASSES_PER_FILE = 4;

function analyzeMetered(input: AnalyzeInput): Analysis {
  const { manifest, files } = input;

  // the per-file bookkeeping below (the path map, sorting, the order of reading, the facts) for every file
  for (const f of files) chargeText("score", f.path.length + 64, 12);
  chargeText("score", JSON.stringify(manifest).length, 8);
  const ambiguous = ambiguousPaths(files);

  if (ambiguous.length > 0) throw new AmbiguousPathsError(ambiguous);
  const found = collector();
  // Round 15 review of c139b5b: what the branch reads beyond production's walk (a binary's view after a load, a file a
  // shell script or a command runs, a file read again as code) changed how production's own readings were read, by
  // replacing them or by changing which reader a file got. The walk now has two layers: "production", production's walk
  // (274d284's order, roots, exact paths and reader for every file), whose results are production's; and "extra", what
  // the branch reads besides, kept apart. The analysis is assessed on the first alone, then with the second, and takes
  // from the second only what it adds (withExtras): nothing production's reading concluded is replaced or read again.
  let layer: "production" | "extra" = "production";
  const extraAdds: { id: SignalId; ev: string; confidence: Confidence | undefined; cited: Cited | undefined }[] = [];

  const add: Found["add"] = (id, ev, confidence, cited) => {
    if (layer === "production") found.add(id, ev, confidence, cited);
    else extraAdds.push({ id, ev, confidence, cited });
  };

  // Why this run read less is added before anything it found: only the first SHOWN_EVIDENCE lines are shown, and a
  // smaller re-run of a big package also has parser-limit and skipped-file warnings, so the reason added last was cut
  // (six parser-depth warnings pushed it out). Same rank ("tree") and first in, so first shown.
  for (const why of input.incompleteBecause ?? []) add("incomplete", why);

  for (const why of input.stoppedBecause ?? []) add("incomplete", why);

  const byPath = new Map(files.map((f) => [f.path, f]));
  // what the second layer may read of a streamed read: everything held
  const notHeldExtra: ReadonlySet<TarEntry> = input.notHeld ?? new Set();
  const heldForExtra = input.extraHeld ?? new Set<string>();
  // what production's walk may read: what production's plan held, so not a file held only for the second layer
  const notHeld: ReadonlySet<TarEntry> = heldForExtra.size === 0 ? notHeldExtra : new Set([...notHeldExtra, ...files.filter((f) => heldForExtra.has(f.path))]);
  const hooks = expandHooks(manifest);
  // read as source whatever their bytes: what scripts and bin run, and (as the walk finds them) what code runs
  const invoked = invokedFiles(manifest, byPath, hooks);

  // a hook whose commands apm stopped expanding runs commands apm did not read
  for (const h of hooks) if (h.cut !== null && h.kind !== "publish") add("incomplete", `scripts.${h.hook}: apm stopped reading the commands it runs at ${h.cut}`);
  const hookEvidence = analyzeHooks(found, manifest, hooks);
  // what runs on the installing machine: install hooks, and the git hooks npm runs when it installs from git
  // every hook's commands before what only the shell reading adds to any of them (HookCommand.added)
  const hookCommands = hooks
    .filter((h) => h.kind !== "publish")
    .flatMap((h) => h.commands.map((c) => ({ ...c, kind: h.kind })))
    .toSorted((a, b) => Number(a.added) - Number(b.added));
  const installCommands = hookCommands;

  // binding.gyp runs at install; its actions and <!(...) expansions are commands like any install script
  const gyp = byPath.get("binding.gyp");

  if (gyp) add("install-script", "binding.gyp: node-gyp build runs at install");

  // the commands node-gyp runs are in the file: one a streamed read did not hold is code that runs and was not read
  // files left unread for their size or the budget: the analysis's coverage, not a finding (apm-score-v11)
  const omittedByName: SkippedFile[] = [];
  const pj = byPath.get("package.json");
  const notes = [...(input.coverageNotes ?? [])];

  // a tarball's package.json a streamed read did not hold: the manifest read is the registry's copy, so the
  // tarball's own was not read, and the coverage says so
  if (pj && notHeld.has(pj)) {
    omittedByName.push({ path: pj.path, size: pj.size, reason: pj.size > MANIFEST_LIMITS.chars ? "too-large" : "over-budget" });
    notes.push(MANIFEST_NOT_READ);
  }

  if (gyp && notHeld.has(gyp)) omittedByName.push({ path: gyp.path, size: gyp.size, reason: gyp.size > MAX_ANALYZED_FILE_BYTES ? "too-large" : "over-budget" });
  else if (gyp) {
    for (const cmd of gypCommands(new TextDecoder().decode(gyp.data))) {
      if (isInlineDownload(cmd)) add("install-download", `binding.gyp: ${cmd.slice(0, 80)}`);

      for (const f of scanText(cmd, "plain")) {
        add(f.id, `binding.gyp: ${cmd.slice(0, 80)}`, f.confidence);
        hookEvidence.add(`binding.gyp: ${cmd.slice(0, 80)}`);
      }
    }
  }

  // a Makefile or CMakeLists.txt that an install hook builds is an install script too
  if (installCommands.some((c) => /\b(?:make|cmake-js|cmake)\b/.test(c.text))) {
    for (const name of ["Makefile", "makefile", "GNUmakefile", "CMakeLists.txt"]) {
      const f = byPath.get(name);

      if (f && notHeld.has(f)) omittedByName.push({ path: f.path, size: f.size, reason: f.size > MAX_ANALYZED_FILE_BYTES ? "too-large" : "over-budget" });
      else if (f && isInlineDownload(new TextDecoder().decode(f.data))) add("install-download", `${name}: built by an install script and downloads code`);
    }
  }

  // What gets read, in order: what install hooks run, then entry points, then whatever those reach
  // through a path apm can resolve; then every other file that could be code, whatever its name.
  // A byte budget, not a file count, bounds the work, so filler files can only push out other filler.
  const budget = input.maxScannedBytes ?? MAX_SCANNED_BYTES;
  const installTargets = new Set<string>();
  // what install hooks run as the second layer reads them (scriptTargets): production's roots are production's
  const installTargetsX = new Set<string>();
  const first: string[] = [];
  // what install hooks run that only the shell reading reaches (HookCommand.added): read after the entries
  const later = new Set<string>();

  for (const c of installCommands) {
    for (const w of [...scriptTargetsBefore(c.text), ...commandWords(c.text)]) {
      const f = resolveIn(byPath, w);

      if (f && f.path !== "package.json") {
        installTargets.add(f.path);
        if (c.added) later.add(f.path);
        else first.push(f.path);
      }
    }

    for (const w of scriptTargets(c.text)) {
      const f = resolveIn(byPath, w);

      if (f && f.path !== "package.json") installTargetsX.add(f.path);
    }
  }

  if (gyp) first.push(gyp.path);

  // node runs an entry point or a required file as JavaScript whatever its extension, so it is read as JavaScript
  const runsAsCode = new Set<string>();
  const entries = declaredEntries(manifest, files.map((f) => f.path));

  for (const p of entries.paths) {
    const f = resolveIn(byPath, p);

    // type declarations listed under exports never run
    if (f && !/\.d\.[cm]?ts$/.test(f.path)) {
      first.push(f.path);
      runsAsCode.add(f.path);
    }
  }

  // every file a pattern exposes can be loaded, and runs as JavaScript whatever its extension (`docs/*.txt` too)
  const exposedOnly = new Set<string>();

  for (const p of entries.files) {
    if (NEVER_RUN.test(p)) continue;
    first.push(p);

    if (!runsAsCode.has(p)) exposedOnly.add(p);
    runsAsCode.add(p);
  }

  for (const p of later) first.push(p);

  const reachable = new Set<string>(first);
  const queue = [...reachable];
  const seen = new Set<string>();
  const skipped: SkippedFile[] = [];
  const unanalyzed: SkippedFile[] = [];
  let scanned = 0;
  let qi = 0;
  const limits = new Map<string, string[]>();
  // files whose whole text the text rules read here, with v3's imports of each parsed one, for the v3 walk below
  const readWhole = new Map<TarEntry, Imports | null>();
  // files production's walk read whole through their views (a Mach-O production read as plain text): the floor's walk
  // reads their imports again from the view, as production's read them again from its text
  const viewedWhole = new Set<TarEntry>();
  const dynamicAt = new Set<string>();
  // what each file shows beyond the code signals, and which files each one loads, for the v10 risk signals
  const fileFacts = new Map<string, Fact[]>();
  const edges = new Map<string, Set<string>>();
  // where values go in each parsed file (flow.ts) and what it exports, resolved across files once every file is read
  const fileFlows = new Map<string, { flows: FlowFinding[]; exports: Exports }>();
  const heldBytes = new Map<string, number>();
  // files read with no tree: nothing there can show where a value goes, so v9's reading of them stands
  const rawFiles = new Set<string>();
  // files whose flow reading stopped before it finished, in code that runs: each is incomplete, and its evidence says so
  const flowStopped = new Set<string>();
  // the extra layer's own: what its readings found, apart from production's (layer, above)
  const extraFacts = new Map<string, Fact[]>();
  const extraFlows = new Map<string, { flows: FlowFinding[]; exports: Exports }>();
  const extraEdges = new Map<string, Set<string>>();
  const extraRaw = new Set<string>();
  const extraFlowStopped = new Set<string>();
  const factsIn = (): Map<string, Fact[]> => (layer === "production" ? fileFacts : extraFacts);
  const flowsIn = (): Map<string, { flows: FlowFinding[]; exports: Exports }> => (layer === "production" ? fileFlows : extraFlows);

  const edge = (from: string, to: string): void => {
    const m = layer === "production" ? edges : extraEdges;
    m.set(from, (m.get(from) ?? new Set()).add(to));
  };

  /**
   * Code a file holds as text (run from a string, recovered from its own comments or regexes, or held in a string that
   * reads as a program), read as a program of its own: its facts and flows are the file's, cited at the line that holds
   * it, so what runs at install still counts as install time. A string that only holds code adds its risks, not its
   * capabilities; recovered text that does not parse, or that names a dangerous call, is code the file hid and runs.
   */
  const readHeld = (path: string, e: ExecutedCode, depth: number): void => {
    const spent = heldBytes.get(path) ?? 0;

    if (depth > MAX_HELD_DEPTH || spent + e.code.length > MAX_HELD_BYTES) {
      // code that runs is never left unread quietly; a string that only holds code is not run, so it may be
      if (e.origin === "run" || e.origin === "recovered") add("incomplete", `${path}:${e.line}: ${e.snippet} (${depth > MAX_HELD_DEPTH ? `code run from a string more than ${MAX_HELD_DEPTH} levels deep` : `more than ${MAX_HELD_BYTES / 1024} KB of code run from strings in one file`}; apm did not read it)`);

      return;
    }

    heldBytes.set(path, spent + e.code.length);
    chargeText("held", e.code.length, TEXT_PASSES_PER_FILE);
    const scan = inPhase("held", () => scanFile(e.code, "js"));
    const facts = factsIn().get(path) ?? [];
    const snippet = `${e.snippet}${HELD_NOTES[e.origin]}`;

    for (const fact of readFacts(e.code, scan.hidden, scan.commands)) if ((e.origin !== "held" && e.origin !== "data") || HELD_RISKS.has(fact.kind)) facts.push({ ...fact, line: e.line, snippet, near: true });

    if (e.origin === "recovered" && (scan.read === "raw" || scan.findings.some((x) => x.confidence === "confirmed"))) facts.push({ kind: "runs-hidden", line: e.line, snippet, text: false, near: true });
    factsIn().set(path, facts);
    const flows: { flows: FlowFinding[]; exports: Exports } = flowsIn().get(path) ?? { flows: [], exports: new Map() };

    // a string kept as data (an export, a property value, an array element) is not run: its flows are not the file's
    // (a package that exports example code), and what it would do counts only through the facts above
    if (e.origin !== "data") for (const x of scan.flows ?? []) flows.flows.push({ ...x, line: e.line, snippet });
    flowsIn().set(path, flows);

    if (e.origin === "run" || e.origin === "recovered") {
      for (const u of scan.unread ?? []) add("incomplete", `${path}:${e.line}: ${e.snippet} (${u.why})`);

      // the stop is one of `unread`, so it is incomplete already; a string only held is not read for this, as before
      if (scan.flowStopped === true) (layer === "production" ? flowStopped : extraFlowStopped).add(path);
    }

    // code that code held as text runs or holds in turn, as sure as the outer one is to run
    for (const inner of scan.executed ?? []) readHeld(path, { ...inner, line: e.line, snippet: e.snippet, origin: e.origin === "run" ? inner.origin : e.origin }, depth + 1);
  };

  // files production's walk read no text of (a native name, an ELF file, data), and ones it read through a binary's view
  const unreadText = new Set<string>();
  const viewedEver = new Set<string>();
  // the extra layer's walk: what it reaches beyond production's, and what it has read
  const queueX: string[] = [];
  const reachedX = new Set<string>();
  const doneX = new Set<string>();

  /** Reaches `path` in the current layer's walk: production's queue, or the extra layer's. */
  const reach = (path: string): void => {
    if (layer === "production") {
      if (!reachable.has(path)) {
        reachable.add(path);
        queue.push(path);
      }
    } else if (!reachable.has(path) && !reachedX.has(path)) {
      reachedX.add(path);
      queueX.push(path);
    }
  };

  /** Whether the current layer's walk has read `path`. */
  const readYet = (path: string): boolean => seen.has(path) || (layer === "extra" && doneX.has(path));

  /**
   * `word`, in a command `from` runs, names a file it runs: read as source whatever its bytes, and reached when `from`
   * is. Only in the extra layer: production's walk followed a command to one file, by its path, and read nothing more.
   */
  const runs = (from: TarEntry, word: string, reached: boolean): void => {
    // only ever adds: every plausible target is read as source, and a word it cannot resolve takes nothing away
    for (const target of candidatesOf(byPath, from.path, word)) {
      if (target.path === from.path || target.path === "package.json") continue;
      edge(from.path, target.path);
      invoked.add(target.path);

      if (reached && !readYet(target.path)) reach(target.path);
    }
  };

  // what production's walk read that the extra layer reads on: the commands code runs, and the scripts a shell runs
  const laterCommands: { f: TarEntry; line: number; value: string; reached: boolean }[] = [];
  const laterShell: { f: TarEntry; reached: boolean }[] = [];

  /** The language a file is read in: the one its name or shebang gives, and JavaScript (or TypeScript) when code loads it. */
  const languageOf = (path: string, text: string): Lang => {
    const named = langOf(path, text);

    // a type declaration code loads runs too (node strips its types, or older node runs it as JavaScript)
    return runsAsCode.has(path) && (named === "plain" || named === "c" || named === "python") ? "js" : runsAsCode.has(path) && named === "declaration" ? "ts" : named;
  };

  /**
   * The language production (274d284) read `f` in: langOf reads no more of a text than its first line (a shebang), and a
   * newline byte is never inside a UTF-8 sequence, so the line decodes as it does in the whole text.
   */
  const languageBefore = (f: TarEntry): Lang => {
    const eol = f.data.indexOf(0x0a);

    charge("score", eol === -1 ? f.data.length : eol);

    return languageOf(f.path, new TextDecoder().decode(eol === -1 ? f.data : f.data.subarray(0, eol + 1)));
  };

  // every file a load in some file's reading names, reached or not, read before or after it (followImports)
  const loadedAnywhere = new Set<string>();
  // binaries read through the plain view: one a load names by the end of the walks is read again as production reads code
  // it loads (round 6 review of fbc6738, P1). A view counts as it is read, as production's plain reading counted it, so
  // nothing waits but the file: what views add to the result is held to MAX_KEPT_VIEW_BYTES (viewBytes), and its imports
  // are followed and let go (round 7 review of dce1655, memory review of 49b35f9)
  const viewed = new Map<string, { f: TarEntry; reached: boolean }>();
  let viewBytes = 0;
  // what binaries' NUL-deleted views found that their production views did not, by file (countView)
  const viewExtras: { path: string; findings: readonly TextFinding[]; facts: readonly Fact[] }[] = [];
  // a reading stopped for its resources (a binary's text past what it may hold, a shell walk past its bound): what it
  // did not read could cost more than `incomplete`'s 61 points, so the analysis scores 0 (round 13 review of d594415)
  // a streamed read's plan that stopped for its resources stops the analysis too
  let resourceStopped = (input.stoppedBecause ?? []).length > 0;

  /** A shell walk cut at its bound: incomplete, and stopped for its resources. */
  const shellCut = (why: string): void => {
    resourceStopped = true;
    add("incomplete", why);
  };

  // text files read in the language their name gives (plain, C, Python, a declaration) because nothing had loaded them
  // yet: one a load names by the end of the walks is read again as code, as production read a file loaded before it was
  // reached. The order the walk meets files in decides nothing then (round 8 review: a stand-in path reached lib/t字 as
  // well as lib/t漢, its __dirname path reached lib/bridge.dat before lib/middle's load did, and bridge.dat was read as
  // plain text where production read it as JavaScript)
  const plainRead = new Map<string, { f: TarEntry; reached: boolean }>();

  /**
   * Counts a binary's view, as production's plain reading counted the file, and what it keeps against what views may add
   * (viewBytes): the next view's reading is given what is left (kept.ts). Its imports are followed and let go: only its
   * findings and facts stay.
   */
  const countWithin = (f: TarEntry, read: Pick<Extract<BinaryTextScan, { kind: "read" }>, "findings" | "facts" | "extraFindings" | "extraFacts">): void => {
    viewBytes += keptBytes({ findings: [...read.findings, ...read.extraFindings], facts: [...read.facts, ...read.extraFacts] });
    countView(f, read);
  };

  /** Records that some file's reading loads `path`: one read as plain text, or through a view, the extra layer reads again as code. */
  const markLoaded = (path: string): void => {
    loadedAnywhere.add(path);
  };

  /**
   * A Mach-O or universal binary production (274d284) read as text (its executable check never matched one), which
   * nothing runs as a script: read through its views (binary-text.ts), with every finding and fact a plain file gets,
   * from its text decoded as production decoded it (review of 45d3655). Called after the file passed production's
   * holding, size and byte-budget checks and spent its bytes (analyzeFile), as production spent them before reading it
   * (round 16 review of c272202, P2). False when production read it in a language other than plain text: the caller
   * reads it as production did.
   */
  const readBinaryText = (f: TarEntry, reached: boolean): boolean => {
    // production read it as plain text, which is what the view reads, or in a language (JavaScript when code loads it,
    // or one its name gives), whose reading also tokenizes it: `require('./p'/*x*/+'ayload.txt')` (round 5 review of
    // 535a5b5, P1). That one is read below exactly as production read it, at production's cost, as is one any file
    // was already found to load
    if (languageBefore(f) !== "plain" || loadedAnywhere.has(f.path)) return false;

    // its reading may keep what is left of the views' budget, charged as it finds it (kept.ts)
    const read = scanBinaryText(f.data, (input.maxKeptViewBytes ?? MAX_KEPT_VIEW_BYTES) - viewBytes);

    if (read.kind === "read") {
      // what it reaches and loads counts now, as production's plain reader had it count, and what it holds too: a load
      // found later reads it again as code (viewed), which only adds to what it counted
      followImports(f, read.imports, reached, false);
      countWithin(f, read);

      // a reading that did not finish keeps what it found, every signal of it, and says so: an analysis that stopped is
      // incomplete, never a file left out for its size or the budget, and the install verdict holds it (round 12 review
      // of 7cd0b2b, P2: its findings were dropped and the file reported unread for the budget, so a Mach-O production
      // scored 65 (C), complete, scored 100 (P), which installs)
      if (read.stopped) resourceStopped = true;

      // a load whose path holds a stand-in the bytes could not give: which file production's path loaded is not known
      if (read.unresolved) {
        resourceStopped = true;
        add("incomplete", `${f.path}: a load in its text names a path built from pieces around a character apm holds as a stand-in, so which file it loads was not known; apm stopped there`);
      }

      if (read.stopped) add("incomplete", `${f.path}: apm stopped reading its text at what one reading may hold (${(MAX_KEPT_VIEW_BYTES / 1024 / 1024).toFixed(0)} MiB of results, ${(MAX_SCAN_TEMP_BYTES / 1024 / 1024).toFixed(0)} MiB a list while reading); what it found counts, and the rest of it was not read`);

      viewed.set(f.path, { f, reached });
      viewedEver.add(f.path);

      // production's floor (readLikeV3) does not read it again, as production's did not read a file its first walk read
      // whole, but reads its imports again when it reaches it, from its view (scanBinaryImports)
      if (layer === "production") viewedWhole.add(f);

      return true;
    }

    return false;
  };

  /** What `read` found in the text of `f`, a file production read as plain text: counted as production counted it. */
  const countView = (f: TarEntry, read: Pick<Extract<BinaryTextScan, { kind: "read" }>, "findings" | "facts" | "extraFindings" | "extraFacts">): void => {
    for (const finding of read.findings) add(finding.id, describeFinding(f.path, finding), finding.confidence, citedAs(finding));
    (layer === "production" ? rawFiles : extraRaw).add(f.path);
    factsIn().set(f.path, [...(factsIn().get(f.path) ?? []), ...read.facts]);

    // what the NUL-deleted view adds is kept apart: the analysis is assessed on production's reading alone, then again
    // with these, and takes only what they add (viewExtras, below)
    if (read.extraFindings.length > 0 || read.extraFacts.length > 0) viewExtras.push({ path: f.path, findings: read.extraFindings, facts: read.extraFacts });
  };

  /**
   * What `f`'s reading imports, followed as analyzeFile follows a file's: each path an edge and, from a reached file,
   * reached; each load also code (runsAsCode) and, from any file, reached or not, recorded (loadedAnywhere); a computed
   * load evidence where analyzeFile cites one. A path read from a binary's view holds the real characters production's
   * text held (binary-text.ts): it names the file production's exact path named, and no other.
   */
  const followImports = (f: TarEntry, imports: Imports, reached: boolean, javascript: boolean): void => {
    for (const d of javascript || reached ? imports.dynamic : []) {
      add("dynamic-require", `${f.path}:${d.line}: ${d.snippet}`);
      dynamicAt.add(`${f.path}:${d.line}`);
    }

    for (const spec of imports.paths) {
      const load = imports.loads.includes(spec);
      // the file production's exact path named (a binary's paths hold its real characters: binary-text.ts)
      const target = resolveIn(byPath, joinPath(dirOf(f.path), spec));

      if (!target) continue;
      edge(f.path, target.path);

      if (load) markLoaded(target.path);

      if (readYet(target.path)) continue;

      if (load) {
        runsAsCode.add(target.path);
        exposedOnly.delete(target.path);
      }

      if (reached) reach(target.path);
    }
  };

  // what the extra layer has read of the budget: its own, so production's walk reads what production's read
  let scannedExtra = 0;
  // files production's walk left unread for their holding, size or the byte budget: the extra layer reads none of them
  const leftUnread = new Set<string>();

  const analyzeFile = (f: TarEntry, reached: boolean): void => {
    const production = layer === "production";
    // read as source whatever its bytes: what a script or command runs, in the extra layer (production read every file
    // by its name and first bytes)
    const asSource = !production && invoked.has(f.path);
    // a Mach-O read through its views rather than decoded whole
    let view: boolean;

    if (production) {
      // production's (274d284) reader, exactly, whoever loads or runs the file (round 16 review of c272202, P1): a native
      // name or an ELF file is listed as `binary` and not read, nor is data (an image, a font, an archive, WebAssembly).
      // A Mach-O, which its check never matched, is read as the text it read
      const native = nativeBefore(f.path, f.data);

      if (native || isBinary(f)) add("binary", f.path);

      if (native || hasDataMagic(f.data)) {
        unreadText.add(f.path);

        return;
      }

      view = isBinary(f);
    } else {
      if (leftUnread.has(f.path)) return;
      // node loads an entry or a required file as JavaScript: only a .node addon or a real executable is native there;
      // what a script or command runs is read as source whatever its bytes
      const native = runsAsCode.has(f.path) ? isNativeEntry(f) : isBinary(f);

      if (native) add("binary", f.path);
      view = !asSource && (native || isBinaryData(f));

      // what production never read and nothing reads as source stays unread
      if (view && !readAsTextBefore(f.path, f.data)) {
        unreadText.add(f.path);

        return;
      }
    }

    // production's holding, size and byte-budget checks, in its order, before anything of the file is read or its loads
    // followed; the extra layer has the same checks on an allowance of its own
    if ((production ? notHeld : notHeldExtra).has(f)) {
      if (production) {
        skipNotHeld(f, reached, skipped, unanalyzed);
        leftUnread.add(f.path);
      }

      return;
    }

    if (f.data.length > MAX_ANALYZED_FILE_BYTES) {
      if (production) {
        skipped.push({ path: f.path, size: f.data.length, reason: "too-large" });
        leftUnread.add(f.path);
      }

      return;
    }

    if ((production ? scanned : scannedExtra) + f.data.length > budget) {
      if (production) {
        (reached ? skipped : unanalyzed).push({ path: f.path, size: f.data.length, reason: "over-budget" });
        leftUnread.add(f.path);
      }

      return;
    }

    if (production) scanned += f.data.length;
    else scannedExtra += f.data.length;
    // decoding the bytes, choosing the language, and the passes below over the whole text: the file's facts, v3's
    // imports and the joined text it reads them from
    chargeText("text", f.data.length, TEXT_PASSES_PER_FILE);

    if (view && readBinaryText(f, reached)) return;
    // read whatever the bytes are: skipping "non-text" would let a NUL byte hide code
    const text = new TextDecoder().decode(f.data);

    const lang = languageOf(f.path, text);
    const scan = scanFile(text, lang);

    // read in its own language only because nothing loads it yet: a later load reads it again as code (plainRead)
    if (!runsAsCode.has(f.path) && (lang === "plain" || lang === "c" || lang === "python" || lang === "declaration")) plainRead.set(f.path, { f, reached });

    // a README or LICENSE a pattern exposes is not JavaScript: node would throw a SyntaxError, so nothing in it runs
    if (scan.rejected && exposedOnly.has(f.path) && NOT_CODE.test(f.path)) return;

    for (const finding of scan.findings) add(finding.id, describeFinding(f.path, finding), finding.confidence, citedAs(finding));

    for (const note of scan.notes) {
      const list = limits.get(note);

      if (list) list.push(f.path);
      else limits.set(note, [f.path]);
    }

    if (lang !== "json" && lang !== "declaration") {
      if (scan.read === "raw") (production ? rawFiles : extraRaw).add(f.path);
      const facts = readFacts(text, scan.hidden, scan.commands);
      // the parser's environment reads follow aliases and `globalThis.process.env`; a name read through one sits as near
      // the network as the file is small
      const near = text.length < 16 * 1024;

      for (const e of scan.env ?? []) facts.push(e.name === null ? { kind: "env-object", line: e.line, snippet: e.snippet, text: false, near } : { kind: "env", line: e.line, snippet: e.snippet, name: e.name, text: false, near });

      // production read each file once; an extra reading of it adds to what the extra layer has of it, never replaces
      if (production) {
        fileFacts.set(f.path, facts);
        fileFlows.set(f.path, { flows: [...(scan.flows ?? [])], exports: scan.exports ?? new Map() });
      } else {
        extraFacts.set(f.path, [...(extraFacts.get(f.path) ?? []), ...facts]);
        const had = extraFlows.get(f.path);

        extraFlows.set(f.path, { flows: [...(had?.flows ?? []), ...(scan.flows ?? [])], exports: scan.exports ?? had?.exports ?? new Map() });
      }

      for (const e of scan.executed ?? []) readHeld(f.path, e, 1);

      for (const u of scan.unread ?? []) add("incomplete", `${f.path}:${u.line}: ${u.snippet} (${u.why})`);

      if (scan.flowStopped === true) (production ? flowStopped : extraFlowStopped).add(f.path);
    }

    // a file a command runs (`exec('node app.js')`) runs when this file does, as a file it loads does: production
    // linked the first file a word names (an edge, nothing read); the extra layer follows every one (laterCommands)
    for (const c of scan.commands ?? []) {
      if (production) {
        // production's words for it (scriptTargetsBefore), each list held to MAX_SHELL_TOKENS: one cut there stops the
        // reading, since production linked every word
        const lists = [scriptTargetsBeforeWithin(c.value, MAX_SHELL_TOKENS), commandWordsWithin(c.value, MAX_SHELL_TOKENS)];

        if (lists.some((l) => l.kind === "cut")) shellCut(`${f.path}:${c.line}: apm read the first ${MAX_SHELL_TOKENS.toLocaleString("en-US")} words of the command it runs and stopped, so what the rest runs was not followed`);

        // each word once: the edges are a set, and resolving a word again finds the same file
        for (const word of new Set(lists.flatMap((l) => l.words))) {
          const target = resolveIn(byPath, joinPath(dirOf(f.path), word)) ?? resolveIn(byPath, word);

          if (target && target.path !== f.path && target.path !== "package.json") edge(f.path, target.path);
        }

        laterCommands.push({ f, line: c.line, value: c.value, reached });
      } else followCommand(f, c.line, c.value, reached);
    }

    // a shell script runs what its commands name, sourced files too (`sh lib/tool`, `. ./lib/env`), whatever their
    // bytes: a bounded walk, since each file is read once (review of 4ac264b, P1: `sh setup.sh` running `sh lib/tool`,
    // a valid Mach-O followed by shell lines, scored 90 where the same bytes run directly scored 0). A walk cut at its
    // bound did not finish: it is incomplete, and scores 0 (round 13 review of d594415, P2). Production did not walk a
    // script: the extra layer does (laterShell)
    if (lang === "plain" && (asSource || isShellScript(f, text))) {
      if (production) laterShell.push({ f, reached });
      else walkShell(f, text, reached);
    }

    if ((installTargets.has(f.path) || (!production && installTargetsX.has(f.path))) && isShellScript(f, text) && isInlineDownload(text)) add("install-download", `${f.path}: run by an install script and downloads code`);
    // every path apm-score-v3's pattern finds in the text is reached too, so no file v3 read goes unread
    const v3Imports = scan.read === "parsed" ? importsOf(joinStrings(text).text) : null;
    const imports = v3Imports ? { ...scan.imports, paths: [...new Set([...scan.imports.paths, ...v3Imports.paths])] } : scan.imports;

    if (production) readWhole.set(f, v3Imports);

    // a computed load in JavaScript counts wherever it is: a file nothing here reaches can still be loaded and run by its
    // path. In any other file it is only v3's pattern over text, reported where v3 reported it, in a reached file.
    const javascript = lang === "js" || lang === "jsx" || lang === "ts" || lang === "tsx";

    for (const d of javascript || reached ? imports.dynamic : []) {
      add("dynamic-require", `${f.path}:${d.line}: ${d.snippet}`);

      if (production) dynamicAt.add(`${f.path}:${d.line}`);
    }

    for (const spec of imports.paths) {
      const target = resolveIn(byPath, joinPath(dirOf(f.path), spec));

      if (target) edge(f.path, target.path);

      // a load from any file, reached or not, makes its target code: one production's walk read as plain text before the
      // load is read again as code by the extra layer (viewed, plainRead), which only adds
      if (target && imports.loads.includes(spec)) markLoaded(target.path);

      if (!target || readYet(target.path)) continue;

      if (imports.loads.includes(spec)) {
        runsAsCode.add(target.path);
        exposedOnly.delete(target.path);
      }

      if (reached) reach(target.path);
    }
  };

  /** A command code runs, followed as the extra layer follows one: every file each word could name, read as source. */
  const followCommand = (f: TarEntry, line: number, value: string, reached: boolean): void => {
    const lists = [scriptTargetsWithin(value, MAX_SHELL_TOKENS), commandWordsWithin(value, MAX_SHELL_TOKENS)];

    for (const word of new Set(lists.flatMap((l) => l.words))) runs(f, word, reached);

    if (lists.some((l) => l.kind === "cut")) shellCut(`${f.path}:${line}: apm read the first ${MAX_SHELL_TOKENS.toLocaleString("en-US")} words of the command it runs and stopped, so what the rest runs was not followed`);
  };

  /** A shell script's commands, followed as the extra layer follows them: every file a word could name, read as source. */
  const walkShell = (f: TarEntry, text: string, reached: boolean): void => {
    const shell = shellWords(text);

    // each word once: a script that names one word 100,000 times runs one file (round 17: 800 scripts of `a a a ...`
    // resolved 200,000 words each, about 0.3 s a script)
    for (const word of new Set(shell.words)) runs(f, word, reached);

    if (shell.kind === "cut") shellCut(`${f.path}: apm read the first ${MAX_SHELL_TOKENS.toLocaleString("en-US")} words of this script's commands and stopped, so what the rest runs was not followed`);
  };

  for (; qi < queue.length; qi++) {
    const f = byPath.get(queue[qi] ?? "");

    if (!f || seen.has(f.path)) continue;
    seen.add(f.path);
    analyzeFile(f, true);
  }

  const rest = files.filter((f) => !seen.has(f.path) && !NOT_CODE.test(f.path)).sort((a, b) => Number(!CODE_EXT.test(a.path)) - Number(!CODE_EXT.test(b.path)));

  for (const f of rest) {
    seen.add(f.path);
    analyzeFile(f, false);

    // anything the second pass reaches by a resolvable path is read too, even with a non-code name
    for (; qi < queue.length; qi++) {
      const g = byPath.get(queue[qi] ?? "");

      if (!g || seen.has(g.path)) continue;
      seen.add(g.path);
      analyzeFile(g, true);
    }
  }

  // the floor: every file apm-score-v3 reads, in its order and within its budget, read whole by its rules
  const readRaw = (f: TarEntry, text: string): void => {
    if (NEVER_RUN.test(f.path) || fileFacts.has(f.path)) return;
    fileFacts.set(f.path, readFacts(text));
    rawFiles.add(f.path);
  };

  // production's floor, as production's: it read no file as source for being run (the extra layer does)
  // a viewed file's imports, read again from its production view as production read them again from its text: held only
  // while the floor's walk follows them. A reading that stops here did not finish
  const viewImports = (f: TarEntry): Imports => {
    const read = scanBinaryImports(f.data);

    if (read.kind !== "read") return { paths: [], loads: [], dynamic: [] };

    if (read.stopped) {
      resourceStopped = true;
      add("incomplete", `${f.path}: apm stopped reading the paths its text loads at what one reading may hold (${(MAX_KEPT_VIEW_BYTES / 1024 / 1024).toFixed(0)} MiB of results, ${(MAX_SCAN_TEMP_BYTES / 1024 / 1024).toFixed(0)} MiB a list while reading), so what the rest loads was not followed`);
    }

    return read.imports;
  };

  const v3 = readLikeV3({ files, byPath, manifest, installCommands, gyp, budget, readWhole, dynamicAt, add, read: readRaw, notHeld, invoked: new Set(), viewed: viewedWhole, viewImports });
  // production's facts before its flows across files add theirs: the extra layer's assessment works those out again
  const productionFacts = new Map([...fileFacts].map(([path, list]) => [path, [...list]]));

  const { cross, cut } = inPhase("cross-file", () => addFlowFacts(fileFlows, fileFacts, byPath, input.maxCrossFileSteps));

  for (const why of cut) add("incomplete", why);

  if (cross.exhausted) add("incomplete", `flows across files: stopped at the work budget (${input.maxCrossFileSteps ?? MAX_CROSS_FILE_STEPS} steps), so values one file gives another were not all followed`);

  // Files left unread for their size or the byte budget, reached or not, are what the analysis did not read, not
  // something it found: they make its coverage partial and cost no points (apm-score-v11; before, -61 as `incomplete`
  // and -20 as `unanalyzed-files`). Installs check coverage apart from the score, so a partial reading still warns,
  // and strict mode and ~safe refuse it. Each file is counted once, whichever walk skipped it.
  const omitted = new Map([...omittedByName, ...skipped, ...unanalyzed, ...v3.skipped, ...v3.unanalyzed].map((s) => [s.path, s]));

  const coverage: Coverage =
    omitted.size === 0
      ? { kind: "complete" }
      : {
          kind: "partial",
          omittedFiles: omitted.size,
          omittedBytes: [...omitted.values()].reduce((n, s) => n + s.size, 0),
          reasons: COVERAGE_REASONS.filter((r) => [...omitted.values()].some((s) => s.reason === r)),
          notes,
        };

  for (const f of files) if (!seen.has(f.path) && (nativeBefore(f.path, f.data) || isBinary(f))) add("binary", f.path);

  const facts = factsOf(manifest, files);

  if (!facts.license) add("no-license", "package.json has no license field");
  const typos = typoConflicts(input.name);

  for (const t of typos) add("typosquat", t.reason);

  if (input.previousPublishers.length > 0 && !input.previousPublishers.includes(input.publisher)) {
    add("new-publisher", `${input.publisher} has not published this package before (previous: ${publisherList(input.previousPublishers)})`);
  }

  for (const d of input.riskyDependencies ?? []) add("risky-dependency", `${d.name}@${d.version} scores ${d.score}/100`);

  for (const d of input.addedDependencies ?? []) add("new-dependency", `adds ${d}`);

  // ---------- the extra layer: what the branch reads beyond production's walk, kept apart ----------
  const productionStopped = resourceStopped;

  layer = "extra";

  for (const c of laterCommands) followCommand(c.f, c.line, c.value, c.reached);

  for (const sh of laterShell) walkShell(sh.f, new TextDecoder().decode(sh.f.data), sh.reached);

  // until nothing more is read: what a script or a command runs that production's walk read no text of (a native name,
  // an ELF file, data), read as source; what that reaches; and a file production's walk read as plain text, or through
  // a binary's plain view, that some file loads, read again as code (round 6 review of fbc6738: index.js -> lib/first
  // (plain, `require('./tool')`) -> lib/tool (`require('./p'/*x*/+'ayload.txt')`) reaches the payload). Each only adds
  for (let more = true, qx = 0; more; ) {
    more = false;

    // a file production's walk read no text of, or read only through a binary's view, that a script or command runs, or
    // that node loads as JavaScript (an entry, a required file) under a native name other than `.node`: read as source.
    // Production listed these as binary and read none of them (round 16 review of c272202, P1); one its walk did not
    // reach at all is read only when the extra layer reaches it
    for (const path of [...invoked, ...runsAsCode]) {
      const f = byPath.get(path);

      if (!f || doneX.has(path) || !seen.has(path) || !(unreadText.has(path) || viewedEver.has(path))) continue;
      doneX.add(path);
      // read as source here, so not again below as a view a load names
      viewed.delete(path);
      analyzeFile(f, reachable.has(path) || reachedX.has(path));
      more = true;
    }

    for (; qx < queueX.length; qx++) {
      const path = queueX[qx] ?? "";
      const f = byPath.get(path);

      if (!f || seen.has(path) || doneX.has(path)) continue;
      doneX.add(path);
      analyzeFile(f, true);
      more = true;
    }

    for (const path of [...viewed.keys(), ...plainRead.keys()]) {
      if (!loadedAnywhere.has(path) && !runsAsCode.has(path)) continue;
      const v = viewed.get(path) ?? plainRead.get(path);

      viewed.delete(path);
      plainRead.delete(path);

      if (v === undefined) continue;
      runsAsCode.add(path);
      exposedOnly.delete(path);
      analyzeFile(v.f, v.reached || reachable.has(path) || reachedX.has(path));
      more = true;
    }
  }

  layer = "production";

  // scoring weighs every fact of every file, every edge between files and every piece of evidence
  charge("score", [...fileFacts.values()].reduce((n, l) => n + l.length * 8, 0) + [...edges.values()].reduce((n, s) => n + s.size * 4, 0));

  const assessInput = {
    edges,
    // every lifecycle script that runs on the installing machine: install hooks, and prepare, prepack and postpack,
    // which npm runs when it installs a package from git
    installRoots: [...installRunsOf(hookCommands, byPath), ...(gyp ? [gyp.path] : [])],
    // production's binaries (a native name, ELF's magic) and every executable whose structure parses
    installBinaries: installRunsOf(hookCommands, byPath).filter((p) => {
      const f = byPath.get(p);

      return f !== undefined && (nativeBefore(f.path, f.data) || isBinary(f));
    }),
    reached: reachable,
    rawFiles,
    flowStopped,
    crossStopped: cross.exhausted,
    hookEvidence,
    resourceStopped: productionStopped,
    gyp: gyp !== undefined,
    binPaths: new Set(entryPoints(manifest).flatMap((e) => (e.field.startsWith("bin") ? [joinPath("", e.path)] : []))),
    declaration: declarationOf(manifest),
  };

  // production's walk, assessed on its own: every file read as production read it, so this is production's assessment
  // (round 14 review of e2b3b8e, P1: assessed with a binary's NUL-deleted view, a distant dump took the place of a nearby
  // harvest, and 62 (C) became 97 (A); round 15 review of c139b5b, P1: a file read again as code replaced the facts its
  // plain reading gave, and a stand-in changed which reader a file got, and 35 (F) became 97 (A))
  const production = inPhase("score", () => assess({ ...assessInput, found, fileFacts }));
  const extras = extraAdds.length > 0 || extraFacts.size > 0 || extraFlows.size > 0 || extraEdges.size > 0 || extraRaw.size > 0 || extraFlowStopped.size > 0 || viewExtras.length > 0 || reachedX.size > 0 || resourceStopped !== productionStopped;
  // then with what the extra layer and the NUL-deleted views add, of which only what it adds is taken: a signal
  // production's assessment lacks. Nothing production's assessment concluded is removed or changed, so the score is
  // never above it, and the verdict never looser

  const assessed = !extras
    ? production
    : withExtras(
        production,
        inPhase("score", () => {
          const more = found.clone();
          // a piece of evidence the extra layer read at a line production's reading cites already for that signal adds
          // nothing (the same text read again, perhaps with a stand-in shown: round 15 review, P3)
          const cited = new Set<string>();

          for (const id of new Set(extraAdds.map((x) => x.id))) {
            const got = found.get(id);

            for (const ev of [...(got?.evidence ?? []), ...(got?.possible ?? [])]) {
              const at = evidenceAt(ev);

              if (at) cited.add(`${id} ${at.file}:${at.line}`);
            }
          }

          for (const x of extraAdds) {
            const at = evidenceAt(x.ev);

            if (!at || !cited.has(`${x.id} ${at.file}:${at.line}`)) more.add(x.id, x.ev, x.confidence, x.cited);
          }

          for (const x of viewExtras) for (const f of x.findings) more.add(f.id, describeFinding(x.path, f), f.confidence, citedAs(f));
          const facts = new Map<string, Fact[]>([...productionFacts].map(([path, list]) => [path, [...list]]));

          for (const [path, list] of extraFacts) facts.set(path, [...(facts.get(path) ?? []), ...list]);

          for (const x of viewExtras) facts.set(x.path, [...(facts.get(x.path) ?? []), ...x.facts]);
          const flows = new Map(fileFlows);

          for (const [path, x] of extraFlows) flows.set(path, { flows: [...(flows.get(path)?.flows ?? []), ...x.flows], exports: flows.get(path)?.exports ?? x.exports });
          const both = inPhase("cross-file", () => addFlowFacts(flows, facts, byPath, input.maxCrossFileSteps));

          for (const why of both.cut) more.add("incomplete", why);

          if (both.cross.exhausted) more.add("incomplete", `flows across files: stopped at the work budget (${input.maxCrossFileSteps ?? MAX_CROSS_FILE_STEPS} steps), so values one file gives another were not all followed`);
          const allEdges = new Map([...edges].map(([from, to]) => [from, new Set(to)]));

          for (const [from, to] of extraEdges) allEdges.set(from, new Set([...(allEdges.get(from) ?? []), ...to]));

          const installRunsX = installRunsOf(hookCommands, byPath, scriptTargets);

          return assess({
            ...assessInput,
            // what install hooks run as the second layer reads them
            installRoots: [...new Set([...assessInput.installRoots, ...installRunsX])],
            installBinaries: [
              ...new Set([
                ...assessInput.installBinaries,
                ...installRunsX.filter((p) => {
                  const f = byPath.get(p);

                  return f !== undefined && (nativeBefore(f.path, f.data) || isBinary(f));
                }),
              ]),
            ],
            found: more,
            fileFacts: facts,
            edges: allEdges,
            reached: new Set([...reachable, ...reachedX]),
            rawFiles: new Set([...rawFiles, ...extraRaw]),
            flowStopped: new Set([...flowStopped, ...extraFlowStopped]),
            crossStopped: cross.exhausted || both.cross.exhausted,
            resourceStopped,
          });
        }),
      );

  const signals = assessed.signals;

  const notChecked = [
    ...NOT_CHECKED,
    ...[...limits].map(([note, paths]) => `${note} (${paths.slice(0, 3).join(", ")}${paths.length > 3 ? ` and ${paths.length - 3} more files` : ""})`),
    ...[unanalyzed, v3.unanalyzed].flatMap((list) => (list.length === 0 ? [] : [`${list.length} file(s) not analyzed: the package is larger than the ${(budget / (1024 * 1024)).toFixed(1)} MB one analysis reads`])),
    ...(input.uncheckedDependencies ?? []).map((d) => `dependency ${d}`),
  ];

  // both walks can skip the same file
  // what coverage counts, each file once: the files left unread by name too (package.json, binding.gyp, the Makefiles)
  const skippedOnce = new Map([...omittedByName, ...skipped, ...unanalyzed, ...v3.skipped, ...v3.unanalyzed].map((s) => [`${s.reason}:${s.path}`, s]));

  return {
    scorer: SCORER,
    signals,
    facts,
    notChecked: [...new Set(notChecked)],
    skipped: [...skippedOnce.values()],
    capabilities: assessed.capabilities,
    declaration: assessed.declaration,
    coverage,
  };
}

/**
 * Production's assessment, and of `more` (the same with what the NUL-deleted views added) only what production's lacks:
 * a signal it does not have, which costs points, and a capability it does not list. Every signal production's
 * assessment has stays as it gave it, so the score is never above production's and the verdict never looser, whatever
 * the second views hold.
 */
function withExtras(production: Assessed, more: Assessed): Assessed {
  const had = new Set(production.signals.map((s) => s.id));
  const added = more.signals.filter((s) => !had.has(s.id) && s.points < 0);
  const listed = new Set(production.capabilities.map((c) => c.id));
  const stronger = more.signals.find((s) => s.id === "incomplete");

  // production's signals first, in its order, as it gave them, except that an `incomplete` the second reading stopped
  // for its resources (-100) raises production's (-61) and adds its reasons; what the second views add after
  return {
    signals: [...production.signals.map((s) => (s.id === "incomplete" && stronger !== undefined ? strongerIncomplete(s, stronger) : s)), ...added],
    capabilities: [...production.capabilities, ...more.capabilities.filter((c) => !listed.has(c.id))],
    declaration: production.declaration,
  };
}

/**
 * Production's `incomplete`, raised to `stronger`'s points when those are lower (a reading the extra layer stopped for its
 * resources scores 0: round 16 review of c272202, P2), with both readings' reasons: production's as it gave them, after
 * the reasons only the extra layer has, so the reason it stopped is among what every surface shows.
 */
function strongerIncomplete(had: Signal, stronger: Signal): Signal {
  if (stronger.points >= had.points) return had;
  const kept = [...had.evidence, ...(had.more ?? [])];
  const theirs = [...stronger.evidence, ...(stronger.more ?? [])].filter((e) => !kept.includes(e));
  const all = [...theirs, ...kept];
  const out = keepRest({ id: had.id, label: had.label, points: stronger.points, evidence: all.slice(0, SHOWN_EVIDENCE), confidence: had.confidence }, all);

  if (had.fallback !== undefined) out.fallback = had.fallback;
  const uncounted = (had.uncounted ?? 0) + (stronger.uncounted ?? 0);

  // evidence either reading counted and did not keep stays counted, and every source either cited stays on record
  if (uncounted > 0) {
    out.uncounted = (out.uncounted ?? 0) + uncounted;
    out.sources = [...new Set([...(out.sources ?? all.map(citedSource)), ...(had.sources ?? []), ...(stronger.sources ?? [])])];
  }

  return out;
}

// ---------- apm-score-v10: code held as text, and flows across files ----------

/** How deep code held as text is read (code in a string that runs code in a string), and how much of it per file. */
const MAX_HELD_DEPTH = 3;
const MAX_HELD_BYTES = 256 * 1024;

/** What a fact found in code held as text says after its snippet. */
const HELD_NOTES: Record<ExecutedCode["origin"], string> = {
  run: " (in code it runs from a string)",
  recovered: " (in its own source, which it turns back into code and runs)",
  held: " (in a string that holds code)",
  data: " (in a string it keeps as data)",
};

/** The facts a string that only holds code adds: what it would do that malware does, not what it can do. */
const HELD_RISKS: ReadonlySet<Fact["kind"]> = new Set(RISK_FACT_KINDS);



/** Paths a shell script's commands may run: after an interpreter or `.`/`source`, and every word that could name a file. */
function shellWords(text: string): ShellWords {
  // each list at most MAX_SHELL_TOKENS: a script's whole text is read for them (round 12: a 4 MB quoted word ended the
  // isolate where production, which never read a script's words this way, also did, though elsewhere). Past that the
  // walk is cut, and says so (round 13 review of d594415, P2: 100,010 commands before `sh ./payload.node` scored 90,
  // complete, where 99,000 scored 0)
  const lists = [scriptTargetsWithin(text, MAX_SHELL_TOKENS), commandWordsWithin(text, MAX_SHELL_TOKENS), shellTokens(text)];
  const words = lists.flatMap((l) => l.words);

  charge("score", words.length);

  return { kind: lists.some((l) => l.kind === "cut") ? "cut" : "complete", words };
}

/** Characters that end a shell word outside quotes. */
const SHELL_BREAK = new Set([" ", "\t", "\n", "\r", ";", "&", "|", "(", ")", "<", ">"]);

/** At most this many words are read from one script: more is not a real install script, and bounds the walk. */
const MAX_SHELL_TOKENS = 100_000;

/** The longest word that can name a file (PATH_MAX): one longer is let go as it is read, never built whole. */
const MAX_SHELL_WORD = 4096;

/**
 * The words a shell would see in `text`, quotes removed (`"lib/pay load.txt"`, `'a b'`, `lib/pay\ load.txt`), comments
 * left out. A word whose value depends on the run (a `$` expansion, a backtick, an unquoted glob) cannot be resolved
 * here and is left out: it adds nothing, and takes nothing away.
 */
export function shellTokens(text: string): ShellWords {
  const out: string[] = [];
  let cut = false;
  let word = "";
  let long = false;
  let has = false;
  let open = false;
  let quote: "'" | '"' | null = null;

  // a word is built a character at a time: past MAX_SHELL_WORD it names no file, and is let go
  const put = (c: string): void => {
    if (word.length < MAX_SHELL_WORD) word += c;
    else long = true;
  };

  const end = (): void => {
    if (has && !open && !long && word.length > 0) {
      if (out.length < MAX_SHELL_TOKENS) out.push(word);
      else cut = true;
    }

    word = "";
    long = false;
    has = false;
    open = false;
  };

  chargeText("score", text.length, 2);

  for (let i = 0; i < text.length; i++) {
    const c = text[i] ?? "";

    if (quote === "'") {
      if (c === "'") quote = null;
      else put(c);
      continue;
    }

    if (c === "\\" && i + 1 < text.length) {
      const next = text[++i] ?? "";

      // a backslash before a newline joins the lines; before anything else it quotes it
      if (next !== "\n") {
        put(next);
        has = true;
      }

      continue;
    }

    if (quote === '"') {
      if (c === '"') quote = null;
      else {
        if (c === "$" || c === "`") open = true;
        put(c);
      }

      continue;
    }

    if (c === "'" || c === '"') {
      quote = c;
      has = true;
      continue;
    }

    if (c === "#" && !has) {
      while (i < text.length && text[i] !== "\n") i++;
      end();
      continue;
    }

    if (SHELL_BREAK.has(c)) {
      end();
      continue;
    }

    if (c === "$" || c === "`" || c === "*" || c === "?" || c === "[" || (c === "~" && !has)) open = true;
    put(c);
    has = true;
  }

  end();

  return { kind: cut ? "cut" : "complete", words: out };
}

/** At most this many flow facts of one kind per file. */
const MAX_FLOW_FACTS = 40;

/** At most this many reasons one file's cut flows make the analysis incomplete: one is enough to say so. */
const MAX_CUT_REASONS = 5;

/**
 * What a flow cut at a precision bound may carry that makes its call a reason the analysis is incomplete, by what the
 * call does: a request may send the whole environment or a credential file's contents; a call that runs, loads or
 * executes may run downloaded data or this program's own source; a call apm could not name may do either. A read is
 * not among them (opening a path sends and runs nothing), and neither is one named token or a cut value with none of
 * these, which stay a note.
 */
function cutCarries(kind: Sink["kind"], labels: ReadonlySet<Label>): string[] {
  const out: string[] = [];
  const has = (l: Label): boolean => labels.has(l);
  const sends = kind === "request" || kind === "bounded";
  const runs = kind === "code" || kind === "shell" || kind === "file" || kind === "splice" || kind === "bounded";

  if (sends && (has("env") || has("env-key"))) out.push("the whole environment");

  if (sends && has("cred")) out.push("a credential file's contents");

  if (runs && (has("net") || has("net-field"))) out.push("what a network response gave");

  if (runs && [...labels].some((l) => l.startsWith("src:"))) out.push("its own source");

  return out;
}

/** What a cut flow's reason says the call does with it. */
const CUT_CALL: Record<Sink["kind"], string> = {
  code: "what this call runs as code",
  shell: "what this call runs as a command",
  request: "what this call sends",
  read: "the path this call opens",
  file: "the file this call runs",
  splice: "what this call puts into a command",
  bounded: "apm could not tell what this call does, and what it is given",
};

/**
 * What reached a call in each parsed file, as facts: the whole environment, a credential file's contents or three
 * families of tokens sent in a request; a credential path opened by a read; downloaded data run as code or as a
 * command. What a relative import carries is what that file exports (worked out the same way, through its own imports),
 * so a read in one file and a request in another are one flow.
 */
/** The cross-file resolution the facts came from, and why cut flows make the analysis incomplete. */
type FlowFacts = { cross: CrossFile; cut: string[] };

function addFlowFacts(fileFlows: ReadonlyMap<string, { flows: readonly FlowFinding[]; exports: Exports }>, fileFacts: Map<string, Fact[]>, byPath: ReadonlyMap<string, TarEntry>, maxSteps?: number): FlowFacts {
  const cross = new CrossFile(
    (path) => fileFlows.get(path)?.exports,
    (from, spec) => resolveIn(byPath, joinPath(dirOf(from), spec))?.path,
    maxSteps,
  );

  const resolve = (path: string, labels: readonly Label[]): Set<Label> => cross.resolve(path, labels);
  const cut: string[] = [];

  for (const [path, { flows }] of fileFlows) {
    const facts = fileFacts.get(path) ?? [];

    // facts of each kind counted once, not by filtering the list for every one
    const counts = new Map<Fact["kind"], number>();

    for (const x of facts) counts.set(x.kind, (counts.get(x.kind) ?? 0) + 1);

    const fact = (kind: Fact["kind"], f: FlowFinding, name: string): void => {
      const n = counts.get(kind) ?? 0;

      if (n >= MAX_FLOW_FACTS) return;
      counts.set(kind, n + 1);
      facts.push({ kind, line: f.line, snippet: f.snippet, name, text: false, near: true });
    };

    let cutReasons = 0;

    for (const f of flows) {
      const labels = resolve(path, f.labels);

      const bounds = [...labels].flatMap((l): Bound[] => {
        const b = boundOf(l);

        return b === null ? [] : [b];
      });

      // a value cut at a bound may carry more than apm saw: when what it carries is what a stealer sends, or code to
      // run, apm cannot say the call is harmless, nor that it does what the labels say, so the analysis is incomplete
      if (bounds.length > 0) {
        const carried = cutCarries(f.kind, labels);

        if (carried.length > 0) {
          if (cutReasons++ < MAX_CUT_REASONS) cut.push(`${path}:${f.line}: ${f.snippet} (apm stopped following a value here at ${[...new Set(bounds)].map((b) => PRECISION_BOUNDS[b]).join(" and ")}; ${CUT_CALL[f.kind]} may be ${carried.join(" or ")})`);

          continue;
        }
      }

      if (f.kind === "bounded") continue;

      if (f.kind === "request") {
        if (labels.has("env")) fact("sends-env", f, "sends the whole environment in a request");

        if (labels.has("cred")) fact("sends-credential", f, "sends what it read from a credential file");
        charge("cross-file", labels.size);
        const families = new Set([...labels].flatMap((l) => (l.startsWith("secret:") ? [l.slice("secret:".length)] : [])));

        if (families.size >= 3) fact("sends-secrets", f, `sends ${[...families].join(", ")} tokens in one request`);
      } else if (f.kind === "read") {
        if (labels.has("cred-path")) fact("reads-credential", f, "opens a path that names a credential file");
      } else if (!labels.has("net") && !(labels.has("net-field") && f.kind !== "splice")) continue;
      else if (f.kind === "splice") fact("splices-download", f, "puts downloaded text into a longer command a shell runs");
      else fact("runs-download", f, f.kind === "code" ? "runs code it downloaded" : f.kind === "file" ? "runs a program it downloaded and wrote to a file" : "runs a command it downloaded");
    }

    fileFacts.set(path, facts);
  }

  return { cross, cut };
}

// ---------- apm-score-v10: capabilities and risk signals ----------

type AssessInput = {
  found: Found;
  /** A reading stopped for its resources (analyze, resourceStopped): `incomplete` then costs every point. */
  resourceStopped: boolean;
  fileFacts: ReadonlyMap<string, readonly Fact[]>;
  /** The files each file loads by a path apm resolved. */
  edges: ReadonlyMap<string, ReadonlySet<string>>;
  /** What install hooks and binding.gyp run directly. */
  installRoots: readonly string[];
  installBinaries: readonly string[];
  /** Files an entry point or an install hook reaches. */
  reached: ReadonlySet<string>;
  /** Files read with no tree, where a hidden credential name counts as a read, as in v9. */
  rawFiles: ReadonlySet<string>;
  /** Evidence cited from install-time commands (hooks and binding.gyp). */
  hookEvidence: ReadonlySet<string>;
  gyp: boolean;
  /** What package.json's `bin` names: programs the package ships on purpose. */
  binPaths: ReadonlySet<string>;
  declaration: Declaration;
  /** Files whose flow reading stopped before it finished, in code that runs (each is incomplete for it too). */
  flowStopped: ReadonlySet<string>;
  /** Whether the reading of flows across files stopped at its work budget (CrossFile.exhausted). */
  crossStopped: boolean;
};

type Assessed = { signals: Signal[]; capabilities: Capability[]; declaration: { kind: Declaration["kind"]; notes: string[] } };

/** The order risk signals are listed in: the heaviest and most specific first. */
const RISK_ORDER: readonly SignalId[] = [
  "incomplete",
  "remote-shell",
  "capture-endpoint",
  "credential-read",
  "exfiltration",
  "install-download",
  "runs-decoded-code",
  "install-network",
  "install-shell",
  "install-eval",
  "obfuscated",
  "suspicious-combination",
  "risky-dependency",
  "typosquat",
  "undeclared-capability",
  "install-script",
  "git-install-script",
  "unanalyzed-files",
  "new-publisher",
  "new-dependency",
  "credential-mention",
  "encoded-data",
  "dynamic-require",
  "no-license",
];

/** v9 evidence that a dangerous name was hidden: joined from pieces, decoded, or run from such a string. */
const HIDDEN_NAME = /\((?:after joining strings|decoded|joined, then run|decoded, then run)\)|: builds "|: hides code in /;

/** v9 evidence of code that ran from a decoded or joined string. */
const DECODED_RUN = /\((?:decoded, then run|joined, then run)\)/;

/** v9 evidence of a call found inside a string the program runs (`Function("fetch(u)")()`). */
const STRING_RUN = /\(run from a string\)/;

/** The `file:line` a piece of evidence cites, or the evidence itself when it cites none. */
function lineKey(evidence: string): string {
  const at = evidenceAt(evidence);

  return at ? `${at.file}:${at.line}` : evidence;
}

function factLine(path: string, f: Fact, note = ""): string {
  return `${path}:${f.line}: ${f.snippet}${note}${f.text ? TEXT_MATCH : ""}${isTestPath(path) ? IN_TEST_FILE : ""}`;
}

/** What evidence rests on: a call, load, command or file (`code`), only text matches, or only possible evidence. */
function basisOf(evidence: readonly string[], confidence: Confidence): Capability["basis"] {
  if (evidence.length === 0) return "none";

  if (confidence === "possible") return "possible";

  return evidence.some((e) => !isTextEvidence(e)) ? "code" : "text";
}

/** The files `roots` load, directly or through other files, by paths apm resolved. */
function closure(roots: readonly string[], edges: ReadonlyMap<string, ReadonlySet<string>>): Set<string> {
  const out = new Set(roots);
  const queue = [...roots];

  for (let next = queue.pop(); next !== undefined; next = queue.pop()) {
    for (const to of edges.get(next) ?? []) {
      if (out.has(to)) continue;
      out.add(to);
      queue.push(to);
    }
  }

  return out;
}

/**
 * apm-score-v10's reading of everything `analyze` found: what the package can do (capabilities, never scored on their
 * own) and what in it looks like malware (risk signals). Every v9 finding lands in one of the two, with its evidence:
 * shell-exec, network, eval, binary and install-script are capabilities (install-script is also a risk signal), and
 * credential-access and obfuscated become the risk signals that say how strong their evidence is.
 */
function assess(input: AssessInput): Assessed {
  const { found, fileFacts, declaration } = input;
  const installFiles = closure(input.installRoots, input.edges);
  // a test file counts toward a risk only when code that runs loads it
  const counts = (path: string): boolean => !isTestPath(path) || input.reached.has(path) || installFiles.has(path);
  const factsIn = (path: string, kind: Fact["kind"]): Fact[] => (counts(path) ? (fileFacts.get(path) ?? []).filter((f) => f.kind === kind) : []);
  const allFacts = (kind: Fact["kind"]): { path: string; fact: Fact }[] => [...fileFacts.keys()].flatMap((path) => factsIn(path, kind).map((fact) => ({ path, fact })));
  // files where a code signal stands outside comments, regex bodies and types
  const filesWith = (id: SignalId): Set<string> => new Set(found.confirmed(id).flatMap((e) => (e.cited === "hidden" ? [] : [citedSource(e.evidence)])));
  const netFiles = filesWith("network");
  const shellFiles = filesWith("shell-exec");
  const atInstall = (id: SignalId): string[] => found.confirmed(id).flatMap((e) => (e.cited !== "hidden" && (input.hookEvidence.has(e.evidence) || installFiles.has(citedSource(e.evidence))) ? [e.evidence] : []));

  const risks = new Map<SignalId, Signal>();

  const put = (id: SignalId, evidence: string[], confidence: Confidence = "confirmed", fallback: readonly string[] = []): void => {
    if (evidence.length > 0) risks.set(id, signal(id, evidence, confidence, fallback));
  };

  // a whole-flow stop, which `incomplete` already holds for (its unread evidence and the cross-file line): named first
  // among its evidence, so the reason a person should look is in what every surface shows. A test file's stop counts
  const stops = [...[...input.flowStopped].sort().map((p) => `${p}: apm could not finish tracing where values go in this file`), ...(input.crossStopped ? ["flows across files: apm could not finish tracing where values go between the files"] : [])];
  const unfinished = found.get("incomplete");

  if (unfinished || stops.length > 0) put("incomplete", [...stops, ...(unfinished?.evidence ?? [])], unfinished?.confidence, unfinished?.possible);
  const stoppedForResources = risks.get("incomplete");

  // what a reading stopped for its resources did not read could cost more than 61 points: it scores 0, its findings
  // kept as evidence, so it is never above production's reading of the whole (round 13 review of d594415, P2)
  if (stoppedForResources && input.resourceStopped) stoppedForResources.points = -100;

  // v9's non-code signals keep their ids; their points are v10's
  for (const id of ["install-download", "git-install-script", "risky-dependency", "typosquat", "install-script", "unanalyzed-files", "new-publisher", "new-dependency", "dynamic-require", "no-license"] as const) {
    const got = found.get(id);

    if (got) put(id, got.evidence, got.confidence, got.possible);
  }

  // install time, by what runs there
  put("install-network", atInstall("network"));
  put("install-shell", [...atInstall("shell-exec"), ...input.installBinaries.map((p) => `${p}: an install script runs this compiled program`)]);
  put("install-eval", atInstall("eval"));

  // credentials: a credential file read is heavy; a name in text is weak evidence. A read is a credential path the
  // flow analysis saw reach a read (or, in a file with no tree, a path next to a read), or one an install command names.
  const flowReads = allFacts("reads-credential").map(({ path, fact }) => factLine(path, fact, " (a credential path reaches a file read)"));
  const textReads = allFacts("credential-read").map(({ path, fact }) => factLine(path, fact, " (a credential path next to a file read)"));
  const nearReads = allFacts("credential-near").map(({ path, fact }) => factLine(path, fact, " (a credential path near a file read; apm did not see the path reach it)"));
  const readFiles = new Set([...allFacts("reads-credential"), ...allFacts("credential-read")].map(({ path }) => path));
  // a credential path or token name an install command names, or one the code hid by joining or encoding it
  const hookCredentials = found.confirmed("credential-access").flatMap((e) => (input.hookEvidence.has(e.evidence) ? [e.evidence] : []));
  const hiddenCredentials = found.confirmed("credential-access").flatMap((e) => (e.cited !== "hidden" && HIDDEN_NAME.test(e.evidence) && counts(citedSource(e.evidence)) ? [e.evidence] : []));
  // a hidden name is a read in a file that reads a credential file, where the line reads a token from the environment
  // (`process.env['NPM' + '_TOKEN']`), in a file with no tree, or in obfuscator output; elsewhere it names one
  const secretLines = new Set(allFacts("env").flatMap(({ path, fact }) => (fact.name !== undefined && secretFamily(fact.name) !== null ? [`${path}:${fact.line}`] : [])));
  // obfuscator output builds its strings through tables no flow analysis follows, so there a hidden name is a read too
  const obfuscatorFiles = new Set(allFacts("obfuscator").map(({ path }) => path));
  const isRead = (e: string): boolean => readFiles.has(citedSource(e)) || secretLines.has(lineKey(e)) || input.rawFiles.has(citedSource(e)) || obfuscatorFiles.has(citedSource(e));
  const hiddenReads = hiddenCredentials.filter(isRead);
  const credential = found.get("credential-access");
  const reads = [...flowReads, ...textReads];

  if (reads.length > 0 || hookCredentials.length > 0 || hiddenReads.length > 0) {
    put("credential-read", [...new Set([...reads, ...hookCredentials, ...hiddenReads.map((e) => `${e} (a credential name hidden by joining or encoding)`), ...(credential?.evidence ?? [])])]);
  } else if (credential || nearReads.length > 0 || hiddenCredentials.length > 0) {
    const named = [...nearReads, ...hiddenCredentials.filter((e) => !isRead(e)).map((e) => `${e} (a credential name hidden by joining or encoding; apm did not see it read)`)];

    put("credential-mention", [...new Set([...named, ...(credential?.evidence ?? [])])], named.length > 0 ? "confirmed" : (credential?.confidence ?? "confirmed"), credential?.possible ?? []);
    const mention = risks.get("credential-mention");

    if (mention && nearReads.length > 0 && mention.confidence === "confirmed") {
      mention.points = MENTION_NEAR_READ_POINTS;
      mention.label = "Names a credential file next to a file read; apm did not see the path reach the read";
    }
  }

  // obfuscation: obfuscator output or a hidden dangerous name is heavy; long encoded data alone is weak evidence. A
  // credential path hidden by joining (`'.npm' + 'rc'`) in a file that reads no credential file names it, and hides
  // no call: that is encoded data, not obfuscated code.
  const obfuscator = allFacts("obfuscator");
  const obfuscation = found.get("obfuscated");
  const hiddenLines = (id: SignalId): Set<string> => new Set(found.confirmed(id).flatMap((e) => (e.cited !== "hidden" && HIDDEN_NAME.test(e.evidence) ? [lineKey(e.evidence)] : [])));
  const hiddenCalls = new Set([...hiddenLines("shell-exec"), ...hiddenLines("network"), ...hiddenLines("eval")]);
  const hiddenPaths = hiddenLines("credential-access");
  const onlyNamesCredential = (e: string): boolean => hiddenPaths.has(lineKey(e)) && !hiddenCalls.has(lineKey(e)) && !isRead(e);
  const hiddenNames = found.confirmed("obfuscated").flatMap((e) => (e.cited !== "hidden" && HIDDEN_NAME.test(e.evidence) && !onlyNamesCredential(e.evidence) ? [e.evidence] : []));

  if (obfuscator.length > 0 || hiddenNames.length > 0) {
    put("obfuscated", [...new Set([...obfuscator.map(({ path, fact }) => factLine(path, fact, ` (${fact.name ?? "obfuscator output"})`)), ...hiddenNames, ...(obfuscation?.evidence ?? [])])]);
  } else if (obfuscation) put("encoded-data", obfuscation.evidence, obfuscation.confidence, obfuscation.possible);

  // code decoded or joined and then run, or a network, process or credential call kept in a string the program runs
  const decodedRuns = (["shell-exec", "network", "credential-access", "eval", "obfuscated"] as const).flatMap((id) =>
    found.confirmed(id).flatMap((e) => (DECODED_RUN.test(e.evidence) || (id !== "eval" && id !== "obfuscated" && STRING_RUN.test(e.evidence)) ? [e.evidence] : [])),
  );

  const hiddenRuns = allFacts("runs-hidden").map(({ path, fact }) => factLine(path, fact, " (runs text it kept in a comment or a regex)"));

  put("runs-decoded-code", [...new Set([...decodedRuns, ...hiddenRuns])]);

  put("capture-endpoint", allFacts("capture-endpoint").map(({ path, fact }) => factLine(path, fact, ` (${fact.name ?? "endpoint"})`)));
  // remote execution: downloaded data the flow analysis saw reach an evaluator or a process, or a shell command that
  // opens a remote shell or pipes a download into a shell, is confirmed; an evaluator near a network call is not
  const downloads = allFacts("runs-download").map(({ path, fact }) => factLine(path, fact, ` (${fact.name ?? "runs what it downloaded"})`));
  const shells = allFacts("remote-shell").flatMap(({ path, fact }) => (shellFiles.has(path) || installFiles.has(path) ? [factLine(path, fact)] : []));

  // downloaded text spliced into a longer command may run as one (`exec('echo ' + body)`); apm cannot tell, so possible
  const spliced = allFacts("splices-download").map(({ path, fact }) => factLine(path, fact, ` (${fact.name ?? "downloaded text in a command"}; it may run as a command)`));

  put("remote-shell", [...new Set([...downloads, ...shells, ...spliced, ...allFacts("fetched-code").map(({ path, fact }) => factLine(path, fact, " (runs a value right after a network call)"))])]);
  const remote = risks.get("remote-shell");

  if (remote && downloads.length + shells.length > 0) remote.points = CONFIRMED_FLOW_POINTS;

  // exfiltration: what a stealer collects, and the network, in one file or in the code that runs at install
  const exfil: string[] = [];

  for (const path of fileFacts.keys()) {
    if (!counts(path)) continue;
    const list = fileFacts.get(path) ?? [];
    const secrets = list.filter((f) => f.kind === "env" && f.name !== undefined && secretFamily(f.name) !== null);
    const families = new Set(secrets.map((f) => secretFamily(f.name ?? "")));
    const install = installFiles.has(path);
    // of each kind, one beside a network call if there is one: the first may be far from it and a later one not
    const pick = (kind: Fact["kind"]): Fact | undefined => list.find((f) => f.kind === kind && f.near) ?? list.find((f) => f.kind === kind);
    const dump = pick("env-dump");
    const credentialRead = pick("credential-read");
    const host = install ? pick("host-info") : undefined;

    const harvest: [Fact, string] | undefined = dump
      ? [dump, "reads the whole environment"]
      : credentialRead
        ? [credentialRead, "reads a credential file"]
        : families.size >= 3 && secrets[0]
          ? [secrets[0], `reads ${[...families].join(", ")} tokens`]
          : host
            ? [host, "collects the machine's identity at install"]
            : install && secrets[0]
              ? [secrets[0], `reads ${secrets[0].name ?? "a token"} at install`]
              : undefined;

    if (!harvest) continue;
    const sends = (netFiles.has(path) && harvest[0].near) || list.some((f) => f.kind === "capture-endpoint") || (install && atInstall("network").length > 0);

    if (sends) exfil.push(factLine(path, harvest[0], ` (${harvest[1]}, and ${install && !netFiles.has(path) ? "install-time code uses" : "code beside it uses"} the network)`));
  }

  if (hookCredentials.length > 0 && atInstall("network").length > 0) exfil.push(...hookCredentials.map((e) => `${e} (an install command names a credential, and install-time code uses the network)`));
  // what the flow analysis saw sent: the whole environment, a credential file's contents, three families of tokens
  const sent = (["sends-env", "sends-credential", "sends-secrets"] as const).flatMap((kind) => allFacts(kind).map(({ path, fact }) => factLine(path, fact, ` (${fact.name ?? "sends what it collected"})`)));

  put("exfiltration", [...new Set([...sent, ...exfil])]);
  const exfiltration = risks.get("exfiltration");

  if (exfiltration && sent.length > 0) exfiltration.points = CONFIRMED_FLOW_POINTS;

  // capabilities, each with v9's evidence (and, for env and filesystem, the facts above)
  const capabilities: Capability[] = [];
  const envFacts = allFactsAnywhere(fileFacts, "env");
  const envNames = [...new Set(envFacts.map(({ fact }) => fact.name ?? "*"))];

  const fromFound = (id: SignalId): { evidence: string[]; confidence: Confidence } => {
    const got = found.get(id);

    return got ? { evidence: got.evidence, confidence: got.confidence } : { evidence: [], confidence: "confirmed" };
  };

  const used: Record<CapabilityId, { evidence: string[]; confidence: Confidence }> = {
    network: fromFound("network"),
    env: { evidence: [...new Set([...envFacts, ...allFactsAnywhere(fileFacts, "env-dump"), ...allFactsAnywhere(fileFacts, "env-object")].map(({ path, fact }) => factLine(path, fact)))], confidence: "confirmed" },
    filesystem: { evidence: allFactsAnywhere(fileFacts, "filesystem").map(({ path, fact }) => factLine(path, fact)), confidence: "confirmed" },
    shell: fromFound("shell-exec"),
    eval: fromFound("eval"),
    native: { evidence: [...fromFound("binary").evidence, ...(input.gyp ? ["binding.gyp: node-gyp builds a native addon at install"] : [])], confidence: "confirmed" },
    install: fromFound("install-script"),
  };

  const declared = declaration.kind === "declared" ? declaration.capabilities : {};

  for (const id of CAPABILITY_IDS) {
    const u = used[id];
    const decl = declared[id];

    if (u.evidence.length === 0) {
      if (decl) capabilities.push({ id, label: CAPABILITY_LABELS[id], status: "unused", basis: "none", declared: decl.shown, evidence: [] });
      continue;
    }

    const shown = signal("install-script", u.evidence, u.confidence);
    const status: Capability["status"] = declaration.kind === "none" ? "not-declared" : decl ? "declared" : "undeclared";
    const cap: Capability = { id, label: CAPABILITY_LABELS[id], status, basis: basisOf(u.evidence, u.confidence), evidence: shown.evidence };

    if (shown.more) cap.more = shown.more;

    if (shown.uncounted !== undefined) cap.uncounted = shown.uncounted;

    if (shown.sources) cap.sources = shown.sources;

    if (decl) cap.declared = decl.shown;

    if (id === "env") {
      cap.names = envNames.slice(0, 100);
      const outside = decl && decl.patterns.length > 0 ? envNames.filter((n) => n !== "*" && !decl.patterns.some((p) => matchesPattern(n, p))) : [];

      if (outside.length > 0) cap.outside = outside.slice(0, 50);
    }

    capabilities.push(cap);
  }

  // a declaring package's undeclared capabilities, where the code (not only text) shows them
  const undeclared = capabilities.filter((c) => c.status === "undeclared" && c.basis === "code");

  if (undeclared.length > 0) {
    const s = signal("undeclared-capability", undeclared.map((c) => `${c.id}: ${c.evidence[0] ?? ""}`));
    s.points = Math.max(UNDECLARED_MAX, POINTS["undeclared-capability"] + UNDECLARED_MORE * (undeclared.length - 1));
    risks.set("undeclared-capability", s);
  }

  // combinations malware has and ordinary packages rarely do
  const combos: string[] = [];
  const cap = (id: CapabilityId): Capability | undefined => capabilities.find((c) => c.id === id && c.basis === "code");
  const evalCap = cap("eval");
  const netCap = cap("network");

  if (evalCap && netCap && used.install.evidence.length > 0) combos.push(`runs code built at runtime (${evalCap.evidence[0] ?? ""}), uses the network (${netCap.evidence[0] ?? ""}) and runs a script at install`);
  const obfuscatedFiles = new Set([...obfuscator.map(({ path }) => path), ...hiddenNames.map(citedSource)]);

  const computedLoads = new Set((found.get("dynamic-require")?.evidence ?? []).map(citedSource));

  for (const path of obfuscatedFiles) {
    if (netFiles.has(path) || shellFiles.has(path)) combos.push(`${path}: obfuscated code that also ${netFiles.has(path) ? "uses the network" : "starts processes"}`);
    else if (computedLoads.has(path)) combos.push(`${path}: obfuscated code that loads modules by names built at runtime`);
  }

  for (const { path, fact } of allFacts("capture-endpoint")) {
    if (shellFiles.has(path)) combos.push(factLine(path, fact, " (a capture endpoint in a file that starts processes)"));
  }

  for (const { path, fact } of allFacts("detached")) {
    if (installFiles.has(path) && shellFiles.has(path)) combos.push(factLine(path, fact, " (install-time code starts a process that outlives the install)"));
  }

  const executables = fromFound("binary").evidence.filter((e) => !citedSource(e).endsWith(".node") && !input.binPaths.has(citedSource(e)));

  if (atInstall("shell-exec").length > 0 && executables.length > 0) combos.push(`starts processes at install and ships a compiled program (${executables[0] ?? ""})`);

  if (found.has("typosquat") && used.install.evidence.length > 0) combos.push(`a name like a popular package's that runs a script at install (${used.install.evidence[0] ?? ""})`);
  put("suspicious-combination", combos);
  const combined = risks.get("suspicious-combination");

  if (combined) combined.points = Math.max(COMBINATION_MAX, POINTS["suspicious-combination"] + COMBINATION_MORE * (combos.length - 1));

  return {
    signals: RISK_ORDER.flatMap((id) => {
      const s = risks.get(id);

      return s ? [s] : [];
    }),
    capabilities,
    declaration: { kind: declaration.kind, notes: declaration.notes },
  };
}

/** Every fact of one kind, test files included: capabilities list what a package ships. */
function allFactsAnywhere(fileFacts: ReadonlyMap<string, readonly Fact[]>, kind: Fact["kind"]): { path: string; fact: Fact }[] {
  return [...fileFacts].flatMap(([path, list]) => list.filter((f) => f.kind === kind).map((fact) => ({ path, fact })));
}

/** Where each v9 code signal lives since apm-score-v10: a capability, or a risk signal that says how strong its evidence is. */
const V9_HOME: Record<CapabilityId, SignalId | null> = { network: "network", shell: "shell-exec", eval: "eval", native: "binary", install: "install-script", env: null, filesystem: null };

const V9_ID: Partial<Record<SignalId, SignalId>> = { "credential-read": "credential-access", "credential-mention": "credential-access", "encoded-data": "obfuscated" };

/**
 * Every finding of an analysis under the id apm-score-v9 gave it, whether it is scored or not: a capability (network,
 * shell, eval, native, install) as v9's code signal, `credential-read` and `credential-mention` as
 * `credential-access`, `encoded-data` as `obfuscated`, and every other signal as itself. A capability costs 0 points
 * here. This is what "detection did not shrink" is checked on: v10's findings include every v3 finding.
 */
export function findingsOf(analysis: Analysis): Signal[] {
  const out = new Map<SignalId, Signal>();

  for (const s of analysis.signals) {
    const id = V9_ID[s.id] ?? s.id;

    if (!out.has(id)) out.set(id, { ...s, id });
  }

  for (const c of analysis.capabilities) {
    const id = V9_HOME[c.id];

    if (id === null || c.status === "unused" || out.has(id)) continue;
    const finding: Signal = { id, label: c.label, points: 0, evidence: c.evidence, confidence: c.basis === "possible" ? "possible" : "confirmed" };

    if (c.more) finding.more = c.more;

    if (c.uncounted !== undefined) finding.uncounted = c.uncounted;

    if (c.sources) finding.sources = c.sources;
    out.set(id, finding);
  }

  return [...out.values()];
}

export function gradeOf(score: number): Grade {
  if (score >= 90) return "A";

  if (score >= 75) return "B";

  if (score >= 60) return "C";

  if (score >= 40) return "D";

  return "F";
}

/**
 * What a score is worked out with besides the analysis: the version's age and state, and, for an upstream package, npm's
 * record of its name (settleEstablishedName); null or absent when there is none.
 */
export type VersionState = { publishedAt: number; now: number; deprecated: string | null; status: "active" | "yanked" | "revoke-pending" | "revoked"; statusReason: string | null; name?: NameHistory | null };

/** Applies time- and state-based signals and computes the number. */
export function finalize(stored: Analysis, state: VersionState): ScoreReport {
  const analysis = settleEstablishedName(stored, state.name ?? null, state.now);
  const signals = [...analysis.signals];

  if (state.now - state.publishedAt < COOLDOWN_MS) {
    const hours = Math.max(0, Math.floor((state.now - state.publishedAt) / 3_600_000));
    signals.push(signal("recent", [`published ${hours}h ago`]));
  }

  if (state.deprecated) signals.push(signal("deprecated", [state.deprecated]));

  if (state.status === "yanked") signals.push(signal("yanked", [state.statusReason ?? "no reason given"]));

  if (state.status === "revoked" || state.status === "revoke-pending") signals.push(signal("revoked", [state.statusReason ?? "no reason given"]));
  const raw = 100 + signals.reduce((n, s) => n + s.points, 0);
  const score = Math.max(0, Math.min(100, raw));

  // "P" only for a reading whose sole gap is whole files left unread for their size or the byte budget (readingOf):
  // an analysis incomplete for any other reason gets the letter its score earns, as an incomplete one always did
  return { ...analysis, signals, score, grade: readingOf(analysis).kind === "partial" ? "P" : gradeOf(score) };
}

/** One evidence item an apm reviewer dismissed: the scorer that cited it, the signal, and the file and line it cites. */
export type EvidenceDismissal = { scorer: string; signal: string; file: string; line: number; reason: string; at: number };

/**
 * The signals a reviewer may dismiss evidence of: what the source rules read, never a fact like an install script or a
 * name. The first five are the v9 code signals, for analyses earlier scorers stored.
 */
export const DISMISSABLE: ReadonlySet<string> = new Set<string>([
  "shell-exec",
  "network",
  "credential-access",
  "eval",
  "obfuscated",
  "credential-read",
  "credential-mention",
  "encoded-data",
  "exfiltration",
  "capture-endpoint",
  "remote-shell",
  "runs-decoded-code",
  "install-network",
  "install-shell",
  "install-eval",
]);

const CITED_LINE = /^([^\s:][^:\n]*?):(\d+)(?=: |$)/;

/** The file and line a piece of code evidence cites (`lib/a.js:4: …`), or null when it cites none. */
export function evidenceAt(evidence: string): { file: string; line: number } | null {
  const m = CITED_LINE.exec(evidence);

  return m?.[1] && m[2] ? { file: m[1], line: Number(m[2]) } : null;
}

/**
 * What one piece of evidence cites: the file for evidence that names a file and line (`lib/a.js:4: …`), else the
 * part before the first ": " (`package.json scripts.postinstall`, `binding.gyp`, a binary's path).
 */
export function citedSource(evidence: string): string {
  return evidenceAt(evidence)?.file ?? evidence.split(": ")[0] ?? evidence;
}

/**
 * The analysis with the evidence apm's reviewers dismissed left out, for the scorer that wrote it: a signal keeps
 * what is left, falls back to its possible evidence when every confirmed item went, and goes when nothing is left
 * (so `finalize` scores without it). A dismissal names a scorer, and the registry hands over only those made for
 * this version's exact tarball digest, so none carries over to other bytes, another version or another scorer.
 * What was dismissed stays listed in `dismissed`, with the reason, so a page can show it struck through and a
 * reviewer can undo it; that includes a dismissed item of the possible evidence a signal falls back to.
 */
export function applyDismissals(analysis: Analysis, list: readonly EvidenceDismissal[]): Analysis {
  const mine = list.filter((d) => d.scorer === analysis.scorer && DISMISSABLE.has(d.signal));

  if (mine.length === 0) return analysis;
  const dismissed: DismissedEvidence[] = [];
  const signals: Signal[] = [];

  for (const s of analysis.signals) {
    const own = mine.filter((d) => d.signal === s.id);
    const all = [...s.evidence, ...(s.more ?? [])];
    const possible = s.fallback ?? [];

    const matchOf = (e: string): EvidenceDismissal | undefined => {
      const at = evidenceAt(e);

      return at ? own.find((d) => d.file === at.file && d.line === at.line) : undefined;
    };

    const gone = own.length === 0 ? [] : all.filter((e) => matchOf(e) !== undefined);
    // the possible evidence a confirmed signal falls back to can be dismissed too, and is listed like the rest
    const goneFallback = own.length === 0 ? [] : possible.filter((e) => matchOf(e) !== undefined);

    if (gone.length === 0 && goneFallback.length === 0) {
      signals.push(s);
      continue;
    }

    for (const d of own) {
      const evidence = [...gone, ...goneFallback].filter((e) => matchOf(e) === d);

      if (evidence.length > 0) dismissed.push({ signal: s.id, file: d.file, line: d.line, evidence, reason: d.reason, at: d.at });
    }

    const left = all.filter((e) => matchOf(e) === undefined);
    const fallback = possible.filter((e) => matchOf(e) === undefined);
    const uncounted = s.uncounted ?? 0;

    if (left.length > 0 || uncounted > 0) {
      const { more: _more, fallback: _fallback, ...rest } = s;
      // with evidence past what was kept, the label stays as the full list made it
      const label = uncounted > 0 || gone.length === 0 ? s.label : labelOf(s.id, s.confidence, left);

      const kept: Signal = { ...rest, label, evidence: left.slice(0, SHOWN_EVIDENCE) };

      if (left.length > SHOWN_EVIDENCE) kept.more = left.slice(SHOWN_EVIDENCE);

      if (fallback.length > 0) kept.fallback = fallback;
      signals.push(kept);
      continue;
    }

    if (s.confidence === "confirmed" && isCodeSignal(s.id) && fallback.length > 0) signals.push(signal(s.id, fallback, "possible"));
  }

  return { ...analysis, signals: recombined(signals, settledByDismissal(signals, dismissed)), dismissed: [...(analysis.dismissed ?? []), ...dismissed] };
}

/**
 * What a suspicious-combination pairing can rest on that a later step sets aside: a file whose obfuscated evidence was
 * all dismissed (`file: obfuscated code that also …`), a capture endpoint's line that was dismissed (`file:line: … (a
 * capture endpoint in a file that starts processes)`), and the look-alike name (`a name like a popular package's that
 * runs a script at install (…)`), with the install evidence that pairing quotes.
 */
type Settled = { obfuscatedFiles: ReadonlySet<string>; captureLines: ReadonlySet<string>; name: { install: readonly string[] } | null };

const OBFUSCATED_PAIRINGS = [": obfuscated code that also uses the network", ": obfuscated code that also starts processes", ": obfuscated code that loads modules by names built at runtime"] as const;

const CAPTURE_PAIRING = " (a capture endpoint in a file that starts processes)";

const NAME_PAIRING = "a name like a popular package's that runs a script at install (";

/** The pairings whose line starts with fixed words rather than a file: never a file's own pairing. */
const UNFILED_PAIRINGS = ["runs code built at runtime (", "starts processes at install and ships a compiled program (", NAME_PAIRING] as const;

/** Every piece of evidence a signal keeps, shown or not, and its possible evidence. */
function keptEvidence(s: Signal): string[] {
  return [...s.evidence, ...(s.more ?? []), ...(s.fallback ?? [])];
}

/** Whether a signal still cites `file`: in evidence it keeps, or in the sources it counted and did not keep. */
function stillCites(s: Signal | undefined, file: string): boolean {
  return s !== undefined && (keptEvidence(s).some((e) => citedSource(e) === file) || (s.sources ?? []).includes(file));
}

/**
 * What the dismissals just applied settle for suspicious-combination: each file whose obfuscated evidence is all gone,
 * and each capture endpoint line with nothing left at it. A file or line the signal still cites (in any evidence it
 * keeps, or in the sources of evidence it did not keep) is not settled.
 */
function settledByDismissal(signals: readonly Signal[], dismissed: readonly DismissedEvidence[]): Settled {
  const obfuscated = signals.find((s) => s.id === "obfuscated");
  const capture = signals.find((s) => s.id === "capture-endpoint");

  // a line is left when the signal keeps evidence at it, or counted evidence it did not keep in that file
  const captureLeft = (file: string, line: number): boolean =>
    capture !== undefined && stillCites(capture, file) && (capture.uncounted !== undefined || keptEvidence(capture).some((e) => evidenceAt(e)?.file === file && evidenceAt(e)?.line === line));

  return {
    obfuscatedFiles: new Set(dismissed.flatMap((d) => (d.signal === "obfuscated" && !stillCites(obfuscated, d.file) ? [d.file] : []))),
    captureLines: new Set(dismissed.flatMap((d) => (d.signal === "capture-endpoint" && !captureLeft(d.file, d.line) ? [`${d.file}:${d.line}`] : []))),
    name: null,
  };
}

/** A pairing line without the marks factLine may end it with (a text match, a test file), last first. */
function withoutMarks(line: string): string {
  const inTest = line.endsWith(IN_TEST_FILE) ? line.slice(0, -IN_TEST_FILE.length) : line;

  return inTest.endsWith(TEXT_MATCH) ? inTest.slice(0, -TEXT_MATCH.length) : inTest;
}

/**
 * Whether a pairing line rests only on what `settled` sets aside. Matched exactly against the line assess() writes for
 * it (a file name or a quoted command cannot make another pairing match): an obfuscated file's pairings by the whole
 * line, a capture endpoint's by its file and line at the start and its words at the end, the name's by the whole line
 * with the install evidence it quotes. Anything else stays.
 */
function restsOnSettled(line: string, settled: Settled): boolean {
  if ([...settled.obfuscatedFiles].some((file) => OBFUSCATED_PAIRINGS.some((p) => line === `${file}${p}`))) return true;

  if (settled.name !== null && settled.name.install.some((e) => line === `${NAME_PAIRING}${e})`)) return true;

  if (UNFILED_PAIRINGS.some((p) => line.startsWith(p)) || !withoutMarks(line).endsWith(CAPTURE_PAIRING)) return false;
  const at = evidenceAt(line);

  return at !== null && line.startsWith(`${at.file}:${at.line}: `) && settled.captureLines.has(`${at.file}:${at.line}`);
}

/**
 * suspicious-combination worked out again from the pairings left once `settled` is set aside (a reviewer's dismissal,
 * an established name): the pairings that rest only on it go, and the points are those of the pairings left, as
 * assess() prices them; with none left the signal goes. A signal that counted pairings it did not keep is left as it
 * is, since apm cannot tell what those rest on.
 */
function recombined(signals: readonly Signal[], settled: Settled): Signal[] {
  const combined = signals.find((s) => s.id === "suspicious-combination");

  if (combined === undefined || combined.uncounted !== undefined) return [...signals];
  const all = [...combined.evidence, ...(combined.more ?? [])];
  const left = all.filter((line) => !restsOnSettled(line, settled));

  if (left.length === all.length) return [...signals];

  if (left.length === 0) return signals.filter((s) => s !== combined);
  const again = signal("suspicious-combination", left);
  again.points = Math.max(COMBINATION_MAX, POINTS["suspicious-combination"] + COMBINATION_MORE * (left.length - 1));

  return signals.map((s) => (s === combined ? again : s));
}

/**
 * The analysis with its look-alike name set aside when npm's record shows the name is long established
 * (names.ts isEstablishedName: first published two years ago or more, five versions a year old or more). A typosquat
 * is a new name, and npm's publish times cannot be backdated, so one listed that long is a package in its own right,
 * whatever it resembles: `typosquat` stays listed, at no points, saying when the name was first published, and the
 * install pairing that rested on the name leaves suspicious-combination. Without a record (a tarball scored on its
 * own, a package published here, a record from before this) or for a younger name, nothing changes. Worked out when
 * the score is (finalize), so no stored analysis needs to be read again.
 */
export function settleEstablishedName(analysis: Analysis, history: NameHistory | null, now: number): Analysis {
  const name = analysis.signals.find((s) => s.id === "typosquat");

  if (name === undefined || name.points >= 0 || history === null || !isEstablishedName(history, now)) return analysis;
  const since = new Date(history.first).toISOString().slice(0, 10);
  const kept: Signal = { ...name, label: `${name.label}, but it is an established name (on npm since ${since}), so it costs nothing`, points: 0 };
  const signals = analysis.signals.map((s) => (s === name ? kept : s));
  const install = analysis.signals.find((s) => s.id === "install-script");

  return { ...analysis, signals: recombined(signals, { obfuscatedFiles: new Set(), captureLines: new Set(), name: { install: install ? keptEvidence(install) : [] } }) };
}

/** A stored analysis (v1 or v2), or null when the value is not one. */
export function parseAnalysis(v: unknown): Analysis | null {
  const r = AnalysisSchema.safeParse(v);

  return r.success ? r.data : null;
}

/** The scorer before SCORER, some of whose stored analyses the current one takes as its own (reusableAnalysis). */
export const PREVIOUS_SCORER = "apm-score-v10";

/**
 * Whether an apm-score-v10 analysis is what apm-score-v11 would store for the same bytes: v11 changed only what files
 * left unread for their size or the byte budget cost, so a v10 analysis that left nothing unread and stopped nowhere
 * (no skipped file, no `unanalyzed-files`, no `incomplete`, no partial coverage) is the same reading. The registry's
 * SQL function apm_v10_reusable (migration 0023) is this test; packages/registry/test/scorer-rollout.test.ts holds the
 * two to each other. Checked on the analysis as stored, before any dismissal is applied.
 */
function isReusablePrevious(a: Analysis): boolean {
  return a.scorer === PREVIOUS_SCORER && a.skipped.length === 0 && a.coverage?.kind !== "partial" && !a.signals.some((s) => s.id === "incomplete" || s.id === "unanalyzed-files");
}

/**
 * A stored upstream analysis (parsed: parseAnalysis) as the current scorer reads it: one of its own, or an
 * apm-score-v10 one it would score the same (isReusablePrevious), given `coverage: complete` and kept under its v10 name, so evidence dismissed against v10
 * still applies to it. Null for anything else: the queue analyses that version again.
 */
export function reusableAnalysis(a: Analysis): Analysis | null {
  if (a.scorer === SCORER) return a;

  return isReusablePrevious(a) ? { ...a, coverage: { kind: "complete" } } : null;
}

/**
 * A stored analysis (parsed: parseAnalysis) as a score is worked out from it, whatever its scorer: one the current scorer would store the same
 * (reusableAnalysis) with its coverage stated, any other as it was stored. A package published on apm keeps the
 * analysis made at its publish (nothing analyses it again), so an apm-score-v10 analysis that was `incomplete` for a
 * file's size keeps v10's -61: stricter than v11, it never reads as a pass.
 */
export function storedAnalysis(a: Analysis | null): Analysis | null {
  return a === null ? null : (reusableAnalysis(a) ?? a);
}

/** Human-readable diff of signals between two versions. */
export function signalChanges(prev: readonly Signal[], next: readonly Signal[]): string[] {
  const p = new Set(prev.map((s) => s.id));
  const n = new Set(next.map((s) => s.id));
  const out: string[] = [];

  for (const s of next) if (!p.has(s.id) && s.id !== "recent") out.push(`+${s.id}: ${s.label}`);

  for (const s of prev) if (!n.has(s.id) && s.id !== "recent") out.push(`-${s.id}: ${s.label}`);

  return out;
}
