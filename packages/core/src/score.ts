// apm-score: a per-version safety score. Pure functions, tarball and history in, report out.
// 100 means nothing risky was found. Every deduction is a named signal with evidence.
// Popularity is deliberately not an input: it is gameable and says nothing about compromise.
// What the analysis reads and what it cannot catch is written up in docs/SCORE.md.
import { z } from "zod";
import { dependencySpecs, isRegistryDependency } from "./deps.ts";
import { entryPoints, targetFiles } from "./entries.ts";
import { boundedManifest, measureManifest } from "./manifest.ts";
import { describeSkip, MAX_ANALYZED_FILE_BYTES, MAX_SCANNED_BYTES, SKIP_REASONS, type SkippedFile } from "./limits.ts";
import { charge, chargeText, inPhase, MAX_ANALYSIS_WORK, Meter, MeterExhausted, PHASE_NAMES, withMeter, type Phase } from "./meter.ts";
import { typoConflicts } from "./names.ts";
import { commandWords, expandHooks, gypCommands, isInlineDownload, otherScripts, type ExpandedHook, type HookKind } from "./scripts.ts";
import { importsOf, joinStrings, langOf, scanFile, scanText, type Confidence, type ExecutedCode, type FlowFinding, type Hidden, type Imports, type TextFinding } from "./source.ts";
import { scanTextRules } from "./textrules.ts";
import { ambiguousPaths, type TarEntry } from "./tarball.ts";
import { CAPABILITY_IDS, declarationOf, matchesPattern, type CapabilityId, type Declaration } from "./declare.ts";
import { factsOf as readFacts, secretFamily, type Fact } from "./facts.ts";
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
 */
export const SCORER = "apm-score-v10";

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
  scorer: z.enum(["apm-score-v1", "apm-score-v2", "apm-score-v3", "apm-score-v4", "apm-score-v5", "apm-score-v6", "apm-score-v7", "apm-score-v8", "apm-score-v9", SCORER]),
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
});

export type Signal = z.infer<typeof SignalSchema>;

export type Facts = z.infer<typeof FactsSchema>;

export type ModuleFormat = Facts["moduleFormat"];

export type Analysis = z.infer<typeof AnalysisSchema>;

export type DismissedEvidence = z.infer<typeof DismissedSchema>;

export type Capability = z.infer<typeof CapabilitySchema>;

export type Grade = "A" | "B" | "C" | "D" | "F";

export type ScoreReport = Analysis & { score: number; grade: Grade };

export const SCORE_FLOOR = 40;
export const COOLDOWN_MS = 24 * 60 * 60 * 1000;

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
const NOT_CODE = /(?:^|\/)(?:readme|changelog|changes|history|license|licence|copying|authors|contributors|notice|security|code_of_conduct)(?:\.[\w.-]*)?$|\.(?:md|markdown|mdx|txt|rst|adoc|d\.[cm]?ts|map|json|jsonc|json5|ya?ml|toml|css|scss|sass|less|styl|html?|svg|xml|csv|tsv|lock|flow)$/i;

/** Executables and native modules: never read, reported as `binary`. */
function isBinary(e: TarEntry): boolean {
  if (/\.(?:node|exe|dll|so|dylib)$/.test(e.path)) return true;
  const d = e.data;

  if (d.length < 4) return false;
  const magic = ((d[0] ?? 0) << 24) | ((d[1] ?? 0) << 16) | ((d[2] ?? 0) << 8) | (d[3] ?? 0);

  return magic === 0x7f454c46 || magic === 0xcffaedfe || magic === 0xfeedfacf || magic === 0xcafebabe || (d[0] === 0x4d && d[1] === 0x5a && e.path.endsWith(".exe"));
}

/** Images, fonts, archives and WebAssembly, recognised by their first bytes. JavaScript cannot start with these. */
function isBinaryData(e: TarEntry): boolean {
  const d = e.data;

  if (d.length < 4) return false;
  const b = (i: number): number => d[i] ?? -1;
  const ascii = (s: string, at = 0): boolean => [...s].every((c, i) => b(at + i) === c.charCodeAt(0));

  return (
    (b(0) === 0x89 && ascii("PNG", 1)) ||
    (b(0) === 0xff && b(1) === 0xd8 && b(2) === 0xff) ||
    ascii("GIF8") ||
    (ascii("RIFF") && ascii("WEBP", 8)) ||
    ascii("wOFF") ||
    ascii("wOF2") ||
    ascii("OTTO") ||
    (b(0) === 0 && b(1) === 1 && b(2) === 0 && b(3) === 0) ||
    (b(0) === 0 && ascii("asm", 1)) ||
    (b(0) === 0x1f && b(1) === 0x8b) ||
    (ascii("PK") && b(2) === 3 && b(3) === 4) ||
    ascii("%PDF")
  );
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
function installRunsOf(commands: readonly { text: string; kind: HookKind }[], byPath: ReadonlyMap<string, TarEntry>): string[] {
  const out = new Set<string>();

  for (const c of commands) {
    for (const w of c.kind === "install" ? [...scriptTargets(c.text), ...commandWords(c.text), ...runTargets(c.text)] : runTargets(c.text)) {
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
export function runTargets(cmd: string): string[] {
  const out = [...scriptTargets(cmd)];

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

/** Paths an install-script command runs after an interpreter: `node setup`, `sh ./install.sh`, `bun x.ts`. */
export function scriptTargets(cmd: string): string[] {
  const out: string[] = [];
  const re = /(?:^|[;&|]\s*|\s)(?:node|bun|deno run|sh|bash|zsh|tsx|ts-node)\s+(?:-[\w-]+\s+)*((?:\.{0,2}\/)?[\w@./-]+)/g;

  for (const m of cmd.matchAll(re)) if (m[1] && !m[1].startsWith("-")) out.push(m[1]);

  return out;
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

function isShellScript(f: TarEntry, text: string): boolean {
  return /\.(?:sh|bash|zsh|ps1|cmd|bat)$/i.test(f.path) || /^#!.*\b(?:ba|z|da)?sh\b/.test(text) || (!/\.[^/]+$/.test(f.path) && !/^#!.*\b(?:node|bun|deno)\b/.test(text));
}

export type DependencyRisk = { name: string; version: string; score: number };

export type AnalyzeInput = {
  name: string;
  manifest: Record<string, unknown>;
  files: readonly TarEntry[];
  publisher: string;
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
};

function collector(): Found {
  const found = new Map<SignalId, { confirmed: string[]; possible: string[]; has: Set<string> }>();
  const rank = new Map<string, number>();
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
};

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
    for (const word of [...scriptTargets(c.text), ...commandWords(c.text)]) {
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
    if (isBinary(f)) {
      add("binary", f.path);

      return;
    }

    if (isBinaryData(f)) return;

    if (f.data.length > MAX_ANALYZED_FILE_BYTES) {
      skipped.push({ path: f.path, size: f.data.length, reason: "too-large" });

      return;
    }

    if (scanned + f.data.length > w.budget) {
      (reached ? skipped : unanalyzed).push({ path: f.path, size: f.data.length, reason: "over-budget" });

      return;
    }

    scanned += f.data.length;
    // keyed by the entry, not its path: only these bytes' own read can stand in for reading them
    const known = w.readWhole.get(f);

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
    const imports = known ?? importsOf(joinStrings(textOf()).text);

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

  for (const f of w.files) if (!seen.has(f.path) && isBinary(f)) add("binary", f.path);

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
  return incompleteAnalysis({ manifest: u.manifest, files: u.files, evidence: [meterEvidence(u.phase, u.limit), ...(u.because ?? [])], notChecked: `everything past the analysis work limit (${PHASE_NAMES[u.phase]})` });
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
function incompleteAnalysis(u: { manifest: AnalyzeInput["manifest"]; files: readonly TarEntry[]; evidence: string[]; notChecked: string }): Analysis {
  return {
    scorer: SCORER,
    signals: [signal("incomplete", u.evidence)],
    facts: factsOf(boundedManifest(u.manifest), u.files),
    notChecked: [...NOT_CHECKED, u.notChecked],
    skipped: [],
    capabilities: [],
    declaration: { kind: "none", notes: [] },
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
  const add = found.add;
  const byPath = new Map(files.map((f) => [f.path, f]));
  const hooks = expandHooks(manifest);

  // a hook whose commands apm stopped expanding runs commands apm did not read
  for (const h of hooks) if (h.cut !== null && h.kind !== "publish") add("incomplete", `scripts.${h.hook}: apm stopped reading the commands it runs at ${h.cut}`);
  const hookEvidence = analyzeHooks(found, manifest, hooks);
  // what runs on the installing machine: install hooks, and the git hooks npm runs when it installs from git
  const installCommands = hooks.filter((h) => h.kind !== "publish").flatMap((h) => h.commands);
  const hookCommands = hooks.filter((h) => h.kind !== "publish").flatMap((h) => h.commands.map((c) => ({ text: c.text, kind: h.kind })));

  // binding.gyp runs at install; its actions and <!(...) expansions are commands like any install script
  const gyp = byPath.get("binding.gyp");

  if (gyp) {
    add("install-script", "binding.gyp: node-gyp build runs at install");

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

      if (f && isInlineDownload(new TextDecoder().decode(f.data))) add("install-download", `${name}: built by an install script and downloads code`);
    }
  }

  // What gets read, in order: what install hooks run, then entry points, then whatever those reach
  // through a path apm can resolve; then every other file that could be code, whatever its name.
  // A byte budget, not a file count, bounds the work, so filler files can only push out other filler.
  const budget = input.maxScannedBytes ?? MAX_SCANNED_BYTES;
  const installTargets = new Set<string>();
  const first: string[] = [];

  for (const c of installCommands) {
    for (const w of [...scriptTargets(c.text), ...commandWords(c.text)]) {
      const f = resolveIn(byPath, w);

      if (f && f.path !== "package.json") {
        installTargets.add(f.path);
        first.push(f.path);
      }
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
  const dynamicAt = new Set<string>();
  // what each file shows beyond the code signals, and which files each one loads, for the v10 risk signals
  const fileFacts = new Map<string, Fact[]>();
  const edges = new Map<string, Set<string>>();
  // where values go in each parsed file (flow.ts) and what it exports, resolved across files once every file is read
  const fileFlows = new Map<string, { flows: FlowFinding[]; exports: Exports }>();
  const heldBytes = new Map<string, number>();
  // files read with no tree: nothing there can show where a value goes, so v9's reading of them stands
  const rawFiles = new Set<string>();

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
    const facts = fileFacts.get(path) ?? [];
    const snippet = `${e.snippet}${HELD_NOTES[e.origin]}`;

    for (const fact of readFacts(e.code, scan.hidden, scan.commands)) if ((e.origin !== "held" && e.origin !== "data") || HELD_RISKS.has(fact.kind)) facts.push({ ...fact, line: e.line, snippet, near: true });

    if (e.origin === "recovered" && (scan.read === "raw" || scan.findings.some((x) => x.confidence === "confirmed"))) facts.push({ kind: "runs-hidden", line: e.line, snippet, text: false, near: true });
    fileFacts.set(path, facts);
    const flows: { flows: FlowFinding[]; exports: Exports } = fileFlows.get(path) ?? { flows: [], exports: new Map() };

    // a string kept as data (an export, a property value, an array element) is not run: its flows are not the file's
    // (a package that exports example code), and what it would do counts only through the facts above
    if (e.origin !== "data") for (const x of scan.flows ?? []) flows.flows.push({ ...x, line: e.line, snippet });
    fileFlows.set(path, flows);

    if (e.origin === "run" || e.origin === "recovered") for (const u of scan.unread ?? []) add("incomplete", `${path}:${e.line}: ${e.snippet} (${u.why})`);

    // code that code held as text runs or holds in turn, as sure as the outer one is to run
    for (const inner of scan.executed ?? []) readHeld(path, { ...inner, line: e.line, snippet: e.snippet, origin: e.origin === "run" ? inner.origin : e.origin }, depth + 1);
  };

  const analyzeFile = (f: TarEntry, reached: boolean): void => {
    if (isBinary(f)) {
      add("binary", f.path);

      return;
    }

    if (isBinaryData(f)) return;

    if (f.data.length > MAX_ANALYZED_FILE_BYTES) {
      skipped.push({ path: f.path, size: f.data.length, reason: "too-large" });

      return;
    }

    if (scanned + f.data.length > budget) {
      (reached ? skipped : unanalyzed).push({ path: f.path, size: f.data.length, reason: "over-budget" });

      return;
    }

    scanned += f.data.length;
    // decoding the bytes, choosing the language, and the passes below over the whole text: the file's facts, v3's
    // imports and the joined text it reads them from
    chargeText("text", f.data.length, TEXT_PASSES_PER_FILE);
    // read whatever the bytes are: skipping "non-text" would let a NUL byte hide code
    const text = new TextDecoder().decode(f.data);

    const named = langOf(f.path, text);
    // a type declaration code loads runs too (node strips its types, or older node runs it as JavaScript)
    const lang = runsAsCode.has(f.path) && (named === "plain" || named === "c" || named === "python") ? "js" : runsAsCode.has(f.path) && named === "declaration" ? "ts" : named;
    const scan = scanFile(text, lang);

    // a README or LICENSE a pattern exposes is not JavaScript: node would throw a SyntaxError, so nothing in it runs
    if (scan.rejected && exposedOnly.has(f.path) && NOT_CODE.test(f.path)) return;

    for (const finding of scan.findings) add(finding.id, describeFinding(f.path, finding), finding.confidence, citedAs(finding));

    for (const note of scan.notes) {
      const list = limits.get(note);

      if (list) list.push(f.path);
      else limits.set(note, [f.path]);
    }

    if (lang !== "json" && lang !== "declaration") {
      if (scan.read === "raw") rawFiles.add(f.path);
      const facts = readFacts(text, scan.hidden, scan.commands);
      // the parser's environment reads follow aliases and `globalThis.process.env`; a name read through one sits as near
      // the network as the file is small
      const near = text.length < 16 * 1024;

      for (const e of scan.env ?? []) facts.push(e.name === null ? { kind: "env-object", line: e.line, snippet: e.snippet, text: false, near } : { kind: "env", line: e.line, snippet: e.snippet, name: e.name, text: false, near });
      fileFacts.set(f.path, facts);
      fileFlows.set(f.path, { flows: [...(scan.flows ?? [])], exports: scan.exports ?? new Map() });

      for (const e of scan.executed ?? []) readHeld(f.path, e, 1);

      for (const u of scan.unread ?? []) add("incomplete", `${f.path}:${u.line}: ${u.snippet} (${u.why})`);
    }

    // a file a command runs (`exec('node app.js')`) runs when this file does, as a file it loads does
    for (const c of scan.commands ?? []) {
      for (const word of [...scriptTargets(c.value), ...commandWords(c.value)]) {
        const target = resolveIn(byPath, joinPath(dirOf(f.path), word)) ?? resolveIn(byPath, word);

        if (target && target.path !== f.path && target.path !== "package.json") edges.set(f.path, (edges.get(f.path) ?? new Set()).add(target.path));
      }
    }

    if (installTargets.has(f.path) && isShellScript(f, text) && isInlineDownload(text)) add("install-download", `${f.path}: run by an install script and downloads code`);
    // every path apm-score-v3's pattern finds in the text is reached too, so no file v3 read goes unread
    const v3Imports = scan.read === "parsed" ? importsOf(joinStrings(text).text) : null;
    const imports = v3Imports ? { ...scan.imports, paths: [...new Set([...scan.imports.paths, ...v3Imports.paths])] } : scan.imports;

    readWhole.set(f, v3Imports);

    // a computed load in JavaScript counts wherever it is: a file nothing here reaches can still be loaded and run by its
    // path. In any other file it is only v3's pattern over text, reported where v3 reported it, in a reached file.
    const javascript = lang === "js" || lang === "jsx" || lang === "ts" || lang === "tsx";

    for (const d of javascript || reached ? imports.dynamic : []) {
      add("dynamic-require", `${f.path}:${d.line}: ${d.snippet}`);
      dynamicAt.add(`${f.path}:${d.line}`);
    }

    for (const spec of imports.paths) {
      const target = resolveIn(byPath, joinPath(dirOf(f.path), spec));

      if (target) edges.set(f.path, (edges.get(f.path) ?? new Set()).add(target.path));

      if (!target || seen.has(target.path)) continue;

      if (imports.loads.includes(spec)) {
        runsAsCode.add(target.path);
        exposedOnly.delete(target.path);
      }

      if (reached && !reachable.has(target.path)) {
        reachable.add(target.path);
        queue.push(target.path);
      }
    }
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

  const v3 = readLikeV3({ files, byPath, manifest, installCommands, gyp, budget, readWhole, dynamicAt, add, read: readRaw });

  const { cross, cut } = inPhase("cross-file", () => addFlowFacts(fileFlows, fileFacts, byPath, input.maxCrossFileSteps));

  for (const why of cut) add("incomplete", why);

  if (cross.exhausted) add("incomplete", `flows across files: stopped at the work budget (${input.maxCrossFileSteps ?? MAX_CROSS_FILE_STEPS} steps), so values one file gives another were not all followed`);

  for (const s of [...skipped, ...v3.skipped]) add("incomplete", `not analyzed: ${describeSkip(s)}`);

  for (const why of input.incompleteBecause ?? []) add("incomplete", why);

  for (const list of [unanalyzed, v3.unanalyzed]) {
    if (list.length === 0) continue;
    const bytes = list.reduce((n, s) => n + s.size, 0);

    add("unanalyzed-files", `${list.length} file(s), ${(bytes / (1024 * 1024)).toFixed(1)} MB, past the ${(budget / (1024 * 1024)).toFixed(1)} MB analysis budget (first: ${list[0]?.path ?? ""})`);
    // a file no entry point reaches can still be loaded by its path or run by a command: left unread, it leaves the
    // analysis incomplete, not clean (the full budget is the most a tarball unpacks to, so only a smaller one gets here)
    add("incomplete", `not analyzed: ${list.length} file(s) past the ${(budget / (1024 * 1024)).toFixed(1)} MB analysis budget (first: ${list[0]?.path ?? ""})`);
  }

  for (const f of files) if (!seen.has(f.path) && isBinary(f)) add("binary", f.path);

  const facts = factsOf(manifest, files);

  if (!facts.license) add("no-license", "package.json has no license field");
  const typos = typoConflicts(input.name);

  for (const t of typos) add("typosquat", t.reason);

  if (input.previousPublishers.length > 0 && !input.previousPublishers.includes(input.publisher)) {
    add("new-publisher", `${input.publisher} has not published this package before (previous: ${input.previousPublishers.join(", ")})`);
  }

  for (const d of input.riskyDependencies ?? []) add("risky-dependency", `${d.name}@${d.version} scores ${d.score}/100`);

  for (const d of input.addedDependencies ?? []) add("new-dependency", `adds ${d}`);

  // scoring weighs every fact of every file, every edge between files and every piece of evidence
  charge("score", [...fileFacts.values()].reduce((n, l) => n + l.length * 8, 0) + [...edges.values()].reduce((n, s) => n + s.size * 4, 0));

  const assessed = inPhase("score", () => assess({
    found,
    fileFacts,
    edges,
    // every lifecycle script that runs on the installing machine: install hooks, and prepare, prepack and postpack,
    // which npm runs when it installs a package from git
    installRoots: [...installRunsOf(hookCommands, byPath), ...(gyp ? [gyp.path] : [])],
    installBinaries: installRunsOf(hookCommands, byPath).filter((p) => {
      const f = byPath.get(p);

      return f !== undefined && isBinary(f);
    }),
    reached: reachable,
    rawFiles,
    hookEvidence,
    gyp: gyp !== undefined,
    binPaths: new Set(entryPoints(manifest).flatMap((e) => (e.field.startsWith("bin") ? [joinPath("", e.path)] : []))),
    declaration: declarationOf(manifest),
  }));

  const signals = assessed.signals;

  const notChecked = [
    ...NOT_CHECKED,
    ...[...limits].map(([note, paths]) => `${note} (${paths.slice(0, 3).join(", ")}${paths.length > 3 ? ` and ${paths.length - 3} more files` : ""})`),
    ...[unanalyzed, v3.unanalyzed].flatMap((list) => (list.length === 0 ? [] : [`${list.length} file(s) not analyzed: the package is larger than the ${(budget / (1024 * 1024)).toFixed(1)} MB one analysis reads`])),
    ...(input.uncheckedDependencies ?? []).map((d) => `dependency ${d}`),
  ];

  // both walks can skip the same file
  const skippedOnce = new Map([...skipped, ...unanalyzed, ...v3.skipped, ...v3.unanalyzed].map((s) => [`${s.reason}:${s.path}`, s]));

  return {
    scorer: SCORER,
    signals,
    facts,
    notChecked: [...new Set(notChecked)],
    skipped: [...skippedOnce.values()],
    capabilities: assessed.capabilities,
    declaration: assessed.declaration,
  };
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
const HELD_RISKS: ReadonlySet<Fact["kind"]> = new Set(["env-dump", "credential-read", "credential-near", "remote-shell", "fetched-code", "capture-endpoint"]);

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

  // v9's non-code signals keep their ids; their points are v10's
  for (const id of ["incomplete", "install-download", "git-install-script", "risky-dependency", "typosquat", "install-script", "unanalyzed-files", "new-publisher", "new-dependency", "dynamic-require", "no-license"] as const) {
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

export type VersionState = { publishedAt: number; now: number; deprecated: string | null; status: "active" | "yanked" | "revoke-pending" | "revoked"; statusReason: string | null };

/** Applies time- and state-based signals and computes the number. */
export function finalize(analysis: Analysis, state: VersionState): ScoreReport {
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

  return { ...analysis, signals, score, grade: gradeOf(score) };
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

  return { ...analysis, signals, dismissed: [...(analysis.dismissed ?? []), ...dismissed] };
}

/** A stored analysis (v1 or v2), or null when the value is not one. */
export function parseAnalysis(v: unknown): Analysis | null {
  const r = AnalysisSchema.safeParse(v);

  return r.success ? r.data : null;
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
