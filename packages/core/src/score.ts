// apm-score: a per-version safety score. Pure functions, tarball and history in, report out.
// 100 means nothing risky was found. Every deduction is a named signal with evidence.
// Popularity is deliberately not an input: it is gameable and says nothing about compromise.
// What the analysis reads and what it cannot catch is written up in docs/SCORE.md.
import { z } from "zod";
import { dependencySpecs, isRegistryDependency } from "./deps.ts";
import { entryPoints, targetFiles } from "./entries.ts";
import { describeSkip, MAX_ANALYZED_FILE_BYTES, MAX_SCANNED_BYTES, SKIP_REASONS, type SkippedFile } from "./limits.ts";
import { typoConflicts } from "./names.ts";
import { commandWords, expandHooks, gypCommands, isInlineDownload, otherScripts, type ExpandedHook } from "./scripts.ts";
import { importsOf, joinStrings, langOf, scanFile, scanText, scanWholeText, type Confidence, type TextFinding } from "./source.ts";
import type { TarEntry } from "./tarball.ts";

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
 * harmless; a limit, a value it cannot follow or syntax it does not model leaves v3's finding standing.
 */
export const SCORER = "apm-score-v8";

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

/** What a static read of the tarball cannot see. Shown with every score; docs/SCORE.md explains each. */
export const NOT_CHECKED: readonly string[] = [
  "runtime behavior: code that downloads, decrypts or builds a second stage while running",
  "code hidden by anything but base64, hex, \\x escapes, char codes or joined string literals (XOR, compression, a custom encoding)",
  "names built at runtime from values apm cannot work out in the file (array lookups, computed indexes, values read at runtime, values passed through a function's parameters)",
  "documentation, type, JSON, style and markup files that no code reaches by a path apm can read; a computed require is reported as dynamic-require",
  "native binaries and WebAssembly: listed, not read",
  "a popular name reused under another scope (@someone/react): scopes exist so names can be reused",
  "the code of dependencies beyond their own scores",
  "whether the publisher's machine or CI was compromised",
];

const AnalysisSchema = z.object({
  scorer: z.enum(["apm-score-v1", "apm-score-v2", "apm-score-v3", "apm-score-v4", "apm-score-v5", "apm-score-v6", "apm-score-v7", SCORER]),
  signals: z.array(SignalSchema),
  facts: FactsSchema,
  notChecked: z.array(z.string()).default([...NOT_CHECKED]),
  skipped: z.array(SkippedSchema).default([]),
  /** Evidence an apm reviewer dismissed for these exact bytes and this scorer; the score leaves it out. */
  dismissed: z.array(DismissedSchema).optional(),
});

export type Signal = z.infer<typeof SignalSchema>;

export type Facts = z.infer<typeof FactsSchema>;

export type ModuleFormat = Facts["moduleFormat"];

export type Analysis = z.infer<typeof AnalysisSchema>;

export type DismissedEvidence = z.infer<typeof DismissedSchema>;

export type Grade = "A" | "B" | "C" | "D" | "F";

export type ScoreReport = Analysis & { score: number; grade: Grade };

export const SCORE_FLOOR = 40;
export const COOLDOWN_MS = 24 * 60 * 60 * 1000;

export const POINTS: Record<SignalId, number> = {
  "install-script": -15,
  "shell-exec": -15,
  network: -10,
  "credential-access": -25,
  eval: -10,
  obfuscated: -10,
  binary: -5,
  "new-publisher": -10,
  "no-license": -3,
  typosquat: -20,
  "install-download": -40,
  "risky-dependency": -30,
  "new-dependency": -5,
  // an analysis that did not read every file that runs can never pass the floor on its own
  incomplete: -(100 - SCORE_FLOOR + 1),
  // informational: age is handled by the cooldown, never by the number
  recent: 0,
  deprecated: -5,
  yanked: 0,
  revoked: -100,
  "git-install-script": -10,
  // informational: plugin loaders do this honestly, and every file is read anyway; it marks code apm could not follow
  "dynamic-require": 0,
  "unanalyzed-files": -20,
};

/** Signals the source rules can only suspect, and what each costs then: a third or so of the confirmed points. */
type CodeSignalId = "shell-exec" | "network" | "credential-access" | "eval" | "obfuscated";

export const POSSIBLE_POINTS: Record<CodeSignalId, number> = {
  "shell-exec": -5,
  network: -3,
  "credential-access": -8,
  eval: -3,
  obfuscated: -3,
};

const POSSIBLE_LABELS: Record<CodeSignalId, string> = {
  "shell-exec": "Possible shell use: names a shell command or child_process, but apm did not see one started",
  network: "Possible network use: names a request or download, but apm did not see one made",
  "credential-access": "Possible credential access: names a credential file or token, but apm did not see it read",
  eval: "Possible eval: keeps a way to run code built at runtime, but apm did not see it used",
  obfuscated: "Possibly obfuscated: holds encoded or assembled text that apm did not see run",
};

/**
 * A confirmed code signal whose every piece of evidence is a text match (no call or load the parsed program showed)
 * says what was found, not what the code does. The points are the same: v3's rules count the match.
 */
const TEXT_LABELS: Record<CodeSignalId, string> = {
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
  obfuscated: "Contains obfuscated code",
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

/** Whether a piece of evidence is a text match only, not a call or load the parsed program showed. */
export function isTextEvidence(e: string): boolean {
  return e.includes(TEXT_MATCH) || e.includes(TEXT_MATCH_RUN);
}

function labelOf(id: SignalId, confidence: Confidence, evidence: readonly string[]): string {
  if (!isCodeSignal(id)) return LABELS[id];

  if (confidence === "possible") return POSSIBLE_LABELS[id];

  return evidence.length > 0 && evidence.every(isTextEvidence) ? TEXT_LABELS[id] : LABELS[id];
}

/** Past the shown evidence: what is kept for a reviewer's dismissal, and how many more were not kept. */
function keepRest(out: Signal, sorted: readonly string[]): Signal {
  if (sorted.length > SHOWN_EVIDENCE) out.more = sorted.slice(SHOWN_EVIDENCE, KEPT_EVIDENCE);

  if (sorted.length > KEPT_EVIDENCE) out.uncounted = sorted.length - KEPT_EVIDENCE;

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
  const files: string[] = [];

  for (const e of entryPoints(manifest)) {
    const t = targetFiles(e.path, all);

    if (t.kind === "files") files.push(...t.files);
    else if (t.path.startsWith(".") || /^[\w@]/.test(t.path)) paths.push(t.path);
  }

  return { paths, files: [...new Set(files)] };
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

function resolveIn(byPath: Map<string, TarEntry>, raw: string): TarEntry | undefined {
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
};

/** What each dependency installs: the registry name behind an npm: alias, the key for anything else. */
export function dependencyNames(manifest: Record<string, unknown>): string[] {
  return [...new Set(dependencySpecs(manifest).map((d) => (isRegistryDependency(d) ? d.name : d.key)))];
}

type Found = {
  /**
   * Records evidence; a signal is confirmed once any of its evidence is, and then shows only confirmed evidence.
   * `textOnly`: only a text rule matched it (the floor), so it is listed after what a parsed program showed.
   */
  add: (id: SignalId, ev: string, confidence?: Confidence, textOnly?: boolean) => void;
  has: (id: SignalId) => boolean;
  get: (id: SignalId) => { evidence: string[]; confidence: Confidence; possible: string[] } | undefined;
};

function collector(): Found {
  const found = new Map<SignalId, { confirmed: string[]; possible: string[] }>();
  const textOnly = new Set<string>();
  // the call or load a parsed program showed comes before a text match, so it is what the shown evidence cites
  const ranked = (list: readonly string[]): string[] => [...list].sort((a, b) => Number(textOnly.has(a)) - Number(textOnly.has(b)));

  return {
    add(id, ev, confidence = "confirmed", text = false) {
      const entry = found.get(id) ?? { confirmed: [], possible: [] };
      const list = entry[confidence];

      if (text) textOnly.add(ev);

      if (!list.includes(ev)) list.push(ev);
      found.set(id, entry);
    },
    has: (id) => found.has(id),
    get: (id) => {
      const entry = found.get(id);

      if (!entry) return undefined;

      const possible = ranked(entry.possible);

      return entry.confirmed.length > 0 ? { evidence: ranked(entry.confirmed), confidence: "confirmed", possible } : { evidence: possible, confidence: "possible", possible: [] };
    },
  };
}

/**
 * What a confirmed finding only a text rule made says after its snippet, so a reader of the evidence can tell it from
 * a call or load the parsed program showed: apm counts every such match unless the parse puts it in a comment, a regex
 * literal or a TypeScript type, which is also why a definition, a written key or a string only compared counts.
 */
export const TEXT_MATCH = " (text match: counted unless it sits in a comment, a regex or a type)";

/**
 * What a match in a comment, a regex body or an erased type says when it counts: the package runs code built from
 * text (eval, Function, vm, a shell, a computed load), and that is how such text becomes code (`String(fn)`, `re.source`).
 */
export const TEXT_MATCH_RUN = " (text match in a comment, a regex or a type: counted because this package runs code built from text)";

/** The signals that let a package turn text it holds into code: while one stands, comments, regex bodies and types count. */
const RUNS_TEXT: readonly SignalId[] = ["eval", "shell-exec", "dynamic-require", "install-download"];

function describeFinding(where: string, f: TextFinding, note: string = TEXT_MATCH): string {
  const how = f.how === "as written" ? "" : ` (${f.how})`;
  const why = f.confidence === "possible" ? ` [possible: ${f.why}]` : "";
  const text = f.confidence === "confirmed" && f.tree !== true ? note : "";

  return `${where}:${f.line}: ${f.snippet}${how}${text}${isTestPath(where) ? IN_TEST_FILE : ""}${why}`;
}

function depNames(manifest: AnalyzeInput["manifest"], fields: readonly string[]): Set<string> {
  return new Set(fields.flatMap((f) => (isRecord(manifest[f]) ? Object.keys(manifest[f]) : [])));
}

/** Signals from the lifecycle scripts: what runs at install, at a git install, and on the publisher's machine. */
function analyzeHooks(found: Found, manifest: AnalyzeInput["manifest"], hooks: readonly ExpandedHook[]): void {
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
        found.add(f.id, `${label}${f.how === "as written" ? "" : ` (${f.how})`}`, f.confidence);
        risky = true;
      }
    }

    if (h.kind === "git" && risky) found.add("git-install-script", `package.json scripts.${h.hook}: ${own.slice(0, 80)} (npm runs it when this package is installed from git)`);
  }

  // scripts no hook reaches never run on an installer's machine; only what they would do to one is reported
  for (const [k, cmd] of Object.entries(otherScripts(manifest, hooks))) {
    for (const f of scanText(cmd, "plain")) if (f.id === "credential-access" || f.id === "obfuscated") found.add(f.id, `package.json scripts.${k}: ${cmd.slice(0, 80)}`, f.confidence);
  }
}

/** Static analysis of one version. Run once at publish; stored with the version. */
export function analyze(input: AnalyzeInput): Analysis {
  const { manifest, files } = input;
  const found = collector();
  const add = found.add;
  const byPath = new Map(files.map((f) => [f.path, f]));
  const hooks = expandHooks(manifest);
  analyzeHooks(found, manifest, hooks);
  const installCommands = hooks.filter((h) => h.kind !== "publish").flatMap((h) => h.commands);

  // binding.gyp runs at install; its actions and <!(...) expansions are commands like any install script
  const gyp = byPath.get("binding.gyp");

  if (gyp) {
    add("install-script", "binding.gyp: node-gyp build runs at install");

    for (const cmd of gypCommands(new TextDecoder().decode(gyp.data))) {
      if (isInlineDownload(cmd)) add("install-download", `binding.gyp: ${cmd.slice(0, 80)}`);

      for (const f of scanText(cmd, "plain")) add(f.id, `binding.gyp: ${cmd.slice(0, 80)}`, f.confidence);
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
  // proofs that rest on a global or builtin module (fetch sends, path.join builds) hold only if no file could replace one
  const sinkOnly: { path: string; finding: TextFinding }[] = [];
  let patched: string | null = null;
  const limits = new Map<string, string[]>();
  // parsed files, with the signals their own reading confirmed: read again whole if the package runs code from text
  const parsed: { file: TarEntry; sure: ReadonlySet<SignalId> }[] = [];

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
    // read whatever the bytes are: skipping "non-text" would let a NUL byte hide code
    const text = new TextDecoder().decode(f.data);

    const named = langOf(f.path, text);
    // a type declaration code loads runs too (node strips its types, or older node runs it as JavaScript)
    const declaration = named === "data" && /\.d\.[cm]?ts$/i.test(f.path);
    const lang = runsAsCode.has(f.path) && (named === "plain" || named === "c" || named === "python") ? "js" : runsAsCode.has(f.path) && declaration ? "ts" : named;
    const scan = scanFile(text, lang);

    // a README or LICENSE a pattern exposes is not JavaScript: node would throw a SyntaxError, so nothing in it runs
    if (scan.rejected && exposedOnly.has(f.path) && NOT_CODE.test(f.path)) return;

    for (const finding of scan.findings) add(finding.id, describeFinding(f.path, finding), finding.confidence, finding.tree !== true);

    if (scan.read === "parsed") parsed.push({ file: f, sure: new Set(scan.findings.flatMap((x) => (x.confidence === "confirmed" ? [x.id] : []))) });

    for (const finding of scan.sinkOnly) sinkOnly.push({ path: f.path, finding });

    if (scan.patches) patched ??= `${f.path}, ${scan.patches}`;

    for (const note of scan.notes) limits.set(note, [...(limits.get(note) ?? []), f.path]);

    if (installTargets.has(f.path) && isShellScript(f, text) && isInlineDownload(text)) add("install-download", `${f.path}: run by an install script and downloads code`);
    // every path apm-score-v3's pattern finds in the text is reached too, so no file v3 read goes unread
    const imports = scan.read === "parsed" ? { ...scan.imports, paths: [...new Set([...scan.imports.paths, ...importsOf(joinStrings(text).text).paths])] } : scan.imports;

    for (const d of imports.dynamic) if (reached) add("dynamic-require", `${f.path}:${d.line}: ${d.snippet}`);

    for (const spec of imports.paths) {
      const target = resolveIn(byPath, joinPath(dirOf(f.path), spec));

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

  if (patched) for (const { path, finding } of sinkOnly) add(finding.id, describeFinding(path, finding), finding.confidence, true);

  // `String(fn)` (comments included), `re.source` and a file reading itself turn left-out text into code, but only
  // through an evaluator: while eval, Function, vm, a shell or a computed load stands, that text counts as v3 read it
  if (RUNS_TEXT.some((id) => found.has(id))) {
    for (const { file, sure } of parsed) {
      for (const finding of scanWholeText(new TextDecoder().decode(file.data))) {
        if (!sure.has(finding.id)) add(finding.id, describeFinding(file.path, finding, TEXT_MATCH_RUN), finding.confidence, true);
      }
    }
  }

  for (const s of skipped) add("incomplete", `not analyzed: ${describeSkip(s)}`);

  if (unanalyzed.length > 0) {
    const bytes = unanalyzed.reduce((n, s) => n + s.size, 0);
    add("unanalyzed-files", `${unanalyzed.length} file(s), ${(bytes / (1024 * 1024)).toFixed(1)} MB, past the ${(budget / (1024 * 1024)).toFixed(1)} MB analysis budget (first: ${unanalyzed[0]?.path ?? ""})`);
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

  const order: SignalId[] = [
    "incomplete",
    "credential-access",
    "install-download",
    "shell-exec",
    "install-script",
    "git-install-script",
    "risky-dependency",
    "network",
    "eval",
    "obfuscated",
    "unanalyzed-files",
    "dynamic-require",
    "typosquat",
    "new-publisher",
    "new-dependency",
    "binary",
    "no-license",
  ];

  const signals = order.flatMap((id) => {
    const got = found.get(id);

    return got ? [signal(id, got.evidence, got.confidence, got.possible)] : [];
  });

  const notChecked = [
    ...NOT_CHECKED,
    ...(patched && sinkOnly.length > 0 ? [`what a string sent to fetch, read as a path or built by path.join or an Error holds, because a file could replace those builtins (${patched}): it was judged by the text rules alone`] : []),
    ...[...limits].map(([note, paths]) => `${note} (${paths.slice(0, 3).join(", ")}${paths.length > 3 ? ` and ${paths.length - 3} more files` : ""})`),
    ...(unanalyzed.length > 0 ? [`${unanalyzed.length} file(s) not analyzed: the package is larger than the ${(budget / (1024 * 1024)).toFixed(1)} MB one analysis reads`] : []),
    ...(input.uncheckedDependencies ?? []).map((d) => `dependency ${d}`),
  ];

  return { scorer: SCORER, signals, facts, notChecked, skipped: [...skipped, ...unanalyzed] };
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

/** The signals a reviewer may dismiss evidence of: what the source rules read, never a fact like an install script. */
export const DISMISSABLE: ReadonlySet<string> = new Set<string>(["shell-exec", "network", "credential-access", "eval", "obfuscated"]);

const CITED_LINE = /^([^\s:][^:\n]*?):(\d+)(?=: |$)/;

/** The file and line a piece of code evidence cites (`lib/a.js:4: …`), or null when it cites none. */
export function evidenceAt(evidence: string): { file: string; line: number } | null {
  const m = CITED_LINE.exec(evidence);

  return m?.[1] && m[2] ? { file: m[1], line: Number(m[2]) } : null;
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
