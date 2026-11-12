// apm-score-v1: a per-version safety score. Pure functions, tarball and history in, report out.
// 100 means nothing risky was found. Every deduction is a named signal with evidence.
// Popularity is deliberately not an input: it is gameable and says nothing about compromise.
import { typoConflicts } from "./names.ts";
import type { TarEntry } from "./tarball.ts";

export type SignalId =
  | "install-script"
  | "shell-exec"
  | "network"
  | "credential-access"
  | "eval"
  | "obfuscated"
  | "binary"
  | "new-publisher"
  | "no-license"
  | "typosquat"
  | "install-download"
  | "risky-dependency"
  | "new-dependency"
  | "recent"
  | "deprecated"
  | "yanked"
  | "revoked";

export type Signal = { id: SignalId; label: string; points: number; evidence: string[] };

export type ModuleFormat = "esm" | "cjs" | "dual";
export type Facts = {
  moduleFormat: ModuleFormat;
  types: "bundled" | "none";
  installScripts: boolean;
  hasBin: boolean;
  license: string | null;
  fileCount: number;
  unpackedSize: number;
  dependencyCount: number;
};

export type Analysis = { scorer: "apm-score-v1"; signals: Signal[]; facts: Facts; notChecked: string[] };

export const NOT_CHECKED: readonly string[] = [
  "runtime behavior: code that downloads, decrypts or builds a second stage while running",
  "the code of dependencies beyond their own scores",
  "whether the publisher's machine or CI was compromised",
];
export type Grade = "A" | "B" | "C" | "D" | "F";
export type ScoreReport = Analysis & { score: number; grade: Grade };

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
  // informational: age is handled by the cooldown, never by the number
  recent: 0,
  deprecated: -5,
  yanked: 0,
  revoked: -100,
};

const LABELS: Record<SignalId, string> = {
  "install-script": "Runs a script at install time (preinstall, install or postinstall)",
  "shell-exec": "Starts shell commands or child processes",
  network: "Makes network requests",
  "credential-access": "Reads credential files or secret environment variables",
  eval: "Evaluates code built at runtime (eval, new Function, vm)",
  obfuscated: "Contains obfuscated code",
  binary: "Ships compiled binaries that cannot be reviewed as source",
  "new-publisher": "Published by an account that never published this package before",
  "no-license": "No license declared",
  typosquat: "Name is one typo away from a popular package",
  "install-download": "Install script downloads or runs code inline (curl | sh, node -e with network)",
  "risky-dependency": "Depends on a package that scores below the floor",
  "new-dependency": "Adds dependencies the previous version did not have",
  recent: "Published less than 24 hours ago; most malicious versions are caught within hours",
  deprecated: "Deprecated by its maintainer",
  yanked: "Yanked: hidden from new installs by its maintainer",
  revoked: "Revoked: pulled as malicious or compromised",
};

export const SCORE_FLOOR = 40;
export const COOLDOWN_MS = 24 * 60 * 60 * 1000;

const CODE_EXT = /\.(?:[cm]?[jt]sx?|sh|ps1|py)$/;
const INSTALL_SCRIPTS = ["preinstall", "install", "postinstall"] as const;

const RULES: { id: "shell-exec" | "network" | "credential-access" | "eval" | "obfuscated"; re: RegExp }[] = [
  { id: "shell-exec", re: /\bchild_process\b|\bexec(?:File)?Sync\s*\(|\bspawnSync\s*\(|\|\s*(?:ba|z)?sh\b|\bcurl\s+-?|\bwget\s+|\bpowershell\b|\bBun\.spawn\b|\bBun\.\$|\bDeno\.Command\b/ },
  {
    id: "network",
    re: /\bfetch\s*\(|\bhttps?\.(?:get|request)\s*\(|require\(\s*['"](?:node:)?(?:https?|net|dgram|tls|http2)['"]\s*\)|from\s+['"](?:node:)?(?:https?|net|dgram|tls|http2)['"]|\bXMLHttpRequest\b|\bnew\s+WebSocket\b|\bcurl\s+|\bwget\s+|\bdns\.(?:resolve|lookup)\b|\bimport\s*\(\s*['"`]https?:\/\//,
  },
  {
    id: "credential-access",
    re: /\.npmrc\b|['"/]\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws\/credentials|AWS_SECRET_ACCESS_KEY|\bGITHUB_TOKEN\b|\bNPM_TOKEN\b|\bNODE_AUTH_TOKEN\b|JSON\.stringify\(\s*process\.env\s*\)|\.git-credentials|\.docker\/config\.json|\bLogin Data\b|\.config\/gcloud/,
  },
  {
    id: "eval",
    re: /(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.(?:runIn\w*Context|Script)\b|\[\s*(['"`])[\w$]{0,8}\1\s*\+\s*(['"`])[\w$]{0,8}\2\s*\]|=\s*require\s*[;,\n]|\brequire\s*\(\s*String\.fromCharCode/,
  },
  { id: "obfuscated", re: /(?:_0x[0-9a-f]{4,}[\s\S]*){20}|(?:\\x[0-9a-f]{2}){40}|['"][A-Za-z0-9+/]{2000,}={0,2}['"]/ },
];

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function lineOf(text: string, index: number): { line: number; snippet: string } {
  const before = text.slice(0, index);
  const line = before.split("\n").length;
  const start = before.lastIndexOf("\n") + 1;
  const end = text.indexOf("\n", index);
  const snippet = text.slice(start, end === -1 ? undefined : end).trim().slice(0, 80);
  return { line, snippet };
}

function isBinary(e: TarEntry): boolean {
  if (e.path.endsWith(".node") || e.path.endsWith(".exe") || e.path.endsWith(".dll") || e.path.endsWith(".so") || e.path.endsWith(".dylib")) return true;
  const d = e.data;
  if (d.length < 4) return false;
  const magic = ((d[0] ?? 0) << 24) | ((d[1] ?? 0) << 16) | ((d[2] ?? 0) << 8) | (d[3] ?? 0);
  return magic === 0x7f454c46 || magic === 0xcffaedfe || magic === 0xfeedfacf || magic === 0xcafebabe || (d[0] === 0x4d && d[1] === 0x5a && e.path.endsWith(".exe"));
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

function signal(id: SignalId, evidence: string[]): Signal {
  return { id, label: LABELS[id], points: POINTS[id], evidence: evidence.slice(0, 5) };
}

function isText(data: Uint8Array): boolean {
  const n = Math.min(data.length, 4096);
  for (let i = 0; i < n; i++) if (data[i] === 0) return false;
  return true;
}

/** The canonical dropper shape: an install command that fetches or evaluates remote code itself. */
export function isInlineDownload(cmd: string): boolean {
  if (/\b(?:curl|wget|iwr|Invoke-WebRequest)\b/i.test(cmd)) return true;
  if (/\|\s*(?:ba|z)?sh\b/.test(cmd)) return true;
  const inlineEval = /\b(?:node|bun|deno)\s+(?:-e|--eval|-p|--print|eval)\b/.test(cmd);
  return inlineEval && /https?|fetch|\bnet\b|child_process|exec/.test(cmd);
}

/** Paths an install-script command runs: `node setup`, `sh ./install.sh`, `bun x.ts`. */
export function scriptTargets(cmd: string): string[] {
  const out: string[] = [];
  const re = /(?:^|[;&|]\s*|\s)(?:node|bun|deno run|sh|bash|zsh|tsx|ts-node)\s+(?:-[\w-]+\s+)*((?:\.{0,2}\/)?[\w@./-]+)/g;
  for (const m of cmd.matchAll(re)) if (m[1] && !m[1].startsWith("-")) out.push(m[1]);
  return out;
}

function stringsIn(v: unknown, out: string[]): void {
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) for (const x of v) stringsIn(x, out);
  else if (isRecord(v)) for (const x of Object.values(v)) stringsIn(x, out);
}

function declaredEntries(manifest: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const k of ["main", "module", "browser", "bin", "exports"] as const) stringsIn(manifest[k], out);
  return out.filter((p) => p.startsWith(".") || /^[\w@]/.test(p));
}

function relativeImports(text: string): string[] {
  const out: string[] = [];
  const re = /(?:require\s*\(|import\s*\(|from\s+|import\s+)\s*['"`](\.{1,2}\/[^'"`]+)['"`]/g;
  for (const m of text.matchAll(re)) if (m[1]) out.push(m[1]);
  return out.slice(0, 200);
}

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

function resolveIn(byPath: Map<string, TarEntry>, raw: string): TarEntry | undefined {
  const p = joinPath("", raw);
  for (const c of [p, `${p}.js`, `${p}.cjs`, `${p}.mjs`, `${p}.ts`, `${p}/index.js`, `${p}/index.cjs`, `${p}/index.mjs`]) {
    const f = byPath.get(c);
    if (f) return f;
  }
  return undefined;
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
};

export function dependencyNames(manifest: Record<string, unknown>): string[] {
  const out = new Set<string>();
  for (const k of ["dependencies", "optionalDependencies"] as const) {
    const d = manifest[k];
    if (isRecord(d)) for (const n of Object.keys(d)) out.add(n);
  }
  return [...out];
}

/** Static analysis of one version. Run once at publish; stored with the version. */
export function analyze(input: AnalyzeInput): Analysis {
  const { manifest, files } = input;
  const found = new Map<SignalId, string[]>();
  const add = (id: SignalId, ev: string): void => {
    const list = found.get(id) ?? [];
    if (!list.includes(ev)) list.push(ev);
    found.set(id, list);
  };

  const scripts = installScriptsOf(manifest);
  for (const [k, cmd] of Object.entries(scripts)) {
    add("install-script", `package.json scripts.${k}: ${cmd.slice(0, 80)}`);
    if (isInlineDownload(cmd)) add("install-download", `package.json scripts.${k}: ${cmd.slice(0, 80)}`);
    for (const rule of RULES) {
      if (rule.re.test(cmd)) add(rule.id, `package.json scripts.${k}: ${cmd.slice(0, 80)}`);
    }
  }
  if (files.some((f) => f.path === "binding.gyp")) add("install-script", "binding.gyp: node-gyp build runs at install");

  // Files that run: every file with a code extension, plus whatever install scripts, main, bin and
  // exports point at, plus anything those reach through a relative require/import, whatever its name.
  const byPath = new Map(files.map((f) => [f.path, f]));
  const queue: string[] = files.filter((f) => CODE_EXT.test(f.path)).map((f) => f.path);
  for (const cmd of Object.values(scripts)) for (const p of scriptTargets(cmd)) queue.push(p);
  for (const p of declaredEntries(manifest)) queue.push(p);
  const seen = new Set<string>();
  while (queue.length > 0 && seen.size < 2000) {
    const want = queue.shift() ?? "";
    const f = resolveIn(byPath, want);
    if (!f || seen.has(f.path)) continue;
    seen.add(f.path);
    if (isBinary(f)) {
      add("binary", f.path);
      continue;
    }
    if (f.data.length > 5_000_000 || !isText(f.data)) continue;
    const text = new TextDecoder().decode(f.data);
    for (const rule of RULES) {
      const m = rule.re.exec(text);
      if (m) {
        const { line, snippet } = lineOf(text, m.index);
        add(rule.id, `${f.path}:${line}: ${snippet}`);
      }
    }
    for (const spec of relativeImports(text)) queue.push(joinPath(dirOf(f.path), spec));
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

  const order: SignalId[] = ["credential-access", "install-download", "shell-exec", "install-script", "risky-dependency", "network", "eval", "obfuscated", "typosquat", "new-publisher", "new-dependency", "binary", "no-license"];
  const signals = order.flatMap((id) => {
    const ev = found.get(id);
    return ev ? [signal(id, ev)] : [];
  });
  return { scorer: "apm-score-v1", signals, facts, notChecked: [...NOT_CHECKED] };
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
  return { ...analysis, notChecked: analysis.notChecked ?? [...NOT_CHECKED], signals, score, grade: gradeOf(score) };
}

export function isAnalysis(v: unknown): v is Analysis {
  return isRecord(v) && v.scorer === "apm-score-v1" && Array.isArray(v.signals) && isRecord(v.facts);
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
