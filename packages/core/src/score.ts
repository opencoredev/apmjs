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

export type Analysis = { scorer: "apm-score-v1"; signals: Signal[]; facts: Facts };
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
  recent: -10,
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
    re: /\bfetch\s*\(|\bhttps?\.(?:get|request)\s*\(|require\(\s*['"](?:node:)?(?:https?|net|dgram|tls|http2)['"]\s*\)|from\s+['"](?:node:)?(?:https?|net|dgram|tls|http2)['"]|\bXMLHttpRequest\b|\bnew\s+WebSocket\b|\bcurl\s+|\bwget\s+|\bdns\.(?:resolve|lookup)\b/,
  },
  {
    id: "credential-access",
    re: /\.npmrc\b|['"/]\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws\/credentials|AWS_SECRET_ACCESS_KEY|\bGITHUB_TOKEN\b|\bNPM_TOKEN\b|\bNODE_AUTH_TOKEN\b|JSON\.stringify\(\s*process\.env\s*\)|\.git-credentials|\.docker\/config\.json|\bLogin Data\b|\.config\/gcloud/,
  },
  { id: "eval", re: /(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.(?:runIn\w*Context|Script)\b/ },
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

export type AnalyzeInput = {
  name: string;
  manifest: Record<string, unknown>;
  files: readonly TarEntry[];
  publisher: string;
  previousPublishers: readonly string[];
};

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
    for (const rule of RULES) {
      if (rule.re.test(cmd)) add(rule.id, `package.json scripts.${k}: ${cmd.slice(0, 80)}`);
    }
  }
  if (files.some((f) => f.path === "binding.gyp")) add("install-script", "binding.gyp: node-gyp build runs at install");

  for (const f of files) {
    if (isBinary(f)) {
      add("binary", f.path);
      continue;
    }
    if (!CODE_EXT.test(f.path) || f.data.length > 5_000_000) continue;
    const text = new TextDecoder().decode(f.data);
    for (const rule of RULES) {
      const m = rule.re.exec(text);
      if (m) {
        const { line, snippet } = lineOf(text, m.index);
        add(rule.id, `${f.path}:${line}: ${snippet}`);
      }
    }
  }

  const facts = factsOf(manifest, files);
  if (!facts.license) add("no-license", "package.json has no license field");
  const typos = typoConflicts(input.name);
  for (const t of typos) add("typosquat", t.reason);
  if (input.previousPublishers.length > 0 && !input.previousPublishers.includes(input.publisher)) {
    add("new-publisher", `${input.publisher} has not published this package before (previous: ${input.previousPublishers.join(", ")})`);
  }

  const order: SignalId[] = ["credential-access", "shell-exec", "install-script", "network", "eval", "obfuscated", "typosquat", "new-publisher", "binary", "no-license"];
  const signals = order.flatMap((id) => {
    const ev = found.get(id);
    return ev ? [signal(id, ev)] : [];
  });
  return { scorer: "apm-score-v1", signals, facts };
}

export function gradeOf(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

export type VersionState = { publishedAt: number; now: number; deprecated: string | null; status: "active" | "yanked" | "revoked"; statusReason: string | null };

/** Applies time- and state-based signals and computes the number. */
export function finalize(analysis: Analysis, state: VersionState): ScoreReport {
  const signals = [...analysis.signals];
  if (state.now - state.publishedAt < COOLDOWN_MS) {
    const hours = Math.max(0, Math.floor((state.now - state.publishedAt) / 3_600_000));
    signals.push(signal("recent", [`published ${hours}h ago`]));
  }
  if (state.deprecated) signals.push(signal("deprecated", [state.deprecated]));
  if (state.status === "yanked") signals.push(signal("yanked", [state.statusReason ?? "no reason given"]));
  if (state.status === "revoked") signals.push(signal("revoked", [state.statusReason ?? "no reason given"]));
  const raw = 100 + signals.reduce((n, s) => n + s.points, 0);
  const score = Math.max(0, Math.min(100, raw));
  return { ...analysis, signals, score, grade: gradeOf(score) };
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
