// Builds the text a reviewer model sees for one version: the diff from the previous version when there
// is one, otherwise the files, with new-file line numbers so findings can cite `file:line`, capped to a
// token budget. Files are ordered so what runs at install and import time comes first.
import type { TarEntry } from "../../packages/core/src/tarball.ts";
import { installScriptsOf, scriptTargets } from "../../packages/core/src/score.ts";
import type { SampleFiles } from "./samples.ts";

/** Content budget in estimated tokens (the system prompt and header add about 1k on top). */
export const DEFAULT_BUDGET_TOKENS = 16_000;
/** Conservative chars-per-token for code; minified code tokenizes worse than prose. */
export const CHARS_PER_TOKEN = 3.2;
const MAX_LINE_CHARS = 2_000;
const MAX_FILE_SHARE = 0.5;
/** Changed files get a smaller share so a big rebuilt bundle cannot crowd out the others. */
const DIFF_FILE_SHARE = 0.3;
const CONTEXT = 3;

const CODE = /\.(?:[cm]?jsx?|tsx?|sh|bash|ps1|psm1|bat|cmd|py|vbs|php|rb|pl)$/;
const SKIP_TEXT = /\.(?:d\.[cm]?ts|map|md|markdown|txt|LICENSE|license|css|scss|svg|html?)$|(?:^|\/)(?:LICENSE|LICENCE|CHANGELOG|AUTHORS)[^/]*$/;
const TEXT_DATA = /\.(?:json|ya?ml|toml|ini|cfg|conf|env|gyp|gypi)$|(?:^|\/)(?:\.npmrc|\.env[^/]*|Dockerfile|Makefile)$/;

export type ReviewInput = {
  mode: "diff" | "files";
  text: string;
  estTokens: number;
  /** Paths whose content (or part of it) was shown. */
  shown: string[];
  /** Paths that would have been shown but did not fit. */
  omitted: string[];
  truncated: boolean;
};

function isText(data: Uint8Array): boolean {
  const n = Math.min(data.length, 8192);
  for (let i = 0; i < n; i++) if (data[i] === 0) return false;
  return true;
}

export function textOf(e: TarEntry): string {
  return new TextDecoder().decode(e.data);
}

export function linesOf(text: string): string[] {
  return text.replace(/\r\n?/g, "\n").split("\n");
}

function clip(line: string): string {
  return line.length > MAX_LINE_CHARS ? `${line.slice(0, MAX_LINE_CHARS)} …[line cut, ${line.length - MAX_LINE_CHARS} more chars]` : line;
}

function numbered(lines: readonly string[], from: number, to: number): string {
  const out: string[] = [];
  for (let i = from; i < to; i++) out.push(`${String(i + 1).padStart(5)}  ${clip(lines[i] ?? "")}`);
  return out.join("\n");
}

/** Install script targets, then declared entry points, then the rest of the code by depth and size. */
function priority(manifest: Record<string, unknown>, files: readonly TarEntry[]): TarEntry[] {
  const targets = new Set<string>();
  for (const cmd of Object.values(installScriptsOf(manifest))) for (const t of scriptTargets(cmd)) targets.add(t.replace(/^\.\//, ""));
  const entries = new Set<string>();
  const addEntry = (v: unknown): void => {
    if (typeof v === "string") entries.add(v.replace(/^\.\//, ""));
    else if (Array.isArray(v)) v.forEach(addEntry);
    else if (typeof v === "object" && v !== null) Object.values(v).forEach(addEntry);
  };
  // Node entry points before browser ones: server installs are where tokens and keys live.
  for (const k of ["main", "bin", "module", "exports"]) addEntry(manifest[k]);
  const browser = new Set<string>();
  const addBrowser = (v: unknown): void => {
    if (typeof v === "string") browser.add(v.replace(/^\.\//, ""));
    else if (typeof v === "object" && v !== null) Object.values(v).forEach(addBrowser);
  };
  addBrowser(manifest.browser);
  const rank = (f: TarEntry): number => {
    const p = f.path;
    const bare = p.replace(/\.[cm]?js$/, "");
    if (targets.has(p) || targets.has(bare)) return 0;
    if (entries.has(p) || entries.has(bare) || entries.has(`${bare}.js`)) return 1;
    if (browser.has(p) || browser.has(bare)) return 2;
    if (CODE.test(p) && !p.includes("/")) return 2.5;
    if (CODE.test(p)) return 3 + p.split("/").length;
    return 20;
  };
  return files
    .filter((f) => f.path !== "package.json" && isText(f.data) && !SKIP_TEXT.test(f.path) && (CODE.test(f.path) || TEXT_DATA.test(f.path) || !f.path.includes(".")))
    .sort((a, b) => rank(a) - rank(b) || a.size - b.size);
}

export type Hunk = { newStart: number; lines: { kind: " " | "+" | "-"; text: string; newLine: number | null }[] };

/** Edit script between two id arrays (Myers O(ND)); null when more than `maxD` edits are needed. */
function myers(a: Int32Array, b: Int32Array, maxD: number): ("=" | "+" | "-")[] | null {
  const n = a.length;
  const m = b.length;
  const off = maxD + 1;
  const v = new Int32Array(2 * maxD + 3);
  const trace: Int32Array[] = [];
  let found = -1;
  for (let d = 0; d <= maxD; d++) {
    trace.push(v.slice());
    for (let k = -d; k <= d; k += 2) {
      let x = k === -d || (k !== d && (v[off + k - 1] ?? 0) < (v[off + k + 1] ?? 0)) ? (v[off + k + 1] ?? 0) : (v[off + k - 1] ?? 0) + 1;
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) {
        x++;
        y++;
      }
      v[off + k] = x;
      if (x >= n && y >= m) {
        found = d;
        break;
      }
    }
    if (found >= 0) break;
  }
  if (found < 0) return null;
  const ops: ("=" | "+" | "-")[] = [];
  let x = n;
  let y = m;
  for (let d = found; d > 0; d--) {
    const vd = trace[d] ?? v;
    const k = x - y;
    const prevK = k === -d || (k !== d && (vd[off + k - 1] ?? 0) < (vd[off + k + 1] ?? 0)) ? k + 1 : k - 1;
    const prevX = vd[off + prevK] ?? 0;
    const prevY = prevX - prevK;
    while (x > prevX && y > prevY) {
      ops.push("=");
      x--;
      y--;
    }
    ops.push(x === prevX ? "+" : "-");
    x = prevX;
    y = prevY;
  }
  while (x > 0 && y > 0) {
    ops.push("=");
    x--;
    y--;
  }
  return ops.reverse();
}

/** Line diff with CONTEXT lines around each change. New-file line numbers are 1-based. */
export function diffLines(a: readonly string[], b: readonly string[]): Hunk[] {
  let pre = 0;
  while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++;
  let suf = 0;
  while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;
  const am = a.slice(pre, a.length - suf);
  const bm = b.slice(pre, b.length - suf);
  type Op = { kind: " " | "+" | "-"; text: string; newLine: number | null };
  const ops: Op[] = [];
  for (let i = 0; i < pre; i++) ops.push({ kind: " ", text: a[i] ?? "", newLine: i + 1 });
  const ids = new Map<string, number>();
  const idOf = (t: string): number => {
    let id = ids.get(t);
    if (id === undefined) {
      id = ids.size;
      ids.set(t, id);
    }
    return id;
  };
  const script = myers(Int32Array.from(am, idOf), Int32Array.from(bm, idOf), 3000);
  if (script) {
    let i = 0;
    let j = 0;
    for (const s of script) {
      if (s === "=") ops.push({ kind: " ", text: bm[j++] ?? "", newLine: pre + j });
      else if (s === "+") ops.push({ kind: "+", text: bm[j++] ?? "", newLine: pre + j });
      else ops.push({ kind: "-", text: am[i] ?? "", newLine: null });
      if (s !== "+") i++;
    }
  } else {
    // Too many edits to align: show it as a rewrite.
    for (const t of am) ops.push({ kind: "-", text: t, newLine: null });
    bm.forEach((t, j) => ops.push({ kind: "+", text: t, newLine: pre + j + 1 }));
  }
  for (let k = 0; k < suf; k++) ops.push({ kind: " ", text: b[b.length - suf + k] ?? "", newLine: b.length - suf + k + 1 });
  // Group changes with CONTEXT lines around them.
  const hunks: Hunk[] = [];
  let cur: Hunk | null = null;
  let lastChange = -Infinity;
  ops.forEach((op, idx) => {
    if (op.kind === " ") return;
    const from = Math.max(0, idx - CONTEXT);
    if (!cur || from > lastChange + CONTEXT + 1) {
      cur = { newStart: 0, lines: [] };
      hunks.push(cur);
      for (let k = from; k < idx; k++) {
        const o = ops[k];
        if (o) cur.lines.push(o);
      }
    } else {
      for (let k = lastChange + 1; k < idx; k++) {
        const o = ops[k];
        if (o) cur.lines.push(o);
      }
    }
    cur.lines.push(op);
    lastChange = idx;
  });
  // Trailing context for each hunk.
  for (const h of hunks) {
    const last = h.lines.at(-1);
    const lastIdx = last ? ops.lastIndexOf(last) : -1;
    for (let k = lastIdx + 1; k < Math.min(ops.length, lastIdx + 1 + CONTEXT); k++) {
      const o = ops[k];
      if (o && o.kind === " ") h.lines.push(o);
      else break;
    }
    h.newStart = h.lines.find((l) => l.newLine !== null)?.newLine ?? 0;
  }
  return hunks;
}

function renderHunks(hunks: readonly Hunk[]): string {
  return hunks
    .map((h) =>
      [`@@ new line ${h.newStart} @@`, ...h.lines.map((l) => `${l.newLine === null ? "     " : String(l.newLine).padStart(5)} ${l.kind} ${clip(l.text)}`)].join("\n"),
    )
    .join("\n");
}

class Budget {
  used = 0;
  readonly parts: string[] = [];
  readonly shown: string[] = [];
  readonly omitted: string[] = [];
  truncated = false;
  constructor(readonly maxChars: number) {}
  get left(): number {
    return this.maxChars - this.used;
  }
  /** Adds a block; if it does not fit, adds as many whole lines as fit and marks it cut. */
  add(path: string, header: string, body: string, maxShare = MAX_FILE_SHARE): void {
    const cap = Math.min(this.left, Math.floor(this.maxChars * maxShare));
    if (cap < 400) {
      this.omitted.push(path);
      this.truncated = true;
      return;
    }
    let shownBody = body;
    if (header.length + body.length + 2 > cap) {
      const lines = body.split("\n");
      const kept: string[] = [];
      let n = header.length + 80;
      for (const l of lines) {
        if (n + l.length + 1 > cap) break;
        kept.push(l);
        n += l.length + 1;
      }
      shownBody = `${kept.join("\n")}\n…[${lines.length - kept.length} more lines not shown: budget]`;
      this.truncated = true;
    }
    const block = `${header}\n${shownBody}\n`;
    this.parts.push(block);
    this.used += block.length;
    this.shown.push(path);
  }
}

function headerLines(name: string, version: string, previous: string | null, s: SampleFiles, extra: string[]): string {
  const scripts = installScriptsOf(s.manifest);
  return [
    `Package: ${name}@${version}${previous ? ` (previous version: ${previous})` : " (no previous version available: full review)"}`,
    `Files: ${s.files.length}, unpacked bytes: ${s.files.reduce((n, f) => n + f.size, 0)}`,
    `Install-time scripts: ${Object.keys(scripts).length ? Object.entries(scripts).map(([k, v]) => `${k}: ${v}`).join(" | ") : "none"}`,
    ...extra,
  ].join("\n");
}

export function buildFilesInput(name: string, version: string, s: SampleFiles, budgetTokens = DEFAULT_BUDGET_TOKENS): ReviewInput {
  const b = new Budget(Math.floor(budgetTokens * CHARS_PER_TOKEN));
  const all = s.files.map((f) => `${f.path} (${f.size} bytes)`);
  const listing = all.length > 200 ? [...all.slice(0, 200), `…and ${all.length - 200} more files`] : all;
  b.add("(file list)", "=== FILE LIST ===", listing.join("\n"), 0.1);
  const pj = s.files.find((f) => f.path === "package.json");
  if (pj) {
    const l = linesOf(textOf(pj));
    b.add("package.json", "=== FILE package.json ===", numbered(l, 0, l.length), 0.25);
  }
  for (const f of priority(s.manifest, s.files)) {
    if (b.left < 400) {
      b.omitted.push(f.path);
      b.truncated = true;
      continue;
    }
    const l = linesOf(textOf(f));
    b.add(f.path, `=== FILE ${f.path} ===`, numbered(l, 0, l.length));
  }
  const text = `${headerLines(name, version, null, s, b.omitted.length ? [`Not shown (budget): ${b.omitted.length} files`] : [])}\n\n${b.parts.join("\n")}`;
  return { mode: "files", text, estTokens: Math.ceil(text.length / CHARS_PER_TOKEN), shown: b.shown, omitted: b.omitted, truncated: b.truncated };
}

export function buildDiffInput(name: string, version: string, previous: string, s: SampleFiles, prev: SampleFiles, budgetTokens = DEFAULT_BUDGET_TOKENS): ReviewInput {
  const b = new Budget(Math.floor(budgetTokens * CHARS_PER_TOKEN));
  const before = new Map(prev.files.map((f) => [f.path, f]));
  const after = new Map(s.files.map((f) => [f.path, f]));
  const added = s.files.filter((f) => !before.has(f.path));
  const removed = prev.files.filter((f) => !after.has(f.path));
  const changed = s.files.filter((f) => {
    const o = before.get(f.path);
    return o !== undefined && (o.size !== f.size || Buffer.compare(Buffer.from(o.data), Buffer.from(f.data)) !== 0);
  });
  const summary = [
    `Added files (${added.length}): ${added.slice(0, 60).map((f) => `${f.path} (${f.size} bytes)`).join(", ")}${added.length > 60 ? " …" : ""}`,
    `Removed files (${removed.length}): ${removed.slice(0, 30).map((f) => f.path).join(", ")}${removed.length > 30 ? " …" : ""}`,
    `Changed files (${changed.length}): ${changed.slice(0, 60).map((f) => f.path).join(", ")}${changed.length > 60 ? " …" : ""}`,
  ];
  const pj = s.files.find((f) => f.path === "package.json");
  const pjOld = before.get("package.json");
  if (pj) {
    const l = linesOf(textOf(pj));
    b.add("package.json", "=== FILE package.json (full, new version) ===", numbered(l, 0, l.length), 0.25);
    if (pjOld) {
      const h = diffLines(linesOf(textOf(pjOld)), l);
      if (h.length) b.add("package.json", "=== DIFF package.json ===", renderHunks(h), 0.15);
    }
  }
  const ranked = priority(s.manifest, [...added, ...changed]);
  const isAdded = new Set(added.map((f) => f.path));
  // New files before changed ones, since a new file is the usual home of a payload.
  const addedFirst = [...ranked.filter((f) => isAdded.has(f.path)), ...ranked.filter((f) => !isAdded.has(f.path))];
  for (const f of addedFirst) {
    if (b.left < 400) {
      b.omitted.push(f.path);
      b.truncated = true;
      continue;
    }
    const l = linesOf(textOf(f));
    const old = before.get(f.path);
    if (!old) b.add(f.path, `=== NEW FILE ${f.path} ===`, numbered(l, 0, l.length));
    else {
      const h = diffLines(linesOf(textOf(old)), l);
      if (h.length) b.add(f.path, `=== DIFF ${f.path} ===`, renderHunks(h), DIFF_FILE_SHARE);
    }
  }
  const text = `${headerLines(name, version, previous, s, [...summary, ...(b.omitted.length ? [`Not shown (budget): ${b.omitted.length} files`] : [])])}\n\n${b.parts.join("\n")}`;
  return { mode: "diff", text, estTokens: Math.ceil(text.length / CHARS_PER_TOKEN), shown: b.shown, omitted: b.omitted, truncated: b.truncated };
}
