// What kind of file each tarball entry is, and the order the review reads them in.
//
// The eval (research/ai-review-eval.md) found that four of five benign false alarms came from the model
// not seeing a file it worried about, so the order puts what runs first: install-script targets, then
// Node entry points, then files where apm's rule-based signals fired, then whatever those entries reach
// through relative imports, then browser entries, then the rest of the code by depth and size.
import { analyze, scriptTargets, type TarEntry, findingsOf } from "@apm/core";
import { installScripts, type Manifest } from "./manifest.ts";

const CODE = /\.(?:[cm]?jsx?|[cm]?tsx?|sh|bash|zsh|ps1|psm1|bat|cmd|py|vbs|php|rb|pl|vue|svelte|coffee)$/;
const DOC = /\.(?:d\.[cm]?ts|map|md|markdown|txt|css|scss|less|svg|html?)$|(?:^|\/)(?:LICENSE|LICENCE|COPYING|CHANGELOG|HISTORY|AUTHORS|NOTICE)[^/]*$/i;
const DATA = /\.(?:json|ya?ml|toml|ini|cfg|conf|env|gyp|gypi)$|(?:^|\/)(?:\.npmrc|\.env[^/]*|Dockerfile|Makefile)$/;
const BINARY_EXT = /\.(?:node|exe|dll|so|dylib|wasm|bin|dat|zip|gz|tgz|tar|7z|jar|png|jpe?g|gif|ico|webp|woff2?|ttf|otf|eot|pdf|mp[34]|wav)$/i;

/** Files larger than this are not decoded at all; they are listed as not read. */
export const MAX_DECODED_BYTES = 16 * 1024 * 1024;

export type FileKind = "code" | "data" | "doc" | "binary" | "other";

function hasNul(data: Uint8Array): boolean {
  const n = Math.min(data.length, 8192);

  for (let i = 0; i < n; i++) if (data[i] === 0) return true;

  return false;
}

export function kindOf(f: TarEntry): FileKind {
  if (BINARY_EXT.test(f.path) || hasNul(f.data)) return "binary";

  if (DOC.test(f.path)) return "doc";

  if (CODE.test(f.path)) return "code";

  if (DATA.test(f.path) || !f.path.slice(f.path.lastIndexOf("/") + 1).includes(".")) return "data";

  return "other";
}

/** Code and data are what the model reads; docs, type declarations, maps and binaries are not shown. */
export function isReviewable(f: TarEntry): boolean {
  const k = kindOf(f);

  return k === "code" || k === "data";
}

export function textOf(f: TarEntry): string {
  return new TextDecoder().decode(f.data);
}

export function linesOf(text: string): string[] {
  return text.replace(/\r\n?/g, "\n").split("\n");
}

function stripDot(p: string): string {
  return p.replace(/^\.\//, "").replace(/^\//, "");
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

const RESOLVE_SUFFIXES = ["", ".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".json", "/index.js", "/index.cjs", "/index.mjs", "/index.ts"];

/** Node's extension and index lookup over the tarball's own files. */
export function resolveIn(byPath: ReadonlyMap<string, TarEntry>, raw: string): TarEntry | undefined {
  const p = joinPath("", raw);

  for (const s of RESOLVE_SUFFIXES) {
    const f = byPath.get(p + s);

    if (f) return f;
  }

  return undefined;
}

const RELATIVE_IMPORT = /(?:require\s*\(|import\s*\(|from\s+|import\s+)\s*['"`](\.{1,2}\/[^'"`\n]+)['"`]/g;

/** Relative specifiers a file imports or requires, first 200 only. */
export function relativeImports(text: string): string[] {
  const out: string[] = [];

  for (const m of text.matchAll(RELATIVE_IMPORT)) if (m[1]) out.push(m[1]);

  return out.slice(0, 200);
}

/** Breadth-first distance from the roots through relative imports. Roots are at distance 0. */
export function importDistances(files: readonly TarEntry[], roots: readonly string[]): Map<string, number> {
  const byPath = new Map(files.map((f) => [f.path, f]));
  const dist = new Map<string, number>();
  const queue: { path: string; d: number }[] = [];

  for (const r of roots) {
    const f = resolveIn(byPath, r);

    if (f && !dist.has(f.path)) {
      dist.set(f.path, 0);
      queue.push({ path: f.path, d: 0 });
    }
  }

  for (let qi = 0; qi < queue.length && qi < 5000; qi++) {
    const cur = queue[qi];
    const f = cur ? byPath.get(cur.path) : undefined;

    if (!cur || !f || kindOf(f) !== "code" || f.data.length > MAX_DECODED_BYTES) continue;

    for (const spec of relativeImports(textOf(f))) {
      const next = resolveIn(byPath, joinPath(dirOf(f.path), spec));

      if (next && !dist.has(next.path)) {
        dist.set(next.path, cur.d + 1);
        queue.push({ path: next.path, d: cur.d + 1 });
      }
    }
  }

  return dist;
}

/** Paths where apm's rule-based score found a risky pattern (network, shell, eval, credentials, obfuscation). */
export function ruleSignalFiles(manifest: Manifest, files: readonly TarEntry[]): Set<string> {
  const analysis = analyze({ name: manifest.name, manifest: { name: manifest.name, scripts: Object.fromEntries(manifest.scripts) }, files, publisher: "", previousPublishers: [] });
  const paths = new Set(files.map((f) => f.path));
  const out = new Set<string>();

  // every finding, scored or a capability (apm-score-v10 scores network, shell and eval at 0 but still cites them)
  for (const s of findingsOf(analysis)) {
    if (!["credential-access", "shell-exec", "network", "eval", "obfuscated"].includes(s.id)) continue;

    for (const ev of s.evidence) {
      const m = /^(.+?):\d+: /.exec(ev);
      const p = m?.[1] ?? ev;

      if (paths.has(p)) out.add(p);
    }
  }

  return out;
}

export type Tier = { tier: number; sub: number };

/** Ranks files for reading; lower is earlier. */
export function readingOrder(manifest: Manifest, files: readonly TarEntry[]): (f: TarEntry) => Tier {
  const byPath = new Map(files.map((f) => [f.path, f]));
  const resolved = (raw: string): string | undefined => resolveIn(byPath, stripDot(raw))?.path;
  const targets = new Set(installScripts(manifest).flatMap((s) => scriptTargets(s.command).map(resolved)));
  const nodeEntries = new Set([...manifest.main, ...manifest.bin, ...manifest.module, ...manifest.exports].map(resolved));

  // npm's default entry when `main` is absent
  if (manifest.main.length === 0) nodeEntries.add(resolved("index.js"));
  const browser = new Set(manifest.browser.map(resolved));
  const signals = ruleSignalFiles(manifest, files);
  const reach = importDistances(files, [...targets, ...nodeEntries].filter((p): p is string => p !== undefined));

  return (f) => {
    const p = f.path;

    if (targets.has(p)) return { tier: 0, sub: 0 };

    if (nodeEntries.has(p)) return { tier: 1, sub: 0 };

    if (signals.has(p)) return { tier: 2, sub: 0 };
    const d = reach.get(p);

    if (d !== undefined) return { tier: 3, sub: d };

    if (browser.has(p)) return { tier: 4, sub: 0 };

    if (kindOf(f) === "code") return { tier: 5, sub: p.split("/").length };

    return { tier: 6, sub: p.split("/").length };
  };
}

/** Reviewable files (code and data, not package.json) in reading order; ties break on `prefer`, then size. */
export function ordered(manifest: Manifest, all: readonly TarEntry[], pick: readonly TarEntry[], prefer: (f: TarEntry) => boolean = () => false): TarEntry[] {
  const rank = readingOrder(manifest, all);
  const keyed = pick.flatMap((f) => (f.path !== "package.json" && isReviewable(f) ? [{ f, r: rank(f), p: prefer(f) ? 0 : 1 }] : []));

  keyed.sort((a, b) => a.r.tier - b.r.tier || a.r.sub - b.r.sub || a.p - b.p || a.f.size - b.f.size || (a.f.path < b.f.path ? -1 : 1));

  return keyed.map((k) => k.f);
}
