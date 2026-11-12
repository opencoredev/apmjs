// Downloads malicious npm samples from DataDog's malicious-software-packages-dataset into the cache.
// Samples are encrypted zips (password "infected", documented in the dataset README). They are only
// unzipped and read as bytes: never installed, required, imported or executed.
//
// Usage: bun tools/ai-review/fetch-malicious.ts candidates   # list and download a candidate pool
//        bun tools/ai-review/fetch-malicious.ts select       # classify candidates, write the index
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { typoConflicts } from "../../packages/core/src/names.ts";
import { CACHE_DIR, mapLimit, rng, shuffle } from "./util.ts";
import { installScriptsOf } from "../../packages/core/src/score.ts";
import { loadDir, type SampleFiles } from "./samples.ts";

const REPO = "DataDog/malicious-software-packages-dataset";
const RAW = `https://raw.githubusercontent.com/${REPO}/main/samples/npm`;
const MAL_DIR = join(CACHE_DIR, "malicious");
const NPM_DIR = join(CACHE_DIR, "npm");

/** Compromised releases of popular packages, with the last clean version before each. */
export const COMPROMISED: readonly { name: string; version: string; previous: string; note: string }[] = [
  { name: "debug", version: "4.4.2", previous: "4.4.1", note: "Sept 2025 maintainer phish: browser wallet hijacker" },
  { name: "@ctrl/tinycolor", version: "4.1.1", previous: "4.1.0", note: "Shai-Hulud worm: postinstall secret stealer and self-propagation" },
  { name: "@solana/web3.js", version: "1.95.7", previous: "1.95.5", note: "Dec 2024: private key exfiltration" },
  { name: "eslint-config-prettier", version: "10.1.7", previous: "10.1.5", note: "July 2025 phish: install script drops a Windows DLL" },
  { name: "@rspack/core", version: "1.1.7", previous: "1.1.6", note: "Dec 2024: postinstall cryptominer" },
  { name: "is", version: "5.0.0", previous: "3.3.0", note: "July 2025 phish: loader backdoor" },
];

function sh(cmd: string[], cwd?: string): string {
  const p = Bun.spawnSync(cmd, { cwd: cwd ?? CACHE_DIR, stdout: "pipe", stderr: "pipe" });
  if (p.exitCode !== 0) throw new Error(`${cmd.slice(0, 3).join(" ")} failed: ${p.stderr.toString().slice(0, 300)}`);
  return p.stdout.toString();
}

/** Dataset directory names encode "@scope/name" as "@scope@name". */
function dirToName(dir: string): string {
  return dir.startsWith("@") ? dir.replace(/^(@[^@]+)@/, "$1/") : dir;
}

function treeEntries(category: string): { dir: string; sha: string }[] {
  const file = join(CACHE_DIR, `${category}.tsv`);
  return readFileSync(file, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => {
      const [dir = "", sha = ""] = l.split("\t");
      return { dir, sha };
    });
}

function zipsIn(sha: string): string[] {
  const out = sh(["gh", "api", `repos/${REPO}/git/trees/${sha}?recursive=1`, "--jq", '.tree[]|select(.type=="blob")|.path']);
  return out.split("\n").filter((p) => p.endsWith(".zip"));
}

async function download(url: string, dest: string): Promise<void> {
  if (existsSync(dest)) return;
  const res = await fetch(url, { signal: AbortSignal.timeout(120_000) });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  writeFileSync(dest, new Uint8Array(await res.arrayBuffer()));
}

/** Unzips into a fresh directory; unzip strips absolute paths and "../" components. */
function unzipTo(zip: string, dir: string): void {
  if (existsSync(join(dir, ".done"))) return;
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  sh(["unzip", "-o", "-q", "-P", "infected", zip, "-d", dir]);
  writeFileSync(join(dir, ".done"), "");
}

export async function fetchNpmTarball(name: string, version: string): Promise<string> {
  mkdirSync(NPM_DIR, { recursive: true });
  const dest = join(NPM_DIR, `${name.replace("/", "__")}-${version}.tgz`);
  if (existsSync(dest)) return dest;
  const base = name.includes("/") ? name.split("/")[1] : name;
  await download(`https://registry.npmjs.org/${name}/-/${base}-${version}.tgz`, dest);
  return dest;
}

type Candidate = { id: string; name: string; version: string; discovered: string; dataset: "compromised_lib" | "malicious_intent"; root: string };

async function fetchZip(dataset: Candidate["dataset"], dir: string, zipPath: string): Promise<Candidate | null> {
  const m = /^([^/]+)\/(\d{4}-\d{2}-\d{2})-.*\.zip$/.exec(zipPath);
  if (!m?.[1] || !m[2]) return null;
  const version = m[1];
  const id = `${dir}@${version}`;
  const zipDest = join(MAL_DIR, "zips", `${id}.zip`);
  mkdirSync(join(MAL_DIR, "zips"), { recursive: true });
  await download(`${RAW}/${dataset}/${encodeURIComponent(dir)}/${zipPath.split("/").map(encodeURIComponent).join("/")}`, zipDest);
  const root = join(MAL_DIR, "x", id);
  unzipTo(zipDest, root);
  return { id, name: dirToName(dir), version, discovered: m[2], dataset, root };
}

async function candidates(): Promise<void> {
  mkdirSync(MAL_DIR, { recursive: true });
  const out: Candidate[] = [];
  // Compromised popular packages: the exact versions listed above.
  const comp = treeEntries("compromised_lib");
  for (const c of COMPROMISED) {
    const dir = c.name.replace("/", "@");
    const e = comp.find((x) => x.dir === dir);
    if (!e) {
      process.stdout.write(`missing compromised ${c.name}\n`);
      continue;
    }
    const zip = zipsIn(e.sha).find((p) => p.startsWith(`${c.version}/`));
    if (!zip) {
      process.stdout.write(`no zip for ${c.name}@${c.version}\n`);
      continue;
    }
    const cand = await fetchZip("compromised_lib", dir, zip);
    if (cand) out.push(cand);
    await fetchNpmTarball(c.name, c.previous);
  }
  // Malicious-intent: every name one typo from a popular package, plus a seeded random pool.
  const intent = treeEntries("malicious_intent");
  const typos = intent.filter((e) => typoConflicts(dirToName(e.dir)).length > 0);
  const pool = [...shuffle(typos, rng(7)).slice(0, 30), ...shuffle(intent, rng(20261112)).slice(0, 140)];
  const seen = new Set<string>();
  const picked = await mapLimit(pool, 4, async (e) => {
    if (seen.has(e.dir)) return null;
    seen.add(e.dir);
    try {
      const zips = zipsIn(e.sha).sort((a, b) => (a.slice(a.indexOf("/")) < b.slice(b.indexOf("/")) ? 1 : -1));
      const latest = zips[0];
      if (!latest) return null;
      return await fetchZip("malicious_intent", e.dir, latest);
    } catch (err) {
      process.stdout.write(`skip ${e.dir}: ${String(err).slice(0, 120)}\n`);
      return null;
    }
  });
  for (const p of picked) if (p) out.push(p);
  writeFileSync(join(MAL_DIR, "candidates.json"), JSON.stringify(out, null, 2));
  process.stdout.write(`${out.length} candidates\n`);
}

export type Traits = { installScript: boolean; obfuscated: boolean; typosquat: boolean; stealer: boolean; dropper: boolean; publishSpam: boolean; codeBytes: number };

export function traitsOf(name: string, s: SampleFiles): Traits {
  const text = s.files
    .filter((f) => /\.(?:[cm]?js|ts|sh|json)$/.test(f.path) && f.size < 3_000_000)
    .map((f) => new TextDecoder().decode(f.data))
    .join("\n");
  return {
    installScript: Object.keys(installScriptsOf(s.manifest)).length > 0,
    obfuscated: /_0x[0-9a-f]{4,}|(?:\\x[0-9a-f]{2}){20}|[A-Za-z0-9+/]{600,}={0,2}|eval\(\s*(?:atob|Buffer\.from)/.test(text),
    typosquat: typoConflicts(name).length > 0,
    stealer: /\.npmrc|\.ssh|id_rsa|process\.env|os\.hostname|userInfo\(|Login Data|wallet|discord/i.test(text) && /https?:\/\/|dns\.|\.request\(|fetch\(/.test(text),
    dropper: /(?:curl|wget|Invoke-WebRequest|powershell|child_process|execSync|spawn)\b/.test(text) && /https?:\/\//.test(text),
    publishSpam: /npm publish/.test(text) && /publishCount|tea\.yaml/.test(text),
    codeBytes: s.files.filter((f) => /\.(?:[cm]?js|ts|sh)$/.test(f.path)).reduce((n, f) => n + f.size, 0),
  };
}

function select(): void {
  const cands: Candidate[] = JSON.parse(readFileSync(join(MAL_DIR, "candidates.json"), "utf8"));
  const rows = cands.flatMap((c) => {
    const s = loadDir(c.root);
    if (!s) return [];
    return [{ c, t: traitsOf(c.name, s), files: s.files.length }];
  });
  const compromised = rows.filter((r) => r.c.dataset === "compromised_lib");
  // Drop near-empty samples (no code and no install script leaves the reviewer nothing to judge) and
  // tea.xyz-style publish-spam bots, which flood the registry but do not attack the installer.
  const intent = rows.filter((r) => r.c.dataset === "malicious_intent" && (r.t.codeBytes > 0 || r.t.installScript) && !r.t.publishSpam);
  const take = new Map<string, (typeof rows)[number]>();
  const want = (pred: (r: (typeof rows)[number]) => boolean, n: number): void => {
    for (const r of intent) {
      if (n <= 0) break;
      if (!take.has(r.c.id) && pred(r)) {
        take.set(r.c.id, r);
        n--;
      }
    }
  };
  want((r) => r.t.typosquat, 7);
  want((r) => r.t.obfuscated, 8);
  want((r) => r.t.installScript && r.t.stealer, 10);
  want((r) => r.t.dropper, 5);
  want(() => true, 34 - take.size);
  const chosen = [...compromised, ...take.values()];
  const index = chosen.map((r) => ({
    id: r.c.id,
    name: r.c.name,
    version: r.c.version,
    discovered: r.c.discovered,
    dataset: r.c.dataset,
    root: r.c.root,
    previous: COMPROMISED.find((x) => x.name === r.c.name)?.previous ?? null,
    traits: r.t,
  }));
  writeFileSync(join(MAL_DIR, "index.json"), JSON.stringify(index, null, 2));
  const count = (k: keyof Omit<Traits, "codeBytes" | "publishSpam">): number => index.filter((x) => x.traits[k]).length;
  process.stdout.write(
    `selected ${index.length} (compromised ${compromised.length}); install-script ${count("installScript")}, obfuscated ${count("obfuscated")}, typosquat ${count("typosquat")}, stealer ${count("stealer")}, dropper ${count("dropper")}\n`,
  );
  for (const x of index) process.stdout.write(`${x.dataset.slice(0, 4)} ${x.discovered} ${x.name}@${x.version} ${Object.entries(x.traits).filter(([, v]) => v === true).map(([k]) => k).join(",")}\n`);
}

const mode = process.argv[2];
if (mode === "candidates") await candidates();
else if (mode === "select") select();
else if (mode === "list") process.stdout.write(readdirSync(MAL_DIR).join("\n"));
