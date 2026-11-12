// Static reading of one file's text: the rules, a pass that joins strings split to dodge them, decoders
// for the cheap encodings (base64, hex, \x escapes, char codes) and the paths a file loads. Pure.
import { lex, type Lang, type Lexed, type Region } from "./lexer.ts";

export { commentRanges, langOf, type Lang } from "./lexer.ts";

export type CodeSignal = "shell-exec" | "network" | "credential-access" | "eval" | "obfuscated";

/**
 * `confirmed`: the code does it, or loads the module that does. `possible`: the text only names it, in an
 * ordinary string, an alias or a method apm cannot identify, so the capability is there but apm did not see it used.
 */
export type Confidence = "confirmed" | "possible";

type FindingAt = { id: CodeSignal; line: number; snippet: string; how: "as written" | "after joining strings" | "decoded" };

/** One rule match: the signal, where it is, whether the text had to be joined or decoded first, and how sure it is (with why, when only possible). */
export type TextFinding = FindingAt & ({ confidence: "confirmed" } | { confidence: "possible"; why: string });

function judged(at: FindingAt, confidence: Confidence, why: string): TextFinding {
  return confidence === "confirmed" ? { ...at, confidence } : { ...at, confidence, why };
}

const NET_MODULES = String.raw`(?:node:)?(?:https?|net|dgram|tls|http2|dns)(?:\/promises)?`;
const HTTP_CLIENTS = "(?:axios|undici|node-fetch|got|superagent|needle|phin|ky|ws)";
const GLOBAL = "(?:globalThis|global|window|self)";

// Function('return this')() is how old code finds the global object; anything else built into a Function is eval
const NOT_RETURN_THIS = String.raw`(?!['"\x60]return this['"\x60]\s*\))['"\x60]`;

const alt = (parts: string[]): RegExp => new RegExp(parts.join("|"), "g");

/**
 * How a pattern's match is read, by where it sits (see `Region` in lexer.ts):
 * - `code`: a call or construct. Confirmed in code or a kept string. Inside an ordinary string it is text that
 *   only runs if something evaluates it, and eval, Function, vm and string timers are rules of their own.
 * - `name`: a module name. Confirmed where it is loaded (`require('child_process')`); possible anywhere else.
 * - `text`: shell command text (`curl ... | sh`). Only strings hold it: confirmed when a call runs the string,
 *   possible otherwise. In code, `a || sh` is not a pipe.
 * - `alias`: a reference that gives the power without using it (`r = require`). Always possible.
 * Raw text (a shell script, an install command, a file the lexer could not follow) confirms every kind but `alias`.
 */
type Kind = "code" | "name" | "text" | "alias";

type Pattern = { kind: Kind; re: RegExp; why?: string };

const RULES: { id: Exclude<CodeSignal, "obfuscated">; patterns: Pattern[] }[] = [
  {
    id: "shell-exec",
    patterns: [
      {
        kind: "code",
        re: alt([
          String.raw`\bexec(?:File)?Sync\s*\(`,
          String.raw`\bspawnSync\s*\(`,
          String.raw`\bBun\.spawn(?:Sync)?\b`,
          String.raw`\bBun\.\$`,
          String.raw`\bDeno\.Command\b`,
          String.raw`\bprocess\s*\.\s*(?:binding|_linkedBinding|dlopen)\s*\(`,
          String.raw`\binternalBinding\s*\(`,
        ]),
      },
      { kind: "name", re: /\bchild_process\b/g, why: "names child_process without loading it" },
      { kind: "text", re: /\|\s*(?:ba|z)?sh\b|\bcurl\s+-?|\bwget\s+|\bpowershell\b/g, why: "a string holds a shell command, but apm did not see it run" },
    ],
  },
  {
    id: "network",
    patterns: [
      {
        kind: "code",
        re: alt([
          // fetch('data:...') reads an inline value and never leaves the machine
          String.raw`(?<![\w$.])fetch\s*\((?!\s*['"\x60]data:)`,
          String.raw`\b${GLOBAL}\s*\.\s*fetch\s*\((?!\s*['"\x60]data:)`,
          String.raw`\bhttps?\.(?:get|request)\s*\(`,
          String.raw`(?:require|import)\s*\(\s*['"\x60]${NET_MODULES}['"\x60]\s*\)`,
          String.raw`\bfrom\s+['"]${NET_MODULES}['"]`,
          String.raw`(?:require\s*\(\s*|from\s+|import\s*\(\s*)['"]${HTTP_CLIENTS}['"]`,
          String.raw`\bnew\s+(?:[\w$]+\s*\.\s*)*(?:XMLHttpRequest|WebSocket|EventSource|RTCPeerConnection)\b`,
          String.raw`\bsendBeacon\s*\(`,
          String.raw`\bdns(?:\.promises)?\.(?:resolve\w*|lookup\w*|reverse)\s*\(`,
          String.raw`\bimport\s*\(\s*['"\x60]https?:\/\/`,
        ]),
      },
      { kind: "alias", re: /\.\s*fetch\s*\(/g, why: "calls a method named fetch on an object apm cannot identify" },
      { kind: "alias", re: /\bXMLHttpRequest\b/g, why: "refers to XMLHttpRequest without creating one" },
      { kind: "text", re: /\bcurl\s+|\bwget\s+/g, why: "a string holds a download command, but apm did not see it run" },
    ],
  },
  {
    id: "credential-access",
    patterns: [
      { kind: "code", re: /\bAWS_SECRET_ACCESS_KEY\b|\bGITHUB_TOKEN\b|\bNPM_TOKEN\b|\bNODE_AUTH_TOKEN\b|JSON\.stringify\(\s*process\.env\s*\)/g },
      {
        kind: "text",
        re: /\.npmrc\b|['"/]\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws\/credentials|\.git-credentials|\.docker\/config\.json|\bLogin Data\b|\.config\/gcloud/g,
        why: "a string names a credential file, but apm did not see it read",
      },
    ],
  },
  {
    id: "eval",
    patterns: [
      {
        kind: "code",
        re: alt([
          String.raw`(?<![\w$.])eval\s*\(`,
          String.raw`\b${GLOBAL}\s*\.\s*eval\s*\(`,
          String.raw`\(\s*0\s*,\s*eval\s*\)`,
          String.raw`=\s*eval\s*[;,)\n]`,
          String.raw`\bnew\s+Function\s*\(`,
          String.raw`(?<![\w$.])Function\s*\(\s*${NOT_RETURN_THIS}`,
          String.raw`\.\s*Function\s*\(\s*${NOT_RETURN_THIS}`,
          String.raw`\.constructor\s*\.\s*constructor\s*\(`,
          String.raw`\bset(?:Timeout|Interval|Immediate)\s*\(\s*['"\x60]`,
          String.raw`\bvm\.(?:runIn\w*Context|Script|compileFunction|SourceTextModule)\b`,
          String.raw`\brunIn(?:This|New)Context\s*\(`,
          String.raw`(?:require|import)\s*\(\s*['"](?:node:)?vm['"]\s*\)|\bfrom\s+['"](?:node:)?vm['"]`,
          String.raw`\bmodule\s*\._compile\s*\(|\bModule\.prototype\._compile\b`,
          String.raw`\brequire\s*\(\s*String\.fromCharCode`,
        ]),
      },
      { kind: "alias", re: /=\s*require\s*[;,\n]/g, why: "keeps require under another name, so apm cannot read what it loads" },
      { kind: "alias", re: new RegExp(String.raw`\b${GLOBAL}\s*\.\s*require\b`, "g"), why: "reaches require through the global object" },
      { kind: "alias", re: new RegExp(String.raw`=\s*${GLOBAL}\s*\.\s*Function\s*[;,\n]`, "g"), why: "keeps a reference to Function without calling it" },
      { kind: "alias", re: /\.\s*eval\s*\(/g, why: "calls a method named eval on an object apm cannot identify" },
    ],
  },
];

/** Reading the whole environment: a credential grab when a network call sits right next to it. */
const WHOLE_ENV = /\bObject\.(?:keys|entries|values)\s*\(\s*process\.env\s*\)|\bfor\s*\(\s*(?:const|let|var)\s+[\w$]+\s+in\s+process\.env\b/g;

/** How close (in characters) an environment dump and a network call must be to read as one exfiltration. */
const NEAR = 400;

/** A string that, once built or decoded, names something dangerous. */
const NAMED: { id: Exclude<CodeSignal, "obfuscated">; re: RegExp }[] = [
  { id: "shell-exec", re: /^(?:(?:node:)?child_process|execSync|execFileSync|execFile|spawnSync|spawn|exec)$/ },
  { id: "network", re: new RegExp(`^(?:${NET_MODULES}|fetch|XMLHttpRequest|WebSocket|sendBeacon|EventSource|request)$`) },
  { id: "eval", re: /^(?:eval|Function|require|(?:node:)?vm|runInThisContext|runInNewContext)$/ },
  { id: "credential-access", re: /\.npmrc$|^(?:NPM_TOKEN|GITHUB_TOKEN|NODE_AUTH_TOKEN|AWS_SECRET_ACCESS_KEY)$|\.ssh\/|\bid_(?:rsa|ed25519|ecdsa)$/ },
];

/** obfuscator.io output: twenty or more `_0x1a2b` identifiers. Counted in one linear pass. Returns the first one's index, or -1. */
function hexIdentifierRun(text: string): number {
  const re = /_0x[0-9a-f]{4,}/g;
  let first = -1;
  let n = 0;

  for (let m = re.exec(text); m; m = re.exec(text)) {
    if (first < 0) first = m.index;

    if (++n >= 20) return first;
  }

  return -1;
}

/** A line number and the text around a position, trimmed to about 80 characters. */
export type Where = { line: number; snippet: string };

/** Where `index` is. On a long (minified) line the snippet is the stretch around `index`, so it shows what matched. */
export function lineOf(text: string, index: number): Where {
  let line = 1;

  for (let i = text.indexOf("\n"); i !== -1 && i < index; i = text.indexOf("\n", i + 1)) line++;
  const start = text.lastIndexOf("\n", index - 1) + 1;
  const end = text.indexOf("\n", index);
  const whole = text.slice(start, end === -1 ? undefined : end);

  if (whole.trim().length <= 80) return { line, snippet: whole.trim() };
  const col = index - start;
  const from = Math.max(0, col - 30);
  const to = from + 80;
  const snippet = `${from > 0 ? "…" : ""}${whole.slice(from, to).trim()}${to < whole.length ? "…" : ""}`;

  return { line, snippet };
}

// ---------- joining split strings ----------
const LIT = String.raw`(?:'[^'\\\n]*'|"[^"\\\n]*"|\x60[^\x60\\$\n]*\x60)`;
const CHAIN = new RegExp(`${LIT}(?:[ \\t]*\\+[ \\t\\n]*${LIT})+`, "g");
const ONE_LIT = new RegExp(LIT, "g");
const ESCAPED_LIT = /(['"])((?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|[\w./:@ -])*)\1/g;

function unescapeJs(s: string): string {
  return s.replace(/\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})/g, (_, x: string | undefined, u: string | undefined) => String.fromCharCode(Number.parseInt(x ?? u ?? "0", 16)));
}

function quote(s: string): string {
  return `'${s.replace(/['\\\n]/g, " ")}'`;
}

/**
 * Undoes the disguises that only move characters around: `'\x63hild'` becomes `'child'`, `'chi' + 'ld_'`
 * becomes `'child_'`, and `x['ex' + 'ec']` becomes `x.exec`. Nothing is run. Returns the new text and every
 * string it had to build (from escapes or from two or more pieces), which the caller checks by name.
 */
export type Joined = { text: string; built: string[] };

export function joinStrings(text: string): Joined {
  const built: string[] = [];
  let out = text;

  if (out.includes("\\x") || out.includes("\\u")) {
    out = out.replace(ESCAPED_LIT, (m, _q: string, body: string) => {
      if (!/\\[xu]/.test(body)) return m;
      const s = unescapeJs(body);
      built.push(s);

      return quote(s);
    });
  }

  if (out.includes("+")) {
    out = out.replace(CHAIN, (m) => {
      const s = [...m.matchAll(ONE_LIT)].map((p) => p[0].slice(1, -1)).join("");
      built.push(s);

      return quote(s);
    });
  }

  if (out.includes("[")) out = out.replace(/(?<=[\w$)\]])\s*\[\s*(['"])([A-Za-z_$][\w$]*)\1\s*\]/g, ".$2");

  return { text: out, built };
}

// ---------- decoding ----------
const MAX_DECODED_BYTES = 256 * 1024;

function printable(s: string): boolean {
  if (s.length < 4) return false;
  let ok = 0;

  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);

    if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) ok++;
  }

  return ok / s.length >= 0.95;
}

export type Decoded = { value: string; how: string; index: number };

/** Strings hidden by base64, hex or char codes, decoded when the result is readable text. Bounded per file. */
export function decodedStrings(text: string): Decoded[] {
  const out: Decoded[] = [];
  let budget = MAX_DECODED_BYTES;

  const push = (value: string, how: string, index: number): void => {
    if (budget <= 0 || !printable(value)) return;
    budget -= value.length;
    out.push({ value, how, index });
  };

  for (const m of text.matchAll(/(['"\x60])([A-Za-z0-9+/]{16,65536}={0,2})\1/g)) {
    const raw = m[2] ?? "";

    if (budget <= 0) break;

    // identifiers and alphabets are base64-shaped too; real payloads mix cases and digits
    if (raw.length % 4 === 1 || !/[0-9+/=]/.test(raw)) continue;
    push(Buffer.from(raw, "base64").toString("latin1"), "base64", m.index);
  }

  for (const m of text.matchAll(/(['"])((?:[0-9a-fA-F]{2}){4,32768})\1\s*,\s*['"]hex['"]/g)) push(Buffer.from(m[2] ?? "", "hex").toString("latin1"), "hex", m.index);

  if (text.includes("fromCharCode")) {
    for (const m of text.matchAll(/fromCharCode\s*\(\s*((?:\d{1,3}\s*,\s*){2,}\d{1,3})\s*\)|\[\s*((?:\d{2,3}\s*,\s*){3,}\d{2,3})\s*\]/g)) {
      const codes = (m[1] ?? m[2] ?? "").split(",").map((n) => Number(n.trim()));

      if (codes.every((c) => c >= 32 && c < 127)) push(String.fromCharCode(...codes), "char codes", m.index);
    }
  }

  return out;
}

/** The dangerous thing a built or decoded string names, if any: `'child_process'`, `'fetch'`. */
export function namedSignal(s: string): Exclude<CodeSignal, "obfuscated"> | null {
  const t = s.trim();

  return NAMED.find((n) => n.re.test(t))?.id ?? null;
}

// ---------- the scan ----------
type RegionOf = (index: number) => Region;

const RAW: RegionOf = () => "raw";

/** What a match of each kind means in each region; a region a kind does not list is not a match. */
const CONFIDENCE: Record<Kind, Partial<Record<Region, Confidence>>> = {
  code: { code: "confirmed", kept: "confirmed", raw: "confirmed" },
  name: { kept: "confirmed", raw: "confirmed", code: "possible", string: "possible" },
  text: { kept: "confirmed", raw: "confirmed", string: "possible" },
  alias: { code: "possible", kept: "possible", raw: "possible" },
};

const IN_STRING = "only inside an ordinary string, not in code apm saw run";

/**
 * Whether the call-shaped match ending at the `(` at `open` defines a function rather than calling one:
 * `function fetch(url) {`, or a method `async fetch(url) {`. A call is never followed by `{` after its `)`.
 */
function isDefinition(text: string, start: number, open: number): boolean {
  if (/\bfunction\s*\*?\s*$/.test(text.slice(Math.max(0, start - 16), start))) return true;
  let depth = 0;

  for (let j = open; j < Math.min(text.length, open + 400); j++) {
    const c = text[j];

    if (c === "(") depth++;
    else if (c === ")" && --depth === 0) {
      let k = j + 1;

      while (k < text.length && /[ \t]/.test(text[k] ?? "")) k++;

      return text[k] === "{";
    }
  }

  return false;
}

/**
 * Whether a match is TypeScript's `import('undici').RequestInit`: a type, erased before anything runs. At runtime
 * `import()` returns a promise, which has no capitalised members, so a real import never looks like this.
 */
function isTypeImport(text: string, start: number, match: string): boolean {
  if (!/^import\s*\(/.test(match)) return false;
  const close = text.indexOf(")", start + match.length - 1);

  return close > 0 && close - start < 300 && /^\s*\.\s*[A-Z]/.test(text.slice(close + 1, close + 40));
}

/** The first confirmed match of each rule, or its first possible one. Every match is looked at; there is no budget to run out. */
function ruleHits(text: string, how: TextFinding["how"], skip: ReadonlySet<CodeSignal>, region: RegionOf): TextFinding[] {
  const out: TextFinding[] = [];

  for (const rule of RULES) {
    if (skip.has(rule.id)) continue;
    let confirmed: TextFinding | null = null;
    let possible: TextFinding | null = null;

    for (const p of rule.patterns) {
      if (confirmed) break;

      // an alias can only ever be possible
      if (possible && p.kind === "alias") continue;
      p.re.lastIndex = 0;

      for (let m = p.re.exec(text); m; m = p.re.exec(text)) {
        if (m[0].length === 0) {
          p.re.lastIndex++;
          continue;
        }

        const r = region(m.index);
        const confidence = CONFIDENCE[p.kind][r];

        if (!confidence || r === "excluded") continue;

        if (m[0].endsWith("(") && isDefinition(text, m.index, m.index + m[0].length - 1)) continue;

        if (isTypeImport(text, m.index, m[0])) continue;

        if (confidence === "confirmed") {
          confirmed = { id: rule.id, ...lineOf(text, m.index), how, confidence };
          break;
        }

        if (!possible) {
          const why = p.why ?? IN_STRING;
          possible = { id: rule.id, ...lineOf(text, m.index), how, confidence, why };
        }

        if (p.kind === "alias") break;
      }
    }

    const best = confirmed ?? possible;

    if (best) out.push(best);
  }

  return out;
}

const NETWORK_NEAR = RULES.filter((r) => r.id === "network").flatMap((r) => r.patterns.filter((p) => p.kind !== "alias").map((p) => new RegExp(p.re.source)));

/** An environment dump with a network call within NEAR characters of it. */
function envExfil(text: string, region: RegionOf): { index: number; confidence: Confidence } | null {
  let tries = 0;

  for (const m of text.matchAll(WHOLE_ENV)) {
    const r = region(m.index);

    if (r !== "excluded") {
      const window = text.slice(Math.max(0, m.index - NEAR), m.index + NEAR);

      if (NETWORK_NEAR.some((re) => re.test(window))) return { index: m.index, confidence: r === "string" ? "possible" : "confirmed" };
    }

    if (++tries >= 50) break;
  }

  return null;
}

/**
 * Text hidden in a literal: 40 or more `\x` escapes in a row, or a base64 string of 2000+ characters. Each counts
 * only when it decodes to readable text; data tables, images, fonts and WebAssembly (`\0asm`) are binary data,
 * which apm lists or skips like the files that hold them. Escapes spelling out text have no honest use, so they
 * are confirmed; a long base64 text is confirmed only when code loads or runs it.
 */
function encodedLiterals(text: string, region: RegionOf): TextFinding[] {
  const out: TextFinding[] = [];

  for (const m of text.matchAll(/(?:\\x[0-9a-fA-F]{2}){40,}/g)) {
    const r = region(m.index);
    const value = m[0].slice(0, 4000).replace(/\\x([0-9a-fA-F]{2})/g, (_, h: string) => String.fromCharCode(Number.parseInt(h, 16)));

    if (r === "excluded" || !printable(value)) continue;
    out.push({ id: "obfuscated", ...lineOf(text, m.index), how: "as written", confidence: "confirmed" });
    break;
  }

  for (const m of text.matchAll(/['"]([A-Za-z0-9+/]{2000,}={0,2})['"]/g)) {
    const r = region(m.index);
    const raw = (m[1] ?? "").slice(0, 4000);
    const value = Buffer.from(raw.slice(0, raw.length - (raw.length % 4)), "base64").toString("latin1");

    if (r === "excluded" || value.startsWith("\0asm") || !printable(value)) continue;
    const confidence: Confidence = r === "string" ? "possible" : "confirmed";
    out.push(judged({ id: "obfuscated", ...lineOf(text, m.index), how: "as written" }, confidence, "a long base64 string decodes to text, but apm did not see code load or run it"));
    break;
  }

  return out;
}

function regionsOf(text: string, lang: Lang): RegionOf {
  if (lang === "plain") return RAW;
  let lexed: Lexed | null = null;

  // tokenized once, and only when something matched
  return (index) => (lexed ??= lex(text, lang)).region(index);
}

/**
 * Every rule that matches one file's text. The rules run on the text as written, then on the text with
 * split strings joined, then on readable strings decoded from base64, hex and char codes. A dangerous
 * name that had to be built or decoded also counts as obfuscation. `lang` says how to tell code from
 * comments and strings; `plain` (install commands, shell scripts) counts every match.
 */
export function scanText(text: string, lang: Lang = "js"): TextFinding[] {
  const region = regionsOf(text, lang);
  const out = ruleHits(text, "as written", new Set(), region);
  const confirmed = (): Set<CodeSignal> => new Set(out.filter((f) => f.confidence === "confirmed").map((f) => f.id));
  const hex = hexIdentifierRun(text);

  if (hex >= 0) out.push({ id: "obfuscated", ...lineOf(text, hex), how: "as written", confidence: "confirmed" });
  out.push(...encodedLiterals(text, region));
  const joined = joinStrings(text);
  const jregion = joined.text === text ? region : regionsOf(joined.text, lang);

  if (joined.text !== text) {
    const found = new Set(out.map((f) => f.id));

    // joining can confirm what the text as written only suggested, but a second "possible" adds nothing
    for (const f of ruleHits(joined.text, "after joining strings", confirmed(), jregion)) if (f.confidence === "confirmed" || !found.has(f.id)) out.push(f);
  }

  for (const s of joined.built) {
    const id = namedSignal(s);

    if (!id) continue;
    const at = joined.text.indexOf(quote(s));
    // a string that became a member access (x['ex' + 'ec'] is x.exec) is code
    const r: Region = at < 0 ? "code" : jregion(at);

    if (r === "excluded") continue;
    const confidence: Confidence = r === "string" ? "possible" : "confirmed";
    const why = `builds "${s.slice(0, 40)}" from pieces, but apm did not see it loaded or called`;
    const where = lineOf(joined.text, Math.max(0, at));

    out.push(judged({ id, ...where, how: "after joining strings" }, confidence, why));
    out.push(judged({ id: "obfuscated", line: where.line, snippet: `builds "${s.slice(0, 40)}" from pieces: ${where.snippet}`, how: "after joining strings" }, confidence, why));
  }

  for (const d of decodedStrings(joined.text)) {
    const r = jregion(d.index);

    if (r === "excluded") continue;
    const outer: Confidence = r === "string" ? "possible" : "confirmed";
    const where = lineOf(joined.text, d.index);
    const named = namedSignal(d.value);
    const hits = ruleHits(d.value, "decoded", new Set(), RAW);

    if (named) hits.push({ id: named, line: where.line, snippet: d.value.slice(0, 80), how: "decoded", confidence: "confirmed" });

    if (hits.length === 0) continue;
    const hidden = `decoded from ${d.how} in an ordinary string that apm did not see code load or run`;

    for (const h of hits) {
      const confidence: Confidence = outer === "possible" || h.confidence === "possible" ? "possible" : "confirmed";
      const snippet = `${d.how} "${d.value.slice(0, 60)}" at ${where.snippet}`.slice(0, 120);

      out.push(judged({ id: h.id, line: where.line, snippet, how: "decoded" }, confidence, h.confidence === "possible" ? h.why : hidden));
    }

    out.push(judged({ id: "obfuscated", line: where.line, snippet: `hides code in ${d.how}: ${where.snippet}`, how: "decoded" }, outer, hidden));
  }

  if (!confirmed().has("credential-access") && out.some((f) => f.id === "network")) {
    const hit = envExfil(text, region);

    if (hit) out.push(judged({ id: "credential-access", ...lineOf(text, hit.index), how: "as written" }, hit.confidence, IN_STRING));
  }

  return out;
}

// ---------- what a file loads ----------
export type Imports = { paths: string[]; dynamic: { line: number; snippet: string }[] };

const STATIC_IMPORT = /(?:\brequire(?:\.resolve)?\s*\(|\bimport\s*\(|\bfrom\s+|\bimport\s+)\s*['"\x60](\.{1,2}\/[^'"\x60\n]+)['"\x60]/g;
const DIRNAME_JOIN = /\b[\w$]+\.(?:join|resolve)\s*\(\s*__dirname\s*((?:,\s*['"][^'"\n]+['"]\s*)+)\)/g;
const DIRNAME_PLUS = /\b__dirname\s*\+\s*['"](\/[^'"\n]+)['"]/g;
const CALL = /(?<![\w$.])(?:require|import)\s*\(/g;

/**
 * Relative paths a file loads (a literal require or import, require.resolve, path.join(__dirname, ...)
 * and __dirname + '/...'), and the calls whose argument is not a path apm can read.
 * Run it on joined text so `require('./lib/' + 'x')` is a literal.
 */
export function importsOf(text: string): Imports {
  const paths: string[] = [];

  for (const m of text.matchAll(STATIC_IMPORT)) if (m[1]) paths.push(m[1]);

  for (const m of text.matchAll(DIRNAME_JOIN)) {
    const segs = [...(m[1] ?? "").matchAll(/['"]([^'"\n]+)['"]/g)].map((s) => s[1] ?? "");
    paths.push(`./${segs.join("/")}`);
  }

  for (const m of text.matchAll(DIRNAME_PLUS)) paths.push(`.${m[1] ?? ""}`);
  const dynamic: Imports["dynamic"] = [];

  for (const m of text.matchAll(CALL)) {
    const before = text.slice(Math.max(0, m.index - 12), m.index);

    if (/function\s*$/.test(before)) continue;
    const arg = text.slice(m.index + m[0].length, m.index + m[0].length + 200).trimStart();

    if (arg.startsWith(")")) continue;

    if (/^(['"])[^'"\n]*\1\s*[),]/.test(arg)) continue;

    if (/^\x60[^\x60$]*\x60\s*[),]/.test(arg)) continue;

    if (/^require\.resolve\s*\(\s*['"][^'"\n]*['"]\s*\)\s*\)/.test(arg) || /^[\w$]+\.(?:join|resolve)\s*\(\s*__dirname\s*(?:,\s*['"][^'"\n]+['"]\s*)+\)\s*\)/.test(arg)) continue;

    if (/^__dirname\s*\+\s*['"][^'"\n]+['"]\s*\)/.test(arg)) continue;

    if (dynamic.length < 5) dynamic.push(lineOf(text, m.index));
    else break;
  }

  return { paths: paths.slice(0, 500), dynamic };
}
