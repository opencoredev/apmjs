// Static reading of one file's text: the rules, a pass that joins strings split to dodge them, decoders
// for the cheap encodings (base64, hex, \x escapes, char codes) and the paths a file loads. Pure.

export type CodeSignal = "shell-exec" | "network" | "credential-access" | "eval" | "obfuscated";

/** One rule match: the signal, where it is, and whether the text had to be joined or decoded first. */
export type TextFinding = { id: CodeSignal; line: number; snippet: string; how: "as written" | "after joining strings" | "decoded" };

const NET_MODULES = String.raw`(?:node:)?(?:https?|net|dgram|tls|http2|dns)(?:\/promises)?`;
const HTTP_CLIENTS = "(?:axios|undici|node-fetch|got|superagent|needle|phin|ky|ws)";

const alt = (parts: string[]): RegExp => new RegExp(parts.join("|"));

/**
 * The rules. `re` matches anywhere. `docSafe` holds the patterns docs show as examples (`new EventSource(...)`
 * in a JSDoc block), so its matches on lines that start like a comment (`*`, `//`) are passed over.
 */
const RULES: { id: CodeSignal; re: RegExp; docSafe?: RegExp }[] = [
  {
    id: "shell-exec",
    re: /\bchild_process\b|\bexec(?:File)?Sync\s*\(|\bspawnSync\s*\(|\|\s*(?:ba|z)?sh\b|\bcurl\s+-?|\bwget\s+|\bpowershell\b|\bBun\.spawn\b|\bBun\.\$|\bDeno\.Command\b/,
    docSafe: /\bprocess\s*\.\s*(?:binding|_linkedBinding|dlopen)\s*\(|\binternalBinding\s*\(/,
  },
  {
    id: "network",
    re: /\bfetch\s*\(|\bhttps?\.(?:get|request)\s*\(|require\(\s*['"](?:node:)?(?:https?|net|dgram|tls|http2)['"]\s*\)|from\s+['"](?:node:)?(?:https?|net|dgram|tls|http2)['"]|\bXMLHttpRequest\b|\bnew\s+WebSocket\b|\bcurl\s+|\bwget\s+|\bdns\.(?:resolve|lookup)\b|\bimport\s*\(\s*['"`]https?:\/\//,
    docSafe: alt([
      String.raw`(?:require|import)\s*\(\s*['"\x60]${NET_MODULES}['"\x60]\s*\)`,
      String.raw`from\s+['"]${NET_MODULES}['"]`,
      String.raw`(?:require\s*\(\s*|from\s+|import\s*\(\s*)['"]${HTTP_CLIENTS}['"]`,
      String.raw`\bnew\s+(?:EventSource|RTCPeerConnection)\b`,
      String.raw`\bsendBeacon\s*\(`,
      String.raw`\bdns(?:\.promises)?\.(?:resolve\w*|lookup\w*|reverse)\s*\(`,
    ]),
  },
  {
    id: "credential-access",
    re: /\.npmrc\b|['"/]\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws\/credentials|AWS_SECRET_ACCESS_KEY|\bGITHUB_TOKEN\b|\bNPM_TOKEN\b|\bNODE_AUTH_TOKEN\b|JSON\.stringify\(\s*process\.env\s*\)|\.git-credentials|\.docker\/config\.json|\bLogin Data\b|\.config\/gcloud/,
  },
  {
    id: "eval",
    re: /(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.(?:runIn\w*Context|Script)\b|=\s*require\s*[;,\n]|\brequire\s*\(\s*String\.fromCharCode/,
    docSafe: alt([
      String.raw`\.\s*eval\s*\(`,
      String.raw`\(\s*0\s*,\s*eval\s*\)`,
      String.raw`=\s*eval\s*[;,)\n]`,
      // Function('return this')() is how old code finds the global object; anything else built into a Function is eval
      String.raw`(?<![\w$.])Function\s*\(\s*(?!['"\x60]return this['"\x60]\s*\))['"\x60]`,
      String.raw`\.\s*Function\s*\(\s*(?!['"\x60]return this['"\x60]\s*\))['"\x60]`,
      String.raw`=\s*(?:globalThis|global|window|self)\s*\.\s*Function\s*[;,\n]`,
      String.raw`\.constructor\s*\.\s*constructor\s*\(`,
      String.raw`\bset(?:Timeout|Interval|Immediate)\s*\(\s*['"\x60]`,
      String.raw`\bvm\.(?:compileFunction|SourceTextModule)\b`,
      String.raw`\brunIn(?:This|New)Context\s*\(`,
      String.raw`(?:require|import)\s*\(\s*['"](?:node:)?vm['"]\s*\)|from\s+['"](?:node:)?vm['"]`,
      String.raw`\bmodule\s*\._compile\s*\(|\bModule\.prototype\._compile\b`,
      String.raw`(?:globalThis|global|window|self)\s*\.\s*require\b`,
    ]),
  },
  { id: "obfuscated", re: /(?:\\x[0-9a-f]{2}){40}|['"][A-Za-z0-9+/]{2000,}={0,2}['"]/ },
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

/** A line number and that line, trimmed to 80 characters. */
export type Where = { line: number; snippet: string };

export function lineOf(text: string, index: number): Where {
  let line = 1;

  for (let i = text.indexOf("\n"); i !== -1 && i < index; i = text.indexOf("\n", i + 1)) line++;
  const start = text.lastIndexOf("\n", index - 1) + 1;
  const end = text.indexOf("\n", index);
  const snippet = text.slice(start, end === -1 ? undefined : end).trim().slice(0, 80);

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
/** Whether the line holding `index` starts like a comment: `* ...` inside a JSDoc block, or `// ...`. */
function onCommentLine(text: string, index: number): boolean {
  const start = text.lastIndexOf("\n", index - 1) + 1;

  return /^\s*(?:\*|\/\/|\/\*)/.test(text.slice(start, Math.min(index, start + 200)));
}

/** First match of `re` in `text` that is not on a comment-shaped line. Bounded: gives up after 200 tries. */
function firstOutsideComments(re: RegExp, text: string): number {
  const g = new RegExp(re.source, "g");
  let tries = 0;

  for (let m = g.exec(text); m && tries < 200; m = g.exec(text), tries++) {
    if (!onCommentLine(text, m.index)) return m.index;

    if (m[0].length === 0) g.lastIndex++;
  }

  return -1;
}

function ruleHits(text: string, how: TextFinding["how"], skip: ReadonlySet<CodeSignal>): TextFinding[] {
  const out: TextFinding[] = [];

  for (const rule of RULES) {
    if (skip.has(rule.id)) continue;
    const m = rule.re.exec(text);
    const at = m ? m.index : rule.docSafe ? firstOutsideComments(rule.docSafe, text) : -1;

    if (at >= 0) out.push({ id: rule.id, ...lineOf(text, at), how });
  }

  return out;
}

const NETWORK = RULES.filter((r) => r.id === "network").flatMap((r) => (r.docSafe ? [r.re, r.docSafe] : [r.re]));

/** An environment dump with a network call within NEAR characters of it: the index of the dump, or -1. */
function envExfil(text: string): number {
  let tries = 0;

  for (const m of text.matchAll(WHOLE_ENV)) {
    const window = text.slice(Math.max(0, m.index - NEAR), m.index + NEAR);

    if (NETWORK.some((re) => re.test(window))) return m.index;

    if (++tries >= 50) break;
  }

  return -1;
}

/**
 * Every rule that matches one file's text. The rules run on the text as written, then on the text with
 * split strings joined, then on readable strings decoded from base64, hex and char codes. A dangerous
 * name that had to be built or decoded also counts as obfuscation.
 */
export function scanText(text: string): TextFinding[] {
  const out = ruleHits(text, "as written", new Set());
  const have = (): Set<CodeSignal> => new Set(out.map((f) => f.id));
  const hex = hexIdentifierRun(text);

  if (hex >= 0 && !have().has("obfuscated")) out.push({ id: "obfuscated", ...lineOf(text, hex), how: "as written" });
  const joined = joinStrings(text);

  if (joined.text !== text) out.push(...ruleHits(joined.text, "after joining strings", have()));

  for (const s of joined.built) {
    const id = namedSignal(s);

    if (!id) continue;
    const at = Math.max(0, joined.text.indexOf(quote(s)));
    const where = lineOf(joined.text, at);
    out.push({ id, ...where, how: "after joining strings" });
    out.push({ id: "obfuscated", line: where.line, snippet: `builds "${s.slice(0, 40)}" from pieces: ${where.snippet}`, how: "after joining strings" });
  }

  for (const d of decodedStrings(joined.text)) {
    const where = lineOf(joined.text, d.index);
    const named = namedSignal(d.value);
    const hits = ruleHits(d.value, "decoded", new Set());

    if (named) hits.push({ id: named, line: where.line, snippet: d.value.slice(0, 80), how: "decoded" });

    if (hits.length === 0) continue;

    for (const h of hits) out.push({ ...h, line: where.line, snippet: `${d.how} "${d.value.slice(0, 60)}" at ${where.snippet}`.slice(0, 120) });
    out.push({ id: "obfuscated", line: where.line, snippet: `hides code in ${d.how}: ${where.snippet}`, how: "decoded" });
  }

  if (!have().has("credential-access") && have().has("network")) {
    const at = envExfil(text);

    if (at >= 0) out.push({ id: "credential-access", ...lineOf(text, at), how: "as written" });
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
