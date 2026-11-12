// The text rules every reader shares: what each code signal matches, how sure a match is in each place it can sit,
// where a position is (line and snippet), and the names that count when a string is built or decoded. Pure.

/**
 * Text a parsed program does not run as written, where a text match can still sit and still counts (apm-score-v9):
 * a comment, a regex literal's body, TypeScript that emits no code, or a JSON file. `String(fn)`, `re.source` and a
 * file reading itself give such text back at runtime, so it is cited, and named in the evidence, never left out.
 */
export type Hidden = "comment" | "regex" | "type" | "json";

export type CodeSignal = "shell-exec" | "network" | "credential-access" | "eval" | "obfuscated";

/** The signals a rule can find directly; `obfuscated` is how the text was hidden, not what it does. */
export type Capability = Exclude<CodeSignal, "obfuscated">;

/**
 * `confirmed`: the code does it, or loads the module that does. `possible`: the text only names it, in an
 * ordinary string, an alias or a method apm cannot identify, so the capability is there but apm did not see it used.
 */
export type Confidence = "confirmed" | "possible";

/**
 * What apm had to undo to see a match: nothing, joined string pieces, a decoded payload, or code held in a string
 * that the file runs (`eval`, `Function`, `vm`), possibly joined or decoded first.
 */
export type How = "as written" | "after joining strings" | "decoded" | "run from a string" | "joined, then run" | "decoded, then run";

/**
 * `tree`: the parsed program itself showed it (a call, a load, a string's role); otherwise only a text rule matched.
 * `hidden`: the text match sits in a comment, a regex body, a type or a JSON file.
 */
type FindingAt = { id: CodeSignal; line: number; snippet: string; how: How; tree?: true; hidden?: Hidden };

/** One rule match: the signal, where it is, whether the text had to be joined or decoded first, and how sure it is (with why, when only possible). */
export type TextFinding = FindingAt & ({ confidence: "confirmed" } | { confidence: "possible"; why: string });

export function judged(at: FindingAt, confidence: Confidence, why: string): TextFinding {
  return confidence === "confirmed" ? { ...at, confidence } : { ...at, confidence, why };
}

export const NET_MODULES = String.raw`(?:node:)?(?:https?|net|dgram|tls|http2|dns)(?:\/promises)?`;
const HTTP_CLIENTS = "(?:axios|undici|node-fetch|got|superagent|needle|phin|ky|ws)";
const GLOBAL = "(?:globalThis|global|window|self)";

// Function('return this')() is how old code finds the global object; anything else built into a Function is eval
const NOT_RETURN_THIS = String.raw`(?!['"\x60]return this['"\x60]\s*\))['"\x60]`;

const alt = (parts: string[]): RegExp => new RegExp(parts.join("|"), "g");

/**
 * What a pattern matches. Over text (every file, every install command) every kind counts, as apm-score-v3 counted
 * it. The parsed program's tree also reads strings with the `name` and `text` patterns, to say what a string it saw
 * used holds:
 * - `code`: a call or construct.
 * - `name`: a module name (`child_process`).
 * - `text`: shell command text (`curl ... | sh`).
 * - `alias`: a reference that gives the power without using it (`r = require`).
 */
export type Kind = "code" | "name" | "text" | "alias";

type Pattern = { kind: Kind; re: RegExp; why?: string };

/**
 * apm-score-v3's own patterns (`test/v3/source.ts`, commit 5437674), copied verbatim: each rule's `re` and its
 * `docSafe` list. They come last in their rule, so they decide only where the patterns above found nothing, and they
 * keep every raw read at least as strong as v3's was: v3 had no `data:` exception to `fetch(`, read `$fetch(` and
 * `$eval(` as calls, `dns.lookup` without a call, and any name ending in `AWS_SECRET_ACCESS_KEY`.
 */
const V3_NET_MODULES = String.raw`(?:node:)?(?:https?|net|dgram|tls|http2|dns)(?:\/promises)?`;
const V3_HTTP_CLIENTS = "(?:axios|undici|node-fetch|got|superagent|needle|phin|ky|ws)";
const v3 = (re: RegExp): Pattern => ({ kind: "code", re: new RegExp(re.source, "g") });
const v3Any = (parts: string[]): Pattern => ({ kind: "code", re: alt(parts) });

const V3_PATTERNS: Record<Capability, Pattern[]> = {
  "shell-exec": [
    v3(/\bchild_process\b|\bexec(?:File)?Sync\s*\(|\bspawnSync\s*\(|\|\s*(?:ba|z)?sh\b|\bcurl\s+-?|\bwget\s+|\bpowershell\b|\bBun\.spawn\b|\bBun\.\$|\bDeno\.Command\b/),
    v3(/\bprocess\s*\.\s*(?:binding|_linkedBinding|dlopen)\s*\(|\binternalBinding\s*\(/),
  ],
  network: [
    v3(/\bfetch\s*\(|\bhttps?\.(?:get|request)\s*\(|require\(\s*['"](?:node:)?(?:https?|net|dgram|tls|http2)['"]\s*\)|from\s+['"](?:node:)?(?:https?|net|dgram|tls|http2)['"]|\bXMLHttpRequest\b|\bnew\s+WebSocket\b|\bcurl\s+|\bwget\s+|\bdns\.(?:resolve|lookup)\b|\bimport\s*\(\s*['"`]https?:\/\//),
    v3Any([
      String.raw`(?:require|import)\s*\(\s*['"\x60]${V3_NET_MODULES}['"\x60]\s*\)`,
      String.raw`from\s+['"]${V3_NET_MODULES}['"]`,
      String.raw`(?:require\s*\(\s*|from\s+|import\s*\(\s*)['"]${V3_HTTP_CLIENTS}['"]`,
      String.raw`\bnew\s+(?:EventSource|RTCPeerConnection)\b`,
      String.raw`\bsendBeacon\s*\(`,
      String.raw`\bdns(?:\.promises)?\.(?:resolve\w*|lookup\w*|reverse)\s*\(`,
    ]),
  ],
  "credential-access": [
    v3(/\.npmrc\b|['"/]\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws\/credentials|AWS_SECRET_ACCESS_KEY|\bGITHUB_TOKEN\b|\bNPM_TOKEN\b|\bNODE_AUTH_TOKEN\b|JSON\.stringify\(\s*process\.env\s*\)|\.git-credentials|\.docker\/config\.json|\bLogin Data\b|\.config\/gcloud/),
  ],
  eval: [
    v3(/(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.(?:runIn\w*Context|Script)\b|=\s*require\s*[;,\n]|\brequire\s*\(\s*String\.fromCharCode/),
    v3Any([
      String.raw`\.\s*eval\s*\(`,
      String.raw`\(\s*0\s*,\s*eval\s*\)`,
      String.raw`=\s*eval\s*[;,)\n]`,
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
  ],
};

const OWN_RULES: { id: Capability; patterns: Pattern[] }[] = [
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

/** Each rule's own patterns, then apm-score-v3's for the same signal. */
export const RULES: { id: Capability; patterns: Pattern[] }[] = OWN_RULES.map((r) => ({ id: r.id, patterns: [...r.patterns, ...V3_PATTERNS[r.id]] }));

/** Reading the whole environment: a credential grab when a network call sits right next to it. */
export const WHOLE_ENV = /\bObject\.(?:keys|entries|values)\s*\(\s*process\.env\s*\)|\bfor\s*\(\s*(?:const|let|var)\s+[\w$]+\s+in\s+process\.env\b/g;

/** How close (in characters) an environment dump and a network call must be to read as one exfiltration. */
export const NEAR = 400;

/** Environment variables that hold publishing or cloud credentials. */
export const TOKEN_NAMES: ReadonlySet<string> = new Set(["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "NPM_TOKEN", "NODE_AUTH_TOKEN"]);

/** A string that, once built or decoded, names something dangerous. */
const NAMED: { id: Capability; re: RegExp }[] = [
  { id: "shell-exec", re: /^(?:(?:node:)?child_process|execSync|execFileSync|execFile|spawnSync|spawn|exec)$/ },
  { id: "network", re: new RegExp(`^(?:${NET_MODULES}|fetch|XMLHttpRequest|WebSocket|sendBeacon|EventSource|request)$`) },
  { id: "eval", re: /^(?:eval|Function|require|(?:node:)?vm|runInThisContext|runInNewContext)$/ },
  { id: "credential-access", re: /\.npmrc$|^(?:NPM_TOKEN|GITHUB_TOKEN|NODE_AUTH_TOKEN|AWS_SECRET_ACCESS_KEY)$|\.ssh\/|\bid_(?:rsa|ed25519|ecdsa)$/ },
];

/** The dangerous thing a built or decoded string names, if any: `'child_process'`, `'fetch'`. */
export function namedSignal(s: string): Capability | null {
  const t = s.trim();

  return NAMED.find((n) => n.re.test(t))?.id ?? null;
}

const NET_MODULE = new RegExp(`^${NET_MODULES}$`);
const HTTP_CLIENT = new RegExp(`^${HTTP_CLIENTS}$`);

/** What loading the module `spec` gives the code: child_process runs commands, http and its kin reach the network, vm evaluates. */
export function moduleSignal(spec: string): Capability | null {
  if (/^(?:node:)?child_process$/.test(spec)) return "shell-exec";

  if (NET_MODULE.test(spec) || HTTP_CLIENT.test(spec) || /^https?:\/\//.test(spec)) return "network";

  if (/^(?:node:)?vm$/.test(spec)) return "eval";

  return null;
}

/** obfuscator.io output: twenty or more `_0x1a2b` identifiers. Counted in one linear pass. Returns the first one's index, or -1. */
export function hexIdentifierRun(text: string): number {
  const re = /_0x[0-9a-f]{4,}/g;
  let first = -1;
  let n = 0;

  for (let m = re.exec(text); m; m = re.exec(text)) {
    if (first < 0) first = m.index;

    if (++n >= 20) return first;
  }

  return -1;
}

/** A line number and the text around a position, trimmed to about 80 characters, and the left-out text it sits in. */
export type Where = { line: number; snippet: string; hidden?: Hidden };

/**
 * Where `index` is. Lines are counted by `\n`, the way the file view numbers them. A carriage return or a Unicode
 * line or paragraph separator also ends a JavaScript line, so the snippet shows each one as `↵`: that is how a
 * comment that looks like it runs to the end of the line can stop early.
 */
export function lineOf(text: string, index: number): Where {
  let line = 1;

  for (let i = text.indexOf("\n"); i !== -1 && i < index; i = text.indexOf("\n", i + 1)) line++;
  const start = text.lastIndexOf("\n", index - 1) + 1;
  const end = text.indexOf("\n", index);

  // a CRLF line's \r is its own end; any other carriage return or separator is inside the line
  const whole = text
    .slice(start, end === -1 ? undefined : end)
    .replace(/\r$/, "")
    .replace(/[\r\u2028\u2029]/g, "↵");

  if (whole.trim().length <= 80) return { line, snippet: whole.trim() };
  const col = index - start;
  const from = Math.max(0, col - 30);
  const to = from + 80;
  const snippet = `${from > 0 ? "…" : ""}${whole.slice(from, to).trim()}${to < whole.length ? "…" : ""}`;

  return { line, snippet };
}

/** Whether a decoded string reads as text: at least 95% printable ASCII, tabs and newlines. */
export function printable(s: string): boolean {
  if (s.length < 4) return false;
  let ok = 0;

  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);

    if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) ok++;
  }

  return ok / s.length >= 0.95;
}

const IN_STRING = "only inside an ordinary string, not in code apm saw run";

/**
 * The first match of each rule, every one confirmed: text is read as it is, as apm-score-v3 read every file, and
 * nothing in it is taken for a definition, a type, a comment or a string that does not run. Every match is looked at;
 * there is no budget to run out. `place` says where a match is cited (text that was joined first is cited where the
 * original text has it) and what left-out text it sits in.
 */
export function ruleHits(text: string, how: How, skip: ReadonlySet<CodeSignal>, place: (index: number) => Where = (i) => lineOf(text, i)): TextFinding[] {
  const out: TextFinding[] = [];

  for (const rule of RULES) {
    if (skip.has(rule.id)) continue;

    for (const p of rule.patterns) {
      p.re.lastIndex = 0;
      const m = firstMatch(p.re, text);

      if (m >= 0) {
        out.push({ id: rule.id, ...place(m), how, confidence: "confirmed" });
        break;
      }
    }
  }

  return out;
}

/** The index of the first non-empty match of the global `re` in `text`, or -1. */
function firstMatch(re: RegExp, text: string): number {
  re.lastIndex = 0;

  for (let m = re.exec(text); m; m = re.exec(text)) {
    if (m[0].length > 0) return m.index;
    re.lastIndex++;
  }

  return -1;
}

/** The `why` a possible match of this rule and kind gives, for text that sits in a string. */
export function whyOf(id: Capability, kind: Kind): string {
  const rule = RULES.find((r) => r.id === id);

  return rule?.patterns.find((p) => p.kind === kind && p.why)?.why ?? IN_STRING;
}

/** One match of a rule's `name` or `text` pattern in a string's value: which rule, which kind, and where in the value. */
export type StringMatch = { id: Capability; kind: Kind; index: number };

/** The first match of each rule's `name` and `text` patterns in `value`; code and alias patterns describe code, not text. */
export function stringMatches(value: string): StringMatch[] {
  const out: StringMatch[] = [];

  for (const rule of RULES) {
    for (const p of rule.patterns) {
      if (p.kind !== "name" && p.kind !== "text") continue;
      p.re.lastIndex = 0;
      const m = p.re.exec(value);

      if (m) {
        out.push({ id: rule.id, kind: p.kind, index: m.index });
        break;
      }
    }
  }

  return out;
}

const NETWORK_NEAR = RULES.filter((r) => r.id === "network").flatMap((r) => r.patterns.filter((p) => p.kind !== "alias").map((p) => new RegExp(p.re.source)));

/** An environment dump with a network call within NEAR characters of it: the index of the dump, or -1. */
export function envExfil(text: string): number {
  let tries = 0;

  for (const m of text.matchAll(WHOLE_ENV)) {
    const window = text.slice(Math.max(0, m.index - NEAR), m.index + NEAR);

    if (NETWORK_NEAR.some((re) => re.test(window))) return m.index;

    if (++tries >= 50) break;
  }

  return -1;
}

/**
 * Text hidden in a literal: 40 or more `\x` escapes in a row, or a base64 string of 2000+ characters. Escapes or base64
 * that decode to readable text are cited first; when there are none, apm-score-v3's rule counts escapes and base64
 * whatever they decode to (data tables, images, fonts and WebAssembly included), as v3 did.
 */
export function encodedLiterals(text: string, place: (index: number) => Where = (i) => lineOf(text, i)): TextFinding[] {
  const escapes = escapedTextAt(text);

  if (escapes >= 0) return [{ id: "obfuscated", ...place(escapes), how: "as written", confidence: "confirmed" }];

  for (const m of text.matchAll(/['"]([A-Za-z0-9+/]{2000,}={0,2})['"]/g)) {
    if (longBase64Text(m[1] ?? "")) return [{ id: "obfuscated", ...place(m.index), how: "as written", confidence: "confirmed" }];
  }

  const v3 = v3Encoded(text);

  return v3 >= 0 ? [{ id: "obfuscated", ...place(v3), how: "as written", confidence: "confirmed" }] : [];
}

/** apm-score-v3's `obfuscated` rule, verbatim: 40 `\x` escapes in a row, or a quoted base64 run of 2000+ characters. */
const V3_ENCODED = /(?:\\x[0-9a-f]{2}){40}|['"][A-Za-z0-9+/]{2000,}={0,2}['"]/g;

/** Where apm-score-v3's `obfuscated` rule first matches `text`, or -1. */
export function v3Encoded(text: string): number {
  return firstMatch(V3_ENCODED, text);
}

/** Where 40 or more `\x` escapes in a row spell readable text, or -1. */
export function escapedTextAt(text: string): number {
  for (const m of text.matchAll(/(?:\\x[0-9a-fA-F]{2}){40,}/g)) {
    const value = m[0].slice(0, 4000).replace(/\\x([0-9a-fA-F]{2})/g, (_, h: string) => String.fromCharCode(Number.parseInt(h, 16)));

    if (printable(value)) return m.index;
  }

  return -1;
}

/** Whether a base64 body of 2000+ characters decodes to readable text rather than WebAssembly, a font or other data. */
export function longBase64Text(raw: string): boolean {
  if (raw.length < 2000) return false;
  const head = raw.slice(0, 4000);
  const value = Buffer.from(head.slice(0, head.length - (head.length % 4)), "base64").toString("latin1");

  return !value.startsWith("\0asm") && printable(value);
}
