// What a secret looks like, for the secret scan (secrets.ts, which scores on SECRET_CONTENT_RULES) and for masking text
// apm shows people (an AI review's quoted lines and sentences can carry a live key the publisher shipped). Pure, and
// with no imports, so the website can mask in the browser too (@apm/core/redact).

export const SECRET_CONTENT_RULES: { kind: string; re: RegExp }[] = [
  // PEM ("-----BEGIN RSA PRIVATE KEY-----", "ENCRYPTED", "OPENSSH", "PGP ... BLOCK") and SSH2 ("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----")
  { kind: "private key", re: /-{4,5} ?BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)? ?-{4,5}/ },
  { kind: "PuTTY private key", re: /PuTTY-User-Key-File-\d+:/ },
  { kind: "AWS access key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { kind: "npm token", re: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { kind: "GitHub token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/ },
  { kind: "Stripe live key", re: /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/ },
  { kind: "Slack token", re: /\bxox[abprs]-[0-9A-Za-z-]{10,}\b/ },
  { kind: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/ },
  { kind: "OpenAI key", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/ },
  { kind: "Anthropic key", re: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/ },
  { kind: "registry auth token", re: /_authToken[^\S\r\n]*=[^\S\r\n]*[^\s$]{8,}/ },
  // npm's basic auth: "//host/:_auth=base64(user:pass)" or ":_password=base64(pass)"
  // the host is matched looking back from `:_`, so each start is tried once (a forward `//[^\s:]+` from every `//` of
  // `////…` scanned to the end of the file from each)
  { kind: "registry password", re: /(?<=\/\/[^\s:]+):_(?:auth|password)[^\S\r\n]*=[^\S\r\n]*[^\s$]{4,}/ },
  { kind: "Slack webhook", re: /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9_/-]{20,}/ },
  { kind: "Discord webhook", re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{20,}/ },
];

// In an .npmrc the auth keys need no registry prefix: "_auth=..." on its own line is a default credential.
export const SECRET_NPMRC_RULES: { kind: string; re: RegExp }[] = [{ kind: "registry password", re: /^[^\S\n]*_(?:auth|password)[^\S\r\n]*=[^\S\r\n]*[^\s$]{4,}/m }];

// ---------- redaction ----------
// Best effort, for the people who may read a flag's quoted lines: the package's owners and apm's reviewers. The public
// never gets a quoted line at all (packages/registry/src/review.ts publicFinding), so nothing public depends on this.
// Each secret is masked to its first and last few characters and its length, so a reader can tell which key it is.
//
// Two passes. Formats first: the scan's rules (a known key or token format, a private key block), a password in a URL,
// a JWT. Then assignments: a value given to a key whose name says it is a secret (namesSecret), quoted in any style,
// or unquoted in an .env, shell or YAML line. Names are checked whole, segment by segment, and values are scanned by
// hand, so every pattern here matches in time linear in its input (test/runtime-regex.test.ts, test/redact-timing).

/** A format rule: `secret` is the capture group that is the secret (0: the whole match). */
type Rule = { re: RegExp; secret: number };

/** A whole PEM or SSH2 private key block, its base64 body with it (the scan's rule matches the header line alone). */
const KEY_BLOCK = /-{4,5} ?BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)? ?-{4,5}[\s\S]*?(?:-{4,5} ?END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)? ?-{4,5}|$)/g;

const global = (re: RegExp): RegExp => new RegExp(re.source, `${re.flags.replace("g", "")}g`);

/**
 * A scan rule as a masking rule. The registry password rule looks back for `//host` before `:_auth=`: one test of it is
 * fine, but a global scan runs that look-back from every position, which is quadratic. Masking drops the look-back and
 * masks any `:_auth=` or `:_password=` value, which is broader and linear.
 */
const forMasking = (r: { kind: string; re: RegExp }): RegExp => (r.re.source.startsWith("(?<=") ? /:_(?:auth|password)[^\S\r\n]*=[^\S\r\n]*[^\s$]{4,}/g : global(r.re));

const FORMAT_RULES: readonly Rule[] = [
  { re: KEY_BLOCK, secret: 0 },
  ...[...SECRET_CONTENT_RULES, ...SECRET_NPMRC_RULES].map((r) => ({ re: forMasking(r), secret: 0 })),
  // user:password@ in any URL: mongodb://, postgres://, redis://, amqp://, https://, and redis://:password@ with no user
  { re: /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:/@'"`]*:([^\s@/'"`]{3,})@/gi, secret: 1 },
  // a signed URL's credential parameter: ?sig=, &signature=, &token=, X-Amz-Signature=, X-Goog-Credential=, … The host
  // and path stay readable; only the value goes
  { re: /[?&](?:sig|signature|token|access_token|refresh_token|id_token|key|apikey|api_key|auth|password|secret|client_secret|x-amz-signature|x-amz-credential|x-amz-security-token|x-goog-signature|x-goog-credential)=([^&#\s"'`<>]{4,})/gi, secret: 1 },
  // .NET and ODBC connection strings: "Server=…;Password=…;" (after a `;` or a quote, so `PASSWORD=` at a line's start is
  // the .env rule's; bounded: a value is at most 256 characters)
  // the value ends at a `;`, a quote or the line's end: the last pair of a string usually has no `;` after it
  { re: /[;"'`][ \t]*(?:password|pwd)[ \t]*=([^;"'`\r\n]{1,256})(?=[;"'`\r\n]|$)/gi, secret: 1 },
  { re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, secret: 0 },
];

/** Last words of a name that make its value a secret: password, dbPassword, DB_PASSWORD, authToken, client_secret, … */
const SECRET_LAST = new Set(["password", "passwd", "passphrase", "pass", "pwd", "secret", "token", "auth", "credential", "credentials", "apikey"]);

/** Words after a secret word that only say which environment it is for: DB_PASSWORD_PROD, API_KEY_V2, TOKEN_2. */
const ENVIRONMENT_WORDS = new Set(["prod", "production", "dev", "development", "staging", "stage", "test", "testing", "live", "local", "old", "new", "backup", "bak"]);

function isEnvironmentWord(word: string): boolean {
  return ENVIRONMENT_WORDS.has(word) || /^v?\d{1,4}$/.test(word);
}

/** Last two words that do: api_key, apiKey, access_key, private_key, secret_key, signing_key. */
const SECRET_PAIRS = new Set(["api key", "access key", "private key", "secret key", "signing key"]);

/** The longest name looked at: a longer run of letters is not a variable a person named. */
const MAX_NAME = 128;

/**
 * A name's words, lowercased: split at `_`, `-`, `.` and spaces, and at camelCase boundaries (dbPassword: db,
 * password; APIKey: api, key; tokenType: token, type).
 */
export function nameWords(name: string): string[] {
  const words: string[] = [];
  let word = "";

  for (let i = 0; i < name.length; i++) {
    const c = name.charAt(i);

    if (c === "_" || c === "-" || c === "." || c === " " || c === "$") {
      if (word !== "") words.push(word);
      word = "";
      continue;
    }

    const prev = name.charAt(i - 1);
    const next = name.charAt(i + 1);
    const upper = c >= "A" && c <= "Z";
    // a capital starts a word after a lowercase letter or digit (dbPassword), or ends a run of capitals before a
    // lowercase letter (APIKey: API, Key)
    const starts = upper && word !== "" && ((prev >= "a" && prev <= "z") || (prev >= "0" && prev <= "9") || (prev >= "A" && prev <= "Z" && next >= "a" && next <= "z"));

    if (starts) {
      words.push(word);
      word = "";
    }

    word += c;
  }

  if (word !== "") words.push(word);

  return words.map((w) => w.toLowerCase());
}

/**
 * Whether a name says its value is a secret: its last word is one (password, token, secret, auth, …) or its last two
 * are (api key, access key, …), once words that only name an environment are taken off the end (DB_PASSWORD_PROD,
 * API_KEY_V2). Whole words only: tokenizer, tokenType, tokens, passThrough, AUTHOR, AUTHORITY and AUTHORIZE are not.
 */
export function namesSecret(name: string): boolean {
  if (name.length === 0 || name.length > MAX_NAME) return false;
  const words = nameWords(name);

  while (words.length > 1 && isEnvironmentWord(words.at(-1) ?? "")) words.pop();
  const last = words.at(-1);

  if (last === undefined) return false;

  return SECRET_LAST.has(last) || SECRET_PAIRS.has(words.slice(-2).join(" "));
}

/** A key, its separator and an opening quote: `password = "`, `"client_secret": '`, `apiKey: \``. Starts only at a name's start. */
const QUOTED = /(?<![\w$.-])([A-Za-z_$][\w$.-]*)["'`]?[ \t]*(?:=>|[:=])[ \t]*(["'`])/g;

/** NAME=value as an .env file or a shell line writes it, unquoted. Upper-case names only: lower case is code. */
const ENV = /(?<![\w$.-])(?:export[ \t]+)?([A-Z_][A-Z0-9_]*)[ \t]*=(?![=>])[ \t]*(?=[^\s"'`$=;])/g;

/** key: value as YAML writes it, unquoted, at the start of a line. */
const YAML = /^[ \t]*(?:-[ \t]+)?["']?([A-Za-z_][\w.-]*)["']?[ \t]*:[ \t]+(?=[^\s"'`{[|>&*!#])/gm;

/** Where a quoted value that starts at `from` ends: its matching quote (escaped quotes skipped), or the end of the text. */
function quotedEnd(text: string, from: number, quote: string): number {
  for (let i = from; i < text.length; i++) {
    const c = text.charAt(i);

    if (c === "\\") i++;
    else if (c === quote) return i;
  }

  return text.length;
}

/** Where an unquoted value that starts at `from` ends: the end of its line, a ` #` comment, or (`shell`) a `;`, `&` or `|`. */
function lineEnd(text: string, from: number, shell: boolean): number {
  let end = from;

  for (; end < text.length; end++) {
    const c = text.charAt(end);

    if (c === "\n" || c === "\r") break;

    if (c === "#" && end > from && (text.charAt(end - 1) === " " || text.charAt(end - 1) === "\t")) break;

    if (shell && (c === ";" || c === "&" || c === "|")) break;
  }

  // trailing spaces before a comment or the line's end are not the value's
  while (end > from && (text.charAt(end - 1) === " " || text.charAt(end - 1) === "\t")) end--;

  return end;
}

/** A mask redactSecrets wrote: `sk-p…9xYz [redacted, 51 chars]` or `[redacted, 4 chars]`. Bounded, so linear. */
const MASK = /[^\n…]{0,4}…[^\n…]{0,4} \[redacted, \d{1,9} chars\]|\[redacted, \d{1,9} chars\]/g;

/** Whether `value` is masks and nothing else: then an earlier rule already masked it, and it stays as it is. */
function onlyMasks(value: string): boolean {
  return value.includes("[redacted, ") && value.replace(MASK, "").trim() === "";
}

/**
 * Whether an assigned value should be masked: long enough, not already masked, not a reference to another value. A URL
 * given to a secret-named key is masked like any other value: it may be the credential itself.
 */
function maskable(value: string): boolean {
  const v = value.trim();

  return v.length >= 4 && !onlyMasks(v) && !v.startsWith("process.env") && !v.startsWith("$");
}

type Span = { from: number; to: number };

/**
 * The values a secret-named key is given in `text`, in order, none overlapping. Each pattern's matches come in order,
 * and a match inside a value already examined (masked or not) is skipped without being scanned again, so the work stays
 * linear however many assignments a line holds (re-check of 70dc3df: `PASSWORD=process.env.X ` repeated).
 */
function assignedSecrets(text: string): Span[] {
  const found: Span[] = [];

  const collect = (re: RegExp, valueEnd: (m: RegExpMatchArray, from: number) => number, accept: (value: string) => boolean, quoted = false) => {
    let covered = 0;

    for (const m of text.matchAll(re)) {
      if (m.index < covered || !namesSecret(m[1] ?? "")) continue;
      const from = m.index + m[0].length;

      // an unquoted reference to another value (`process.env.X`, `$X`) is one token: step past it, not past the rest of
      // the line, so a later assignment on the line is still examined (re-check of d38f704: PASSWORD=process.env.X
      // TOKEN=<secret>). A quoted one ends at its quote like any quoted value (re-check of ef953ed: "$X","token":"…")
      if (!quoted && (text.startsWith("process.env", from) || text.charAt(from) === "$")) {
        let end = from;

        while (end < text.length && !/\s/.test(text.charAt(end))) end++;
        covered = Math.max(covered, end);
        continue;
      }

      const to = valueEnd(m, from);

      covered = Math.max(covered, to);

      if (to > from && accept(text.slice(from, to))) found.push({ from, to });
    }
  };

  collect(QUOTED, (m, from) => quotedEnd(text, from, m[2] ?? ""), maskable, true);
  collect(ENV, (_, from) => lineEnd(text, from, true), maskable);
  // a line of code (`password: getPassword(),`) ends in punctuation; a YAML value does not
  collect(YAML, (_, from) => lineEnd(text, from, false), (value) => maskable(value) && !/[,;{(]$/.test(value));

  // the earliest of overlapping spans wins
  const spans: Span[] = [];

  for (const s of found.sort((a, b) => a.from - b.from)) {
    const last = spans.at(-1);

    if (last === undefined || s.from >= last.to) spans.push(s);
  }

  return spans;
}

/** How many characters of a secret of `length` stay visible at each end. */
function visible(length: number): number {
  if (length >= 24) return 4;

  if (length >= 12) return 2;

  return length >= 6 ? 1 : 0;
}

/** One secret as shown: its first and last few characters and its length, e.g. `sk-p…9xYz [redacted, 51 chars]`. */
export function maskSecret(secret: string): string {
  const chars = [...secret];
  const n = visible(chars.length);
  const ends = n === 0 ? "" : `${chars.slice(0, n).join("")}…${chars.slice(-n).join("")} `;

  return `${ends}[redacted, ${chars.length} chars]`;
}

const MASKED = " [redacted,";

/** One format match masked: the whole match, or only the rule's secret group. */
function masked(m: RegExpExecArray | RegExpMatchArray, rule: Rule): string {
  const match = m[0];
  const secret = m[rule.secret];

  if (secret === undefined) return match;
  const at = rule.secret === 0 ? 0 : match.lastIndexOf(secret);

  return `${match.slice(0, at)}${maskSecret(secret)}${match.slice(at + secret.length)}`;
}

/** `text` with every secret-shaped run masked (maskSecret). Text with none comes back as it was. */
export function redactSecrets(text: string): string {
  let out = text;

  for (const rule of FORMAT_RULES) {
    let next = "";
    let from = 0;

    for (const m of out.matchAll(rule.re)) {
      const at = m.index;
      const end = at + m[0].length;

      // a run an earlier rule already masked (`npm_…aaaa [redacted, 40 chars]` inside `_authToken=…`) stays as it is
      if (out.startsWith(MASKED, end)) continue;
      next += out.slice(from, at) + masked(m, rule);
      from = end;
    }

    out = next + out.slice(from);
  }

  let next = "";
  let from = 0;

  for (const span of assignedSecrets(out)) {
    next += out.slice(from, span.from) + maskSecret(out.slice(span.from, span.to));
    from = span.to;
  }

  return next + out.slice(from);
}

/** Whether `text` holds anything redactSecrets would mask. */
export function hasSecret(text: string): boolean {
  return redactSecrets(text) !== text;
}
