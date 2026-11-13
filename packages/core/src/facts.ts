// What one file shows about the capabilities and risks apm-score-v10 reports beyond the code signals: which
// environment variables it reads, whether it dumps the whole environment, loads the filesystem, reads a credential
// file, fingerprints the host, names a data-capture endpoint, holds a remote shell or download-and-run command, or
// carries obfuscator output. Text rules over the file; in a parsed file a match in a comment, a regex body or a type
// is left out, and in a file with no tree every match is kept and marked as a text match. In a parsed file the flow
// analysis (flow.ts) adds what a character window cannot show: a value reaching the call that sends, runs or reads it
// (`sends-*`, `runs-download`, `reads-credential`); score.ts turns those into facts. Pure.
import type { Command } from "./js.ts";
import { escapedTextAt, hexIdentifierRun, lineOf, longBase64Text, type Hidden } from "./rules.ts";
import { chargeText } from "./meter.ts";

export const FACT_KINDS = [
  "env",
  "env-dump",
  "env-object",
  "filesystem",
  "credential-read",
  "credential-near",
  "host-info",
  "capture-endpoint",
  "remote-shell",
  "obfuscator",
  "fetched-code",
  "detached",
  // what the flow analysis shows a value reach (score.ts makes these from flow.ts)
  "reads-credential",
  "sends-env",
  "sends-credential",
  "sends-secrets",
  "runs-download",
  "runs-hidden",
  // downloaded text spliced into a longer shell command: a possible flow, not a confirmed one
  "splices-download",
] as const;

export type FactKind = (typeof FACT_KINDS)[number];

/**
 * One fact: what, where, and for `env` the variable's name (`*` for a name built at runtime). `text` says the file had
 * no tree, so apm could not tell whether the match sits in code. `near` says a network call sits within NEAR_NETWORK
 * characters of it, or the whole file is shorter than SMALL_FILE: what a stealer collects and sends sits together.
 */
export type Fact = { kind: FactKind; line: number; snippet: string; name?: string; text: boolean; near: boolean };

/** How close a network call must be to what a file collects for the two to read as one flow, and a file short enough to be one. */
const NEAR_NETWORK = 1500;
const SMALL_FILE = 16 * 1024;

const NETWORK_CALL =
  /\bfetch\s*\(|\b(?:https?|http2|net|tls|dgram)\s*\.\s*(?:get|request|connect|createConnection|Socket)\b|\b(?:axios|got|superagent|needle|request)\s*[.(]|\brequire\s*\(\s*['"](?:axios|got|superagent|needle|request|node-fetch|undici|ws)['"]\s*\)|\bXMLHttpRequest\b|\bWebSocket\b|\bsendBeacon\b|\bdns\s*\.\s*(?:lookup|resolve)|\b(?:curl|wget)\s|\bInvoke-WebRequest\b/;

/** At most this many facts of one kind per file: enough to name what a file does, bounded on a 30 MB bundle. */
const MAX_PER_KIND = 40;

/** What a stealer collects: past MAX_PER_KIND, these are still recorded where they sit beside a network call. */
const PLACED_PAST_CAP: ReadonlySet<FactKind> = new Set(["env-dump", "credential-read", "host-info"]);

/** Literal environment reads: `process.env.X`, `process.env?.X`, `process.env['X']`, `Bun.env.X`, `Deno.env.get('X')`. */
const ENV_READ = /\b(?:process\s*\.\s*env|Bun\s*\.\s*env)\s*(?:\?\.\s*|\.\s*)([A-Za-z_$][\w$]*)|\b(?:process\s*\.\s*env|Bun\s*\.\s*env)\s*(?:\?\.)?\[\s*(['"`])([^'"`\n]{1,100})\2\s*\]|\bDeno\s*\.\s*env\s*\.\s*get\s*\(\s*(['"`])([^'"`\n]{1,100})\4/g;

/** A read by a name built at runtime: `process.env[name]`. */
const ENV_COMPUTED = /\b(?:process\s*\.\s*env|Bun\s*\.\s*env)\s*(?:\?\.)?\[\s*(?!['"`])[^\]\n]{1,100}\]|\bDeno\s*\.\s*env\s*\.\s*get\s*\(\s*(?!['"`])/g;

/** `const { A, B: b } = process.env`. */
const ENV_DESTRUCTURE = /\{([^{}]{1,600})\}\s*=\s*(?:process\s*\.\s*env|Bun\s*\.\s*env)\b/g;

/** The environment object itself, ended: `process.env` or `Bun.env` with no member after it (`process.env.X` is one variable). */
const ENV_OBJECT = String.raw`(?:\b(?:globalThis|global|window|self)\s*\.\s*)?\b(?:process\s*\.\s*env|Bun\s*\.\s*env)(?!\s*(?:\?\.|\.|\[|[\w$]))`;

/**
 * Methods that hand back the variables themselves, not one value: these read the whole environment. No two blank runs
 * sit next to each other with only optional text between them (`\s*(?:const)?\s*` split a run of n blanks n ways, from
 * one `for (`), so a run is read once.
 */
const ENV_DUMP = new RegExp(
  String.raw`\bJSON\s*\.\s*stringify\s*\(\s*${ENV_OBJECT}|\bObject\s*\.\s*(?:keys|entries|values|getOwnPropertyNames)\s*\(\s*${ENV_OBJECT}\s*\)|\bObject\s*\.\s*assign\s*\(\s*\{\s*\}\s*,\s*${ENV_OBJECT}\s*\)|\bfor\s*\(\s*(?:(?:const|let|var)\s+)?[\w$]+\s+in\s+${ENV_OBJECT}|\bDeno\s*\.\s*env\s*\.\s*toObject\s*\(|\bprintenv\b`,
  "g",
);

const FS_LOAD =
  /(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s+|\bgetBuiltinModule\s*\(\s*)['"`](?:node:)?(?:fs|fs\/promises)['"`]|(?:\brequire\s*\(\s*|\bfrom\s+)['"](?:fs-extra|graceful-fs)['"]|\bBun\s*\.\s*(?:file|write)\s*\(|\bDeno\s*\.\s*(?:readTextFile|readFile|writeTextFile|writeFile|open|remove|mkdir)\b/g;

/**
 * Files that hold credentials or session data: npm, yarn and pip settings, SSH keys, cloud and container credentials,
 * git and netrc logins, shell history, GnuPG, browser profiles and wallet stores.
 */
const CREDENTIAL_PATH =
  /\.npmrc\b|\.yarnrc\b|\.pypirc\b|\.ssh[/\\]|['"`/\\]\.ssh\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws[/\\](?:credentials|config)\b|\.git-credentials\b|\.netrc\b|\.docker[/\\]config\.json|\.kube[/\\]config\b|\.config[/\\]gcloud|\.azure[/\\]|\.gnupg\b|\.(?:bash|zsh)_history\b|\bLogin Data\b|\bLocal State\b|Local Extension Settings|User Data[/\\]|Google[/\\]Chrome|BraveSoftware|Mozilla[/\\]Firefox|\.mozilla[/\\]firefox|Library[/\\]Keychains|wallet\.dat\b|\.electrum\b|\.config[/\\]solana|\bExodus[/\\]/g;

/** One credential path in a string, for the flow analysis (flow.ts) to tell a path that names a credential file. */
export const CREDENTIAL_NAME = new RegExp(CREDENTIAL_PATH.source);

/**
 * A read: a file API call, a file read named on its own (`require('fs')['readFileSync']`, `const read = fs.readFileSync`),
 * or a shell command that prints, copies or packs a file.
 */
const READ_NEAR = /\b(?:readFileSync|readFile|createReadStream|readdirSync|readdir|copyFileSync|copyFile|existsSync|accessSync|openSync)\s*\(|\b(?:readFileSync|readFile|createReadStream|copyFileSync|copyFile|openSync)\b|\bBun\s*\.\s*file\s*\(|\bDeno\s*\.\s*read\w*\s*\(|(?:^|[\s'"`;|&(])(?:cat|type|more|cp|scp|tar|zip|base64|Get-Content)\s/;

/** How far apart (in characters) a credential path and a read may sit to count as one read. */
const READ_WINDOW = 300;

/** Identity of the machine and its user: what a dependency-confusion probe collects and sends home. */
const HOST_INFO = /\bos\s*\.\s*(?:hostname|userInfo|networkInterfaces)\s*\(|\b(?:hostname|userInfo|networkInterfaces)\s*\(\s*\)|\bwhoami\b|\buname\s+-a\b|\b(?:api\.ipify\.org|ipinfo\.io|ifconfig\.me|icanhazip\.com|checkip\.amazonaws\.com|ip-api\.com)\b/g;

/**
 * Services that exist to receive data from anywhere: request bins, out-of-band interaction servers, chat webhooks
 * with their secret in the URL, and raw TCP tunnels. Packages that use them in shipped code are, almost always, sending
 * the installing machine's data to whoever holds the bin.
 */
const CAPTURE_ENDPOINT =
  /\bwebhook\.site\b|\b(?:oastify\.com|burpcollaborator\.net|interact\.sh|interactsh\.com|dnslog\.cn|ceye\.io|bxss\.me|requestbin\.(?:com|net)|requestcatcher\.com|beeceptor\.com|hookbin\.com|canarytokens\.(?:com|org)|pipedream\.net|webhook\.office\.com)\b|\.oast\.(?:fun|me|pro|live|site|online)\b|discord(?:app)?\.com\/api\/webhooks\/\d{6,}|api\.telegram\.org\/bot\d{5,}:|\b\d+\.tcp\.(?:\w+\.)?ngrok\.io\b|hooks\.slack\.com\/services\/T\w+\//g;

/**
 * A command that opens a shell to another machine, or downloads a program and runs it: `/dev/tcp/` redirects, `nc -e`,
 * `sh -i`, `curl … | sh`, `curl -o x; chmod +x`, PowerShell's `IEX … DownloadString` and encoded commands, certutil.
 */
const REMOTE_SHELL =
  /\/dev\/tcp\/|\bnc(?:at)?\s+(?:-\w+\s+)*-e\s|\b(?:ba)?sh\s+-i\b|\b(?:curl|wget)\b[^\n'"`]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\b(?:curl|wget)\b[^\n]{0,200}\s-[oO]\s*\S+[^\n]{0,120}\bchmod\s+\+?[0-7x]+|\bIEX\b[^\n]{0,120}DownloadString|Invoke-Expression[^\n]{0,120}(?:DownloadString|WebClient)|powershell[^\n]{0,60}\s-(?:e|enc|EncodedCommand)\s|\bcertutil\b[^\n]{0,60}-urlcache/gi;

/** An evaluator handed a value, not a literal: `eval(r.data)`, `new Function.constructor("require", s)`, `vm.runInThisContext(code)`. */
const EVAL_VALUE = /(?<![\w$.])eval\s*\(\s*(?!['"`)])|\bFunction(?:\s*\.\s*constructor)?\s*\(\s*(?:['"`][\w$]*['"`]\s*,\s*)*(?!['"`)])[\w$]|\brunIn(?:This|New)?Context\s*\(\s*(?!['"`)])|\bcompileFunction\s*\(\s*(?!['"`)])/g;

/** How far before an evaluator a network call may sit for the two to read as running what was fetched. */
const FETCH_WINDOW = 600;

/** A child process started so that it outlives its parent. */
const DETACHED = /\bdetached\s*:\s*(?:true|!0)\b/g;

const SECRET_FAMILIES: readonly { family: string; re: RegExp }[] = [
  { family: "npm", re: /^(?:NPM_TOKEN|NODE_AUTH_TOKEN|NPM_AUTH_TOKEN|NPM_CONFIG__?AUTH(?:TOKEN)?)$/i },
  { family: "GitHub", re: /^(?:GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT|GH_PAT|GITHUB_PERSONAL_ACCESS_TOKEN)$/ },
  { family: "AWS", re: /^AWS_(?:SECRET_ACCESS_KEY|ACCESS_KEY_ID|SESSION_TOKEN)$/ },
  { family: "Google Cloud", re: /^(?:GOOGLE_APPLICATION_CREDENTIALS|GCP_\w*KEY\w*|GOOGLE_\w*API_KEY)$/ },
  { family: "Azure", re: /^AZURE_\w*(?:SECRET|KEY|TOKEN|PASSWORD)\w*$/ },
  { family: "CI", re: /^(?:CI_JOB_TOKEN|GITLAB_TOKEN|CIRCLE_TOKEN|TRAVIS_TOKEN|BUILDKITE_\w*TOKEN|VERCEL_TOKEN|NETLIFY_AUTH_TOKEN)$/ },
  { family: "chat", re: /^(?:SLACK_\w*TOKEN|DISCORD_\w*TOKEN|TELEGRAM_\w*TOKEN)$/ },
  { family: "AI", re: /^(?:OPENAI_API_KEY|ANTHROPIC_API_KEY)$/ },
];

/** The credential family an environment variable belongs to, for the variables stealers go for; null for any other. */
export function secretFamily(name: string): string | null {
  return SECRET_FAMILIES.find((f) => f.re.test(name))?.family ?? null;
}

type Where = (index: number) => Hidden | undefined;

/**
 * The facts in one file's text. `hidden`, from the parser, says what left-out text a position sits in; without it
 * (no tree) every match counts and is marked `text`.
 */
export function factsOf(text: string, hidden?: Where, commands?: readonly Command[]): Fact[] {
  const out: Fact[] = [];
  const counts = new Map<FactKind, number>();
  const isText = hidden === undefined;
  const inCode = (index: number): boolean => hidden?.(index) === undefined;

  const nearCounts = new Map<FactKind, number>();

  const push = (kind: FactKind, index: number, name?: string): boolean => {
    const n = counts.get(kind) ?? 0;

    if (!inCode(index)) return false;

    // past MAX_PER_KIND, a harvest kind is still placed: one beside a network call is recorded (up to MAX_PER_KIND
    // more), so forty far ones cannot hide the one next to the request
    if (n >= MAX_PER_KIND && (!PLACED_PAST_CAP.has(kind) || (nearCounts.get(kind) ?? 0) >= MAX_PER_KIND || text.length < SMALL_FILE)) return false;

    if (text.length >= SMALL_FILE) chargeText("text", 2 * NEAR_NETWORK, 2);
    const near = text.length < SMALL_FILE || NETWORK_CALL.test(text.slice(Math.max(0, index - NEAR_NETWORK), index + NEAR_NETWORK));

    if (n >= MAX_PER_KIND && !near) return false;
    counts.set(kind, n + 1);

    if (near) nearCounts.set(kind, (nearCounts.get(kind) ?? 0) + 1);

    const where = lineOf(text, index);
    out.push(name === undefined ? { kind, ...where, text: isText, near } : { kind, ...where, name, text: isText, near });

    return true;
  };

  const each = (re: RegExp, fn: (m: RegExpExecArray) => void): void => {
    chargeText("text", text.length);
    re.lastIndex = 0;
    let tries = 0;

    for (let m = re.exec(text); m; m = re.exec(text)) {
      chargeText("text", m[0].length + 32);

      if (m[0].length === 0) re.lastIndex++;
      else fn(m);

      // a bundle can match thousands of times; the facts stop at MAX_PER_KIND, the scan a little later
      if (++tries >= MAX_PER_KIND * 50) break;
    }
  };

  const names = new Set<string>();

  each(ENV_READ, (m) => {
    const written = m[1] ?? m[3] ?? m[5] ?? "";
    // a template with a placeholder is a name built at runtime
    const name = written.includes("${") ? "*" : written;

    if (!names.has(name) && push("env", m.index, name)) names.add(name);
  });
  each(ENV_DESTRUCTURE, (m) => {
    for (const part of (m[1] ?? "").split(",")) {
      const name = part.split(":")[0]?.trim().replace(/^\.\.\./, "") ?? "";

      if (/^[A-Za-z_$][\w$]*$/.test(name) && !names.has(name) && push("env", m.index, name)) names.add(name);
    }
  });
  each(ENV_COMPUTED, (m) => {
    if (!names.has("*") && push("env", m.index, "*")) names.add("*");
  });
  each(ENV_DUMP, (m) => push("env-dump", m.index));
  each(FS_LOAD, (m) => push("filesystem", m.index));
  // a credential path near a read: in a file with no tree that is the read; in a parsed file the flow analysis shows
  // the reads, and the window is only a supplement (a deny list beside a generic read names the path and reads nothing)
  each(CREDENTIAL_PATH, (m) => {
    chargeText("text", 2 * READ_WINDOW + m[0].length, 2);
    const window = text.slice(Math.max(0, m.index - READ_WINDOW), m.index + m[0].length + READ_WINDOW);

    if (READ_NEAR.test(window)) push(isText ? "credential-read" : "credential-near", m.index);
  });
  each(HOST_INFO, (m) => push("host-info", m.index));
  each(EVAL_VALUE, (m) => {
    chargeText("text", FETCH_WINDOW, 2);

    if (NETWORK_CALL.test(text.slice(Math.max(0, m.index - FETCH_WINDOW), m.index))) push("fetched-code", m.index);
  });
  each(DETACHED, (m) => push("detached", m.index));
  each(CAPTURE_ENDPOINT, (m) => push("capture-endpoint", m.index, m[0]));

  // a parsed file's commands are what it hands a process; text that only prints such a command (install instructions) is not one
  if (commands) {
    for (const c of commands) {
      chargeText("text", c.value.length);
      REMOTE_SHELL.lastIndex = 0;

      if (REMOTE_SHELL.test(c.value) && (counts.get("remote-shell") ?? 0) < MAX_PER_KIND) {
        counts.set("remote-shell", (counts.get("remote-shell") ?? 0) + 1);
        out.push({ kind: "remote-shell", line: c.line, snippet: c.snippet, text: false, near: true });
      }
    }
  } else each(REMOTE_SHELL, (m) => push("remote-shell", m.index));

  const hex = hexIdentifierRun(text);

  if (hex >= 0) push("obfuscator", hex, "_0x identifiers");
  const escapes = escapedTextAt(text);

  if (escapes >= 0) push("obfuscator", escapes, "\\x escapes that spell text");

  chargeText("text", text.length);

  for (const m of text.matchAll(/['"]([A-Za-z0-9+/]{2000,}={0,2})['"]/g)) {
    if (longBase64Text(m[1] ?? "")) {
      push("obfuscator", m.index, "base64 that decodes to text");
      break;
    }
  }

  return out;
}
