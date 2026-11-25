// What package.json scripts run at install time, followed the way the package managers follow them:
// `npm run x` and its pre/post scripts, yarn and pnpm shorthands, `sh -c '...'`, and payloads passed to
// `node -e` as base64. Also the commands a binding.gyp runs. Pure.
import { z } from "zod";
import { decodedStrings } from "./source.ts";
import { wildcardMatch } from "./glob.ts";
import { chargeText } from "./meter.ts";

/**
 * When npm runs a lifecycle script. "install": every install of the tarball. "git": when the package is
 * installed from a git URL (npm builds it with prepare and packs it). "publish": only on the publisher's machine.
 */
export type HookKind = "install" | "git" | "publish";

export const LIFECYCLE = {
  preinstall: "install",
  install: "install",
  postinstall: "install",
  prepare: "git",
  prepack: "git",
  postpack: "git",
  prepublish: "publish",
  prepublishOnly: "publish",
} as const satisfies Record<string, HookKind>;

/**
 * One command a hook runs, after following script references. `from` says how it was reached. `added`: only the shell
 * reading reaches it (expandHooks' third pass), so a reading budget takes it after every command the first two read.
 */
export type HookCommand = { from: string; text: string; viaEval: boolean; added: boolean };

/**
 * A lifecycle hook, the commands it reaches and the names of the scripts it runs (itself included). `cut` says why the
 * expansion stopped before it reached every command (nesting past MAX_DEPTH, or more than MAX_COMMANDS commands), or
 * is null when it read them all: a hook read in part is never read as one that runs nothing more.
 */
export type ExpandedHook = { hook: string; kind: HookKind; commands: HookCommand[]; scripts: string[]; cut: string | null };

const MAX_DEPTH = 8;
const MAX_COMMANDS = 200;

const SH_C = /\b(?:sh|bash|zsh|dash)\s+-c\s+(?:'([^']*)'|"((?:[^"\\]|\\.)*)")/g;
const FLAGS = String.raw`(?:[ \t]+--?\w[\w-]*(?:=[^\s;&|()'"\\$\`{}<>]*)?)*(?:[ \t]+--)?`;
const SCRIPT = String.raw`[ \t]+["']?([\w:.@/-]+)`;

// a match takes only the package manager's word: its flags and the script name are read ahead without being consumed, so
// the scan goes on from the next word, and a run held in a flag value or taken for the name (`npm --x=`npm run payload``,
// `yarn --silent npm run payload`) is still found, as main's regex, which read no flags, found it. A flag value stops at
// any separator, quote, escape or expansion, a newline ends the command, and a command may start a backtick substitution.
// A bare `--` ends the flags, as it ends npm's options: the next word is the name, and a flag after it is the script's
const RUN_REF = new RegExp(String.raw`(?:^|[;&|(\`]\s*|\s)(?:npm(?=${FLAGS}[ \t]+(?:run(?:-script)?${FLAGS}${SCRIPT}|(start|test|stop|restart)\b))|yarn(?=${FLAGS}(?:[ \t]+run${FLAGS})?${SCRIPT})|pnpm(?=${FLAGS}(?:[ \t]+run${FLAGS})?${SCRIPT})|bun(?=${FLAGS}[ \t]+run${FLAGS}${SCRIPT}))`, "dg");

// main's reading, which takes no flags, beside it: every script it finds is still followed, with its pre and post scripts
const BARE_RUN_REF = /(?:^|[;&|(]\s*|\s)(?:npm\s+(?:run(?:-script)?\s+([\w:.@/-]+)|(start|test|stop|restart)\b)|yarn(?:\s+run)?\s+([\w:.@/-]+)|pnpm(?:\s+run)?\s+([\w:.@/-]+)|bun\s+run\s+([\w:.@/-]+))/g;

// the only spellings read as setting npm's ignore-scripts; anything else that might touch it is a doubt (ignoreScriptsDoubt)
const IGNORE_SCRIPTS = /(?<!\S)--ignore-scripts(?:=true)?(?!\S)/;
const ENABLES = new Set(["--ignore-scripts", "--ignore-scripts=true"]);
const SHELL_WORD = /\S+/g;

// quoting, escapes, expansion, grouping and redirection: with any of them, where npm's arguments start and end is not known
const SHELL_SYNTAX = /['"\\$`(){}<>*?[\]]/;

// xargs appends words from its input to npm's, so they are not the words written either
const ARGS_FROM_INPUT = /(?<![\w.-])xargs(?![\w.-])/;
const RUN_ALL = /\b(?:npm-run-all|run-s|run-p)\s+((?:[\w:.@/*-]+\s*)+)/g;

// any case, as cmd.exe finds `NODE.EXE`
const INTERPRETER = /\b(?:node(?:js)?|bun|deno)(?:\.exe)?(?=\s)/gi;

// starts only after a non-space, as the sticky walk always does, so a search over a run of whitespace is linear too
const NEXT_WORD = /(?<!\s)\s+(\S+)/y;
const EVAL_FLAG = /^(?:-[a-z]*[ep]|--eval|--print|eval)\b/;
const OTHER_FLAG = /^-{1,2}\w[\w-]*(?:=\S+)?$/;

// node's options that take the next word as their value (`--conditions dev`, `-r ./x`), from `node --help` (Node 18 to
// 24); any other flag takes none, so the first other word is the program node runs and what follows is its own
const VALUE_FLAG = new RegExp(
  String.raw`^(?:-[rC]|--(?:${[
    "conditions", "require", "import", "loader", "experimental-loader", "experimental-default-type", "input-type", "redirect-warnings", "title",
    "env-file", "env-file-if-exists", "disable-warning", "watch-path", "watch-kill-signal", "unhandled-rejections", "dns-result-order",
    "icu-data-dir", "openssl-config", "tls-cipher-list", "tls-keylog", "secure-heap", "secure-heap-min", "max-http-header-size",
    "heapsnapshot-signal", "heapsnapshot-near-heap-limit", "trace-event-categories", "trace-event-file-pattern", "use-largepages",
    "localstorage-file", "experimental-config-file", "report-dir", "report-directory", "report-filename", "report-signal", "diagnostic-dir",
    "cpu-prof-dir", "cpu-prof-name", "cpu-prof-interval", "heap-prof-dir", "heap-prof-name", "heap-prof-interval", "inspect-port", "debug-port",
    "test-reporter", "test-reporter-destination", "test-name-pattern", "test-skip-pattern", "test-concurrency", "test-shard", "test-timeout",
  ].join("|")}))$`,
);

/**
 * Whether a command runs inline code: `node -e`, `node --no-warnings -pe`, `$(nodejs -e …)`, `deno eval`. An interpreter
 * may start anywhere a word boundary is, as in the regex this replaces; its flags are then read a word at a time and the
 * search goes on after the last one, so no byte is read twice: `--conditions=node` repeated cannot make each one rescan
 * the flags after it (the regex did, in time quadratic in the script), and no list of a long command's words is built.
 */
function inlineEval(cmd: string): boolean {
  const interpreter = new RegExp(INTERPRETER);
  const word = new RegExp(NEXT_WORD);

  for (let m = interpreter.exec(cmd); m !== null; m = interpreter.exec(cmd)) {
    word.lastIndex = m.index + m[0].length;
    let value = false;

    for (let w = word.exec(cmd); w !== null; w = word.exec(cmd)) {
      // the word the shell hands the interpreter: `'-e'`, `"--eval"` and `\-e` are all `-e`
      const raw = w[1] ?? "";
      const quoted = raw.length > 1 && (raw[0] === "'" || raw[0] === '"') && raw.endsWith(raw[0]);
      const flag = (quoted ? raw.slice(1, -1) : raw).replace(/^\\/, "");

      if (EVAL_FLAG.test(flag)) return true;

      if (OTHER_FLAG.test(flag)) value = VALUE_FLAG.test(flag);
      else if (value) value = false;
      else break;
      interpreter.lastIndex = word.lastIndex;
    }
  }

  return false;
}

/** package.json `scripts`, as npm reads it: entries that are not strings run nothing and are dropped. */
const ScriptsSchema = z.record(z.string(), z.string().catch("")).catch({});

export type Scripts = z.infer<typeof ScriptsSchema>;

/** The part of a manifest the lifecycle analysis reads. */
export type ScriptsManifest = { readonly scripts?: unknown };

function scriptsOf(manifest: ScriptsManifest): Scripts {
  const out: Scripts = {};

  for (const [k, v] of Object.entries(ScriptsSchema.parse(manifest.scripts))) if (v.trim()) out[k] = v;

  return out;
}

/**
 * A script a command runs through the package manager. `alone`: npm runs it without its pre and post scripts, as it does
 * for `npm run --ignore-scripts x` (npm docs, config `ignore-scripts`: commands that run a particular script still run it,
 * "but they will not run any pre- or post-scripts").
 */
type ScriptRef = { name: string; alone: boolean };

/** expandHooks' passes: main's reading, the flag-aware regex's additions, the shell reading's additions. */
type Pass = 1 | 2 | 3;

/**
 * Where the last word of `cmd` starts that could leave npm's ignore-scripts other than set: -1 when none does, and
 * Infinity when the command has any quote, escape, expansion, grouping or redirection, since then the words npm gets are
 * not the words written (`--foo="a --ignore-scripts"` is one argument). npm reads its flags anywhere in the invocation,
 * the last one winning (`npm run --ignore-scripts x --no-ignore-scripts` runs prex), and takes abbreviations (`--no-ig`)
 * and a separate `false` after the flag. So any word with "ig" in a flag other than the two spellings that set it, and a
 * `false` after a bare `--ignore-scripts`, is a doubt, read to the end of the command: past the invocation it can only
 * make apm follow more.
 */
function ignoreScriptsDoubt(cmd: string, xargs: boolean): number {
  if (SHELL_SYNTAX.test(cmd) || (xargs && ARGS_FROM_INPUT.test(cmd))) return Number.POSITIVE_INFINITY;
  let last = -1;
  let bare = false;

  for (const m of cmd.matchAll(SHELL_WORD)) {
    const w = m[0];

    if ((bare && /^false\b/i.test(w)) || (w.startsWith("-") && /ig/i.test(w) && !ENABLES.has(w))) last = m.index;
    bare = w === "--ignore-scripts";
  }

  return last;
}

/** Scripts main's reading finds a command run, in its order: its regex, then npm-run-all. */
function mainReferences(cmd: string, scripts: Scripts): string[] {
  const out: string[] = [];

  for (const m of cmd.matchAll(BARE_RUN_REF)) {
    const name = m[1] ?? m[2] ?? m[3] ?? m[4] ?? m[5];

    // `yarn add x` or `pnpm install` are package manager commands, not scripts
    if (name && Object.hasOwn(scripts, name)) out.push(name);
  }

  for (const m of cmd.matchAll(RUN_ALL)) {
    for (const pattern of (m[1] ?? "").trim().split(/\s+/)) {
      for (const name of Object.keys(scripts)) if (wildcardMatch(name, pattern)) out.push(name);
    }
  }

  return out;
}

/**
 * Whether the words between npm and the script name set ignore-scripts and do nothing else: `run` or `run-script`, the
 * two spellings that set it, and `--`. Any other word may be a flag that takes the next word as its value
 * (`--registry --ignore-scripts` sets the registry), so npm may not have read the flag at all.
 */
function setsIgnoreScripts(words: string): boolean {
  const ws = words.trim().split(/\s+/);

  return IGNORE_SCRIPTS.test(words) && ws.every((w) => ENABLES.has(w) || w === "run" || w === "run-script" || w === "--");
}

/** Scripts the flag-aware reading finds a command run, in order, each with whether npm runs it alone. */
function flagReferences(cmd: string, scripts: Scripts): (ScriptRef & { aloneStrictly: boolean })[] {
  const out: (ScriptRef & { aloneStrictly: boolean })[] = [];
  let doubt: number | null = null;
  let strictDoubt: number | null = null;

  for (const m of cmd.matchAll(RUN_REF)) {
    const npm = m[1] ?? m[2];
    const name = npm ?? m[3] ?? m[4] ?? m[5];

    if (!name || !Object.hasOwn(scripts, name)) continue;

    // npm's flags before the name set ignore-scripts, and nothing from there on may unset it; the doubt is found once per
    // command, so a script of many such runs is still read in one pass. `alone` is fe2e641's reading, which the second
    // pass keeps; `aloneStrictly` also doubts a flag that may take the next word as its value and words xargs adds, and
    // the third pass reads the pre and post scripts where only the first says alone
    const [nameAt] = m.indices?.[m[1] === undefined ? 2 : 1] ?? [m.index];
    const sets = npm !== undefined && IGNORE_SCRIPTS.test(cmd.slice(m.index, nameAt));
    const alone = sets && (doubt ??= ignoreScriptsDoubt(cmd, false)) < m.index;

    out.push({ name, alone, aloneStrictly: alone && setsIgnoreScripts(cmd.slice(m.index + m[0].length, nameAt)) && (strictDoubt ??= ignoreScriptsDoubt(cmd, true)) < m.index });
  }

  return out;
}

/**
 * Scripts the shell reading finds a command run that neither main's reading nor the flag-aware regex read in that
 * invocation, each run with its pre and post scripts: the regex's reading of an invocation stands for it, and any other
 * invocation runs them whether or not the same name was run alone elsewhere.
 */
function shellReferences(cmd: string, scripts: Scripts): ScriptRef[] {
  const read = new Set<string>(mainReferences(cmd, scripts));
  const regex = new Set<string>();

  for (const m of cmd.matchAll(RUN_REF)) regex.add(`${m.index + m[0].length}\0${m[1] ?? m[2] ?? m[3] ?? m[4] ?? m[5]}`);

  const doubted = flagReferences(cmd, scripts).flatMap((r) => (r.alone && !r.aloneStrictly ? [{ name: r.name, alone: false }] : []));
  const shell = shellRunReferences(cmd, scripts).flatMap((r) => (read.has(r.name) || regex.has(`${r.end}\0${r.name}`) ? [] : [{ name: r.name, alone: false }]));

  return [...doubted, ...shell];
}

const PACKAGE_MANAGERS = new Set(["npm", "yarn", "pnpm", "bun"]);
const NPM_LIFECYCLE_COMMANDS = new Set(["start", "test", "stop", "restart"]);
const COMMAND_END = new Set([";", "&", "|", "(", ")", "`", "\n"]);

/**
 * The words of `cmd` as the shell hands them over, quotes and escapes removed (`'-s'`, `\\-s` and `""-s` are all
 * `-s`, `'a b'` is one word), each with where it ends in `cmd` and whether an unquoted `*` makes it a glob, and `null`
 * where a command ends: `;`, `&`, `|`, a newline, a parenthesis, `$(` or a backtick. One pass; a quote left open runs
 * to the end of `cmd`.
 */
export function* shellWords(cmd: string): Generator<{ word: string; end: number; glob: boolean } | null> {
  let word: string | null = null;
  let glob = false;
  let i = 0;
  // what closes each context the reading is in: `"` a double-quoted string, `)` or a backtick a command substitution
  const open: string[] = [];

  const flush = function* (): Generator<{ word: string; end: number; glob: boolean }> {
    if (word !== null) yield { word, end: i, glob };
    word = null;
    glob = false;
  };

  for (; i < cmd.length; i++) {
    const c = cmd[i] ?? "";
    const next = cmd[i + 1] ?? "";

    if (open.at(-1) === '"') {
      // inside double quotes: a backslash escapes only $, `, ", \ and a newline (which it removes), as the shell reads it,
      // and a command substitution is a command of its own
      if (c === '"') open.pop();
      else if (c === "\\" && next === "\n") i++;
      else if (c === "\\" && /[$`"\\]/.test(next)) word = (word ?? "") + (cmd[++i] ?? "");
      else if ((c === "$" && next === "(") || c === "`") {
        yield* flush();
        yield null;
        open.push(c === "`" ? "`" : ")");

        if (c === "$") i++;
      } else word = (word ?? "") + c;
    } else if (c === "'") {
      const j = cmd.indexOf("'", i + 1);
      const close = j < 0 ? cmd.length : j;

      word = (word ?? "") + cmd.slice(i + 1, close);
      i = close;
    } else if (c === '"') {
      open.push('"');
      word ??= "";
    } else if (c === "\\") {
      if (next === "\n") i++;
      else word = (word ?? "") + (cmd[++i] ?? "");
    } else if ((c === ")" || c === "`") && open.at(-1) === c) {
      yield* flush();
      yield null;
      open.pop();
    } else if ((c === "$" && next === "(") || c === "`") {
      yield* flush();
      yield null;
      open.push(c === "`" ? "`" : ")");

      if (c === "$") i++;
    } else if (COMMAND_END.has(c)) {
      yield* flush();
      yield null;

      // a group's `)` closes it, not the substitution around it
      if (c === "(") open.push(")");
    } else if (/\s|[<>]/.test(c)) yield* flush();
    else {
      glob ||= c === "*";
      word = (word ?? "") + c;
    }
  }

  yield* flush();
}

/**
 * Scripts a command runs through a package manager, read from the words the shell hands it, so quoted and escaped flags
 * and names and flags that take the next word as their value (`npm --prefix . run x`, `npm run -w pkg x`) do not hide
 * the run. Where a word after a flag may be its value or the name, both readings are followed: following a script npm
 * does not run can only make the reading stricter. Each word is read once. `end` is where the manager's word ends.
 */
function shellRunReferences(cmd: string, scripts: Scripts): { name: string; end: number }[] {
  // a manager's word is in the text as written unless quotes or escapes split it
  if (!/npm|yarn|bun|['"\\]/.test(cmd)) return [];
  const out: { name: string; end: number }[] = [];
  let pm: string | null = null;
  let pmEnd = 0;
  let phase: "manager" | "run" | "named" = "manager";
  let afterFlag = false;

  const takesName = (): boolean => pm !== null && (phase !== "manager" || pm === "yarn" || pm === "pnpm");

  const name = (w: string): void => {
    if (Object.hasOwn(scripts, w)) out.push({ name: w, end: pmEnd });

    if (afterFlag) afterFlag = false;
    else pm = null;
  };

  for (const t of shellWords(cmd)) {
    if (t === null) {
      pm = null;
      continue;
    }

    const w = t.word;

    if (PACKAGE_MANAGERS.has(w)) {
      // a manager's name may also be the script's (`npm run --silent npm`) or a flag's value (`npm --prefix npm run x`),
      // and the regex's reading still takes it as a manager (flagReferences)
      if (takesName() && Object.hasOwn(scripts, w)) out.push({ name: w, end: pmEnd });

      if (pm !== null && afterFlag) {
        afterFlag = false;
        continue;
      }

      pm = w;
      pmEnd = t.end;
      phase = "manager";
      afterFlag = false;
      continue;
    }

    if (pm === null) continue;

    if (phase === "named") {
      name(w);
      pm = null;
    } else if (w === "--") {
      afterFlag = false;

      if (phase === "run" || pm === "yarn" || pm === "pnpm") phase = "named";
    } else if (w.length > 1 && w.startsWith("-")) {
      afterFlag = !w.includes("=");
    } else if (phase === "manager" && (w === "run" || (pm === "npm" && w === "run-script"))) {
      phase = "run";
      afterFlag = false;
    } else if (takesName() || (pm === "npm" && NPM_LIFECYCLE_COMMANDS.has(w))) {
      name(w);
    } else if (afterFlag) {
      afterFlag = false;
    } else {
      pm = null;
    }
  }

  return out;
}

/**
 * Every lifecycle hook in the manifest with the commands it reaches, read in two passes so main's coverage holds by
 * construction. The first is main's traversal exactly: main's references only, with every pre and post script, its depth
 * rule and its MAX_COMMANDS budget, so it reads the commands main reads and is cut where main is. The second goes back
 * over each command the first read, at the depth it read it, and follows only what the flag-aware reading adds there,
 * and everything that reaches, with the budget left. It reads no script the first did, so it pushes no command twice, and
 * a script npm runs alone (`npm run --ignore-scripts x`) loses only pre and post scripts the first never read.
 */
export function expandHooks(manifest: ScriptsManifest): ExpandedHook[] {
  const scripts = scriptsOf(manifest);
  const out: ExpandedHook[] = [];

  for (const [hook, kind] of Object.entries(LIFECYCLE)) {
    const own = scripts[hook];

    if (own === undefined) continue;
    const commands: HookCommand[] = [];
    const followed = new Set<string>([hook]);
    // what the first two passes read, for the next to read its references in
    const read: { text: string; depth: number }[] = [];
    let cut: string | null = null;

    /** Whether a command at this depth may be read, or the reading is cut, and why. */
    const admits = (from: string, depth: number): boolean => {
      if (depth > MAX_DEPTH) {
        cut ??= `${from}: commands nested more than ${MAX_DEPTH} levels deep (sh -c, decoded text, npm run)`;

        return false;
      }

      if (commands.length >= MAX_COMMANDS) {
        cut ??= `${from}: more than ${MAX_COMMANDS} commands`;

        return false;
      }

      return true;
    };

    // the first pass marks a script followed before its body is admitted, as main does; the later ones only once it is, so
    // a script they reached but could not read stays one no hook reaches and keeps its standalone reading (otherScripts)
    const follow = (refs: readonly ScriptRef[], depth: number, pass: Pass): void => {
      for (const { name, alone } of refs) {
        for (const n of alone ? [name] : [`pre${name}`, name, `post${name}`]) {
          const body = scripts[n];
          const from = `scripts.${n} (run by scripts.${hook})`;

          if (body === undefined || followed.has(n) || (pass !== 1 && !admits(from, depth + 1))) continue;
          followed.add(n);
          visit(body, from, depth + 1, false, pass);
        }
      }
    };

    const visit = (text: string, from: string, depth: number, viaEval: boolean, pass: Pass): void => {
      if (!admits(from, depth)) return;

      const evals = viaEval || inlineEval(text);
      commands.push({ from, text, viaEval: evals, added: pass === 3 });

      if (pass !== 3) read.push({ text, depth });

      for (const m of text.matchAll(SH_C)) visit((m[1] ?? m[2] ?? "").replace(/\\(.)/g, "$1"), `${from} (sh -c)`, depth + 1, evals, pass);

      for (const d of decodedStrings(text)) visit(d.value, `${from} (decoded ${d.how})`, depth + 1, evals, pass);

      const main = mainReferences(text, scripts).map((name) => ({ name, alone: false }));

      follow(pass === 1 ? main : [...main, ...flagReferences(text, scripts), ...(pass === 3 ? shellReferences(text, scripts) : [])], depth, pass);
    };

    visit(own, `scripts.${hook}`, 0, false, 1);

    // the second pass over what the first read, then the third over what either read
    for (const [pass, n] of [[2, read.length], [3, Number.POSITIVE_INFINITY]] as const) {
      for (let i = 0; i < Math.min(n, read.length); i++) {
        const { text, depth } = read[i] ?? { text: "", depth: 0 };
        const main = new Set(mainReferences(text, scripts));
        const refs = pass === 2 ? flagReferences(text, scripts).filter((r) => !main.has(r.name)) : shellReferences(text, scripts);

        follow(refs, depth, pass);
      }
    }

    out.push({ hook, kind, commands, scripts: [...followed], cut });
  }

  return out;
}

/** The scripts no lifecycle hook reaches: `test`, `build`, `lint`. They never run on an installer's machine. */
export function otherScripts(manifest: ScriptsManifest, hooks: readonly ExpandedHook[]): Scripts {
  const reached = new Set(hooks.flatMap((h) => h.scripts));
  const out: Scripts = {};

  for (const [k, v] of Object.entries(scriptsOf(manifest))) if (!reached.has(k)) out[k] = v;

  return out;
}

/** Packages a command runs with npx, bunx, pnpx, `pnpm dlx`, `yarn dlx` or `npm exec`, without their version. */
export function npxPackages(cmd: string): string[] {
  const out: string[] = [];

  for (const m of cmd.matchAll(/(?:^|[;&|(\s])(?:npx|bunx|pnpx|pnpm\s+dlx|yarn\s+dlx|npm\s+exec)((?:\s+[^\s;&|()]+)+)/g)) {
    const words = (m[1] ?? "").trim().split(/\s+/);

    for (let i = 0; i < words.length; i++) {
      const w = words[i] ?? "";

      // --package=x and -p x name the package; other flags (--yes, -y) are skipped
      if (w === "-p" || w === "--package") {
        out.push(words[i + 1] ?? "");
        i++;
        continue;
      }

      if (w.startsWith("--package=")) {
        out.push(w.slice("--package=".length));
        continue;
      }

      if (w.startsWith("-")) continue;
      out.push(w);
      break;
    }
  }

  return out.flatMap((p) => (p ? [p.replace(/(.)@[^/@]*$/, "$1")] : []));
}

export type DownloadContext = {
  /** The command reached `node -e` or similar, so network words in it are code that runs. */
  viaEval?: boolean;
  /** Packages installed alongside this one: running their bins with npx downloads nothing. */
  localBins?: ReadonlySet<string>;
};

/** The canonical dropper shape: a command that fetches remote code, or fetches a package and runs it. */
export function isInlineDownload(cmd: string, ctx: DownloadContext = {}): boolean {
  if (/\b(?:curl|wget|iwr|Invoke-WebRequest)\b/i.test(cmd)) return true;

  if (/\|\s*(?:ba|z)?sh\b/.test(cmd)) return true;

  if (npxPackages(cmd).some((p) => !ctx.localBins?.has(p))) return true;
  const evals = ctx.viaEval === true || inlineEval(cmd);

  return evals && /https?|fetch|\bnet\b|child_process|exec/.test(cmd);
}

/** Words a reading of a command or script found: all of them, or the first few and a cut, past which it read no more. */
export type ShellWords = { readonly kind: "complete" | "cut"; readonly words: string[] };

/** Paths a command runs or reads: every word that could name a file, `./setup` and `setup.js` alike. */
export function commandWords(cmd: string): string[] {
  return commandWordsWithin(cmd, Number.POSITIVE_INFINITY).words;
}

/**
 * commandWords, `max` at most, read one at a time (a script's whole text is read for them: a split of 32 MB of short
 * words was an array of millions), and cut past that: what the rest names is not known (round 13 review of d594415, P2).
 */
export function commandWordsWithin(cmd: string, max: number): ShellWords {
  const words: string[] = [];

  for (const m of cmd.matchAll(/[^\s;&|()<>'"=`]+/g)) {
    const w = m[0];

    if (w.startsWith("-") || w.startsWith("$") || !/^[\w@./-]+$/.test(w)) continue;

    if (words.length >= max) return { kind: "cut", words };
    words.push(w.replace(/^\.\//, ""));
  }

  return { kind: "complete", words };
}

/** Commands a binding.gyp runs at install: `<!(...)` expansions and the argv of every action. */
export function gypCommands(text: string): string[] {
  const out: string[] = [];

  for (const m of text.matchAll(/<!@?\(([^)]*)\)/g)) out.push(m[1] ?? "");

  for (const m of text.matchAll(/['"]action['"]\s*:\s*\[([^\]]*)\]/g)) {
    out.push(quotedStrings(m[1] ?? "").join(" "));
  }

  return out;
}

/**
 * The bodies of the single- and double-quoted strings in `s`, backslash escapes kept, as
 * `/'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"/g` finds them, in one pass. That regex scanned to the end from every quote
 * of an unterminated run (`'\'\'\'…`), quadratic in it. Once a quote character has been read to the end of `s` without
 * closing, every later one of that character would be too (its read is the end of the first one's), so it is skipped.
 */
function quotedStrings(s: string): string[] {
  const out: string[] = [];
  const open = new Set<string>();

  chargeText("text", s.length, 3);

  for (let i = 0; i < s.length; i++) {
    const q = s[i];

    if ((q !== "'" && q !== '"') || open.has(q)) continue;
    let j = i + 1;

    while (j < s.length && s[j] !== q) j += s[j] === "\\" ? 2 : 1;

    if (j >= s.length) {
      open.add(q);
      continue;
    }

    out.push(s.slice(i + 1, j));
    i = j;
  }

  return out;
}
