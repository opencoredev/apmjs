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

/** One command a hook runs, after following script references. `from` says how it was reached. */
export type HookCommand = { from: string; text: string; viaEval: boolean };

/**
 * A lifecycle hook, the commands it reaches and the names of the scripts it runs (itself included). `cut` says why the
 * expansion stopped before it reached every command (nesting past MAX_DEPTH, or more than MAX_COMMANDS commands), or
 * is null when it read them all: a hook read in part is never read as one that runs nothing more.
 */
export type ExpandedHook = { hook: string; kind: HookKind; commands: HookCommand[]; scripts: string[]; cut: string | null };

const MAX_DEPTH = 8;
const MAX_COMMANDS = 200;

const SH_C = /\b(?:sh|bash|zsh|dash)\s+-c\s+(?:'([^']*)'|"((?:[^"\\]|\\.)*)")/g;
const FLAGS = String.raw`(?:\s+--?\w[\w-]*(?:=[^\s;&|()]*)?)*`;
const SCRIPT = String.raw`\s+["']?([\w:.@/-]+)`;
const RUN_REF = new RegExp(String.raw`(?:^|[;&|(]\s*|\s)(?:npm${FLAGS}\s+(?:run(?:-script)?${FLAGS}${SCRIPT}|(start|test|stop|restart)\b)|yarn${FLAGS}(?:\s+run${FLAGS})?${SCRIPT}|pnpm${FLAGS}(?:\s+run${FLAGS})?${SCRIPT}|bun${FLAGS}\s+run${FLAGS}${SCRIPT})`, "g");

// the only spellings read as setting npm's ignore-scripts; anything else that might touch it is a doubt (ignoreScriptsDoubt)
const IGNORE_SCRIPTS = /(?<!\S)--ignore-scripts(?:=true)?(?!\S)/;
const ENABLES = new Set(["--ignore-scripts", "--ignore-scripts=true"]);
const SHELL_WORD = /\S+/g;
const RUN_ALL = /\b(?:npm-run-all|run-s|run-p)\s+((?:[\w:.@/*-]+\s*)+)/g;
const INTERPRETER = /\b(?:node(?:js)?|bun|deno)(?:\.exe)?(?=\s)/g;

// starts only after a non-space, as the sticky walk always does, so a search over a run of whitespace is linear too
const NEXT_WORD = /(?<!\s)\s+(\S+)/y;
const EVAL_FLAG = /^(?:-[a-z]*[ep]|--eval|--print|eval)\b/;
const OTHER_FLAG = /^-{1,2}\w[\w-]*(?:=\S+)?$/;

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

    for (let w = word.exec(cmd); w !== null; w = word.exec(cmd)) {
      const flag = w[1] ?? "";

      if (EVAL_FLAG.test(flag)) return true;

      if (!OTHER_FLAG.test(flag)) break;
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

/**
 * Where the last word of `cmd` starts that could leave npm's ignore-scripts other than set, or -1. npm reads its flags
 * anywhere in the invocation, the last one winning (`npm run --ignore-scripts x --no-ignore-scripts` runs prex), takes
 * abbreviations (`--no-ig`), a separate `false` after the flag, and words the shell builds (`"--no-ig"`, `$FLAG`). So any
 * word with "ig" in a flag other than the two spellings that set it, a `false` after a bare `--ignore-scripts`, and any word
 * the shell expands is a doubt, read to the end of the command: past the invocation it can only make apm follow more.
 */
function ignoreScriptsDoubt(cmd: string): number {
  let last = -1;
  let bare = false;

  for (const m of cmd.matchAll(SHELL_WORD)) {
    const w = m[0].replace(/['"\\]/g, "");

    if ((bare && /^false$/i.test(w)) || /[$`{]/.test(w) || (w.startsWith("-") && /ig|[*?[]/i.test(w) && !ENABLES.has(w))) last = m.index;
    bare = w === "--ignore-scripts";
  }

  return last;
}

/** Scripts a command runs through the package manager, in order. */
function referencedScripts(cmd: string, scripts: Scripts): ScriptRef[] {
  const out: ScriptRef[] = [];
  let doubt: number | null = null;

  for (const m of cmd.matchAll(RUN_REF)) {
    const npm = m[1] ?? m[2];
    const name = npm ?? m[3] ?? m[4] ?? m[5];

    // `yarn add x` or `pnpm install` are package manager commands, not scripts
    if (!name || !Object.hasOwn(scripts, name)) continue;

    // npm's flags before the name (the match ends with it) set ignore-scripts, and nothing from there on may unset it;
    // the doubt is found once per command, so a script of many such runs is still read in one pass
    const sets = npm !== undefined && IGNORE_SCRIPTS.test(m[0].slice(0, m[0].length - name.length));

    out.push({ name, alone: sets && (doubt ??= ignoreScriptsDoubt(cmd)) < m.index });
  }

  for (const m of cmd.matchAll(RUN_ALL)) {
    for (const pattern of (m[1] ?? "").trim().split(/\s+/)) {
      for (const name of Object.keys(scripts)) if (wildcardMatch(name, pattern)) out.push({ name, alone: false });
    }
  }

  return out;
}

/** Every lifecycle hook in the manifest with the commands it reaches. */
export function expandHooks(manifest: ScriptsManifest): ExpandedHook[] {
  const scripts = scriptsOf(manifest);
  const out: ExpandedHook[] = [];

  for (const [hook, kind] of Object.entries(LIFECYCLE)) {
    const own = scripts[hook];

    if (own === undefined) continue;
    const commands: HookCommand[] = [];
    const followed = new Set<string>([hook]);
    let cut: string | null = null;

    const visit = (text: string, from: string, depth: number, viaEval: boolean): void => {
      if (depth > MAX_DEPTH) {
        cut ??= `${from}: commands nested more than ${MAX_DEPTH} levels deep (sh -c, decoded text, npm run)`;

        return;
      }

      if (commands.length >= MAX_COMMANDS) {
        cut ??= `${from}: more than ${MAX_COMMANDS} commands`;

        return;
      }

      const evals = viaEval || inlineEval(text);
      commands.push({ from, text, viaEval: evals });

      for (const m of text.matchAll(SH_C)) visit((m[1] ?? m[2] ?? "").replace(/\\(.)/g, "$1"), `${from} (sh -c)`, depth + 1, evals);

      for (const d of decodedStrings(text)) visit(d.value, `${from} (decoded ${d.how})`, depth + 1, evals);

      for (const { name, alone } of referencedScripts(text, scripts)) {
        for (const n of alone ? [name] : [`pre${name}`, name, `post${name}`]) {
          const body = scripts[n];

          if (body === undefined || followed.has(n)) continue;
          followed.add(n);
          visit(body, `scripts.${n} (run by scripts.${hook})`, depth + 1, false);
        }
      }
    };

    visit(own, `scripts.${hook}`, 0, false);
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
