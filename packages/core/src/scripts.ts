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

/** A lifecycle hook, the commands it reaches and the names of the scripts it runs (itself included). */
export type ExpandedHook = { hook: string; kind: HookKind; commands: HookCommand[]; scripts: string[] };

const MAX_DEPTH = 8;
const MAX_COMMANDS = 200;

const SH_C = /\b(?:sh|bash|zsh|dash)\s+-c\s+(?:'([^']*)'|"((?:[^"\\]|\\.)*)")/g;
const RUN_REF = /(?:^|[;&|(]\s*|\s)(?:npm\s+(?:run(?:-script)?\s+([\w:.@/-]+)|(start|test|stop|restart)\b)|yarn(?:\s+run)?\s+([\w:.@/-]+)|pnpm(?:\s+run)?\s+([\w:.@/-]+)|bun\s+run\s+([\w:.@/-]+))/g;
const RUN_ALL = /\b(?:npm-run-all|run-s|run-p)\s+((?:[\w:.@/*-]+\s*)+)/g;
const INLINE_EVAL = /\b(?:node|bun|deno)\s+(?:-e|--eval|-p|--print|eval)\b/;

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

/** Script names a command runs through the package manager, in order. */
function referencedScripts(cmd: string, scripts: Scripts): string[] {
  const out: string[] = [];

  for (const m of cmd.matchAll(RUN_REF)) {
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

/** Every lifecycle hook in the manifest with the commands it reaches. */
export function expandHooks(manifest: ScriptsManifest): ExpandedHook[] {
  const scripts = scriptsOf(manifest);
  const out: ExpandedHook[] = [];

  for (const [hook, kind] of Object.entries(LIFECYCLE)) {
    const own = scripts[hook];

    if (own === undefined) continue;
    const commands: HookCommand[] = [];
    const followed = new Set<string>([hook]);

    const visit = (text: string, from: string, depth: number, viaEval: boolean): void => {
      if (depth > MAX_DEPTH || commands.length >= MAX_COMMANDS) return;
      const evals = viaEval || INLINE_EVAL.test(text);
      commands.push({ from, text, viaEval: evals });

      for (const m of text.matchAll(SH_C)) visit((m[1] ?? m[2] ?? "").replace(/\\(.)/g, "$1"), `${from} (sh -c)`, depth + 1, evals);

      for (const d of decodedStrings(text)) visit(d.value, `${from} (decoded ${d.how})`, depth + 1, evals);

      for (const name of referencedScripts(text, scripts)) {
        for (const n of [`pre${name}`, name, `post${name}`]) {
          const body = scripts[n];

          if (body === undefined || followed.has(n)) continue;
          followed.add(n);
          visit(body, `scripts.${n} (run by scripts.${hook})`, depth + 1, false);
        }
      }
    };

    visit(own, `scripts.${hook}`, 0, false);
    out.push({ hook, kind, commands, scripts: [...followed] });
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
  const inlineEval = ctx.viaEval === true || INLINE_EVAL.test(cmd);

  return inlineEval && /https?|fetch|\bnet\b|child_process|exec/.test(cmd);
}

/** Paths a command runs or reads: every word that could name a file, `./setup` and `setup.js` alike. */
export function commandWords(cmd: string): string[] {
  return cmd.split(/[\s;&|()<>'"=`]+/).flatMap((w) => (w.length > 0 && !w.startsWith("-") && !w.startsWith("$") && /^[\w@./-]+$/.test(w) ? [w.replace(/^\.\//, "")] : []));
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
