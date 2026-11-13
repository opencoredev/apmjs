// Which dependency groups the package manager installs (review of 2b7767f, finding 3, and of efef668, findings 1 and
// 3). A production install (npm's --omit=dev, npm_config_omit=dev, NODE_ENV=production; pnpm's --prod or
// production=true; bun's --production) leaves the folders' devDependencies out. apm reads that once, the way the
// package manager does, and the same answer drives every step: the lockfile is still computed and checked whole
// (every locked package is scanned), every install and rebuild apm runs is told it explicitly, and the check of what
// was installed lets those devDependencies be missing.
//
// When apm cannot tell, it answers "include": the install then gets no flag, and a devDependency the package manager
// leaves out anyway makes the check refuse. It never answers "omit" for an install that would put them in place.
import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { z } from "zod";
import { decodeIni, envReplace, type IniScalar, type IniValue, jsonText, type SectionSyntax, text } from "./ini.ts";
import type { LockPm } from "./lockfile.ts";

type Env = Readonly<Record<string, string | undefined>>;

/** Whether the install leaves devDependencies out, and what said so. */
export type DevGroup = { kind: "include" } | { kind: "omit"; why: string };

/** One place settings come from: the environment's npm_config_* variables, or one config file. */
type Layer = { source: string; values: ReadonlyMap<string, IniValue> };

const EMPTY: Layer = { source: "", values: new Map() };

/** npm_config_<key> variables (any case; `_` in the key is `-`). An empty one sets nothing, as in npm and pnpm. */
function envLayer(env: Env): Layer {
  const values = new Map<string, IniValue>();

  for (const [k, v] of Object.entries(env)) {
    if (!/^npm_config_/i.test(k) || v === undefined || v === "") continue;
    const key = k.slice("npm_config_".length);

    values.set(key.startsWith("//") ? key : key.replace(/(?!^)_/g, "-").toLowerCase(), { kind: "one", item: text(v) });
  }

  return { source: "the environment", values };
}

function fileLayer(path: string, sections: SectionSyntax): Layer {
  try {
    return existsSync(path) && statSync(path).isFile() ? { source: path, values: decodeIni(readFileSync(path, "utf8"), sections) } : { source: path, values: new Map() };
  } catch {
    return { source: path, values: new Map() };
  }
}

const homeOf = (env: Env): string => env.HOME ?? homedir();

/** An executable on the environment's PATH, symlinks resolved: where npm and node really are. */
function onPath(env: Env, name: string): string | null {
  for (const dir of (env.PATH ?? "").split(":")) {
    if (dir === "") continue;
    const p = join(dir, name);

    try {
      if (statSync(p).isFile()) return realpathSync(p);
    } catch {
      // not here
    }
  }

  return null;
}

/** A path setting (userconfig, globalconfig, prefix) from the first layer that sets it, as npm resolves it. */
function pathSetting(layers: readonly Layer[], key: string, input: { root: string; env: Env }): string | null {
  for (const l of layers) {
    const v = l.values.get(key);

    if (v?.kind !== "one" || v.item.kind !== "text") continue;
    const f = envReplace(v.item.text.trim(), input.env);

    return f.startsWith("~/") ? resolve(homeOf(input.env), f.slice(2)) : resolve(input.root, f);
  }

  return null;
}

/** npm's own directory, from the npm-cli.js the npm on PATH runs, or null when the npm on PATH is not that. */
const npmRootOf = (npmCli: string | null): string | null => (npmCli !== null && basename(npmCli) === "npm-cli.js" ? dirname(dirname(npmCli)) : null);

const PackageVersion = z.object({ version: z.string() });

/** Whether the first package.json of `dirs` that can be read has a version at least `min` (major, minor); null if none can. */
function versionAtLeast(dirs: readonly string[], min: { major: number; minor: number }): boolean | null {
  for (const dir of dirs) {
    let raw: unknown;

    try {
      raw = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
    } catch {
      continue;
    }

    const pkg = PackageVersion.safeParse(raw);
    const v = pkg.success ? /^(\d+)\.(\d+)\./.exec(pkg.data.version) : null;

    if (v === null) return null;
    const [major, minor] = [Number(v[1]), Number(v[2])];

    return major > min.major || (major === min.major && minor >= min.minor);
  }

  return null;
}

/**
 * The section syntax of the ini package that npm reads its config files with (review of a24c6aa, finding 1): npm's
 * own copy, or the shared one a distribution installs beside it (Debian's /usr/share/nodejs/ini for its npm 9.2).
 * null when it cannot be found.
 */
function npmSectionSyntax(npmRoot: string | null): SectionSyntax | null {
  if (npmRoot === null) return null;
  const spaced = versionAtLeast([join(npmRoot, "node_modules", "ini"), join(dirname(npmRoot), "ini")], { major: 4, minor: 1 });

  return spaced === null ? null : spaced ? "spaced" : "exact";
}

/**
 * How npm's values reach the list of groups it omits (review of a24c6aa, finding 2). npm 9.3 and later build it from
 * the values as read (`raw`): production=0 is the text "0", which is true, and a list keeps every item, valid or not.
 * npm 9.2 and earlier type-check them first (`typed`): production=0 is false and invalid list items are dropped. Real
 * installs with npm 9.2.0 (upstream and Debian's), 9.3.1 to 9.8.1, 9.9.4, 10.9.3 and 11.16.0 showed the split.
 */
type NpmReading = "typed" | "raw";

function npmReading(npmRoot: string | null): NpmReading | null {
  if (npmRoot === null) return null;
  const raw = versionAtLeast([npmRoot], { major: 9, minor: 3 });

  return raw === null ? null : raw ? "raw" : "typed";
}

/**
 * npm's config files, lowest priority first, then the environment: its builtin npmrc (beside the npm on PATH), the
 * global config, the user's, the project's (`root`, where apm runs the install), as npm 9 to 11 load them.
 */
function npmLayers(input: { root: string; env: Env; npmRoot: string | null; sections: SectionSyntax }): Layer[] {
  const env = envLayer(input.env);
  const builtin = input.npmRoot === null ? EMPTY : fileLayer(join(input.npmRoot, "npmrc"), input.sections);
  const projectPath = join(input.root, ".npmrc");
  const defaultUser = join(homeOf(input.env), ".npmrc");
  // npm reads the project file unless it is the user config (a project in the home directory)
  const project = (pathSetting([env, builtin], "userconfig", input) ?? defaultUser) === projectPath ? EMPTY : fileLayer(projectPath, input.sections);
  const user = fileLayer(pathSetting([env, project, builtin], "userconfig", input) ?? defaultUser, input.sections);
  const node = onPath(input.env, "node");
  const prefix = pathSetting([env, project, user, builtin], "prefix", input) ?? input.env.PREFIX ?? (node === null ? null : dirname(dirname(node)));
  const globalPath = pathSetting([env, project, user, builtin], "globalconfig", input) ?? (prefix === null ? null : resolve(prefix, "etc", "npmrc"));
  const global = globalPath === null ? EMPTY : fileLayer(globalPath, input.sections);

  return [builtin, global, user, project, env];
}

/** A value as a package manager's parseField leaves it: text, a literal, or `undefined` (the text "undefined"). */
type Field = IniScalar | { kind: "undefined" };

/**
 * npm's parseField for a value that is not a path: trimmed, true/false/null/undefined read as such, an empty Boolean
 * true, ${VAR} replaced. pnpm's does the same after reading a double-quoted value as JSON, and replaces ${VAR} only
 * after the literals, so `${P}` with P=false is the text "false" to pnpm.
 */
function parseField(v: IniScalar, input: { bool: boolean; env: Env; pm: "npm" | "pnpm" }): Field {
  if (v.kind === "literal") return v;
  let f = v.text.trim();

  if (input.pm === "pnpm" && /^".*"$/.test(f)) f = jsonText(f);

  if (input.bool && f === "") return { kind: "literal", value: true };

  switch (f) {
    case "true":
      return { kind: "literal", value: true };
    case "false":
      return { kind: "literal", value: false };
    case "null":
      return { kind: "literal", value: null };
    case "undefined":
      return { kind: "undefined" };
    default:
      return text(envReplace(f, input.env));
  }
}

const npmField = (v: IniScalar, input: { bool: boolean; env: Env }): Field => parseField(v, { ...input, pm: "npm" });

/** What a layer sets, after npm's type check: an invalid value is dropped and the next layer's counts. */
type NpmOwn = { omit: string[] | undefined; include: string[] | undefined; only: string | null | undefined; also: string | null | undefined; production: boolean | null | undefined; dev: boolean | undefined; optional: boolean | null | undefined };

const OMIT_TYPES = ["dev", "optional", "peer"];
const INCLUDE_TYPES = ["prod", "dev", "optional", "peer"];

/** A list setting: one text splits on blank lines, each item must be one of `allowed`, and an empty list still counts. */
function npmList(v: IniValue | undefined, allowed: readonly string[], env: Env): string[] | undefined {
  if (v === undefined) return undefined;
  const items = v.kind === "list" ? v.items : v.item.kind === "text" ? v.item.text.trim().split("\n\n").map(text) : [v.item];

  return items.flatMap((i) => {
    const f = npmField(i, { bool: false, env });

    return f.kind === "text" && allowed.includes(f.text.trim()) ? [f.text.trim()] : [];
  });
}

/** One typed choice item: one of a few words, or null; anything else is dropped (`false` reads as null, as nopt does). */
function npmChoiceItem(i: IniScalar, allowed: readonly string[], env: Env): string | null | undefined {
  const f = npmField(i, { bool: false, env });

  if (f.kind === "literal") return f.value === true ? undefined : null;

  return f.kind === "text" && allowed.includes(f.text) ? f.text : undefined;
}

/** A list item as npm leaves it in a list it does not parse: ini's text, or its literal as text (null as nothing). */
const rawItem = (i: IniScalar): string => (i.kind === "text" ? i.text : i.value === null ? "" : String(i.value));

/**
 * A choice setting (only, also), as the text npm tests (null when it can match nothing). A `key[]=` list is a list to
 * npm (review of a24c6aa, finding 2), tested as its items joined by commas: `only[]=prod` is "prod" and omits, two
 * items never read as one word. Typed, invalid items are dropped first and a list with none left sets nothing; raw,
 * every item stays, so `only[]=prod` with `only[]=bogus` is "prod,bogus".
 */
function npmChoice(v: IniValue | undefined, input: { allowed: readonly string[]; env: Env; reading: NpmReading }): string | null | undefined {
  if (v === undefined) return undefined;

  if (input.reading === "raw") {
    if (v.kind === "list") return v.items.map(rawItem).join(",");
    const f = npmField(v.item, { bool: false, env: input.env });

    return f.kind === "text" ? f.text : null;
  }

  if (v.kind === "one") return npmChoiceItem(v.item, input.allowed, input.env);
  const kept = v.items.map((i) => npmChoiceItem(i, input.allowed, input.env)).filter((c) => c !== undefined);

  return kept.length === 0 ? undefined : kept.map((c) => c ?? "").join(",");
}

/**
 * A Boolean setting. A `key[]=` list stays a list, and npm tests production and dev for truth, so any list is true,
 * `production[]=false` included (review of a24c6aa, finding 2). Raw, any text is true (production=0 too) and the text
 * "undefined" hides the layers below it; typed, as nopt reads it: a number is its truth, "false" and "null" are false,
 * other text true.
 */
function npmBool(v: IniValue | undefined, input: { nullable: boolean; env: Env; reading: NpmReading }): boolean | null | undefined {
  if (v === undefined) return undefined;

  if (v.kind === "list") return true;
  const f = npmField(v.item, { bool: true, env: input.env });

  switch (f.kind) {
    case "undefined":
      return input.reading === "raw" && input.nullable ? null : false;
    case "literal":
      return f.value === null ? (input.nullable ? null : false) : f.value;
    case "text":
      if (input.reading === "raw") return true;

      return f.text !== "" && !Number.isNaN(Number(f.text)) ? Number(f.text) !== 0 : f.text !== "false" && f.text !== "null";
    default: {
      const _exhaustive: never = f;

      return _exhaustive;
    }
  }
}

function npmOwn(l: Layer, input: { env: Env; reading: NpmReading }): NpmOwn {
  const { env, reading } = input;
  // npm 9.2 reads dev as it is too: dev=0 with omit=dev installs devDependencies on every npm checked
  const dev = npmBool(l.values.get("dev"), { nullable: false, env, reading: "raw" });

  return {
    omit: npmList(l.values.get("omit"), OMIT_TYPES, env),
    include: npmList(l.values.get("include"), INCLUDE_TYPES, env),
    only: npmChoice(l.values.get("only"), { allowed: ["prod", "production"], env, reading }),
    also: npmChoice(l.values.get("also"), { allowed: ["dev", "development"], env, reading }),
    production: npmBool(l.values.get("production"), { nullable: true, env, reading }),
    dev: dev === null ? false : dev,
    // npm tests optional only for === true and === false, so a list sets it to neither
    optional: l.values.get("optional")?.kind === "list" ? null : npmBool(l.values.get("optional"), { nullable: true, env, reading }),
  };
}

/** The settings in force at a layer, and the layer each came from. */
type NpmEffective = { only: string | null; onlyFrom: string; also: string | null; production: boolean | null; productionFrom: string; dev: boolean };

const isProdOnly = (only: string | null): boolean => only === "prod" || only === "production";

/**
 * npm's omit list, built the way npm builds it: from its defaults (omit=dev when NODE_ENV=production) up to the
 * environment, each layer that sets omit, include, only, also, production, dev or optional folds them in. A dev an
 * include, production=false, also=dev or dev=true puts in the include list stays installed, whichever layer set it.
 */
function npmFold(input: { env: Env; layers: readonly Layer[]; reading: NpmReading }): DevGroup {
  const nodeEnv = input.env.NODE_ENV === "production";
  let omit: string[] = nodeEnv ? ["dev"] : [];
  let include: string[] = [];
  let why = nodeEnv ? "NODE_ENV=production" : "";
  let eff: NpmEffective = { only: null, onlyFrom: "", also: null, production: null, productionFrom: "", dev: false };

  for (const l of input.layers) {
    const own = npmOwn(l, input);

    if (Object.values(own).every((v) => v === undefined)) continue;
    eff = {
      only: own.only === undefined ? eff.only : own.only,
      onlyFrom: own.only === undefined ? eff.onlyFrom : l.source,
      also: own.also === undefined ? eff.also : own.also,
      production: own.production === undefined ? eff.production : own.production,
      productionFrom: own.production === undefined ? eff.productionFrom : l.source,
      dev: own.dev ?? eff.dev,
    };
    const o = [...(own.omit ?? omit)];
    const inc = [...(own.include ?? include)];

    if (own.omit?.includes("dev") === true) why = `omit=dev in ${l.source}`;
    else if (own.omit !== undefined) why = "";

    if (isProdOnly(eff.only) || eff.production === true) {
      o.push("dev");
      why = isProdOnly(eff.only) ? `only=${String(eff.only)} in ${eff.onlyFrom}` : `production=true in ${eff.productionFrom}`;
    } else if (eff.production === false) {
      inc.push("dev");
    }

    if (eff.also?.startsWith("dev") === true) inc.push("dev");

    if (eff.dev) inc.push("dev");
    include = [...new Set(inc)];
    omit = [...new Set(o)].filter((t) => !include.includes(t));
  }

  return omit.includes("dev") ? { kind: "omit", why: why === "" ? "npm's configuration" : why } : { kind: "include" };
}

/**
 * npm's answer, with its config files read in the section syntax of the ini it uses and its values as its version
 * reads them. What cannot be found (no npm-cli.js on PATH, no ini or version beside it) is tried every way, and the
 * answer is "omit" only when every way omits.
 */
function npmDevGroup(input: { root: string; env: Env }): DevGroup {
  const npmRoot = npmRootOf(onPath(input.env, "npm"));
  const known = { sections: npmSectionSyntax(npmRoot), reading: npmReading(npmRoot) };
  const sectionsTried: readonly SectionSyntax[] = known.sections === null ? ["exact", "spaced"] : [known.sections];
  const readingsTried: readonly NpmReading[] = known.reading === null ? ["typed", "raw"] : [known.reading];
  const answers = sectionsTried.flatMap((sections) => readingsTried.map((reading) => npmFold({ env: input.env, layers: npmLayers({ ...input, npmRoot, sections }), reading })));
  const first = answers[0];

  return first !== undefined && answers.every((a) => a.kind === "omit") ? first : { kind: "include" };
}

/** A value as pnpm takes it: a field, or a `key[]=` list, which pnpm keeps as a list. */
type PnpmValue = Field | { kind: "list" };

/** Whether pnpm takes a value as set: any text but the empty one, the literal true, and any list (it is truthy). */
const pnpmTruthy = (f: PnpmValue): boolean => (f.kind === "text" ? f.text !== "" : f.kind === "list" || (f.kind === "literal" && f.value === true));

/**
 * pnpm 10: the first of the environment, the project's .npmrc, the user's, npm's global config (when a setting names
 * it) and pnpm's own rc that sets a key wins. It leaves devDependencies out when only is prod or production, or, with
 * no only, when production is set to anything but false or null (production=0 counts). It reads neither omit nor
 * NODE_ENV for this. Its .npmrc reader takes a section header only when the line ends at the `]` (checked on 10.18.3).
 * A list is truthy: `production[]=false` omits and `only[]=prod`, not the word prod, includes (real 10.18.3 installs).
 * `production=undefined` hides a production=true below it.
 */
function pnpmDevGroup(input: { root: string; env: Env }): DevGroup {
  const home = homeOf(input.env);
  const userPath = input.env.npm_config_userconfig ?? input.env.NPM_CONFIG_USERCONFIG ?? join(home, ".npmrc");
  const rc = join(input.env.XDG_CONFIG_HOME ?? join(home, ".config"), "pnpm", "rc");
  const [env, project, user] = [envLayer(input.env), fileLayer(join(input.root, ".npmrc"), "exact"), fileLayer(userPath, "exact")];
  const globalPath = pathSetting([env, project, user], "globalconfig", input);
  const layers = [env, project, user, globalPath === null ? EMPTY : fileLayer(globalPath, "exact"), fileLayer(rc, "exact")];

  const first = (key: string, bool: boolean): { value: PnpmValue; source: string } | null => {
    for (const l of layers) {
      const v = l.values.get(key);

      if (v === undefined) continue;

      if (v.kind === "list") return { value: { kind: "list" }, source: l.source };

      // the text "undefined" is a value too: it hides the layers below it and is not set (real 10.18.3 installs)
      return { value: parseField(v.item, { bool, env: input.env, pm: "pnpm" }), source: l.source };
    }

    return null;
  };

  const only = first("only", false);

  if (only?.value.kind === "text" && (only.value.text === "prod" || only.value.text === "production")) return { kind: "omit", why: `only=${only.value.text} in ${only.source}` };

  if (only !== null && pnpmTruthy(only.value)) return { kind: "include" };
  const production = first("production", true);

  return production !== null && pnpmTruthy(production.value) ? { kind: "omit", why: `production=${production.value.kind === "text" ? production.value.text : production.value.kind === "list" ? "[]" : "true"} in ${production.source}` } : { kind: "include" };
}

/**
 * Whether the package manager at `root` leaves devDependencies out. `production`: apm add was given --omit=dev,
 * --prod or --production, which asks every package manager. Otherwise npm and pnpm decide from their own settings,
 * read here the way each reads them (npm also from NODE_ENV). bun reads none of these: only its --production flag (and
 * bunfig's production = true, which also freezes the lockfile, so bun refuses the add itself).
 */
export function devGroup(input: { pm: LockPm; root: string; env: Env; production: boolean }): DevGroup {
  if (input.production) return { kind: "omit", why: "apm add was asked for a production install" };

  switch (input.pm) {
    case "npm":
      return npmDevGroup(input);
    case "pnpm":
      return pnpmDevGroup(input);
    case "bun":
      return { kind: "include" };
    default: {
      const _exhaustive: never = input.pm;

      return _exhaustive;
    }
  }
}

/** The flag that tells the frozen install to leave devDependencies out, so it does what apm verifies. */
export function omitArgs(pm: LockPm, group: DevGroup): string[] {
  if (group.kind === "include") return [];

  switch (pm) {
    case "npm":
      return ["--omit=dev"];
    case "pnpm":
      return ["--prod"];
    case "bun":
      return ["--production"];
    default: {
      const _exhaustive: never = pm;

      return _exhaustive;
    }
  }
}

/**
 * The same omission for the command that runs held install scripts (review of efef668, finding 1). bun runs scripts
 * only while it installs, so its second install must be told --production again, or it puts the devDependencies back
 * and runs their scripts. npm rebuild takes --omit=dev. pnpm rebuild has no --prod flag: it builds only the named
 * packages, from the dependency groups its install recorded, and is given production=true in its environment.
 */
export type ReleaseOmission = { args: string[]; env: { npm_config_production?: "true" } };

export function releaseOmission(pm: LockPm, group: DevGroup): ReleaseOmission {
  if (group.kind === "include") return { args: [], env: {} };

  switch (pm) {
    case "npm":
      return { args: ["--omit=dev"], env: {} };
    case "pnpm":
      return { args: [], env: { npm_config_production: "true" } };
    case "bun":
      return { args: ["--production"], env: {} };
    default: {
      const _exhaustive: never = pm;

      return _exhaustive;
    }
  }
}
