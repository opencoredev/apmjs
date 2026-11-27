// The commands apm runs itself (everything else goes to the package manager), the flags each one reads, and the help
// each prints. Every one of them prints its help for --help or -h anywhere in its arguments, and refuses a flag it does
// not read, before it reads the network, packs, publishes or writes anything (on 0.1.3, `apm publish --help`
// packed, scored and ran `bun publish`).
import type { Args } from "./args.ts";
import type { Pm } from "./pm.ts";
import { takesValue } from "./xargs.ts";

type FlagKind = "switch" | "value";

type Command = {
  help: string;
  flags: Readonly<Record<string, FlagKind>>;
  /** How many positional arguments it takes at most; null for any number. */
  maxPositional: number | null;
  /**
   * Value flags only the package manager's own command reads (`apm install --tag next` with no packages is npm's
   * install): parsed with their value so it is not taken for a package, and refused when apm runs the command itself.
   * A bare install passes them on only to npm, with a checked value (bareInstallArgs).
   */
  native?: readonly string[];
};

/** Read by every command apm runs itself. */
const COMMON = { pm: "value", json: "switch", help: "switch" } satisfies Readonly<Record<string, FlagKind>>;

const CHECKS = { strict: "switch", force: "switch", "no-cooldown": "switch", cooldown: "value", floor: "value", "ignore-scripts": "switch" } satisfies Readonly<Record<string, FlagKind>>;

const PROOF = { otp: "value", password: "value", "password-stdin": "switch" } satisfies Readonly<Record<string, FlagKind>>;

const ADD: Command = {
  help: `usage: apm add <package>[@range]... [flags]   (also apm install, apm i)

Resolves each package, checks its whole dependency tree and the lockfile your package manager computes, then installs
the exact versions. With no packages, apm install runs your package manager's own install, checking nothing; it passes on
plain switches such as --frozen-lockfile or --force, and npm's --tag and --omit.

  -D, --dev, --save-dev    add to devDependencies
  --production, --prod, --omit dev   leave devDependencies out of the install
  --strict                 refuse what is otherwise only a warning (also APM_STRICT=1)
  --force                  install past the score floor and the cooldown
  --no-cooldown            no 24-hour cooldown for anything in the tree
  --cooldown <duration>    another cooldown, such as 48h
  --floor <n>              another score floor (default 40)
  --ignore-scripts         run no install script (pnpm and bun only; also APM_IGNORE_SCRIPTS=1)
  --pm bun|npm|pnpm|yarn   the package manager to run
  --json                   print one JSON document on stdout`,
  flags: { ...COMMON, ...CHECKS, dev: "switch", production: "switch", prod: "switch", omit: "value" },
  maxPositional: null,
  native: ["tag"],
};

export const COMMANDS = {
  add: ADD,
  install: ADD,
  i: ADD,
  x: {
    help: `usage: apm x [flags] <package>[@version] [args...] [-- args...]   (also apm exec, apm dlx)

Shows the package's risk card and any warning, then runs its binary (bunx / npx). Flags before the package are apm's.
After it, apm's own flags below and --help and -h are still apm's; every other argument is the binary's
(apm x tool --version runs tool --version), and after -- every argument goes to the binary unread
(apm x tool -- --help prints the binary's help).

  --strict, --force, --no-cooldown, --cooldown <duration>, --floor <n>, --ignore-scripts   as for apm add
  --pm bun|npm|pnpm|yarn   the package manager to run
  --json                   before the package: apm's lines go to stderr`,
    flags: { ...COMMON, ...CHECKS },
    maxPositional: 1,
  },
  score: {
    help: "usage: apm score <package>[@version] [--json]\n\nThe explained security score of a version (default: the latest).",
    flags: COMMON,
    maxPositional: 1,
  },
  name: {
    help: "usage: apm name <name> [--json]\n\nWhether a package name is free to publish, and available alternatives.",
    flags: COMMON,
    maxPositional: 1,
  },
  explain: {
    help: "usage: apm explain <package>[@range] [--strict] [--json]\n\nWhether to install it: install (exit 0), review-first (exit 3) or do-not-install (exit 1), and why.",
    flags: { ...COMMON, strict: "switch" },
    maxPositional: 1,
  },
  search: {
    help: "usage: apm search <words> [--size <n>] [--json]\n\nSearches apm and npm, with the apm score where there is one.",
    flags: { ...COMMON, size: "value" },
    maxPositional: null,
  },
  audit: {
    help: "usage: apm audit [--json]\n\nChecks every installed package against revocations, yanks and advisories. Any finding fails the audit.",
    flags: COMMON,
    maxPositional: 0,
  },
  yank: {
    help: 'usage: apm yank <package>@<version> [--reason "..."] [--otp <code>] [--json]\n\nHides a version from new installs; lockfiles that pin it keep working.',
    flags: { ...COMMON, reason: "value", otp: "value" },
    maxPositional: 1,
  },
  unyank: {
    help: "usage: apm unyank <package>@<version> [--otp <code>] [--json]\n\nUndoes a yank.",
    flags: { ...COMMON, reason: "value", otp: "value" },
    maxPositional: 1,
  },
  revoke: {
    help: 'usage: apm revoke <package>@<version> --reason "..." [--otp <code>] [--json]\n\nPulls a malicious version for everyone. Asks for your authenticator code.',
    flags: { ...COMMON, ...PROOF, reason: "value" },
    maxPositional: 1,
  },
  restore: {
    help: 'usage: apm restore <package>@<version> [--reason "..."] [--otp <code>] [--json]\n\nUndoes a mistaken revoke (the version goes back to yanked).',
    flags: { ...COMMON, ...PROOF, reason: "value" },
    maxPositional: 1,
  },
  incident: {
    help: 'usage: apm incident --since <ISO time> [--reason "..."] [--dry-run] [--otp <code>] [--json]\n\nAccount compromised: revokes your tokens and every version published since that time. --dry-run previews it.',
    flags: { ...COMMON, ...PROOF, since: "value", reason: "value", "dry-run": "switch" },
    maxPositional: 0,
  },
  publish: {
    help: `usage: apm publish [--bump patch|minor|major|<version>] [--dry-run] [--tag <tag>] [--json]

Publishes the package in this folder: checks it for secrets, packs it with your package manager, previews its score,
then uploads it. With a login token the version is staged until you approve it.

  --bump <kind>            patch, minor, major or an exact version; written to package.json (not with --dry-run)
  --dry-run                run every check and print the preview; upload nothing
  --tag <tag>              the dist-tag (default latest, or next for a prerelease)
  --pm bun|npm|pnpm|yarn   the package manager to pack and publish with
  --json                   print one JSON document on stdout`,
    flags: { ...COMMON, bump: "value", "dry-run": "switch", tag: "value" },
    maxPositional: 0,
  },
  login: {
    help: "usage: apm login [--no-browser] [--json]\n       apm login --username <name> --password-stdin [--email <email>]\n\nSigns in through the browser and saves the token to your user .npmrc. Publishes with it wait for your approval.",
    flags: { ...COMMON, "no-browser": "switch", username: "value", email: "value", password: "value", "password-stdin": "switch" },
    maxPositional: 0,
  },
  whoami: {
    help: "usage: apm whoami [--json]\n\nThe account the saved token belongs to.",
    flags: COMMON,
    maxPositional: 0,
  },
} satisfies Readonly<Record<string, Command>>;

/** By own property only: `apm constructor` is the package manager's. */
function isCommandName(name: string): name is keyof typeof COMMANDS {
  return Object.hasOwn(COMMANDS, name);
}

/** The command apm runs itself under this name. */
export function commandOf(name: string): Command | undefined {
  return isCommandName(name) ? COMMANDS[name] : undefined;
}

/** The flags that take the next argument as their value: the command's own, or only --pm for a package manager's command. */
export function valueFlagsOf(name: string): ReadonlySet<string> {
  const command = commandOf(name);
  const flags = command?.flags ?? COMMON;

  return new Set([...Object.entries(flags).flatMap(([key, kind]) => (kind === "value" ? [key] : [])), ...(command?.native ?? [])]);
}

/** The help `apm help <topic>` prints: exec and dlx are x. */
export function helpTopic(topic: string): Command | undefined {
  return commandOf(topic === "exec" || topic === "dlx" ? "x" : topic);
}

/**
 * The switches a bare install passes on to each package manager, by exact name: ones its install reads as switches of
 * the project's own install, so none names a package, takes the next word as its value, or installs somewhere else
 * (npm and pnpm read `--g`, `--gf` and `--local=false` as a global install, and `--quiet=false` as a package `false`).
 * None of them may loosen a frozen install or install what the lockfile lacks without recording it: npm ignores
 * --frozen-lockfile, and pnpm's --fix-lockfile, --no-frozen-lockfile, --lockfile-only and --ignore-pnpmfile (which skips
 * the project's .pnpmfile.cjs), yarn 1's --force and
 * --pure-lockfile, and --no-save and --no-package-lock are refused. A switch a package manager does not read is
 * its own to refuse or ignore. npm reads each of its switches here as a complete argument (--silent is --loglevel
 * silent), so npm's --tag and --omit keep their values wherever they come.
 */
const BARE_SWITCHES = new Map<Pm, ReadonlySet<string>>([
  ["bun", new Set(["frozen-lockfile", "production", "ignore-scripts", "dry-run", "silent", "verbose", "force", "no-cache", "json"])],
  ["npm", new Set(["production", "ignore-scripts", "prefer-offline", "prefer-online", "offline", "no-audit", "no-fund", "legacy-peer-deps", "strict-peer-deps", "dry-run", "silent", "foreground-scripts", "force", "json", "package-lock-only"])],
  ["pnpm", new Set(["frozen-lockfile", "prod", "production", "dev", "ignore-scripts", "prefer-offline", "offline", "silent", "force", "strict-peer-dependencies"])],
  ["yarn", new Set(["frozen-lockfile", "production", "ignore-scripts", "ignore-engines", "ignore-optional", "ignore-platform", "prefer-offline", "offline", "non-interactive", "silent", "verbose", "json", "immutable"])],
]);

/** npm's install options that take a value, with the values passed on: a dist-tag, and what to omit. */
const NPM_VALUES = new Map<string, (value: string) => boolean>([
  ["tag", (value) => /^[A-Za-z][\w.-]*$/.test(value)],
  ["omit", (value) => value === "dev" || value === "optional" || value === "peer"],
]);

/**
 * What a bare install (`apm install` with no packages, the package manager's own install) passes on to `pm`'s install,
 * or why apm refuses it. apm checks nothing on a bare install, so none of its arguments may reach the package manager
 * as a package or turn it into another install: package managers read the word after an option they do not know, or
 * after a value-taking option, as a package (bun 1.1 to 1.3 install the word after --tag, unchecked). So a bare install
 * passes on only the switches BARE_SWITCHES lists for `pm`, with no value attached, and npm's --tag and --omit with a
 * checked value. apm's --pm and its value are taken out;
 * anything else, -- included, is refused.
 */
export function bareInstallArgs(a: Args, pm: Pm): { args: string[] } | { error: string } {
  const args: string[] = [];

  for (let i = 0; i < a.raw.length; i++) {
    const word = a.raw[i] ?? "";
    const eq = word.indexOf("=");
    const key = word.startsWith("--") ? word.slice(2, eq === -1 ? undefined : eq) : null;

    if (key === "pm") {
      if (eq === -1 ? !takesValue(a.raw[i + 1]) || a.raw[i + 1] === "" : eq === word.length - 1) return { error: "--pm needs a value" };

      if (eq === -1) i++;
      continue;
    }

    if (key !== null && eq === -1 && BARE_SWITCHES.get(pm)?.has(key) === true) {
      args.push(word);
      continue;
    }

    const value = eq === -1 ? a.raw[i + 1] : word.slice(eq + 1);
    const check = pm === "npm" && key !== null ? NPM_VALUES.get(key) : undefined;

    if (pm === "npm" && key === "frozen-lockfile") return { error: `npm ignores ${word} and may rewrite package-lock.json, so apm ${a.cmd} with no packages does not pass it on; for a frozen install run npm ci` };

    if (check === undefined || value === undefined || !check(value)) return { error: `apm ${a.cmd} with no packages does not pass ${word} on to ${pm}: it checks nothing, and passes on only switches of ${pm}'s own install such as --${pm === "yarn" ? "frozen-lockfile" : "ignore-scripts"}` };

    args.push(word);

    if (eq === -1) {
      args.push(value);
      i++;
    }
  }

  return { args };
}

/** Why apm refuses these arguments before running anything, or null when it runs them. */
export function argsError(a: Args, command: Command): string | null {
  for (const [key, value] of a.flags) {
    const shown = key.startsWith("-") ? key : `--${key}`;
    const kind = Object.hasOwn(command.flags, key) ? command.flags[key] : undefined;

    if (kind === undefined && command.native?.includes(key) === true) return `${shown} is read only by your package manager's own install (apm ${a.cmd} with no packages)`;

    if (kind === undefined) return `unknown flag ${shown} for apm ${a.cmd}`;

    if (kind === "value" && (value === true || value === "")) return `${shown} needs a value`;

    // a dist-tag shaped like an option would reach the package manager's publish as one
    if (key === "tag" && value !== true && value.startsWith("-")) return `${shown} cannot start with -`;

    if (kind === "switch" && value !== true) return `${shown} takes no value`;
  }

  if (command.maxPositional !== null && a.positional.length > command.maxPositional) {
    const extra = a.positional.slice(command.maxPositional).join(" ");

    return command.maxPositional === 0 ? `apm ${a.cmd} takes no arguments (got ${extra})` : `apm ${a.cmd} takes one argument (also got ${extra})`;
  }

  return null;
}
