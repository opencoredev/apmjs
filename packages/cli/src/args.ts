// apm's command line, parsed once. `apm exec` and `apm dlx` are `apm x` under other names, so they are normalized to
// `x` before parsing: the three split their arguments the same way (xargs.ts), and the binary gets the same child
// arguments whichever name was typed (review of e83dc4b, finding 3).
import { commandOf, valueFlagsOf } from "./commands.ts";
import { shortFlag, splitXArgs, takesValue } from "./xargs.ts";

/** The other names of `apm x`. */
export const X_ALIASES: ReadonlySet<string> = new Set(["x", "exec", "dlx"]);

/** `child`: what `apm x` (also typed as `apm exec` or `apm dlx`) passes to the binary it runs; empty for every other command. */
export type Args = { cmd: string; positional: string[]; flags: Map<string, string | true>; raw: string[]; child: string[] };

export function parseArgs(argv: readonly string[]): Args {
  const [typed = "help", ...rest] = argv;

  if (X_ALIASES.has(typed)) {
    const x = splitXArgs(rest, valueFlagsOf("x"));

    return { cmd: "x", positional: x.spec === null ? [] : [x.spec], flags: x.flags, raw: rest, child: x.child };
  }

  // each command's own value flags: `apm install --size x` must not read x as --size's value and then run a bare install
  const valueFlags = valueFlagsOf(typed);
  const owned = commandOf(typed) !== undefined;
  const positional: string[] = [];
  const flags = new Map<string, string | true>();

  for (let i = 0; i < rest.length; i++) {
    const a = rest[i] ?? "";

    // no command of apm's reads --, so it is refused, and help after it is still help; a package manager's command
    // gets everything after it, and apm reads none of that (no --pm from there)
    if (a === "--") {
      flags.set("--", true);

      if (owned) continue;
      break;
    }

    const short = shortFlag(a);

    if (short !== null) {
      flags.set(short, true);
      continue;
    }

    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const typedKey = eq > 0 ? a.slice(2, eq) : a.slice(2);
      // npm's spelling of --dev
      const key = typedKey === "save-dev" ? "dev" : typedKey;
      const next = rest[i + 1];

      if (eq > 0) flags.set(key, a.slice(eq + 1));
      else if (valueFlags.has(key) && takesValue(next)) {
        flags.set(key, next);
        i++;
      } else flags.set(key, true);
      continue;
    }

    positional.push(a);
  }

  return { cmd: typed, positional, flags, raw: rest, child: [] };
}
