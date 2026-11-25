// apm's command line, parsed once. `apm exec` and `apm dlx` are `apm x` under other names, so they are normalized to
// `x` before parsing: the three split their arguments the same way (xargs.ts), and the binary gets the same child
// arguments whichever name was typed (review of e83dc4b, finding 3).
import { shortFlag, splitXArgs, takesValue } from "./xargs.ts";

/** The flags of every apm command that take the next argument as their value. */
export const VALUE_FLAGS: ReadonlySet<string> = new Set(["pm", "omit", "reason", "username", "email", "bump", "tag", "since", "cooldown", "floor", "password", "otp", "size"]);


/** The other names of `apm x`. */
export const X_ALIASES: ReadonlySet<string> = new Set(["x", "exec", "dlx"]);

/** `child`: what `apm x` (also typed as `apm exec` or `apm dlx`) passes to the binary it runs; empty for every other command. */
export type Args = { cmd: string; positional: string[]; flags: Map<string, string | true>; raw: string[]; child: string[] };

export function parseArgs(argv: readonly string[]): Args {
  const [typed = "help", ...rest] = argv;

  if (X_ALIASES.has(typed)) {
    const x = splitXArgs(rest, VALUE_FLAGS);

    return { cmd: "x", positional: x.spec === null ? [] : [x.spec], flags: x.flags, raw: rest, child: x.child };
  }

  const positional: string[] = [];
  const flags = new Map<string, string | true>();

  for (let i = 0; i < rest.length; i++) {
    const a = rest[i] ?? "";

    if (a === "--") {
      positional.push(...rest.slice(i + 1));
      break;
    }

    const short = shortFlag(a);

    if (short !== null) {
      flags.set(short, true);
      continue;
    }

    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const key = eq > 0 ? a.slice(2, eq) : a.slice(2);
      const next = rest[i + 1];

      if (eq > 0) flags.set(key, a.slice(eq + 1));
      else if (VALUE_FLAGS.has(key) && takesValue(next)) {
        flags.set(key, next);
        i++;
      } else flags.set(key, true);
      continue;
    }

    positional.push(a);
  }

  return { cmd: typed, positional, flags, raw: rest, child: [] };
}
