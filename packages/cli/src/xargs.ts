// How `apm x` splits its arguments between apm and the binary it runs (review of 96f0ba7, finding 6). apm's own flags
// are consumed and never reach the binary; everything after `--` reaches the binary verbatim and is never read by apm.

/** The flags `apm x` reads, and whether each takes a value. */
export const X_FLAGS: ReadonlyMap<string, "switch" | "value"> = new Map([
  ["strict", "switch"],
  ["force", "switch"],
  ["no-cooldown", "switch"],
  ["ignore-scripts", "switch"],
  ["pm", "value"],
  ["cooldown", "value"],
  ["floor", "value"],
]);

export type XArgs = {
  /** The package to run, or null when none was given. */
  spec: string | null;
  /** apm's flags: everything before the package, and the flags in X_FLAGS between the package and `--`. */
  flags: Map<string, string | true>;
  /** What the binary gets, in order. */
  child: string[];
};

/**
 * `apm x [apm flags] <package> [args] [-- args]`. Before the package every flag is apm's (valueFlags take the next
 * argument). After it, a flag in X_FLAGS is still apm's and is not passed on; anything else is the binary's. `--json`
 * after the package is the binary's and also moves apm's own lines to stderr, as it always did, so the binary's output
 * stays alone on stdout. After `--` every argument is the binary's, untouched.
 */
export function splitXArgs(rest: readonly string[], valueFlags: ReadonlySet<string>): XArgs {
  const flags = new Map<string, string | true>();
  const child: string[] = [];
  let spec: string | null = null;

  for (let i = 0; i < rest.length; i++) {
    const a = rest[i] ?? "";

    if (a === "--") {
      child.push(...rest.slice(i + 1));
      break;
    }

    const eq = a.indexOf("=");
    const key = a.startsWith("--") ? (eq > 0 ? a.slice(2, eq) : a.slice(2)) : null;

    if (spec === null) {
      if (key === null) {
        spec = a;
      } else if (eq > 0) {
        flags.set(key, a.slice(eq + 1));
      } else if (valueFlags.has(key) && i + 1 < rest.length) {
        flags.set(key, rest[++i] ?? "");
      } else {
        flags.set(key, true);
      }

      continue;
    }

    const kind = key === null ? undefined : X_FLAGS.get(key);

    if (key !== null && kind !== undefined) {
      if (eq > 0) flags.set(key, a.slice(eq + 1));
      else if (kind === "value" && i + 1 < rest.length) flags.set(key, rest[++i] ?? "");
      else flags.set(key, true);
      continue;
    }

    if (key === "json") flags.set("json", true);
    child.push(a);
  }

  return { spec, flags, child };
}
