// How `apm` prints what a package can do (apm-score-v10): one line per capability with how it compares with the
// package's declaration, what the declaration says for it, the environment variables it reads outside the declared
// patterns, and its first evidence. Never scored on its own. Pure, so the lines can be tested without a terminal.
import type { Capability } from "./api.ts";

/** The colors the lines use: the CLI passes its ANSI painters, a test the identity. */
export type Paint = { bold: (s: string) => string; dim: (s: string) => string; green: (s: string) => string; yellow: (s: string) => string };

/** How many variable names read outside the declaration one line lists before it counts the rest. */
const SHOWN_OUTSIDE = 8;

/** How a capability compares with the package's declaration, and what its evidence rests on, in a few words. */
function noteOf(c: Capability, paint: Paint): string {
  const status = c.status === "declared" ? paint.green("declared") : c.status === "undeclared" ? paint.yellow("not in its declaration") : c.status === "unused" ? paint.dim("declared, not seen used") : "";
  const basis = c.basis === "text" ? paint.dim("text mention") : c.basis === "possible" ? paint.dim("possible") : "";

  return [status, basis].filter((x) => x !== "").join(", ");
}

/** The lines `apm score`, `apm add` and the publish preview print under the score; none when there are no capabilities. */
export function capabilityLines(list: readonly Capability[], paint: Paint): string[] {
  if (list.length === 0) return [];
  const out = [`  ${paint.bold("capabilities")} ${paint.dim("(what it can do; not scored)")}`];

  for (const c of list) {
    const note = noteOf(c, paint);

    out.push(`    ${c.id.padEnd(11)} ${paint.dim(c.label.replace(/^[^:]+: /, ""))}${note ? `  ${note}` : ""}`);

    if (c.declared !== undefined) out.push(`        ${paint.dim(`declared: ${c.declared}`)}`);
    const outside = c.outside ?? [];

    if (outside.length > 0) {
      const more = outside.length > SHOWN_OUTSIDE ? ` and ${outside.length - SHOWN_OUTSIDE} more` : "";

      out.push(`        ${paint.yellow(`reads outside the declaration: ${outside.slice(0, SHOWN_OUTSIDE).join(", ")}${more}`)}`);
    }

    if (c.evidence[0]) out.push(`        ${paint.dim(c.evidence[0])}`);
  }

  return out;
}
