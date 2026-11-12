// How the version page words a capability: its name, what it covers, how it compares with the package's declaration,
// and what its evidence rests on. Pure, so it is tested without rendering.
import type { Capability, Declaration } from "./registry";

/** "Network: makes requests or opens sockets" as its name and what it covers. */
export function capabilityParts(label: string): { name: string; detail: string } {
  const at = label.indexOf(": ");

  return at < 0 ? { name: label, detail: "" } : { name: label.slice(0, at), detail: label.slice(at + 2) };
}

/** The mark beside a capability, or null for a package that declares nothing (there is nothing to compare). */
export type StatusMark = { text: string; tone: "ok" | "warn" | "muted" };

export function statusMark(c: Pick<Capability, "status">): StatusMark | null {
  switch (c.status) {
    case "declared":
      return { text: "Declared", tone: "ok" };
    case "undeclared":
      return { text: "Not in its declaration", tone: "warn" };
    case "unused":
      return { text: "Declared, not seen used", tone: "muted" };
    case "not-declared":
      return null;
    default: {
      const exhaustive: never = c.status;

      return exhaustive;
    }
  }
}

/** What the evidence rests on, when it is less than code apm read: only text that names the capability, or a guess. */
export function basisNote(c: Pick<Capability, "basis">): string | null {
  switch (c.basis) {
    case "text":
      return "Text mention only";
    case "possible":
      return "Possible";
    case "code":
    case "none":
      return null;
    default: {
      const exhaustive: never = c.basis;

      return exhaustive;
    }
  }
}

/** The sentence under the section title: what the list is, and whether it was compared with a declaration. */
export function capabilitiesIntro(declaration: Pick<Declaration, "kind"> | null | undefined): string {
  return declaration?.kind === "declared"
    ? "What the code can do, compared with the capabilities its package.json declares. A capability it leaves out costs points; the rest are listed, not scored."
    : "What the code can do, with the lines that show it. Listed, not scored: the score counts risk signals only. This package does not declare its capabilities.";
}

/** Environment variables read, by name; a name built at runtime shows as one entry. */
export function envNames(names: readonly string[] | undefined): string[] {
  return (names ?? []).map((n) => (n === "*" ? "names built at runtime" : n));
}
