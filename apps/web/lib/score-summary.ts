// The one line a phone shows for a score before the full report: the signal that cost the most points,
// by name, and how many more there are.
import type { Signal } from "./registry";

export type ScoreLine =
  | { kind: "unscored" }
  | { kind: "unscorable" }
  | { kind: "clean" }
  | { kind: "lost"; name: string; points: number; possible: boolean; more: number };

/** A signal's label up to its first explanation: "Uses the network: fetch, http…" becomes "Uses the network". */
export function shortLabel(label: string): string {
  const cut = /:|;|\s\(|,\s/.exec(label);
  const short = (cut ? label.slice(0, cut.index) : label).trim();

  return short === "" ? label : short;
}

/** The biggest loss first; between equal losses a confirmed signal before a possible one. */
function biggest(lost: readonly Signal[]): Signal | null {
  return lost.reduce<Signal | null>((top, s) => {
    if (top === null || s.points < top.points) return s;

    return s.points === top.points && top.confidence === "possible" && s.confidence === "confirmed" ? s : top;
  }, null);
}

/** `unscorable`: the registry decided this version can never be scored, which is not the same as not yet. */
export function scoreLine(signals: readonly Signal[] | null, unscorable = false): ScoreLine {
  if (signals === null) return unscorable ? { kind: "unscorable" } : { kind: "unscored" };
  const lost = signals.filter((s) => s.points < 0);
  const top = biggest(lost);

  if (top === null) return { kind: "clean" };
  const possible = top.confidence === "possible";
  const name = shortLabel(top.label);

  // possible labels already start "Possible…" or "Possibly…"; one that doesn't is marked here
  return { kind: "lost", name: possible && !/^possibl/i.test(name) ? `Possible: ${name}` : name, points: -top.points, possible, more: lost.length - 1 };
}

/** The line as text, the way the page reads it: "Runs a script at install time · −15 points +1 more". */
export function scoreLineText(line: ScoreLine): string {
  switch (line.kind) {
    case "unscored":
      return "Not scored yet";
    case "unscorable":
      return "Cannot be scored; installs refuse it";
    case "clean":
      return "No points lost";
    case "lost":
      return `${line.name} · −${line.points} point${line.points === 1 ? "" : "s"}${line.more > 0 ? ` +${line.more} more` : ""}`;
    default: {
      const exhaustive: never = line;

      return exhaustive;
    }
  }
}
