// What one binary's text reading may keep, enforced while its rules, facts and imports are found (binary-text.ts).
// Round 10 review of c558aff, P1: a Mach-O of 60,000 lines of `'child_'+'process';` (7 KB gzipped) built 120,000
// findings a view, in two views, and cloned them, before any budget was checked; production (274d284) finished it at
// 77.8 MiB live and this read ended the isolate. A reading runs under a limit installed here, as the meter is
// (meter.ts): the text rules, facts and import passes charge each result as they make it, and the joining pass its
// temporary lists.
//
// Past what it may keep, a reading goes on (it is "saturated"): it keeps a finding only when nothing it kept yet says
// what that finding says to the scorer (findingKey: its signal, how it was found, whether it sits in hidden text, how
// sure it is, and whether it builds or hides a string), every fact with any long name shortened to what the scorer
// reads of it (facts.ts; factsOf already keeps at most MAX_PER_KIND of a kind), and no more import paths. What is kept
// is bounded by the number of distinctions the scorer makes, not of matches (round 13 review of d594415: one per signal
// id dropped a joined credential name beside a plain one, and one fact per kind a three-family harvest). Past a
// temporary list's limit the pass building it stops where it is, keeping what it built. Either way the reading did not
// finish: the analysis has `incomplete`, scores 0 and holds the install verdict, since what it did not read could hold
// more than the 61 points `incomplete` costs (round 12 review of 7cd0b2b; round 13 review of d594415: a stopped joining
// scored 39 where production, which read on, scored 35).
// Outside a binary's reading nothing is installed, and the charges cost one null check.

import type { Fact } from "./facts.ts";
import type { TextFinding } from "./rules.ts";

/** A result a reading keeps: a finding of the text rules, or a fact. */
export type KeptItem = TextFinding | Fact;

/**
 * What a finding says to the scorer, but where: its signal, how it was found (as written, joined, decoded), whether it
 * sits in a comment, regex or type, whether a parser placed it, how sure it is and why, and whether its snippet is a
 * string it builds or hides (score.ts HIDDEN_NAME reads those). Two findings with the same key score the same.
 */
export function findingKey(f: TextFinding): string {
  const built = f.snippet.startsWith("builds \"") ? "b" : f.snippet.startsWith("hides code in ") ? "h" : "";

  return [f.id, f.how, f.hidden ?? "", f.tree === true ? "t" : "", f.confidence, f.confidence === "possible" ? f.why : "", built].join("\u0000");
}

/** A temporary list's running size while it is built (tempBytes). */
export type TempList = { fits(bytes: number): boolean };

/**
 * The most one binary's reading holds at once in a list it builds while it reads (the joining pass's edits and built
 * strings, by tempBytes), apart from what it keeps. A few thousand joins a file is what real code has; 16 MiB is about
 * 250,000.
 */
export const MAX_SCAN_TEMP_BYTES = 16 * 1024 * 1024;

/** How a reading under a limit ended: `saturated`, it kept only what was new past its budget; `stopped`, it ended early. */
export type KeepOutcome = { readonly saturated: boolean; readonly stopped: boolean };

type Limit = { left: number; readonly temp: number; readonly kept: Set<string>; saturated: boolean; stopped: boolean };

let current: Limit | null = null;

/**
 * Runs `fn` with `max` bytes (by itemBytes and stringBytes) for what it keeps, and `temp` for each temporary list it
 * builds, and says how its reading ended. Limits do not nest: an inner one replaces the outer while it runs.
 */
export function withKeepLimit<T>(max: number, temp: number, fn: () => T): { value: T } & KeepOutcome {
  const outer = current;
  const limit: Limit = { left: max, temp, kept: new Set(), saturated: false, stopped: false };
  current = limit;

  try {
    const value = fn();

    return { value, saturated: limit.saturated, stopped: limit.stopped };
  } finally {
    current = outer;
  }
}

/** About what a kept result takes: a little more than an object, and two bytes a character of what it says. */
export function itemBytes(item: KeptItem): number {
  return 64 + 2 * JSON.stringify(item).length;
}

/** About what a kept string takes. */
export function stringBytes(s: string): number {
  return 32 + 2 * s.length;
}

/**
 * Whether to keep `item`, which says `key` to the scorer (findingKey): always outside a limit; within one while there is
 * room, charged; past it, only when nothing that says `key` was kept yet (the reading is saturated).
 */
export function keepItem(item: KeptItem, key: string): boolean {
  if (current === null) return true;

  if (current.left >= 0) {
    current.left -= itemBytes(item);

    if (current.left >= 0) {
      current.kept.add(key);

      return true;
    }
  }

  current.saturated = true;

  if (current.kept.has(key)) return false;
  current.kept.add(key);

  return true;
}

/**
 * Charges a fact within the installed limit: true while there is room; past it false, and the reading is saturated. A
 * fact is kept either way (factsOf keeps at most MAX_PER_KIND of a kind); past the limit the caller shortens it.
 */
export function chargeFact(fact: Fact): boolean {
  if (current === null) return true;

  if (current.left >= 0) {
    current.left -= itemBytes(fact);

    if (current.left >= 0) return true;
  }

  current.saturated = true;

  return false;
}

/** Whether to keep an import path: outside a limit, or within one while there is room; past it, none (saturated). */
export function keepString(s: string): boolean {
  if (current === null) return true;

  if (current.left >= 0) {
    current.left -= stringBytes(s);

    if (current.left >= 0) return true;
  }

  current.saturated = true;

  return false;
}

/**
 * A temporary list's running size while it is built: `fits` charges an item and says whether it fits the installed
 * limit's `temp`. One that does not is not charged, and the reading is stopped: the pass building the list stops there,
 * keeping what it built. With no limit installed everything fits.
 */
export function tempBytes(): TempList {
  const limit = current;
  let held = 0;

  return {
    fits(bytes: number): boolean {
      if (limit === null) return true;

      if (held + bytes > limit.temp) {
        limit.stopped = true;

        return false;
      }

      held += bytes;

      return true;
    },
  };
}
