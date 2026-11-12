// What a score did not check, shortened for the line beside the number. The full list is the `notChecked`
// array the scorer writes (packages/core/src/score.ts NOT_CHECKED, then anything specific to the version).

/** The short form: the three limits that matter most to a reader, then what is specific to this version. */
export type LimitationSummary = { headline: string; extra: string | null; total: number };

const HEADLINE = "Not checked: what the code does at runtime, the code of its dependencies, or a compromised publisher.";

/** The version-specific entries: dependencies apm could not score and files it did not read. */
type Specific = { deps: number; files: string | null };

function specific(notChecked: readonly string[]): Specific {
  const deps = notChecked.filter((n) => n.startsWith("dependency ")).length;
  const files = notChecked.find((n) => /^\d+ file\(s\) not analyzed/.test(n)) ?? null;

  return { deps, files };
}

export function summarizeLimitations(notChecked: readonly string[]): LimitationSummary {
  const { deps, files } = specific(notChecked);
  const parts: string[] = [];

  if (deps > 0) parts.push(`${deps} ${deps === 1 ? "dependency" : "dependencies"} apm could not score`);

  if (files) parts.push(`${/^\d+/.exec(files)?.[0] ?? "some"} ${files.startsWith("1 ") ? "file" : "files"} not analyzed`);

  return { headline: HEADLINE, extra: parts.length > 0 ? `Also: ${parts.join(", ")}.` : null, total: notChecked.length };
}

/** A full list entry split at its first colon, so the topic can be set apart from the detail. */
export type LimitationParts = { topic: string; detail: string | null };

export function splitLimitation(entry: string): LimitationParts {
  const i = entry.indexOf(": ");

  if (i <= 0 || i > 60) return { topic: entry, detail: null };

  return { topic: entry.slice(0, i), detail: entry.slice(i + 2) };
}

/** Evidence the scorer marked as only possible ends in ` [possible: why]`; this splits the reason off. */
export type PossibleEvidence = { text: string; why: string | null };

export function splitPossible(evidence: string): PossibleEvidence {
  const m = /^([\s\S]*?) \[possible: ([^\]]+)\]$/.exec(evidence);

  return m?.[1] !== undefined && m[2] ? { text: m[1], why: m[2] } : { text: evidence, why: null };
}
