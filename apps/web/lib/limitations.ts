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

/** Evidence the scorer marked as only possible ends in ` [possible: why]`; this splits the reason off. */
export type PossibleEvidence = { text: string; why: string | null };

export function splitPossible(evidence: string): PossibleEvidence {
  const m = /^([\s\S]*?) \[possible: ([^\]]+)\]$/.exec(evidence);

  return m?.[1] !== undefined && m[2] ? { text: m[1], why: m[2] } : { text: evidence, why: null };
}

/** Evidence from a shipped test file carries ` (in a test file)` after its snippet (apm-score-v5). */
export type TestFileEvidence = { text: string; testFile: boolean };

const IN_TEST_FILE = " (in a test file)";

/** Splits the test-file mark off evidence whose `[possible: why]` reason, if any, was already split off. */
export function splitTestFile(evidence: string): TestFileEvidence {
  return evidence.endsWith(IN_TEST_FILE) ? { text: evidence.slice(0, -IN_TEST_FILE.length), testFile: true } : { text: evidence, testFile: false };
}
