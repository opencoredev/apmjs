// What a score did not check, sorted for the page. The `notChecked` array the scorer writes holds general limits
// (packages/core/src/score.ts NOT_CHECKED), per-file reading limits ("<limit> (<files>)", js.ts LIMIT_NOTES), files
// left unread and dependencies apm could not score. Stored analyses keep the wording of the scorer that made them,
// so older general entries are recognized here and replaced by today's plain list.

/** Today's general limits, word for word as packages/core NOT_CHECKED writes them (limitations.test.ts checks). */
export const GENERAL_LIMITS: readonly string[] = [
  "runtime behavior: what the code does when it runs, such as downloading or unpacking more code",
  "code hidden by a custom encoding, compression or encryption",
  "the code of its dependencies, beyond their own scores",
  "native binaries and WebAssembly: listed, not read",
  "whether the publisher's machine or CI was compromised",
];

/** General entries earlier scorers wrote. Shown as today's list, not as written. */
const EARLIER_GENERAL: ReadonlySet<string> = new Set([
  "runtime behavior: code that downloads, decrypts or builds a second stage while running",
  "code hidden by anything but base64, hex, \\x escapes, char codes or joined string literals (XOR, compression, a custom encoding)",
  "names built at runtime from values apm cannot work out in the file (array lookups, computed indexes, values read at runtime)",
  "names built at runtime from values apm cannot work out in the file (array lookups, computed indexes, values read at runtime, values passed through a function's parameters)",
  "names built at runtime other than by joining string literals (array lookups, reversed strings, computed indexes)",
  "documentation, type, JSON, style and markup files that no code reaches by a path apm can read; a computed require is reported as dynamic-require",
  "a popular name reused under another scope (@someone/react): scopes exist so names can be reused",
  "the code of dependencies beyond their own scores",
]);

/** One reading limit and the files it was hit in. */
export type ReadingLimit = { limit: string; files: string };

/** Everything the page shows about what was not checked. */
export type Limitations = {
  general: readonly string[];
  /** Files whose code was too complex to follow, so the text rules alone judged them. Empty when none. */
  complex: ReadingLimit[];
  /** "3 file(s) not analyzed: ..." entries. */
  unread: string[];
  /** Dependencies apm could not score. */
  dependencies: string[];
  /** Anything this page does not know how to sort, shown as written. */
  other: string[];
};

// "<limit> (<files>)": a limit note always ends with the files it was hit in
const NOTE = /^(.+?) \(([^()]+)\)$/;

/** An earlier note said what happened past the limit after a colon ("...: the rest were read as unknown, ..."). */
function plainLimit(text: string): string {
  const colon = text.indexOf(": ");

  return colon > 0 ? text.slice(0, colon) : text;
}

export function sortLimitations(notChecked: readonly string[]): Limitations {
  const out: Limitations = { general: GENERAL_LIMITS, complex: [], unread: [], dependencies: [], other: [] };
  const general = new Set(GENERAL_LIMITS);

  for (const n of notChecked) {
    if (general.has(n) || EARLIER_GENERAL.has(n)) continue;

    if (n.startsWith("dependency ")) {
      out.dependencies.push(n.slice("dependency ".length));
      continue;
    }

    if (/^\d+ file\(s\) not analyzed/.test(n)) {
      out.unread.push(n);
      continue;
    }

    const note = NOTE.exec(n);

    if (note?.[1] && note[2]) out.complex.push({ limit: plainLimit(note[1]), files: note[2] });
    else out.other.push(n);
  }

  return out;
}

/** How many lines the disclosure lists: the general limits, one line for complex code, and the rest. */
export function limitationCount(l: Limitations): number {
  return l.general.length + (l.complex.length > 0 ? 1 : 0) + l.unread.length + (l.dependencies.length > 0 ? 1 : 0) + l.other.length;
}

/** The short form beside the number: the plain one-line summary, then what is specific to this version. */
export type LimitationSummary = { headline: string; extra: string | null; total: number };

const HEADLINE = "Not checked: what the code does at runtime, the code of its dependencies, or a compromised publisher.";

export function summarizeLimitations(notChecked: readonly string[]): LimitationSummary {
  const l = sortLimitations(notChecked);
  const parts: string[] = [];
  const deps = l.dependencies.length;
  const unread = l.unread[0];

  if (deps > 0) parts.push(`${deps} ${deps === 1 ? "dependency" : "dependencies"} apm could not score`);

  if (unread) parts.push(`${/^\d+/.exec(unread)?.[0] ?? "some"} ${unread.startsWith("1 ") ? "file" : "files"} not analyzed`);

  return { headline: HEADLINE, extra: parts.length > 0 ? `Also: ${parts.join(", ")}.` : null, total: limitationCount(l) };
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
