// Score evidence is text the scorer writes (packages/core/src/score.ts). The forms that name a file:
//   lib/setup.js:4: require('child_process')...       a line of a file
//   package.json scripts.postinstall: node setup.js   an install script
//   binding.gyp: node-gyp build runs at install       a whole file
//   assets/icon.node                                  a binary (the binary signal's evidence is only the path)
// This splits one into the part to link and the rest, and says where the link goes.

/** Signals whose evidence names a file in the tarball. The others cite dependencies, people or limits. */
const FILE_SIGNALS: ReadonlySet<string> = new Set([
  "install-script",
  "shell-exec",
  "network",
  "credential-access",
  "eval",
  "obfuscated",
  "binary",
  "install-download",
  "git-install-script",
  "dynamic-require",
]);

/** Whether a signal's evidence names a file in the tarball, and so can quote its source after the citation. */
export function namesFile(signal: string): boolean {
  return FILE_SIGNALS.has(signal);
}

/** Where a citation points: a file, and a line or a package.json script in it. */
export type Citation = { path: string; line: number | null; anchor: string | null };

/** One piece of evidence: the cited text (to link) and what follows it (plain text). */
export type CitedEvidence = { cite: string; citation: Citation; rest: string };

const FILE_LINE = /^([^\s:][^:\n]*?):(\d+)(?=: |$)/;
const SCRIPT = /^package\.json (scripts\.[^\s:()]+)/;
const WHOLE_FILE = /^([^\s:]+)(?=: )/;

/** The citation in one piece of evidence, or null when it names no file. */
export function citeEvidence(signal: string, evidence: string): CitedEvidence | null {
  if (!FILE_SIGNALS.has(signal)) return null;
  const line = FILE_LINE.exec(evidence);

  if (line?.[1] && line[2]) return { cite: line[0], citation: { path: line[1], line: Number(line[2]), anchor: null }, rest: evidence.slice(line[0].length) };
  const script = SCRIPT.exec(evidence);

  if (script?.[1]) return { cite: script[0], citation: { path: "package.json", line: null, anchor: script[1] }, rest: evidence.slice(script[0].length) };
  const whole = WHOLE_FILE.exec(evidence);

  if (whole?.[1]) return { cite: whole[0], citation: { path: whole[1], line: null, anchor: null }, rest: evidence.slice(whole[0].length) };

  if (signal === "binary" && evidence.trim() !== "" && !/\s/.test(evidence)) return { cite: evidence, citation: { path: evidence, line: null, anchor: null }, rest: "" };

  return null;
}

/** The 1-based line of `"key":` inside the top-level "scripts" object of a package.json, or null. */
export function scriptLine(packageJson: string, anchor: string): number | null {
  const m = /^scripts\.(.+)$/.exec(anchor);

  if (!m?.[1]) return null;
  const quoted = JSON.stringify(m[1]);
  const lines = packageJson.split("\n");
  const start = lines.findIndex((l) => /^\s*"scripts"\s*:/.test(l));

  if (start < 0) return null;

  // a one-line scripts object: the key is on the same line
  if (lines[start]?.includes(`${quoted}`) && lines[start]?.includes("}")) return start + 1;

  for (let i = start + 1; i < lines.length; i++) {
    const l = lines[i] ?? "";

    if (l.trimStart().startsWith(`${quoted}`) && /^\s*"(?:[^"\\]|\\.)*"\s*:/.test(l)) return i + 1;

    if (/^\s*}/.test(l)) return null;
  }

  return null;
}
