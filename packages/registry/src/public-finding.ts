// What the public may see of an AI review finding, built from nothing the model or the publisher wrote freely
// (independent re-check of 70dc3df: the model's sentence could quote a secret no masking recognised). A public finding
// is its file, line, severity and a label apm chose from a fixed list; the model's sentence only picks which label.
// Pure: review.ts builds every public answer through it.
import type { WireFinding } from "@apm/ai-review";
import { WITHHELD_ISSUE } from "./withheld.ts";

/** The labels a public finding can carry. Fixed text, apm's own. */
export const FINDING_LABELS = ["sends data out", "install script", "runs code", "credential read", "network call", "obfuscated code", "file access", "flagged code"] as const;

export type FindingLabel = (typeof FINDING_LABELS)[number];

/** Words that pick a label, most specific first: the first label any of whose words the sentence has wins. */
const LABEL_WORDS: readonly (readonly [FindingLabel, readonly string[]])[] = [
  ["sends data out", ["exfiltrat", "sends ", "send ", "posts ", "post ", "upload", "transmit", "beacon", "leak"]],
  ["install script", ["postinstall", "preinstall", "install script", "install hook", "lifecycle", "at install"]],
  ["runs code", ["eval", "function(", "child_process", "exec", "spawn", "shell", "| sh", "| bash", "runs a downloaded", "runs code", "vm.run"]],
  ["credential read", ["credential", "token", "secret", "password", ".npmrc", "ssh", "api key", "process.env", "environment variable", "keychain", "wallet"]],
  ["network call", ["http", "request", "fetch", "network", "url", "socket", "dns", "remote", "host", "webhook", "domain"]],
  ["obfuscated code", ["obfuscat", "base64", "encoded", "decode", "hex string", "packed"]],
  ["file access", ["file system", "filesystem", "writes file", "writefile", "deletes", "unlink", "rm -rf", "home directory"]],
];

/** The label for a finding's sentence: a fixed string whatever the sentence says. */
export function labelOf(sentence: string): FindingLabel {
  const s = sentence.toLowerCase();

  for (const [label, words] of LABEL_WORDS) if (words.some((w) => s.includes(w))) return label;

  return "flagged code";
}

/** A finding as anyone may see it once a person confirmed it. */
export type PublicFinding = { file: string; line: number; severity: WireFinding["severity"]; label: FindingLabel; issue: string };

/**
 * The public findings of a confirmed review: each file as `file N` (numbered in order, the same number for the same
 * path), never by name, since a publisher's file name can be a secret of any shape (re-check of d38f704: a UUID or a
 * hyphenated token passed every shape test); owners and admins see names in the private view. Then the line, the
 * severity and a fixed label. `issue` carries the label too,
 * for clients that read it (a withheld version's fixed WITHHELD_ISSUE stays). The model's sentence is read only to
 * pick the label.
 */
export function publicFindings(findings: readonly WireFinding[]): PublicFinding[] {
  const refs = new Map<string, string>();

  const fileOf = (path: string, withheld: boolean): string => {
    // a withheld version's findings already name files by reference; a publisher's file literally named "file 2" is
    // numbered like any other path (re-check of ef953ed)
    if (withheld && /^file \d{1,4}$/.test(path)) return path;
    const known = refs.get(path);

    if (known !== undefined) return known;
    const ref = `file ${refs.size + 1}`;

    refs.set(path, ref);

    return ref;
  };

  return findings.map((f) => {
    const label = labelOf(f.issue);

    return { file: fileOf(f.file, f.issue === WITHHELD_ISSUE), line: f.line, severity: f.severity, label, issue: f.issue === WITHHELD_ISSUE ? WITHHELD_ISSUE : label };
  });
}
