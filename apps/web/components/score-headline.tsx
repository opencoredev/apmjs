import type { Coverage } from "@/lib/coverage";
import { PARTIAL_GRADE } from "./score-badge";

/** The score panel's tones on the inverse surface, by tone. */
export type HeadlineTone = { text: string; bar: string };

/** "2,656 files" */
function files(n: number): string {
  return `${n.toLocaleString("en-US")} file${n === 1 ? "" : "s"}`;
}

/**
 * What the score panel leads with: `stopped`, an analysis that stopped before it finished; `partial`, a reading graded
 * "P" (only whole files left unread for their size or the byte budget, and nothing else unfinished: core readingOf);
 * `score`, anything else, an analysis incomplete for another reason included, which shows its score and letter as an
 * incomplete one always has. Neither of the first two shows a grade letter.
 */
export function headlineKind(grade: string, coverage: Coverage | null | undefined): "stopped" | "partial" | "score" {
  if (coverage?.kind === "partial" && coverage.reasons.includes("stopped")) return "stopped";

  return grade === PARTIAL_GRADE && coverage?.kind === "partial" ? "partial" : "score";
}

/**
 * The score panel's headline. A complete reading leads with its score; a partial one (apm-score-v11) leads with
 * "Partial analysis" and gives the score only as what the code apm read scored, beside how many files it did not read,
 * with no grade letter and no meter: a partial reading is never shown as a pass. One that stopped before it finished
 * says so, with no count of files not read.
 */
export function ScoreHeadline({ score, grade, coverage, tone, version }: { score: number; grade: string; coverage: Coverage | null | undefined; tone: HeadlineTone; version: string | null }) {
  const label = <div className="text-sm text-inverse-muted">{version ? `Version ${version}` : "Latest version"}</div>;
  const kind = headlineKind(grade, coverage);

  // an analysis that stopped (its work limit, a manifest past what apm reads, runs that failed) read nothing it can
  // vouch for: it is said to have stopped, never given a count of files not read
  if (kind === "stopped") {
    return (
      <div>
        {label}
        <div className="mt-2 text-4xl leading-none font-medium tracking-tight text-inverse-warn sm:text-5xl">Analysis did not finish</div>
        <p className="mt-3 text-[15px] leading-6 text-inverse-foreground tabular-nums">{score}/100: apm stopped before it finished reading this version</p>
        <p className="mt-1 max-w-prose text-sm leading-6 text-inverse-muted">Nothing in it was cleared, so the number is not a reading of its code. Installs through apm warn about this version, and strict mode refuses it.</p>
      </div>
    );
  }

  if (kind === "partial" && coverage?.kind === "partial") {
    return (
      <div>
        {label}
        <div className="mt-2 text-4xl leading-none font-medium tracking-tight text-inverse-warn sm:text-5xl">Partial analysis</div>
        <p className="mt-3 text-[15px] leading-6 text-inverse-foreground tabular-nums">
          {score}/100 on the code apm read; {files(coverage.omittedFiles)} not read
        </p>
        <p className="mt-1 max-w-prose text-sm leading-6 text-inverse-muted">
          apm left {coverage.omittedFiles === 1 ? "it" : "them"} unread for their size or the bytes one analysis reads, so nothing in {coverage.omittedFiles === 1 ? "it" : "them"} was checked. Installs through apm warn about this version, and strict mode refuses it.
          {coverage.notes.map((n) => ` ${n.charAt(0).toUpperCase()}${n.slice(1)}.`).join("")}
        </p>
      </div>
    );
  }

  return (
    <div>
      {label}
      <div className="mt-2 flex items-baseline gap-2 tabular-nums">
        <span className={`text-6xl leading-none font-medium tracking-tight ${tone.text}`}>{score}</span>
        <span className="text-xl text-inverse-muted">/100</span>
      </div>
    </div>
  );
}
