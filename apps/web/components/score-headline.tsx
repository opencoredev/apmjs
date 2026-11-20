import { foldersSentence, isNotAllRead, namedFolders, NOT_ALL_READ_INSTALLS_PARTS, scoreOnWhatWasRead, skippedSentence, type Coverage, type OmittedFolder } from "@/lib/coverage";

/** The score panel's tones on the inverse surface, by tone. */
export type HeadlineTone = { text: string; bar: string };

/**
 * What the score panel leads with: `stopped`, an analysis that stopped before it finished; `partial`, a version apm did
 * not read in full, graded "P" (only whole files left unread for their size or the byte budget, and nothing else
 * unfinished: core readingOf); `score`, anything else, an analysis incomplete for another reason included, which shows
 * its score and letter as an incomplete one always has. Neither of the first two shows a grade letter.
 */
export function headlineKind(grade: string, coverage: Coverage | null | undefined): "stopped" | "partial" | "score" {
  if (coverage?.kind === "partial" && coverage.reasons.includes("stopped")) return "stopped";

  return isNotAllRead(grade) && coverage?.kind === "partial" ? "partial" : "score";
}

/**
 * The score panel's headline. A complete reading leads with its score. A version apm did not read in full
 * (apm-score-v11) leads with "Not fully checked", gives the score only as what the files apm read scored, and says
 * what apm skipped, why, where (`folders`, the registry's biggest folders of unread files, when it sends them) and
 * what installs do about it, with no grade letter and no meter: it is never shown as a pass. One that stopped before it
 * finished says so, with no count of files not read. `unpackedSize`: the shown version's, when the page has it.
 */
export function ScoreHeadline(props: {
  score: number;
  grade: string;
  coverage: Coverage | null | undefined;
  tone: HeadlineTone;
  version: string | null;
  name: string;
  unpackedSize: number | null;
  folders: readonly OmittedFolder[];
}) {
  const { score, grade, coverage, tone, version } = props;
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
    const folders = namedFolders(props.folders, coverage.omittedBytes);

    return (
      <div>
        {label}
        <div className="mt-2 text-4xl leading-none font-medium tracking-tight text-inverse-warn sm:text-5xl">Not fully checked</div>
        <p className="mt-3 text-[15px] leading-6 text-inverse-foreground tabular-nums">{scoreOnWhatWasRead(score)}</p>
        <p className="mt-1 max-w-prose text-sm leading-6 text-pretty text-inverse-muted tabular-nums">
          {skippedSentence({ coverage, name: props.name, unpackedSize: props.unpackedSize })}
          {folders.length > 0 && ` ${foldersSentence(folders, { files: coverage.omittedFiles, bytes: coverage.omittedBytes })}`}
          {coverage.notes.map((n) => ` ${n.charAt(0).toUpperCase()}${n.slice(1)}.`).join("")}
        </p>
        <p className="mt-2 max-w-prose text-sm leading-6 text-pretty text-inverse-muted">
          {NOT_ALL_READ_INSTALLS_PARTS.before}
          <code className="font-mono text-[0.92em] text-inverse-foreground">{NOT_ALL_READ_INSTALLS_PARTS.flag}</code>
          {NOT_ALL_READ_INSTALLS_PARTS.after}
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
