import { cn } from "cn";

export type Tone = "none" | "ok" | "warn" | "bad";

/** The grade of a partial reading (apm-score-v11): it scores only what apm read, so it is never shown as a pass. */
export const PARTIAL_GRADE = "P";

export function toneOf(score: number | null | undefined, grade?: string | null): Tone {
  if (score === null || score === undefined) return "none";

  // a partial reading is a warning whatever it scored
  if (grade === PARTIAL_GRADE) return "warn";

  if (score >= 75) return "ok";

  if (score >= 40) return "warn";

  return "bad";
}

const SOFT: Record<Tone, string> = {
  none: "bg-surface text-muted-foreground",
  ok: "bg-ok-soft text-ok",
  warn: "bg-warn-soft text-warn",
  bad: "bg-bad-soft text-bad",
};

/** Tinted fill and text for a score, as Tailwind classes. */
export function scoreTone(score: number | null | undefined, grade?: string | null): string {
  return SOFT[toneOf(score, grade)];
}

/**
 * `unscorable`: the registry decided the version can never be scored (too large, unreadable, over its limits). A partial
 * reading (grade P) reads "partial" in the warning tone, never a letter and a number that look like a pass.
 */
export function ScoreBadge({ score, grade, unscorable = false, className }: { score: number | null | undefined; grade?: string | null; unscorable?: boolean; className?: string }) {
  const unscored = score === null || score === undefined;

  return (
    <span
      className={cn("inline-flex h-7 min-w-[3.75rem] shrink-0 items-center justify-center gap-1.5 rounded-lg px-2 font-mono text-[13px] tabular-nums", unscored && unscorable ? SOFT.warn : scoreTone(score, grade), className)}
      title={unscored ? (unscorable ? "Cannot be scored" : "Not scored yet") : grade === PARTIAL_GRADE ? `Partial analysis: ${score}/100 on the code apm read` : `apm score ${score}/100`}
    >
      {unscored ? (
        <span aria-label={unscorable ? "Cannot be scored" : "Not scored"}>n/a</span>
      ) : grade === PARTIAL_GRADE ? (
        <span aria-label={`Partial analysis, ${score}/100 on the code apm read`}>partial</span>
      ) : (
        <>
          <span className="font-semibold">{grade ?? ""}</span>
          <span>{score}</span>
        </>
      )}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  if (status === "active") return null;
  const tone = status === "yanked" ? SOFT.warn : SOFT.bad;
  const label = status === "revoke-pending" ? "revoke pending" : status;

  return <span className={cn("inline-flex h-6 items-center rounded-md px-2 text-xs font-medium", tone)}>{label}</span>;
}
