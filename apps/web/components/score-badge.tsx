import { cn } from "cn";
import { isNotAllRead, NOT_ALL_READ, PARTIAL_GRADE, scoreOnWhatWasRead } from "@/lib/coverage";

export { PARTIAL_GRADE };

export type Tone = "none" | "ok" | "warn" | "bad";

export function toneOf(score: number | null | undefined, grade?: string | null): Tone {
  if (score === null || score === undefined) return "none";

  // a version apm did not read in full is a warning whatever it scored: it is never shown as a pass
  if (isNotAllRead(grade)) return "warn";

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
 * `unscorable`: the registry decided the version can never be scored (too large, unreadable, over its limits). A version
 * apm did not read in full (grade P) reads "98 · not all read" in the warning tone, never a letter and a number that
 * look like a pass.
 */
export function ScoreBadge({ score, grade, unscorable = false, className }: { score: number | null | undefined; grade?: string | null; unscorable?: boolean; className?: string }) {
  const unscored = score === null || score === undefined;
  const notAllRead = !unscored && isNotAllRead(grade);
  const notAllReadLabel = unscored ? "" : `${scoreOnWhatWasRead(score)}; apm did not read every file`;

  return (
    <span
      className={cn("inline-flex h-7 min-w-[3.75rem] shrink-0 items-center justify-center gap-1.5 rounded-lg px-2 font-mono text-[13px] tabular-nums", unscored && unscorable ? SOFT.warn : scoreTone(score, grade), className)}
      title={unscored ? (unscorable ? "Cannot be scored" : "Not scored yet") : notAllRead ? notAllReadLabel : `apm score ${score}/100`}
    >
      {unscored ? (
        <span aria-label={unscorable ? "Cannot be scored" : "Not scored"}>n/a</span>
      ) : notAllRead ? (
        <span className="inline-flex items-baseline gap-1.5 whitespace-nowrap">
          <span aria-hidden>{score}</span>
          <span aria-hidden className="font-sans">
            · {NOT_ALL_READ}
          </span>
          <span className="sr-only">{notAllReadLabel}</span>
        </span>
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
