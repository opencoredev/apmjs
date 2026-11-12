import { cn } from "cn";

export type Tone = "none" | "ok" | "warn" | "bad";

export function toneOf(score: number | null | undefined): Tone {
  if (score === null || score === undefined) return "none";

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
export function scoreTone(score: number | null | undefined): string {
  return SOFT[toneOf(score)];
}

/** `unscorable`: the registry decided the version can never be scored (too large, unreadable, over its limits). */
export function ScoreBadge({ score, grade, unscorable = false, className }: { score: number | null | undefined; grade?: string | null; unscorable?: boolean; className?: string }) {
  const unscored = score === null || score === undefined;

  return (
    <span
      className={cn("inline-flex h-7 min-w-[3.75rem] shrink-0 items-center justify-center gap-1.5 rounded-lg px-2 font-mono text-[13px] tabular-nums", unscored && unscorable ? SOFT.warn : scoreTone(score), className)}
      title={unscored ? (unscorable ? "Cannot be scored" : "Not scored yet") : `apm score ${score}/100`}
    >
      {unscored ? (
        <span aria-label={unscorable ? "Cannot be scored" : "Not scored"}>n/a</span>
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
