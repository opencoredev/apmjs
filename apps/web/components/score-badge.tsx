import { cn } from "cn";

export function scoreTone(score: number | null | undefined): string {
  if (score === null || score === undefined) return "border-border text-muted-foreground";
  if (score >= 75) return "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400";
  if (score >= 40) return "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400";
  return "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-400";
}

export function ScoreBadge({ score, grade, className }: { score: number | null | undefined; grade?: string | null; className?: string }) {
  return (
    <span
      className={cn("inline-flex h-6 min-w-14 items-center justify-center gap-1 rounded-md border px-1.5 font-mono text-xs tabular-nums", scoreTone(score), className)}
      title={score === null || score === undefined ? "Not scored yet" : `apm score ${score}/100`}
    >
      {score === null || score === undefined ? "–" : (
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
  const tone =
    status === "yanked"
      ? "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400"
      : "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-400";
  const label = status === "revoke-pending" ? "revoke pending" : status;
  return <span className={cn("inline-flex h-5 items-center rounded border px-1.5 text-[11px] font-medium", tone)}>{label}</span>;
}
