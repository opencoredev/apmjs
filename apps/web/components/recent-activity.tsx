// What happened on this registry lately: publishes with their score, yanks and revokes with the reason.
import Link from "next/link";
import { connection } from "next/server";
import { ArrowUpFromLineIcon, BanIcon, RotateCcwIcon, Undo2Icon } from "lucide-react";
import { getRecent, type RecentEvent } from "@/lib/registry";
import { ago } from "@/lib/format";
import { ScoreBadge, StatusBadge } from "@/components/score-badge";
import { cn } from "cn";

const KIND = {
  publish: { label: "published", icon: ArrowUpFromLineIcon, tone: "text-muted-foreground" },
  yank: { label: "yanked", icon: Undo2Icon, tone: "text-warn" },
  unyank: { label: "unyanked", icon: RotateCcwIcon, tone: "text-muted-foreground" },
  revoke: { label: "revoked", icon: BanIcon, tone: "text-bad" },
  restore: { label: "restored", icon: RotateCcwIcon, tone: "text-muted-foreground" },
} as const satisfies Record<RecentEvent["kind"], { label: string; icon: unknown; tone: string }>;

function Row({ e, now }: { e: RecentEvent; now: number }) {
  const k = KIND[e.kind];
  const scope = e.package.startsWith("@") ? e.package.slice(0, e.package.indexOf("/") + 1) : "";

  return (
    <li className="border-b">
      <Link href={`/package/${e.package}`} prefetch={false} className="-mx-3 flex min-h-14 items-center gap-3 rounded-xl px-3 py-2.5 transition-colors hover:bg-surface sm:gap-4">
        <k.icon className={cn("size-4 shrink-0", k.tone)} aria-hidden />
        <span className="flex min-w-0 flex-1 flex-col gap-0.5 sm:flex-row sm:items-baseline sm:gap-3">
          <span className="flex min-w-0 items-baseline gap-2">
            <span className="truncate font-mono text-[15px]">
              {scope && <span className="text-muted-foreground">{scope}</span>}
              {e.package.slice(scope.length)}
              <span className="text-muted-foreground">@{e.version}</span>
            </span>
            {e.kind === "publish" && e.status && e.status !== "active" ? <StatusBadge status={e.status} /> : null}
          </span>
          <span className="truncate text-sm text-muted-foreground">
            <span className={k.tone}>{k.label}</span>
            {e.reason ? `: ${e.reason}` : ` by ${e.actor}`}
          </span>
        </span>
        <span className="hidden shrink-0 text-sm text-muted-foreground tabular-nums sm:block">{ago(e.at, now)}</span>
        <ScoreBadge score={e.score} grade={e.grade} />
      </Link>
    </li>
  );
}

export async function RecentActivity() {
  // Request time only: a build-time prerender would abort this fetch and log a false outage.
  await connection();
  const recent = await getRecent(8);
  const now = Date.now();

  // the registry leaves its own smoke checks out of the feed; with nothing real to show, the home page shows no feed
  if (recent.kind === "ok" && recent.value.length === 0) return null;

  return (
    <section aria-labelledby="recent">
      <h2 id="recent" className="mb-2 text-[15px] font-medium">
        Recently on this registry
      </h2>
      {recent.kind !== "ok" ? (
        <p role="status" className="border-t py-5 text-sm text-muted-foreground">
          Couldn&apos;t load recent activity. The registry did not answer;{" "}
          <a href="/" className="text-foreground underline underline-offset-4">
            reload
          </a>{" "}
          to try again. Search above may still work for npm packages.
        </p>
      ) : (
        <ul className="border-t">
          {recent.value.map((e) => (
            <Row key={`${e.package}@${e.version}:${e.kind}:${e.at}`} e={e} now={now} />
          ))}
        </ul>
      )}
    </section>
  );
}

export function RecentActivitySkeleton() {
  return (
    <div aria-hidden>
      <span className="mb-3 block h-4 w-44 animate-pulse rounded bg-muted" />
      {[0, 1, 2, 3, 4].map((i) => (
        <span key={i} className="flex h-14 items-center gap-4 border-t">
          <span className="size-4 animate-pulse rounded bg-muted" />
          <span className="h-4 w-56 animate-pulse rounded bg-muted" />
        </span>
      ))}
    </div>
  );
}
