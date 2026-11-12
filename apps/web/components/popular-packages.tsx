// The home page with nothing typed: a compact grid of popular packages. Names and links are in the static shell
// (fast, crawlable); each score badge streams in on its own, so a slow read never holds the search box or the grid.
import Link from "next/link";
import { Suspense } from "react";
import { connection } from "next/server";
import { ScoreBadge } from "@/components/score-badge";
import { popularScore } from "@/lib/agent/popular";
import { POPULAR_PACKAGES } from "@/lib/agent/site";
import { packagePath } from "@/lib/package-route";

const BADGE = "h-6 min-w-[3.25rem] gap-1 rounded-md px-1.5 text-[12px]";

async function PopularBadge({ name }: { name: string }) {
  await connection();
  const s = await popularScore(name);

  return <ScoreBadge score={s?.score ?? null} grade={s?.grade ?? null} className={BADGE} />;
}

function BadgeSkeleton() {
  return <span className="inline-block h-6 w-[3.25rem] shrink-0 animate-pulse rounded-md bg-muted" aria-hidden />;
}

export function PopularPackages() {
  return (
    <section aria-labelledby="popular">
      <h2 id="popular" className="mb-3 text-[15px] font-medium">
        Popular packages
      </h2>
      <ul className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
        {POPULAR_PACKAGES.map((p) => (
          <li key={p.name} className="min-w-0">
            <Link
              href={packagePath(p.name)}
              prefetch={false}
              className="flex h-full min-h-[3.75rem] flex-col items-start gap-1.5 rounded-xl border px-3 py-2.5 transition-colors hover:bg-surface focus-visible:bg-surface sm:flex-row sm:items-center sm:justify-between sm:gap-2"
            >
              {/* phones: the name over its badge, so a two-column grid never cuts a name short */}
              <span className="flex w-full min-w-0 flex-col sm:w-auto">
                <span className="truncate font-mono text-[15px]">{p.name}</span>
                <span className="hidden truncate text-[13px] text-muted-foreground sm:block">{p.blurb}</span>
              </span>
              <Suspense fallback={<BadgeSkeleton />}>
                <PopularBadge name={p.name} />
              </Suspense>
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}
