import Link from "next/link";
import { Suspense } from "react";
import { Skeleton } from "@/components/ui/skeleton";
import { CheckIcon, XIcon, TriangleAlertIcon } from "lucide-react";
import { checkName, search, type NameCheck, type SearchResult } from "@/lib/registry";
import { ScoreBadge } from "@/components/score-badge";

function Row({ href, children, className = "" }: { href?: string; children: React.ReactNode; className?: string }) {
  const inner = <div className={`flex min-h-14 items-center gap-3 px-4 py-3 ${className}`}>{children}</div>;
  return href ? (
    <Link href={href} className="block transition-colors hover:bg-muted/50 focus-visible:bg-muted/50 focus-visible:outline-none">
      {inner}
    </Link>
  ) : (
    inner
  );
}

function Name({ name, q }: { name: string; q: string }) {
  const i = name.indexOf(q);
  const scope = name.startsWith("@") ? name.slice(0, name.indexOf("/") + 1) : "";
  const rest = name.slice(scope.length);
  if (i < 0 || q.length === 0) {
    return (
      <span className="truncate font-mono text-sm">
        {scope && <span className="font-semibold">{scope}</span>}
        {rest}
      </span>
    );
  }
  return (
    <span className="truncate font-mono text-sm text-muted-foreground">
      {name.slice(0, i)}
      <span className="text-foreground">{name.slice(i, i + q.length)}</span>
      {name.slice(i + q.length)}
    </span>
  );
}

function Status({ kind, children }: { kind: "free" | "taken" | "warn"; children: React.ReactNode }) {
  const tone = kind === "free" ? "text-emerald-700 dark:text-emerald-400" : kind === "warn" ? "text-amber-700 dark:text-amber-400" : "text-muted-foreground";
  const Icon = kind === "free" ? CheckIcon : kind === "warn" ? TriangleAlertIcon : XIcon;
  return (
    <span className={`flex shrink-0 items-center gap-1.5 text-xs ${tone}`}>
      <Icon className="size-3.5" aria-hidden />
      {children}
    </span>
  );
}

/** Four fixed slots answering "can I use this name, and is it safe to install?" in one glance. */
function TopResults({ check }: { check: NameCheck }) {
  const scoped = check.suggestions.find((s) => s.name.startsWith("@"));
  const nearest = check.lookalikes[0] ?? check.similar[0];
  return (
    <section aria-labelledby="top-results">
      <h2 id="top-results" className="mb-2 text-xs font-medium tracking-wide text-muted-foreground uppercase">
        Top results
      </h2>
      <div className="divide-y overflow-hidden rounded-lg border">
        <Row href={check.taken ? `/package/${check.query}` : undefined}>
          <Name name={check.query} q="" />
          <span className="flex-1 truncate text-sm text-muted-foreground">
            {check.taken ? check.description || (check.source === "upstream" ? "on the public npm registry" : "") : check.valid ? "exact name" : "not a valid package name"}
          </span>
          {check.taken ? (
            <>
              <Status kind="taken">taken{check.owners.length ? ` by ${check.owners.slice(0, 2).join(", ")}` : ""}</Status>
              <ScoreBadge score={check.latest?.score} grade={check.latest?.grade} />
            </>
          ) : check.available ? (
            <Status kind="free">available</Status>
          ) : (
            <Status kind="warn">{check.valid ? "blocked: too close to a popular name" : "invalid"}</Status>
          )}
        </Row>
        <Row>
          <Name name={scoped?.name ?? `@you/${check.query}`} q="" />
          <span className="flex-1 truncate text-sm text-muted-foreground">under your scope, always yours</span>
          {scoped ? (scoped.available ? <Status kind="free">available</Status> : <Status kind="taken">taken</Status>) : <span className="text-xs text-muted-foreground">log in to check</span>}
        </Row>
        <Row href={nearest ? `/package/${nearest.name}` : undefined}>
          {nearest ? (
            <>
              <Name name={nearest.name} q="" />
              <span className="flex-1 truncate text-sm text-muted-foreground">{nearest.reason}</span>
              <Status kind="warn">typo risk</Status>
            </>
          ) : (
            <>
              <span className="font-mono text-sm text-muted-foreground">no look-alikes</span>
              <span className="flex-1 truncate text-sm text-muted-foreground">nothing popular is one typo away</span>
              <Status kind="free">clear</Status>
            </>
          )}
        </Row>
        <Row>
          <span className="font-mono text-sm text-muted-foreground">alternatives</span>
          <span className="flex flex-1 flex-wrap gap-x-3 gap-y-1">
            {check.suggestions
              .filter((s) => !s.name.startsWith("@") && s.available)
              .slice(0, 4)
              .map((s) => (
                <span key={s.name} className="font-mono text-sm">
                  {s.name}
                </span>
              ))}
          </span>
        </Row>
      </div>
    </section>
  );
}

function Results({ results, q }: { results: SearchResult[]; q: string }) {
  return (
    <section aria-labelledby="all-results">
      <h2 id="all-results" className="mb-2 text-xs font-medium tracking-wide text-muted-foreground uppercase">
        All results <span className="tabular-nums">({results.length})</span>
      </h2>
      {results.length === 0 ? (
        <p className="rounded-lg border px-4 py-6 text-sm text-muted-foreground">No packages on this registry match “{q}”. Public npm packages show up when you search their exact name.</p>
      ) : (
        <ul className="divide-y overflow-hidden rounded-lg border">
          {results.map((r) => (
            <li key={r.package.name}>
              <Row href={`/package/${r.package.name}`}>
                <div className="flex min-w-0 flex-1 flex-col gap-0.5 sm:flex-row sm:items-center sm:gap-3">
                  <Name name={r.package.name} q={q} />
                  <span className="truncate text-sm text-muted-foreground">{r.package.description}</span>
                </div>
                <span className="hidden font-mono text-xs text-muted-foreground tabular-nums sm:block">{r.package.version}</span>
                <ScoreBadge score={r.apmScore?.score} grade={r.apmScore?.grade} />
              </Row>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function ResultsSkeleton() {
  return (
    <div className="flex flex-col gap-8" aria-busy="true" aria-label="Loading results">
      {[4, 3].map((n, k) => (
        <div key={k}>
          <Skeleton className="mb-2 h-3 w-24" />
          <div className="divide-y rounded-lg border">
            {Array.from({ length: n }, (_, i) => (
              <div key={i} className="flex h-14 items-center gap-3 px-4">
                <Skeleton className="h-4 w-40" />
                <Skeleton className="h-4 flex-1" />
                <Skeleton className="h-6 w-14" />
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

export default function Home({ searchParams }: PageProps<"/">) {
  return (
    <Suspense fallback={<ResultsSkeleton />}>
      <HomeContent searchParams={searchParams} />
    </Suspense>
  );
}

async function HomeContent({ searchParams }: { searchParams: PageProps<"/">["searchParams"] }) {
  const raw = (await searchParams).q;
  const q = (Array.isArray(raw) ? raw[0] : raw)?.trim().toLowerCase() ?? "";
  if (!q) {
    return (
      <div className="mx-auto max-w-2xl py-16">
        <h1 className="text-2xl font-semibold tracking-tight text-balance">Search a package, or check a name before you publish.</h1>
        <p className="mt-3 text-muted-foreground text-pretty">
          Every version gets an explained security score. Maintainers can yank or revoke a bad release in one step. Point any client at{" "}
          <code className="rounded bg-muted px-1 font-mono text-sm">/~safe/</code> to skip versions younger than 24 hours or scoring under 40.
        </p>
        <div className="mt-8 grid gap-3 font-mono text-sm sm:grid-cols-2">
          <div className="rounded-lg border p-3">
            <div className="text-xs text-muted-foreground">install with a check</div>
            <div className="mt-1">bunx apm add zod</div>
          </div>
          <div className="rounded-lg border p-3">
            <div className="text-xs text-muted-foreground">publish with a preflight</div>
            <div className="mt-1">bunx apm publish --bump patch</div>
          </div>
        </div>
      </div>
    );
  }
  const [check, results] = await Promise.all([checkName(q), search(q)]);
  return (
    <div className="flex flex-col gap-8">
      {check ? <TopResults check={check} /> : <p className="text-sm text-muted-foreground">The registry did not answer.</p>}
      <Results results={results.filter((r) => r.package.name !== q || !check?.taken)} q={q} />
    </div>
  );
}
