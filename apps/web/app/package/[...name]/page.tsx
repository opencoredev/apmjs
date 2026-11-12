import { notFound } from "next/navigation";
import { Suspense } from "react";
import { Skeleton } from "@/components/ui/skeleton";
import { getEvents, getPackage, type Facts, type PackageEvent } from "@/lib/registry";
import { ScoreBadge, StatusBadge, scoreTone } from "@/components/score-badge";
import { InstallTabs } from "@/components/install-tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

function ago(iso: string): string {
  const ms = Date.now() - Date.parse(iso);
  const d = Math.floor(ms / 86_400_000);
  if (d >= 365) return `${Math.floor(d / 365)}y ago`;
  if (d >= 30) return `${Math.floor(d / 30)}mo ago`;
  if (d >= 1) return `${d}d ago`;
  const h = Math.floor(ms / 3_600_000);
  return h >= 1 ? `${h}h ago` : "just now";
}

function size(n: number): string {
  return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} kB` : `${(n / 1048576).toFixed(1)} MB`;
}

function FactRow({ label, value, bad = false }: { label: string; value: string; bad?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-4 py-2 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={bad ? "font-medium text-red-700 dark:text-red-400" : "font-medium"}>{value}</dd>
    </div>
  );
}

function FactsPanel({ facts, maintainers, lastPublish }: { facts: Facts | null; maintainers: string[]; lastPublish: string | null }) {
  return (
    <dl className="divide-y">
      {facts && (
        <>
          <FactRow label="Module format" value={facts.moduleFormat === "dual" ? "ESM + CJS" : facts.moduleFormat.toUpperCase()} />
          <FactRow label="Types" value={facts.types === "bundled" ? "included" : "none"} />
          <FactRow label="Install scripts" value={facts.installScripts ? "yes" : "none"} bad={facts.installScripts} />
          <FactRow label="Dependencies" value={String(facts.dependencyCount)} />
          <FactRow label="Unpacked size" value={size(facts.unpackedSize)} />
          <FactRow label="License" value={facts.license ?? "none"} bad={!facts.license} />
        </>
      )}
      <FactRow label="Maintainers" value={maintainers.length ? maintainers.join(", ") : "unknown"} />
      {lastPublish && <FactRow label="Last publish" value={ago(lastPublish)} />}
    </dl>
  );
}

function describe(e: PackageEvent): string {
  const field = (k: string): string => {
    const val: unknown = typeof e.detail === "object" && e.detail !== null ? Reflect.get(e.detail, k) : undefined;
    return typeof val === "string" ? val : "";
  };
  const v = field("version");
  const why = field("reason") || field("message");
  const reason = why ? `: ${why}` : "";
  switch (e.kind) {
    case "publish":
      return `published ${v}`;
    case "yank":
      return `yanked ${v}${reason}`;
    case "unyank":
      return `restored ${v} to active`;
    case "revoke":
      return `revoked ${v}${reason}`;
    case "revoke-pending":
      return `started revoking ${v}${reason}`;
    case "restore":
      return `downgraded revoke of ${v} to a yank${reason}`;
    case "deprecate":
      return `deprecated ${v}${reason}`;
    case "owner-add":
      return `added owner ${field("user")}`;
    case "owner-remove":
      return `removed owner ${field("user")}`;
    case "dist-tag":
      return `tagged ${v} as ${field("tag")}`;
    default:
      return e.kind;
  }
}

export default function PackagePage({ params }: { params: Promise<{ name: string[] }> }) {
  return (
    <Suspense
      fallback={
        <div className="flex flex-col gap-4" aria-busy="true">
          <Skeleton className="h-8 w-64" />
          <Skeleton className="h-4 w-96 max-w-full" />
          <Skeleton className="mt-4 h-24 w-full" />
          <Skeleton className="h-48 w-full" />
        </div>
      }
    >
      <PackageContent params={params} />
    </Suspense>
  );
}

async function PackageContent({ params }: { params: Promise<{ name: string[] }> }) {
  const parts = (await params).name.map(decodeURIComponent);
  const name = parts.join("/");
  const pkg = await getPackage(name);
  if (!pkg) notFound();
  const events = pkg.source === "local" ? await getEvents(name) : [];
  const latest = pkg.versions.find((v) => v.version === pkg.latest);
  const pulled = pkg.versions.filter((v) => v.status !== "active");
  const bad = pkg.score?.signals.filter((s) => s.points < 0) ?? [];

  return (
    <div className="flex flex-col gap-8">
      <header className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="font-mono text-2xl font-semibold tracking-tight break-all">{pkg.name}</h1>
          {pkg.latest && <span className="font-mono text-sm text-muted-foreground">{pkg.latest}</span>}
          {pkg.source === "upstream" && <span className="rounded border px-1.5 text-xs text-muted-foreground">from npm, scored by apm</span>}
        </div>
        {pkg.description && <p className="max-w-2xl text-muted-foreground text-pretty">{pkg.description}</p>}
        {pulled.length > 0 && (
          <p className="max-w-2xl rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-sm">
            {pulled.length} version{pulled.length === 1 ? " was" : "s were"} pulled by the maintainers: {pulled.map((v) => `${v.version} (${v.status.replace("-", " ")})`).join(", ")}. New installs skip them.
          </p>
        )}
      </header>

      <div className="grid gap-8 lg:grid-cols-[1fr_300px]">
        <div className="flex min-w-0 flex-col gap-8">
          <InstallTabs name={pkg.name} version={pkg.latest} />

          <section aria-labelledby="score">
            <div className="mb-3 flex items-center gap-3">
              <h2 id="score" className="text-sm font-semibold">
                Security score
              </h2>
              <ScoreBadge score={pkg.score?.score} grade={pkg.score?.grade} />
            </div>
            {pkg.score ? (
              <div className="divide-y rounded-lg border">
                {bad.length === 0 && <p className="px-4 py-3 text-sm text-muted-foreground">No risk signals in {pkg.latest}.</p>}
                {bad.map((s) => (
                  <div key={s.id} className="flex gap-3 px-4 py-3">
                    <span className={`mt-0.5 h-6 shrink-0 rounded-md border px-1.5 font-mono text-xs leading-6 tabular-nums ${scoreTone(s.points <= -20 ? 0 : 50)}`}>{s.points}</span>
                    <div className="min-w-0">
                      <div className="text-sm">
                        <span className="font-mono">{s.id}</span> <span className="text-muted-foreground">· {s.label}</span>
                      </div>
                      {s.evidence.slice(0, 3).map((ev) => (
                        <div key={ev} className="mt-1 truncate font-mono text-xs text-muted-foreground">
                          {ev}
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
                {(pkg.score.notChecked ?? []).length > 0 && (
                  <p className="px-4 py-3 text-xs text-muted-foreground">Not checked: {(pkg.score.notChecked ?? []).join("; ")}.</p>
                )}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">Not scored yet.</p>
            )}
          </section>

          <section aria-labelledby="versions">
            <h2 id="versions" className="mb-3 text-sm font-semibold">
              Versions
            </h2>
            <div className="overflow-hidden rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Version</TableHead>
                    <TableHead className="hidden sm:table-cell">Published</TableHead>
                    <TableHead className="hidden sm:table-cell">By</TableHead>
                    <TableHead className="text-right">Score</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pkg.versions.slice(0, 12).map((v) => (
                    <TableRow key={v.version}>
                      <TableCell className="whitespace-normal">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className={`font-mono text-sm ${v.status === "active" ? "" : "text-muted-foreground line-through"}`}>{v.version}</span>
                          <StatusBadge status={v.status} />
                          {v.deprecated && <span className="text-xs text-muted-foreground">deprecated</span>}
                        </div>
                        {v.statusReason && <div className="mt-0.5 text-xs text-muted-foreground">{v.statusReason}</div>}
                      </TableCell>
                      <TableCell className="hidden text-sm text-muted-foreground sm:table-cell">{ago(v.publishedAt)}</TableCell>
                      <TableCell className="hidden font-mono text-xs text-muted-foreground sm:table-cell">{v.publishedBy}</TableCell>
                      <TableCell className="text-right">
                        <ScoreBadge score={v.score} grade={v.grade} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {pkg.versions.length > 12 && <p className="border-t px-3 py-2 text-xs text-muted-foreground">{pkg.versions.length - 12} older versions not shown</p>}
            </div>
          </section>

          {pkg.readme && (
            <section aria-labelledby="readme">
              <h2 id="readme" className="mb-3 text-sm font-semibold">
                Readme
              </h2>
              <details className="group rounded-lg border bg-muted/30">
                <summary className="cursor-pointer px-4 py-2.5 text-sm text-muted-foreground select-none hover:text-foreground">
                  {pkg.readme.length > 600 ? "Show readme" : "Readme"} <span className="font-mono text-xs">({Math.ceil(pkg.readme.length / 1024)} kB)</span>
                </summary>
                <pre className="overflow-x-auto border-t p-4 font-mono text-xs leading-relaxed whitespace-pre-wrap">{pkg.readme.slice(0, 20_000)}</pre>
              </details>
            </section>
          )}
        </div>

        <aside className="flex flex-col gap-8">
          <section aria-labelledby="facts">
            <h2 id="facts" className="mb-1 text-sm font-semibold">
              At a glance
            </h2>
            <FactsPanel facts={pkg.facts} maintainers={pkg.maintainers} lastPublish={latest?.publishedAt ?? null} />
          </section>
          {events.length > 0 && (
            <section aria-labelledby="log">
              <h2 id="log" className="mb-2 text-sm font-semibold">
                Public log
              </h2>
              <ol className="flex flex-col gap-2.5">
                {events.slice(0, 15).map((e, i) => (
                  <li key={`${e.at}-${i}`} className="text-sm">
                    <span className="font-mono text-xs text-muted-foreground">{e.actor}</span> {describe(e)}
                    <div className="text-xs text-muted-foreground">{ago(e.at)}</div>
                  </li>
                ))}
              </ol>
            </section>
          )}
        </aside>
      </div>
    </div>
  );
}
