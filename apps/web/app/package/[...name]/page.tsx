import { notFound } from "next/navigation";
import { Suspense } from "react";
import { ChevronDownIcon } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { getEvents, getPackage, type Facts, type PackageEvent, type PackageInfo } from "@/lib/registry";
import { ScoreBadge, StatusBadge, toneOf, type Tone } from "@/components/score-badge";
import { InstallTabs } from "@/components/install-tabs";
import { ago } from "@/lib/format";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

function size(n: number): string {
  return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} kB` : `${(n / 1048576).toFixed(1)} MB`;
}

function FactRow({ label, value, bad = false }: { label: string; value: string; bad?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b py-3 text-[15px] last:border-b-0">
      <dt className="shrink-0 text-muted-foreground">{label}</dt>
      <dd className={`min-w-0 text-right font-medium break-words ${bad ? "text-bad" : ""}`}>{value}</dd>
    </div>
  );
}

function FactsPanel({ facts, maintainers, lastPublish }: { facts: Facts | null; maintainers: string[]; lastPublish: string | null }) {
  return (
    <dl>
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

const INVERSE_TONE: Record<Tone, { text: string; bar: string }> = {
  none: { text: "text-inverse-muted", bar: "bg-inverse-muted" },
  ok: { text: "text-inverse-ok", bar: "bg-inverse-ok" },
  warn: { text: "text-inverse-warn", bar: "bg-inverse-warn" },
  bad: { text: "text-inverse-bad", bar: "bg-inverse-bad" },
};

/** The page's one dark panel: score, meter, and every signal with its file:line evidence. */
function ScorePanel({ score, version }: { score: NonNullable<PackageInfo["score"]>; version: string | null }) {
  const tone = INVERSE_TONE[toneOf(score.score)];
  const lost = score.signals.filter((s) => s.points < 0);
  const notes = score.signals.filter((s) => s.points >= 0);
  const notChecked = score.notChecked ?? [];
  const pointsLost = lost.reduce((n, s) => n - s.points, 0);
  return (
    <div className="overflow-hidden rounded-2xl bg-inverse text-inverse-foreground">
      <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-5 px-5 pt-5 pb-6 sm:px-6">
        <div>
          <div className="text-sm text-inverse-muted">{version ? `Version ${version}` : "Latest version"}</div>
          <div className="mt-2 flex items-baseline gap-2 tabular-nums">
            <span className={`text-6xl leading-none font-medium tracking-tight ${tone.text}`}>{score.score}</span>
            <span className="text-xl text-inverse-muted">/100</span>
          </div>
        </div>
        <div className="flex flex-col items-end gap-1.5 text-right">
          <span className={`font-mono text-3xl leading-none font-semibold ${tone.text}`}>{score.grade}</span>
          <span className="text-sm text-inverse-muted">
            {lost.length === 0 ? "no points lost" : `${lost.length} signal${lost.length === 1 ? "" : "s"}, ${pointsLost} points lost`}
          </span>
        </div>
        <div
          className="h-1.5 w-full overflow-hidden rounded-full bg-inverse-raised"
          role="meter"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={score.score}
          aria-label="Score out of 100"
        >
          <div className={`h-full rounded-full ${tone.bar}`} style={{ width: `${Math.max(2, score.score)}%` }} />
        </div>
      </div>
      <ul className="border-t border-inverse-border">
        {lost.length === 0 && <li className="px-5 py-4 text-[15px] text-inverse-muted sm:px-6">No risk signals in {version ?? "this version"}.</li>}
        {lost.map((s) => (
          <li key={s.id} className="flex gap-4 border-b border-inverse-border px-5 py-4 last:border-b-0 sm:px-6">
            <span className={`w-9 shrink-0 text-right font-mono text-[15px] leading-6 tabular-nums ${INVERSE_TONE[s.points <= -20 ? "bad" : "warn"].text}`}>{s.points}</span>
            <div className="min-w-0 flex-1">
              <div className="text-[15px] leading-6">
                <span className="font-mono">{s.id}</span> <span className="text-inverse-muted">{s.label}</span>
              </div>
              {s.evidence.slice(0, 3).map((ev) => (
                <div key={ev} className="mt-2 border-l-2 border-inverse-border pl-3 font-mono text-[12.5px] leading-5 text-inverse-muted [overflow-wrap:anywhere]">
                  {ev}
                </div>
              ))}
            </div>
          </li>
        ))}
        {notes.map((s) => (
          <li key={s.id} className="flex gap-4 border-t border-inverse-border px-5 py-3 text-sm leading-6 text-inverse-muted sm:px-6">
            <span className="w-9 shrink-0 text-right font-mono tabular-nums">0</span>
            <span className="min-w-0">
              <span className="font-mono text-inverse-foreground">{s.id}</span> {s.label}
              {s.evidence[0] ? ` (${s.evidence[0]})` : ""}
            </span>
          </li>
        ))}
      </ul>
      {notChecked.length > 0 && (
        <div className="border-t border-inverse-border bg-inverse-raised px-5 py-4 sm:px-6">
          <div className="text-sm text-inverse-foreground">Not checked</div>
          <ul className="mt-1.5 flex flex-col gap-1 text-sm text-pretty text-inverse-muted">
            {notChecked.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
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
        <div className="flex flex-col gap-4" aria-busy="true" aria-label="Loading package">
          <Skeleton className="h-10 w-72 max-w-full" />
          <Skeleton className="h-5 w-[28rem] max-w-full" />
          <div className="mt-8 grid grid-cols-[minmax(0,1fr)] gap-12 lg:grid-cols-[minmax(0,1fr)_320px]">
            <div className="flex flex-col gap-10">
              <Skeleton className="h-28 w-full rounded-xl" />
              <Skeleton className="h-72 w-full rounded-2xl" />
            </div>
            <Skeleton className="h-80 w-full rounded-xl" />
          </div>
        </div>
      }
    >
      <PackageContent params={params} />
    </Suspense>
  );
}

function SectionTitle({ id, children, aside }: { id: string; children: React.ReactNode; aside?: React.ReactNode }) {
  return (
    <div className="mb-4 flex items-baseline justify-between gap-4">
      <h2 id={id} className="text-xl font-medium tracking-tight">
        {children}
      </h2>
      {aside}
    </div>
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

  return (
    <div className="flex flex-col gap-10 sm:gap-12">
      <header className="flex flex-col gap-4">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <h1 className="font-mono text-[28px] leading-tight font-medium tracking-tight break-all sm:text-4xl">{pkg.name}</h1>
          {pkg.latest && <span className="inline-flex h-8 items-center rounded-full bg-surface px-3 font-mono text-sm text-muted-foreground">{pkg.latest}</span>}
          <ScoreBadge score={pkg.score?.score} grade={pkg.score?.grade} className="h-8" />
        </div>
        {pkg.description && <p className="max-w-2xl text-lg leading-8 text-pretty text-muted-foreground">{pkg.description}</p>}
        {pkg.source === "upstream" && <p className="text-sm text-muted-foreground">Proxied from the public npm registry and scored by apm.</p>}
        {pulled.length > 0 && (
          <p className="max-w-2xl rounded-xl bg-warn-soft px-4 py-3 text-[15px] leading-6 text-pretty">
            <span className="font-medium text-warn">
              {pulled.length} version{pulled.length === 1 ? " was" : "s were"} pulled by the maintainers:
            </span>{" "}
            {pulled.map((v) => `${v.version} (${v.status.replace("-", " ")})`).join(", ")}. New installs skip them.
          </p>
        )}
      </header>

      <div className="grid grid-cols-[minmax(0,1fr)] gap-12 lg:grid-cols-[minmax(0,1fr)_320px] lg:gap-14">
        <div className="flex min-w-0 flex-col gap-12">
          <InstallTabs name={pkg.name} version={pkg.latest} />

          <section aria-labelledby="score">
            <SectionTitle id="score">Security score</SectionTitle>
            {pkg.score ? <ScorePanel score={pkg.score} version={pkg.latest} /> : <p className="rounded-xl bg-surface px-5 py-4 text-muted-foreground">Not scored yet.</p>}
          </section>

          <section aria-labelledby="versions">
            <SectionTitle id="versions" aside={<span className="text-sm text-muted-foreground tabular-nums">{pkg.versions.length} total</span>}>
              Versions
            </SectionTitle>
            <div className="overflow-hidden rounded-xl border">
              <Table>
                <TableHeader className="bg-surface">
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="h-10 pl-4 font-normal text-muted-foreground">Version</TableHead>
                    <TableHead className="hidden h-10 font-normal text-muted-foreground sm:table-cell">Published</TableHead>
                    <TableHead className="hidden h-10 font-normal text-muted-foreground sm:table-cell">By</TableHead>
                    <TableHead className="h-10 pr-4 text-right font-normal text-muted-foreground">Score</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pkg.versions.slice(0, 12).map((v) => (
                    <TableRow key={v.version} className="hover:bg-surface/60">
                      <TableCell className="py-3 pl-4 whitespace-normal">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className={`font-mono text-[15px] ${v.status === "active" ? "" : "text-muted-foreground line-through"}`}>{v.version}</span>
                          <StatusBadge status={v.status} />
                          {v.deprecated && <span className="text-xs text-muted-foreground">deprecated</span>}
                        </div>
                        {v.statusReason && <div className="mt-1 text-sm text-muted-foreground">{v.statusReason}</div>}
                        <div className="mt-0.5 text-xs text-muted-foreground sm:hidden">
                          {ago(v.publishedAt)} by <span className="font-mono">{v.publishedBy}</span>
                        </div>
                      </TableCell>
                      <TableCell className="hidden py-3 text-muted-foreground sm:table-cell">{ago(v.publishedAt)}</TableCell>
                      <TableCell className="hidden py-3 font-mono text-[13px] text-muted-foreground sm:table-cell">{v.publishedBy}</TableCell>
                      <TableCell className="py-3 pr-4 text-right">
                        <ScoreBadge score={v.score} grade={v.grade} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {pkg.versions.length > 12 && <p className="border-t bg-surface px-4 py-2.5 text-sm text-muted-foreground">{pkg.versions.length - 12} older versions not shown</p>}
            </div>
          </section>

          {pkg.readme && (
            <section aria-labelledby="readme">
              <SectionTitle id="readme">Readme</SectionTitle>
              <details className="group rounded-xl border">
                <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-[15px] select-none hover:bg-surface/60 [&::-webkit-details-marker]:hidden">
                  <span>
                    {pkg.readme.length > 600 ? "Show readme" : "Readme"} <span className="font-mono text-sm text-muted-foreground">{Math.ceil(pkg.readme.length / 1024)} kB</span>
                  </span>
                  <ChevronDownIcon className="size-4 text-muted-foreground transition-transform group-open:rotate-180" aria-hidden />
                </summary>
                <pre className="overflow-x-auto border-t bg-surface p-4 font-mono text-[13px] leading-relaxed whitespace-pre-wrap">{pkg.readme.slice(0, 20_000)}</pre>
              </details>
            </section>
          )}
        </div>

        <aside className="flex flex-col gap-12">
          <section aria-labelledby="facts">
            <SectionTitle id="facts">At a glance</SectionTitle>
            <div className="border-t">
              <FactsPanel facts={pkg.facts} maintainers={pkg.maintainers} lastPublish={latest?.publishedAt ?? null} />
            </div>
          </section>
          {events.length > 0 && (
            <section aria-labelledby="log">
              <SectionTitle id="log">Public log</SectionTitle>
              <ol className="relative flex flex-col gap-5 border-l pl-5">
                {events.slice(0, 15).map((e, i) => (
                  <li key={`${e.at}-${i}`} className="relative text-[15px] leading-6">
                    <span className="absolute top-2 -left-[25px] size-2 rounded-full bg-faint ring-4 ring-background" aria-hidden />
                    <span className="font-mono text-[13px] text-muted-foreground">{e.actor}</span> {describe(e)}
                    <div className="text-sm text-muted-foreground">{ago(e.at)}</div>
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
