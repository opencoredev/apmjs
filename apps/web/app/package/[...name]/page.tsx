import { notFound } from "next/navigation";
import { Suspense } from "react";
import { z } from "zod";
import { ArrowDownIcon, ChevronDownIcon } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import Link from "next/link";
import { getEvents, getPackage, getReview, getTarballReadme, getVersionScore, type Dismissed, type Facts, type Fetched, type PackageEvent, type PackageInfo } from "@/lib/registry";
import { EvidenceAdminControl, EvidenceAdminProvider, type EvidenceItem } from "@/components/evidence-admin";
import { DismissedEvidence } from "@/components/dismissed-evidence";
import { needsTarballReadme, readmeSource, type ReadmeSource, type TarballReadme } from "@/lib/readme-source";
import { packageLinks, type PackageLink } from "@/lib/package-links";
import { PackageLinks } from "@/components/package-links";
import { headerNotice } from "@/lib/review-schema";
import { AiReviewSection } from "@/components/ai-review";
import { RegistryUnavailable } from "@/components/registry-unavailable";
import { FileView } from "@/components/file-view";
import { OpenDetailsLink } from "@/components/open-details-link";
import { citeEvidence } from "@/lib/evidence";
import { citedLine } from "@/lib/file-excerpt";
import { splitPossible, splitTestFile, summarizeLimitations } from "@/lib/limitations";
import { fileHref, packagePath, parsePackageRoute } from "@/lib/package-route";
import { ScoreBadge, toneOf, type Tone } from "@/components/score-badge";
import { InstallTabs } from "@/components/install-tabs";
import { ago, formatSize } from "@/lib/format";
import { VersionList } from "@/components/version-list";
import { REGISTRY } from "@/lib/registry-url";
import { cutReadme, EXTERNAL_REL, renderReadme } from "@/lib/readme";
import { githubRepo } from "@/lib/repository";
import { ReadmeView } from "@/components/readme-view";
import { scoreLine, scoreLineText } from "@/lib/score-summary";

// The page shows this much of a readme; the rest is one click away at /api/readme.
const README_PREVIEW_CHARS = 20_000;

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
          <FactRow label="Unpacked size" value={formatSize(facts.unpackedSize)} />
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

/** Where one piece of evidence opens, when it cites a file and the version is known. */
function evidenceLink(input: { signal: string; evidence: string; name: string; version: string | null }) {
  const cited = input.version ? citeEvidence(input.signal, input.evidence) : null;
  const href = cited && input.version ? fileHref({ name: input.name, version: input.version, ...cited.citation }) : null;

  return cited && href ? { ...cited, href } : null;
}

/** One cited line under a signal. When it names a file, the whole row opens that file at the line. A possible
 * finding says, in plain text under the line, why apm did not count it as seen; one from a shipped test file says so. */
function Evidence(props: { signal: string; evidence: string; name: string; version: string | null }) {
  const possible = splitPossible(props.evidence);
  const { text, testFile } = splitTestFile(possible.text);
  const link = evidenceLink({ ...props, evidence: text });
  const row = "mt-2 border-l-2 border-inverse-border pl-3 font-mono text-[12.5px] leading-5 text-inverse-muted [overflow-wrap:anywhere]";
  const note = testFile ? <span className="mt-0.5 block font-sans text-[13px] text-inverse-muted">From a test file the package ships.</span> : null;
  const reason = possible.why ? <span className="mt-0.5 block font-sans text-[13px] text-inverse-muted">{possible.why}</span> : null;

  if (!link) {
    return (
      <div className={row}>
        {text}
        {note}
        {reason}
      </div>
    );
  }

  return (
    // a full page load: the file view reads the #L anchor when it starts
    <a href={link.href} className={`group -mr-2 block rounded-r-md py-1 pr-2 transition-colors hover:border-inverse-muted hover:bg-inverse-raised ${row}`}>
      <span className="text-inverse-foreground underline decoration-inverse-muted/60 underline-offset-[3px] group-hover:decoration-inverse-foreground">{link.cite}</span>
      {link.rest}
      {note}
      {reason}
    </a>
  );
}

/** The signals whose evidence an apm reviewer may dismiss: what the source rules read, not facts like an install script. */
const DISMISSABLE: ReadonlySet<string> = new Set(["shell-exec", "network", "credential-access", "eval", "obfuscated"]);

/** What names one evidence item for a reviewer's control, or null when it cites no file line or the score has no digest. */
type ItemKey = { name: string; version: string; digest: string; scorer: string };

function itemOf(key: ItemKey | null, signal: string, evidence: string): EvidenceItem | null {
  const cited = key && DISMISSABLE.has(signal) ? citeEvidence(signal, evidence) : null;

  return key && cited?.citation.line ? { ...key, signal, file: cited.citation.path, line: cited.citation.line } : null;
}

/** What the score did not check: a short line under the number, and the whole list behind a disclosure. */
function LimitationsLine({ notChecked }: { notChecked: readonly string[] }) {
  const s = summarizeLimitations(notChecked);

  return (
    <p className="w-full text-sm leading-6 text-pretty text-inverse-muted">
      {s.headline}
      {s.extra && <span className="text-inverse-foreground"> {s.extra}</span>}{" "}
      <OpenDetailsLink target="not-checked" className="text-inverse-foreground underline decoration-inverse-muted/60 underline-offset-[3px] hover:decoration-inverse-foreground">
        See all {s.total}
      </OpenDetailsLink>
    </p>
  );
}

function LimitationsList({ notChecked }: { notChecked: readonly string[] }) {
  return (
    <details id="not-checked" className="group scroll-mt-44 sm:scroll-mt-24 border-t border-inverse-border bg-inverse-raised">
      <summary className="flex min-h-12 cursor-pointer list-none items-center justify-between gap-3 px-5 py-3 text-sm text-inverse-foreground select-none hover:bg-inverse-border/40 sm:px-6 [&::-webkit-details-marker]:hidden">
        <span>
          What this score does not check <span className="text-inverse-muted tabular-nums">({notChecked.length})</span>
        </span>
        <ChevronDownIcon className="size-4 text-inverse-muted transition-transform group-open:rotate-180" aria-hidden />
      </summary>
      <ul className="flex flex-col gap-2 px-5 pb-4 text-sm leading-6 text-pretty text-inverse-muted sm:px-6">
        {notChecked.map((n) => (
          <li key={n}>{n}</li>
        ))}
      </ul>
    </details>
  );
}

/** The evidence after an informational signal, in brackets; the file part links when there is one. */
function NoteEvidence(props: { signal: string; evidence: string; name: string; version: string | null }) {
  const link = evidenceLink(props);

  if (!link) return <> ({props.evidence})</>;

  return (
    <>
      {" ("}
      <a href={link.href} className="font-mono text-[12.5px] text-inverse-foreground underline decoration-inverse-muted/60 underline-offset-[3px] hover:decoration-inverse-foreground [overflow-wrap:anywhere]">
        {link.cite}
      </a>
      <span className="[overflow-wrap:anywhere]">{link.rest})</span>
    </>
  );
}

/** The page's one dark panel: score, meter, and every signal with its file:line evidence. */
function ScorePanel({ score, name, version }: { score: NonNullable<PackageInfo["score"]>; name: string; version: string | null }) {
  const tone = INVERSE_TONE[toneOf(score.score)];
  const key: ItemKey | null = version && score.digest && score.scorer ? { name, version, digest: score.digest, scorer: score.scorer } : null;
  const dismissedOf = (signal: string) => score.dismissed.filter((d) => d.signal === signal);
  const restoreItem = (d: Dismissed): EvidenceItem | null => (key ? { ...key, signal: d.signal, file: d.file, line: d.line } : null);
  // a signal whose every item was dismissed is gone from the number, but its items stay listed
  const cleared = [...new Set(score.dismissed.map((d) => d.signal))].filter((id) => !score.signals.some((s) => s.id === id));
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
        {notChecked.length > 0 && <LimitationsLine notChecked={notChecked} />}
      </div>
      <EvidenceAdminProvider>
      <ul className="border-t border-inverse-border">
        {lost.length === 0 && cleared.length === 0 && <li className="px-5 py-4 text-[15px] text-inverse-muted sm:px-6">No risk signals in {version ?? "this version"}.</li>}
        {lost.map((s) => (
          <li key={s.id} className="flex gap-4 border-b border-inverse-border px-5 py-4 last:border-b-0 sm:px-6">
            <span className={`w-9 shrink-0 text-right font-mono text-[15px] leading-6 tabular-nums ${s.confidence === "possible" ? "text-inverse-muted" : INVERSE_TONE[s.points <= -20 ? "bad" : "warn"].text}`}>{s.points}</span>
            <div className="min-w-0 flex-1">
              <div className="text-[15px] leading-6">
                <span className="font-mono">{s.id}</span>{" "}
                {s.confidence === "possible" && <span className="mr-1 inline-flex h-5 items-center rounded-full border border-inverse-border px-2 align-[1px] text-xs text-inverse-foreground">possible</span>}
                <span className="text-inverse-muted">{s.label}</span>
              </div>
              {s.evidence.slice(0, 3).map((ev) => {
                const item = itemOf(key, s.id, ev);

                return (
                  <div key={ev}>
                    <Evidence signal={s.id} evidence={ev} name={name} version={version} />
                    {item && <EvidenceAdminControl item={item} mode="dismiss" />}
                  </div>
                );
              })}
              {dismissedOf(s.id).map((d) => (
                <DismissedEvidence key={`${d.file}:${d.line}`} d={d} item={restoreItem(d)} />
              ))}
            </div>
          </li>
        ))}
        {cleared.map((id) => (
          <li key={id} className="flex gap-4 border-b border-inverse-border px-5 py-4 last:border-b-0 sm:px-6">
            <span className="w-9 shrink-0 text-right font-mono text-[15px] leading-6 text-inverse-muted tabular-nums">0</span>
            <div className="min-w-0 flex-1">
              <div className="text-[15px] leading-6">
                <span className="font-mono">{id}</span> <span className="text-inverse-muted">Every piece of evidence was dismissed, so it costs no points.</span>
              </div>
              {dismissedOf(id).map((d) => (
                <DismissedEvidence key={`${d.file}:${d.line}`} d={d} item={restoreItem(d)} />
              ))}
            </div>
          </li>
        ))}
        {notes.map((s) => (
          <li key={s.id} className="flex gap-4 border-t border-inverse-border px-5 py-3 text-sm leading-6 text-inverse-muted sm:px-6">
            <span className="w-9 shrink-0 text-right font-mono tabular-nums">0</span>
            <span className="min-w-0">
              <span className="font-mono text-inverse-foreground">{s.id}</span> {s.label}
              {s.evidence[0] ? <NoteEvidence signal={s.id} evidence={s.evidence[0]} name={name} version={version} /> : null}
            </span>
          </li>
        ))}
      </ul>
      </EvidenceAdminProvider>
      {notChecked.length > 0 && <LimitationsList notChecked={notChecked} />}
    </div>
  );
}

/** Where a readme read from the tarball came from, as a link to that file in the file view. */
type TarballOrigin = { path: string; version: string };

/** The readme, collapsed: rendered from sanitized Markdown, with its source one tab away. Long readmes show
 * their first README_PREVIEW_CHARS characters, cut at a block boundary, and link to the full text. */
function ReadmeSection({ name, readme, repository, origin }: { name: string; readme: string; repository: PackageInfo["repository"]; origin: TarballOrigin | null }) {
  const shown = cutReadme(readme, README_PREVIEW_CHARS);
  const repo = githubRepo(repository);
  const originHref = origin ? fileHref({ name, version: origin.version, path: origin.path }) : null;
  const fullHref = originHref ?? `/api/readme?name=${encodeURIComponent(name)}`;

  const note = origin ? (
    <span>
      From{" "}
      {originHref ? (
        <a href={originHref} className="font-mono text-[13px] text-foreground underline-offset-4 hover:underline">
          {origin.path}
        </a>
      ) : (
        <span className="font-mono text-[13px]">{origin.path}</span>
      )}{" "}
      in the {origin.version} tarball
    </span>
  ) : repo ? (
    <a href={`https://github.com/${repo.owner}/${repo.repo}`} rel={EXTERNAL_REL} className="font-mono text-[13px] underline-offset-4 hover:text-foreground hover:underline">
      github.com/{repo.owner}/{repo.repo}
    </a>
  ) : null;

  return (
    <details className="group rounded-xl border">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-[15px] select-none hover:bg-surface/60 [&::-webkit-details-marker]:hidden">
        <span>
          {readme.length > 600 ? "Show readme" : "Readme"} <span className="font-mono text-sm text-muted-foreground">{Math.ceil(readme.length / 1024)} kB</span>
        </span>
        <ChevronDownIcon className="size-4 text-muted-foreground transition-transform group-open:rotate-180" aria-hidden />
      </summary>
      <ReadmeView rendered={renderReadme(shown, repo)} source={shown} note={note} />
      {shown.length < readme.length && (
        <p className="border-t px-4 py-3 text-sm text-muted-foreground">
          Showing the first {Math.ceil(shown.length / 1024)} of {Math.ceil(readme.length / 1024)} kB.{" "}
          <a href={fullHref} className="text-foreground underline underline-offset-4">
            Open the full readme
          </a>
        </p>
      )}
    </details>
  );
}

type NoReadmeSource = Exclude<ReadmeSource, { kind: "packument" | "tarball" }>;

/** Why there is no readme to render: a title and a sentence. */
type NoReadmeCopy = { title: string; body: React.ReactNode };

/** The sentence for a README that is there but not rendered, linking to the file view when it is only too large. */
function UnreadableReadme({ name, source }: { name: string; source: Extract<ReadmeSource, { kind: "unreadable" }> }) {
  const href = source.reason === "too-large" ? fileHref({ name, version: source.version, path: source.path }) : null;

  return (
    <>
      The tarball&apos;s <span className="font-mono text-[13px]">{source.path}</span> is {source.reason === "binary" ? "not text" : `${formatSize(source.size)}, too large to render here`}.{" "}
      {href && (
        <a href={href} className="text-foreground underline underline-offset-4">
          Open it in the file view
        </a>
      )}
    </>
  );
}

function noReadmeCopy({ name, source, hasLinks }: { name: string; source: NoReadmeSource; hasLinks: boolean }): NoReadmeCopy {
  switch (source.kind) {
    case "none":
      return { title: "No readme published", body: `${name} has no readme in its registry entry or its tarball.${hasLinks ? " Its own links may have documentation:" : " It names no homepage or repository either."}` };
    case "unknown":
      return { title: "Readme not loaded", body: `The registry did not answer when apm looked for a README in the tarball. Reload to try again.${hasLinks ? " Meanwhile:" : ""}` };
    case "unreadable":
      return { title: "Readme not shown", body: <UnreadableReadme name={name} source={source} /> };
    default: {
      const _exhaustive: never = source;

      return _exhaustive;
    }
  }
}

/** No readme to render: says why, and offers the package's own links instead. */
function NoReadme({ name, source, links }: { name: string; source: NoReadmeSource; links: readonly PackageLink[] }) {
  const { title, body } = noReadmeCopy({ name, source, hasLinks: links.length > 0 });

  return (
    <div className="flex flex-col gap-2 rounded-xl border px-4 py-4 sm:px-5">
      <p className="text-[15px] font-medium">{title}</p>
      <p className="text-sm leading-6 text-pretty text-muted-foreground">{body}</p>
      <PackageLinks links={links} className="mt-1" />
    </div>
  );
}

/** The one line a phone shows beside the compact score: what kind of number it is and what it leaves out. */
const SCORE_QUALIFIER = "Heuristic score; runtime behavior and dependency code not checked.";

/** Phones only: the score in one line near the top, naming the signal that cost the most, linking down to the full report. */
function ScoreSummary({ score, className }: { score: PackageInfo["score"]; className?: string }) {
  const line = scoreLine(score ? score.signals : null);

  return (
    <a href="#score" className={`flex min-h-12 items-center gap-3 rounded-xl border px-4 py-2.5 transition-colors hover:bg-surface/60 ${className ?? ""}`}>
      <ScoreBadge score={score?.score} grade={score?.grade} />
      <span className="flex min-w-0 flex-1 flex-col">
        <span className="text-[15px] leading-6 text-pretty">
          {line.kind === "lost" ? (
            <>
              <span>{line.name}</span>
              <span className="text-muted-foreground"> · </span>
              <span className={`whitespace-nowrap tabular-nums ${line.possible ? "text-muted-foreground" : line.points >= 20 ? "text-bad" : "text-warn"}`}>
                −{line.points} point{line.points === 1 ? "" : "s"}
              </span>
              {line.more > 0 && <span className="whitespace-nowrap text-muted-foreground"> +{line.more} more</span>}
            </>
          ) : (
            scoreLineText(line)
          )}
        </span>
        {score !== null && <span className="text-[13px] leading-5 text-pretty text-muted-foreground">{SCORE_QUALIFIER}</span>}
      </span>
      <span className="inline-flex shrink-0 items-center gap-1 text-sm text-muted-foreground">
        Report
        <ArrowDownIcon className="size-3.5" aria-hidden />
      </span>
    </a>
  );
}

/** The item a dismissal or its undo names, as the log shows it: "credential-access evidence (index.js:1)". */
const EvidenceDetail = z.object({ signal: z.string(), file: z.string(), line: z.number() });

function evidenceCited(e: PackageEvent): string {
  const d = EvidenceDetail.safeParse(e.detail);

  return d.success ? `${d.data.signal} evidence (${d.data.file}:${d.data.line})` : "evidence";
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
    case "evidence-dismissed":
      return `dismissed ${evidenceCited(e)} in ${v}${reason}`;
    case "evidence-restored":
      return `restored ${evidenceCited(e)} in ${v}`;
    default:
      return e.kind;
  }
}

type PageProps = { params: Promise<{ name: string[] }>; searchParams: Promise<{ v?: string | string[]; line?: string | string[] }> };

export default function PackagePage({ params, searchParams }: PageProps) {
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
      <PackageContent params={params} searchParams={searchParams} />
    </Suspense>
  );
}

function SectionTitle({ id, children, aside }: { id: string; children: React.ReactNode; aside?: React.ReactNode }) {
  return (
    <div className="mb-4 flex items-baseline justify-between gap-4">
      <h2 id={id} className="scroll-mt-24 text-xl font-medium tracking-tight">
        {children}
      </h2>
      {aside}
    </div>
  );
}

/** The version a link names with ?v=, when the package has it; else the latest. */
function shownVersion(pkg: PackageInfo, v: string | string[] | undefined): string | null {
  const asked = Array.isArray(v) ? v[0] : v;

  return asked !== undefined && pkg.versions.some((x) => x.version === asked) ? asked : pkg.latest;
}

async function PackageContent({ params, searchParams }: PageProps) {
  const route = parsePackageRoute((await params).name);

  if (!route) notFound();

  if (route.kind === "file") return <FileView name={route.name} version={route.version} path={route.path} line={citedLine((await searchParams).line)} />;
  const name = route.name;
  const found = await getPackage(name);

  // proxy.ts already answered 404 or 503 before the shell went out; this covers a registry that
  // fails between that check and this read.
  if (found.kind === "missing") notFound();

  if (found.kind === "unavailable") return <RegistryUnavailable what={`the package ${name}`} retryHref={packagePath(name)} />;
  const pkg = found.value;
  const version = shownVersion(pkg, (await searchParams).v);
  const isLatest = version === pkg.latest;
  const none: Fetched<never> = { kind: "missing" };

  const [events, review, versionScore, tarballReadme] = await Promise.all([
    // an upstream package's log holds what apm's reviewers did to it (dismissed evidence); none answers 404
    getEvents(name),
    version ? getReview(name, version) : Promise.resolve(none),
    version && !isLatest ? getVersionScore(name, version) : Promise.resolve(none),
    // only when npm's packument has no readme (react's has none): the README in the shown version's tarball
    version && needsTarballReadme(pkg.readme) ? getTarballReadme({ name, version }) : Promise.resolve<Fetched<TarballReadme> | null>(null),
  ]);

  const readme = readmeSource({ packument: pkg.readme, version, tarball: tarballReadme });
  const links = packageLinks({ homepage: pkg.homepage, repository: pkg.repository, bugs: pkg.bugs });

  let score = pkg.score;

  if (!isLatest) score = versionScore.kind === "ok" ? versionScore.value : null;
  const latest = pkg.versions.find((v) => v.version === pkg.latest);
  const pulled = pkg.versions.filter((v) => v.status !== "active");
  const aiNotice = review.kind === "ok" && review.value.review !== null ? headerNotice(review.value.review) : null;

  return (
    <div className="flex flex-col gap-10 sm:gap-12">
      <header className="flex flex-col gap-4">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <h1 className="font-mono text-[28px] leading-tight font-medium tracking-tight break-all sm:text-4xl">{pkg.name}</h1>
          {version && <span className="inline-flex h-8 items-center rounded-full bg-surface px-3 font-mono text-sm text-muted-foreground">{version}</span>}
          <ScoreBadge score={score?.score} grade={score?.grade} className="h-8" />
          {aiNotice && (
            <a
              href="#ai-review"
              className={`inline-flex min-h-8 items-center gap-1.5 rounded-full px-3 py-1 text-sm font-medium underline-offset-4 hover:underline ${aiNotice.tone === "bad" ? "bg-bad-soft text-bad" : "bg-warn-soft text-warn"}`}
            >
              {aiNotice.text}
              <span aria-hidden>↓</span>
            </a>
          )}
        </div>
        {!isLatest && pkg.latest && (
          <p className="text-sm text-muted-foreground">
            An older version.{" "}
            <Link href={packagePath(pkg.name)} className="text-foreground underline-offset-4 hover:underline">
              Show the latest, {pkg.latest}
            </Link>
          </p>
        )}
        {pkg.description && <p className="max-w-2xl text-lg leading-8 text-pretty text-muted-foreground">{pkg.description}</p>}
        <PackageLinks links={links} />
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

      {/* Phones get one column in reading order: install, score summary, facts, the full report, readme,
          versions. From lg the two wrappers become columns and the order classes stop applying. */}
      <div className="flex flex-col gap-10 lg:grid lg:grid-cols-[minmax(0,1fr)_320px] lg:items-start lg:gap-14">
        <div className="contents lg:flex lg:min-w-0 lg:flex-col lg:gap-12">
          <div className="order-1 lg:order-none">
            <InstallTabs name={pkg.name} version={version} registry={REGISTRY} />
          </div>

          <section aria-labelledby="score" className="order-4 lg:order-none">
            <SectionTitle id="score">Security score</SectionTitle>
            {score ? <ScorePanel score={score} name={pkg.name} version={version} /> : <p className="rounded-xl bg-surface px-5 py-4 text-muted-foreground">Not scored yet.</p>}
          </section>

          {review.kind === "ok" && (
            <section aria-labelledby="ai-review" className="order-5 lg:order-none">
              <SectionTitle id="ai-review" aside={<span className="font-mono text-sm text-muted-foreground">{review.value.version}</span>}>
                AI review
              </SectionTitle>
              <AiReviewSection answer={review.value} />
            </section>
          )}

          <section aria-labelledby="readme" className="order-6 lg:order-none">
            <SectionTitle id="readme">Readme</SectionTitle>
            {readme.kind === "packument" || readme.kind === "tarball" ? (
              <ReadmeSection name={pkg.name} readme={readme.text} repository={pkg.repository} origin={readme.kind === "tarball" ? { path: readme.path, version: readme.version } : null} />
            ) : (
              <NoReadme name={pkg.name} source={readme} links={links} />
            )}
          </section>

          <section aria-labelledby="versions" className="order-7 lg:order-none">
            <SectionTitle id="versions" aside={<span className="text-sm text-muted-foreground tabular-nums">{pkg.versions.length} total</span>}>
              Versions
            </SectionTitle>
            <VersionList rows={pkg.versions.map((v) => ({ ...v, when: ago(v.publishedAt) }))} packageHref={packagePath(pkg.name)} current={version} />
          </section>
        </div>

        <div className="contents lg:flex lg:flex-col lg:gap-12">
          <ScoreSummary score={score} className="order-2 lg:hidden" />
          <section aria-labelledby="facts" className="order-3 lg:order-none">
            <SectionTitle id="facts">At a glance</SectionTitle>
            <div className="border-t">
              <FactsPanel facts={pkg.facts} maintainers={pkg.maintainers} lastPublish={latest?.publishedAt ?? null} />
            </div>
          </section>
          {events.kind === "unavailable" && (
            <section aria-labelledby="log" className="order-8 lg:order-none">
              <SectionTitle id="log">Public log</SectionTitle>
              <p className="text-[15px] text-muted-foreground">Couldn&apos;t load the public log. The registry did not answer; reload to try again.</p>
            </section>
          )}
          {events.kind === "ok" && events.value.length > 0 && (
            <section aria-labelledby="log" className="order-8 lg:order-none">
              <SectionTitle id="log">Public log</SectionTitle>
              <ol className="relative flex flex-col gap-5 border-l pl-5">
                {events.value.slice(0, 15).map((e, i) => (
                  <li key={`${e.at}-${i}`} className="relative text-[15px] leading-6">
                    <span className="absolute top-2 -left-[25px] size-2 rounded-full bg-faint ring-4 ring-background" aria-hidden />
                    <span className="font-mono text-[13px] text-muted-foreground">{e.actor}</span> {describe(e)}
                    <div className="text-sm text-muted-foreground">{ago(e.at)}</div>
                  </li>
                ))}
              </ol>
            </section>
          )}
        </div>
      </div>
    </div>
  );
}
