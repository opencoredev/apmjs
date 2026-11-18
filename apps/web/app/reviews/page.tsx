// /reviews: what apm's AI review is, how far it has got, and which versions wait for a person. For everyone. It shows
// names, versions and times only: what a model found in an open flag stays private until a person confirms it, because
// the model can be wrong and because a quoted line can hold a publisher's secret.
import Link from "next/link";
import { connection } from "next/server";
import { Suspense } from "react";
import { RegistryUnavailable } from "@/components/registry-unavailable";
import { pageMetadata } from "@/lib/agent/seo";
import { ago } from "@/lib/format";
import { packagePath } from "@/lib/package-route";
import { getReviewStatus } from "@/lib/registry";
import { compactCount, type ReviewStatus } from "@/lib/review-status";

export const metadata = pageMetadata({
  title: "AI review: how it works and what is waiting",
  description: "How apm's AI review reads new releases, what a flag means, live counts, and the versions waiting for a person at apm.",
  path: "/reviews",
});

const STEPS: { title: string; body: string }[] = [
  {
    title: "A model reads the release",
    body: "When a version is published on apm, a popular npm package ships a new one, a release adds an install script, or someone asks, a language model reads what changed since the previous version (the whole package for a first release). It looks for code that works against the person installing it.",
  },
  { title: "It reads twice", body: "A flag is checked with a second, separate read. Each finding has to cite a file and a line; a citation that does not hold up is dropped. If the two reads disagree, the version still waits for a person." },
  { title: "A person decides", body: "A flagged version waits for someone at apm. They read the cited lines and either confirm the version is malicious, which blocks it everywhere, or dismiss the flag." },
  { title: "Until then", body: "The package page says \u201cUnder review\u201d. What the model found stays private until a person confirms it: models make mistakes, and a quoted line can contain a key the publisher shipped by accident. The package's own maintainers can see the findings for their versions." },
];

function Stat({ label, value, note }: { label: string; value: number; note?: string }) {
  return (
    <div className="flex flex-col gap-1 bg-background px-4 py-4">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="text-[28px] leading-none font-medium tracking-tight tabular-nums">{value.toLocaleString("en-US")}</dd>
      {note && <dd className="text-[13px] leading-5 text-muted-foreground">{note}</dd>}
    </div>
  );
}

function HoldLine({ hold }: { hold: boolean }) {
  return (
    <p className="rounded-xl border px-4 py-3 text-[15px] leading-6 text-pretty">
      <span className={`mr-2 inline-block size-2 rounded-full align-middle ${hold ? "bg-warn" : "bg-muted-foreground"}`} aria-hidden />
      {hold ? (
        <>
          <span className="font-medium">Flags hold installs right now.</span> An agent asking apm about a flagged version is told to check with you first, until a person at apm decides.
        </>
      ) : (
        <>
          <span className="font-medium">Flags do not hold installs right now.</span> A flagged version installs as usual, with a note that an AI review flagged it and a person has not looked yet.
        </>
      )}
    </p>
  );
}

function Waiting({ waiting, total }: { waiting: ReviewStatus["waiting"]; total: number }) {
  if (waiting.length === 0) return <p className="rounded-xl bg-surface px-5 py-4 text-[15px] text-muted-foreground">Nothing is waiting for a person.</p>;

  return (
    <>
      <ol className="divide-y rounded-xl border">
        {waiting.map((w) => (
          <li key={`${w.name}@${w.version}`} className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-0.5 px-4 py-3">
            <Link href={`${packagePath(w.name)}?v=${encodeURIComponent(w.version)}`} className="min-w-0 font-mono text-[15px] [overflow-wrap:anywhere] underline-offset-4 hover:underline">
              {w.name}@{w.version}
            </Link>
            <span className="text-sm text-muted-foreground tabular-nums">
              {w.weeklyDownloads !== null && <>{compactCount(w.weeklyDownloads)} a week · </>}
              waiting since{" "}
              <time dateTime={w.since} title={new Date(w.since).toUTCString()} suppressHydrationWarning>
                {ago(w.since)}
              </time>
            </span>
          </li>
        ))}
      </ol>
      {total > waiting.length && <p className="text-sm text-muted-foreground">And {(total - waiting.length).toLocaleString("en-US")} more.</p>}
    </>
  );
}

async function Status() {
  await connection();
  const r = await getReviewStatus();

  if (r.kind === "missing") return <p className="rounded-xl bg-surface px-5 py-4 text-[15px] text-muted-foreground">This registry runs no AI review.</p>;

  if (r.kind === "unavailable") return <RegistryUnavailable what="the AI review status" retryHref="/reviews" />;
  const { counts, flagsHold, waiting } = r.value;

  return (
    <>
      <section aria-labelledby="numbers" className="flex flex-col gap-4">
        <h2 id="numbers" className="text-xl font-medium tracking-tight">
          So far
        </h2>
        <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-xl border bg-border sm:grid-cols-5">
          <Stat label="Reviewed" value={counts.reviewed} />
          <Stat label="Flagged" value={counts.flagged} />
          <Stat label="Waiting for a person" value={counts.waiting} />
          <Stat label="Dismissed" value={counts.dismissed} />
          <Stat label="Confirmed malicious" value={counts.confirmed} />
        </dl>
        <HoldLine hold={flagsHold} />
      </section>
      <section aria-labelledby="waiting" className="flex flex-col gap-4">
        <div className="flex flex-col gap-1">
          <h2 id="waiting" className="text-xl font-medium tracking-tight">
            Waiting for a person <span className="text-muted-foreground tabular-nums">{counts.waiting.toLocaleString("en-US")}</span>
          </h2>
          <p className="text-[15px] leading-6 text-pretty text-muted-foreground">Most downloaded first. A version here is not known to be malicious: a model raised a question and nobody has answered it yet.</p>
        </div>
        <Waiting waiting={waiting} total={counts.waiting} />
      </section>
    </>
  );
}

export default function ReviewsPage() {
  return (
    <div className="flex max-w-3xl flex-col gap-12">
      <header className="flex flex-col gap-3">
        <h1 className="text-[28px] leading-tight font-medium tracking-tight sm:text-4xl">AI review</h1>
        <p className="text-[17px] leading-7 text-pretty text-muted-foreground">
          Besides its score, apm has a language model read new releases for code that works against the person installing them. A flag is a question for a person at apm, not a verdict.
        </p>
      </header>
      <Suspense fallback={<div className="h-64 animate-pulse rounded-xl bg-muted" />}>
        <Status />
      </Suspense>
      <section aria-labelledby="how" className="flex flex-col gap-4">
        <h2 id="how" className="text-xl font-medium tracking-tight">
          How it works
        </h2>
        <ol className="flex flex-col gap-5">
          {STEPS.map((s, i) => (
            <li key={s.title} className="grid grid-cols-[2rem_1fr] gap-x-3">
              <span className="text-[15px] leading-6 text-muted-foreground tabular-nums">{i + 1}</span>
              <div className="flex flex-col gap-1">
                <h3 className="text-[17px] leading-6 font-medium">{s.title}</h3>
                <p className="text-[15px] leading-6 text-pretty text-muted-foreground">{s.body}</p>
              </div>
            </li>
          ))}
        </ol>
        <p className="text-[15px] leading-6 text-pretty text-muted-foreground">
          The AI review cannot see dependencies, binaries or code a package downloads when it runs. It is one model&apos;s reading, separate from the score and not proof either way.{" "}
          <Link href="/docs#ai-review" className="text-foreground underline underline-offset-4">
            What it reads and can&apos;t see
          </Link>
        </p>
      </section>
    </div>
  );
}
