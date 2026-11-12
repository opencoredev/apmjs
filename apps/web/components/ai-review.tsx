"use client";

// The version page's AI review section. Kept apart from the 0-100 score on purpose: the score is apm's rules, this is
// one model's reading of the code. The server renders the public answer; in the browser the card asks again with the
// visitor's session (owners and apm's reviewers see more), keeps asking while the review is queued, and offers a
// review request for a version the automatic review did not take.
import Link from "next/link";
import { useEffect, useState } from "react";
import { ChevronDownIcon, FileSearchIcon, HourglassIcon, OctagonAlertIcon, UserCheckIcon } from "lucide-react";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { call } from "@/lib/account";
import { ago } from "@/lib/format";
import { encodeName } from "@/lib/registry-url";
import { offersRequest, pollStep } from "@/lib/review-poll";
import { coverageText, explanation, headline, notReadText, ReviewAnswer, type NotRead, type PrivateReview, type PublicReview, type PublicState } from "@/lib/review-schema";
import { FindingList } from "./finding-list";

const ICON: Record<PublicState, typeof FileSearchIcon> = {
  "found-nothing": FileSearchIcon,
  "under-review": HourglassIcon,
  "no-answer": HourglassIcon,
  confirmed: OctagonAlertIcon,
  cleared: UserCheckIcon,
};

function Coverage({ r }: { r: PublicReview }) {
  const files = r.notRead.filter((n): n is Extract<NotRead, { kind: "file" }> => n.kind === "file");
  const deps = r.notRead.filter((n): n is Extract<NotRead, { kind: "dependency" }> => n.kind === "dependency");

  return (
    <div className="flex flex-col gap-3 border-t px-5 py-4 text-sm leading-6 text-muted-foreground sm:px-6">
      {files.length > 0 && (
        <p className="text-pretty">
          <span className="text-foreground">Not read: </span>
          <span className="font-mono text-[13px] [overflow-wrap:anywhere]">
            {files.slice(0, 8).map(notReadText).join(", ")}
            {files.length > 8 ? `, and ${files.length - 8} more` : ""}
          </span>
        </p>
      )}
      <p className="text-pretty">
        <span className="text-foreground">Dependencies are not read.</span>{" "}
        {deps.length === 0 ? "This version has none." : `This version has ${deps.length}: `}
        {deps.length > 0 && (
          <span className="font-mono text-[13px] [overflow-wrap:anywhere]">
            {deps
              .slice(0, 12)
              .map((d) => d.name)
              .join(", ")}
            {deps.length > 12 ? ", …" : ""}
          </span>
        )}
      </p>
      {r.read.length > 0 && (
        <details className="group">
          <summary className="flex w-fit cursor-pointer list-none items-center gap-1.5 select-none hover:text-foreground [&::-webkit-details-marker]:hidden">
            Files read ({r.read.length})
            <ChevronDownIcon className="size-3.5 transition-transform group-open:rotate-180" aria-hidden />
          </summary>
          <ul className="mt-2 flex flex-col gap-0.5 font-mono text-[12.5px] [overflow-wrap:anywhere]">
            {r.read.slice(0, 200).map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

function Result({ r, name, version }: { r: PublicReview; name: string; version: string }) {
  const Icon = ICON[r.state];
  const bad = r.state === "confirmed";
  const why = explanation(r);

  return (
    <>
      <div className="flex gap-3.5 px-5 py-4 sm:px-6">
        <span className={`mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-lg ${bad ? "bg-bad-soft text-bad" : "bg-surface text-muted-foreground"}`}>
          <Icon className="size-4" strokeWidth={1.75} aria-hidden />
        </span>
        <div className="flex min-w-0 flex-col gap-1">
          <p className={`text-[17px] leading-7 font-medium text-pretty ${bad ? "text-bad" : ""}`}>{headline(r)}</p>
          {why && <p className="text-[15px] leading-6 text-pretty text-muted-foreground">{why}</p>}
          <p className="flex flex-wrap gap-x-2 text-sm leading-6 text-muted-foreground">
            <span>{coverageText(r.coverage)}</span>
            <span aria-hidden>·</span>
            <span className="font-mono text-[13px]">{r.model}</span>
            <span aria-hidden>·</span>
            <time dateTime={r.reviewedAt} title={new Date(r.reviewedAt).toUTCString()} suppressHydrationWarning>
              {ago(r.reviewedAt)}
            </time>
          </p>
        </div>
      </div>
      {r.findings.length > 0 && (
        <div className="border-t px-5 py-4 sm:px-6">
          <FindingList findings={r.findings} name={name} version={version} />
          {r.note && <p className="mt-4 text-sm text-muted-foreground">Reviewer note: {r.note}</p>}
        </div>
      )}
      <Coverage r={r} />
    </>
  );
}

/** Whether the card is still asking about a queued review, or stopped after three minutes. */
type Watch = "idle" | "watching" | "gave-up";

function Pending({ status, watch }: { status: ReviewAnswer["status"]; watch: Watch }) {
  const text: Record<ReviewAnswer["status"], string> = {
    reviewed: "",
    queued: watch === "gave-up" ? "Still queued; reload later." : "Queued for AI review. Results usually arrive in under a minute.",
    failed: "The AI reviewer could not read this version's tarball.",
    "not-reviewed": "Not reviewed by AI. apm reviews every new apm publish, and new releases of npm packages with 10,000 or more weekly downloads.",
  };

  const Icon = status === "queued" ? HourglassIcon : FileSearchIcon;

  return (
    <div className="flex gap-3.5 px-5 py-4 sm:px-6">
      <span className="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-lg bg-surface text-muted-foreground">
        <Icon className={`size-4 ${status === "queued" && watch === "watching" ? "motion-safe:animate-pulse" : ""}`} strokeWidth={1.75} aria-hidden />
      </span>
      <p className="text-[15px] leading-7 text-pretty text-muted-foreground">{text[status]}</p>
    </div>
  );
}

function PrivateFindings({ p, viewer, name, version }: { p: PrivateReview; viewer: "maintainer" | "admin"; name: string; version: string }) {
  if (p.findings.length === 0 && p.outcome !== "no-answer") return null;
  const who = viewer === "admin" ? "apm's reviewers" : "this package's owners and apm's reviewers";

  return (
    <div className="flex flex-col gap-3 border-t bg-surface/50 px-5 py-4 sm:px-6">
      <p className="text-sm leading-6 text-pretty text-muted-foreground">
        <span className="font-medium text-foreground">Only {who} see this.</span>{" "}
        {p.outcome === "no-answer" && p.reason === "empty" ? "The model gave no usable answer, twice." : null}
        {p.outcome === "no-answer" && p.reason === "unsettled" ? "The model flagged this version once and found nothing on the retry." : null}
        {p.outcome === "flagged" ? `The model flagged ${p.findings.length === 1 ? "this line" : "these lines"}; a person has not confirmed ${p.findings.length === 1 ? "it" : "them"}.` : null}
        {viewer === "admin" && (
          <>
            {" "}
            <Link href="/admin/reviews" className="text-foreground underline-offset-4 hover:underline">
              Open the review queue
            </Link>
          </>
        )}
      </p>
      {p.findings.length > 0 && <FindingList findings={p.findings} name={name} version={version} />}
    </div>
  );
}

const Requested = z.object({ status: z.literal("queued") });

type RequestState = { kind: "idle" } | { kind: "busy" } | { kind: "sign-in" } | { kind: "error"; message: string };

function RequestReview({ onQueued, path, signInHref }: { onQueued: () => void; path: string; signInHref: string }) {
  const [state, setState] = useState<RequestState>({ kind: "idle" });

  async function request() {
    setState({ kind: "busy" });
    const r = await call(`${path}/request`, Requested, { method: "POST", body: {} });

    if (r.kind === "ok") {
      setState({ kind: "idle" });
      onQueued();
    } else if (r.kind === "error" && r.status === 401) setState({ kind: "sign-in" });
    else setState({ kind: "error", message: r.kind === "error" ? r.message : "The registry did not take the request. Try again." });
  }

  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t px-5 py-3 sm:px-6">
      <Button variant="outline" disabled={state.kind === "busy"} onClick={() => void request()}>
        {state.kind === "busy" ? "Requesting…" : "Request an AI review"}
      </Button>
      {state.kind === "sign-in" && (
        <p role="alert" className="text-sm text-muted-foreground">
          <Link href={signInHref} className="text-foreground underline underline-offset-4">
            Sign in
          </Link>{" "}
          to request an AI review.
        </p>
      )}
      {state.kind === "error" && (
        <p role="alert" className="text-sm text-bad">
          {state.message}
        </p>
      )}
    </div>
  );
}

/** The card: the public answer the server rendered, then whatever the registry says to this visitor. */
export function AiReviewSection({ initial, signInHref }: { initial: ReviewAnswer; signInHref: string }) {
  const [answer, setAnswer] = useState(initial);
  const [watch, setWatch] = useState<Watch>("idle");
  // bumped to start a fresh three minutes of polling (after a request is queued)
  const [round, setRound] = useState(0);
  const path = `review/${encodeName(initial.name)}/${encodeURIComponent(initial.version)}`;

  useEffect(() => {
    let live = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const startedAt = Date.now();
    // what a failed read falls back on: queued after a request, else what the server rendered
    let last: ReviewAnswer["status"] = round > 0 ? "queued" : initial.status;

    const ask = async (): Promise<void> => {
      const r = await call(path, ReviewAnswer);

      if (!live) return;

      if (r.kind === "ok") {
        last = r.value.status;
        setAnswer(r.value);
      }

      const step = pollStep({ status: last, startedAt, now: Date.now() });

      if (step.kind === "wait") {
        setWatch("watching");
        timer = setTimeout(() => void ask(), step.ms);
      } else setWatch(step.reason === "gave-up" ? "gave-up" : "idle");
    };

    void ask();

    return () => {
      live = false;

      if (timer !== undefined) clearTimeout(timer);
    };
  }, [path, round, initial.status]);

  return (
    <div className="flex flex-col gap-3">
      <div className="overflow-hidden rounded-xl border" aria-live="polite">
        {answer.review ? <Result r={answer.review} name={answer.name} version={answer.version} /> : <Pending status={answer.status} watch={watch} />}
        {answer.private && answer.viewer !== "public" && <PrivateFindings p={answer.private} viewer={answer.viewer} name={answer.name} version={answer.version} />}
        {offersRequest(answer) && (
          <RequestReview
            path={path}
            signInHref={signInHref}
            onQueued={() => {
              setAnswer((a) => ({ ...a, status: "queued", canRequest: false }));
              setRound((n) => n + 1);
            }}
          />
        )}
      </div>
      <p className="text-sm leading-6 text-pretty text-muted-foreground">
        One model&apos;s reading of the code, separate from the score and not proof either way.{" "}
        <Link href="/docs#ai-review" className="text-foreground underline-offset-4 hover:underline">
          What the AI review can&apos;t see
        </Link>
      </p>
    </div>
  );
}
