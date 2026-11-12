// The version page's AI review section. Kept apart from the 0-100 score on purpose: the score is
// apm's rules, this is one model's reading of the code. Public data renders on the server; what only
// owners and apm's reviewers may see, and the request button, load in the browser (AiReviewViewer).
import Link from "next/link";
import { ChevronDownIcon, FileSearchIcon, HourglassIcon, OctagonAlertIcon, UserCheckIcon } from "lucide-react";
import { ago } from "@/lib/format";
import { coverageText, explanation, headline, notReadText, type NotRead, type PublicReview, type PublicState, type ReviewAnswer } from "@/lib/review-schema";
import { AiReviewViewer } from "./ai-review-viewer";
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
        {deps.length > 0 && <span className="font-mono text-[13px] [overflow-wrap:anywhere]">{deps.slice(0, 12).map((d) => d.name).join(", ")}{deps.length > 12 ? ", …" : ""}</span>}
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

function Result({ r }: { r: PublicReview }) {
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
            <time dateTime={r.reviewedAt} title={new Date(r.reviewedAt).toUTCString()}>
              {ago(r.reviewedAt)}
            </time>
          </p>
        </div>
      </div>
      {r.findings.length > 0 && (
        <div className="border-t px-5 py-4 sm:px-6">
          <FindingList findings={r.findings} />
          {r.note && <p className="mt-4 text-sm text-muted-foreground">Reviewer note: {r.note}</p>}
        </div>
      )}
      <Coverage r={r} />
    </>
  );
}

function Pending({ status }: { status: ReviewAnswer["status"] }) {
  const text: Record<ReviewAnswer["status"], string> = {
    reviewed: "",
    queued: "Queued for AI review. Results usually arrive within minutes.",
    failed: "The AI reviewer could not read this version's tarball.",
    "not-reviewed": "Not reviewed by AI. apm reviews every new apm publish, and new releases of npm packages with 10,000 or more weekly downloads.",
  };

  return (
    <div className="flex gap-3.5 px-5 py-4 sm:px-6">
      <span className="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-lg bg-surface text-muted-foreground">
        <FileSearchIcon className="size-4" strokeWidth={1.75} aria-hidden />
      </span>
      <p className="text-[15px] leading-7 text-pretty text-muted-foreground">{text[status]}</p>
    </div>
  );
}

export function AiReviewSection({ answer }: { answer: ReviewAnswer }) {
  return (
    <div className="flex flex-col gap-3">
      <div className="overflow-hidden rounded-xl border">
        {answer.review ? <Result r={answer.review} /> : <Pending status={answer.status} />}
        <AiReviewViewer name={answer.name} version={answer.version} />
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
