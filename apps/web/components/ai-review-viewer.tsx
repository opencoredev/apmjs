"use client";

// The parts of the AI review that depend on who is looking: findings that only owners and apm's
// reviewers see while a flag is unconfirmed, and the "Request AI review" button for signed-in users.
import Link from "next/link";
import { useEffect, useState } from "react";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { call } from "@/lib/account";
import { encodeName } from "@/lib/registry-url";
import { ReviewAnswer, type PrivateReview } from "@/lib/review-schema";
import { FindingList } from "./finding-list";

const Requested = z.object({ status: z.literal("queued") });

function PrivateFindings({ p, viewer }: { p: PrivateReview; viewer: "maintainer" | "admin" }) {
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
      {p.findings.length > 0 && <FindingList findings={p.findings} />}
    </div>
  );
}

export function AiReviewViewer({ name, version }: { name: string; version: string }) {
  const [answer, setAnswer] = useState<ReviewAnswer | null>(null);
  const [request, setRequest] = useState<{ kind: "idle" } | { kind: "busy" } | { kind: "done" } | { kind: "error"; message: string }>({ kind: "idle" });
  const path = `review/${encodeName(name)}/${encodeURIComponent(version)}`;

  useEffect(() => {
    let live = true;

    void call(path, ReviewAnswer).then((r) => {
      if (live && r.kind === "ok") setAnswer(r.value);
    });

    return () => {
      live = false;
    };
  }, [path]);

  async function requestReview() {
    setRequest({ kind: "busy" });
    const r = await call(`${path}/request`, Requested, { method: "POST", body: {} });

    setRequest(r.kind === "ok" ? { kind: "done" } : { kind: "error", message: r.kind === "error" ? r.message : "Sign in to request an AI review." });
  }

  if (!answer) return null;
  const priv = answer.private;
  const viewer = answer.viewer;

  return (
    <>
      {priv && viewer !== "public" && <PrivateFindings p={priv} viewer={viewer} />}
      {answer.canRequest && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t px-5 py-3 sm:px-6">
          {request.kind === "done" ? (
            <p className="text-sm text-muted-foreground" role="status">
              Queued. Reload this page in a few minutes to see the result.
            </p>
          ) : (
            <Button variant="outline" disabled={request.kind === "busy"} onClick={() => void requestReview()}>
              {request.kind === "busy" ? "Requesting…" : "Request AI review"}
            </Button>
          )}
          {request.kind === "error" && (
            <p role="alert" className="text-sm text-bad">
              {request.message}
            </p>
          )}
        </div>
      )}
    </>
  );
}
