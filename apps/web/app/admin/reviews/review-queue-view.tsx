"use client";

// The second stage, phase 1: every AI review that flagged a version or gave no answer waits here
// until one of apm's reviewers (APM_ADMINS) confirms or dismisses it. Only a confirmed result shows
// its findings in public.
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { z } from "zod";
import { FindingList } from "@/components/finding-list";
import { packagePath } from "@/lib/package-route";
import { SignInPanel } from "@/components/sign-in-panel";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { call, passkeyConfirmation } from "@/lib/account";
import { ago } from "@/lib/format";
import { coverageText, notReadText, PrivateReview, PublicReview } from "@/lib/review-schema";

const Attempt = z.object({ result: z.string(), kept: z.number(), dropped: z.number(), promptTokens: z.number(), completionTokens: z.number(), latencyMs: z.number() });

const Item = z.object({
  name: z.string(),
  version: z.string(),
  digest: z.string(),
  reviewedAt: z.string(),
  public: PublicReview,
  private: PrivateReview.extend({ attempts: z.array(Attempt) }),
  decidedBy: z.string().nullable(),
});

type Item = z.infer<typeof Item>;

const Queue = z.object({ pending: z.array(Item), decided: z.array(Item), secondStage: z.string().nullable() });

type State = { kind: "loading" } | { kind: "signed-out" } | { kind: "error"; message: string } | { kind: "ok"; queue: z.infer<typeof Queue> };

function label(i: Item): string {
  if (i.private.outcome === "flagged") return i.private.verdict === "malicious" ? "Flagged malicious" : "Flagged suspicious";

  return i.private.reason === "unsettled" ? "Flagged, then cleared on retry" : "No answer";
}

// Each decision needs a fresh second factor: a code typed now, or a passkey check made for exactly that decision.
type Factor = { kind: "code"; code: string } | { kind: "confirmation"; id: string } | { kind: "error"; message: string };

function Pending({ item, onDone }: { item: Item; onDone: () => void }) {
  const [note, setNote] = useState("");
  const [code, setCode] = useState("");
  const [usePasskey, setUsePasskey] = useState(false);
  const [busy, setBusy] = useState<"confirm" | "dismiss" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const files = item.public.notRead.flatMap((n) => (n.kind === "file" ? [notReadText(n)] : []));

  async function factor(decision: "confirm" | "dismiss"): Promise<Factor> {
    if (!usePasskey) return /^\d{6}$/.test(code) ? { kind: "code", code } : { kind: "error", message: "Enter the 6-digit code from your authenticator app." };
    const p = await passkeyConfirmation({ kind: "review-decision", name: item.name, version: item.version, digest: item.digest, decision, note: note.trim() });

    return p.kind === "ok" ? { kind: "confirmation", id: p.id } : p;
  }

  async function decide(decision: "confirm" | "dismiss") {
    setBusy(decision);
    setError(null);
    const f = await factor(decision);

    if (f.kind === "error") {
      setBusy(null);

      return setError(f.message);
    }

    const proof = f.kind === "code" ? { code: f.code } : { confirmation: f.id };
    const r = await call("review-admin/decide", z.object({ ok: z.boolean() }), { method: "POST", body: { name: item.name, version: item.version, digest: item.digest, decision, note, ...proof } });

    setBusy(null);
    setCode("");

    if (r.kind === "ok") return onDone();
    setError(r.kind === "error" ? r.message : "Sign in again.");
  }

  return (
    <li className="flex flex-col gap-4 rounded-2xl border p-5 sm:p-6">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <Link href={`${packagePath(item.name)}?v=${encodeURIComponent(item.version)}`} className="font-mono text-[17px] font-medium underline-offset-4 hover:underline">
          {item.name}@{item.version}
        </Link>
        <span className="text-sm text-muted-foreground">
          {label(item)} · {ago(item.reviewedAt)}
        </span>
      </div>
      {item.private.summary && (
        <p className="text-[15px] leading-6 text-pretty">
          <span className="text-muted-foreground">Model&apos;s summary: </span>
          {item.private.summary}
        </p>
      )}
      {item.private.findings.length > 0 && <FindingList findings={item.private.findings} name={item.name} version={item.version} />}
      <p className="text-sm leading-6 text-pretty text-muted-foreground">
        {coverageText(item.public.coverage)}
        {item.public.coverage.previousVersion ? ` from ${item.public.coverage.previousVersion}` : ""} · {item.public.model} · answers: {item.private.attempts.map((a) => a.result).join(", ")}
        {files.length > 0 ? ` · not read: ${files.slice(0, 6).join(", ")}${files.length > 6 ? "…" : ""}` : ""}
      </p>
      <div className="flex flex-wrap items-center gap-2 border-t pt-4">
        <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Note (shown in public on a confirmed result)" className="h-9 min-w-0 flex-1 basis-64" />
        {!usePasskey && (
          <Input
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
            inputMode="numeric"
            autoComplete="one-time-code"
            spellCheck={false}
            placeholder="2FA code"
            aria-label="Code from your authenticator app"
            className="h-9 w-28 font-mono tracking-widest"
          />
        )}
        <Button size="lg" variant="destructive" disabled={busy !== null} onClick={() => void decide("confirm")}>
          {busy === "confirm" ? "Confirming…" : "Confirm malicious"}
        </Button>
        <Button size="lg" variant="outline" disabled={busy !== null} onClick={() => void decide("dismiss")}>
          {busy === "dismiss" ? "Dismissing…" : "Dismiss flag"}
        </Button>
      </div>
      <button
        type="button"
        className="self-start text-sm text-muted-foreground underline underline-offset-4 hover:text-foreground"
        onClick={() => {
          setUsePasskey(!usePasskey);
          setError(null);
        }}
      >
        {usePasskey ? "Use a code from your authenticator app instead" : "Use your passkey instead"}
      </button>
      {error && (
        <p role="alert" className="text-sm text-bad">
          {error}
        </p>
      )}
    </li>
  );
}

export function ReviewQueueView() {
  const [state, setState] = useState<State>({ kind: "loading" });

  const load = useCallback(async () => {
    const r = await call("review-admin/queue", Queue);

    if (r.kind === "ok") setState({ kind: "ok", queue: r.value });
    else if (r.kind === "signed-out") setState({ kind: "signed-out" });
    else setState({ kind: "error", message: r.message });
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (state.kind === "loading") return <div className="h-96 animate-pulse rounded-2xl bg-muted" />;

  if (state.kind === "signed-out") return <SignInPanel next="/admin/reviews" title="Sign in to see the review queue" />;

  if (state.kind === "error") return <p className="rounded-xl bg-surface px-5 py-4 text-muted-foreground">{state.message}</p>;
  const { pending, decided, secondStage } = state.queue;

  return (
    <div className="flex max-w-3xl flex-col gap-10">
      <header className="flex flex-col gap-3">
        <h1 className="text-[28px] leading-tight font-medium tracking-tight sm:text-4xl">AI review queue</h1>
        <p className="text-[17px] leading-7 text-pretty text-muted-foreground">
          Versions the AI review flagged or could not answer. The public sees &ldquo;Under review&rdquo; until you decide. Confirming makes the findings and your note public; dismissing says a
          person checked it. Each decision needs a fresh code from your authenticator app, or your passkey. Stronger-model check: {secondStage ?? "not configured"}.
        </p>
      </header>
      <section aria-labelledby="pending" className="flex flex-col gap-4">
        <h2 id="pending" className="text-xl font-medium tracking-tight">
          Waiting <span className="text-muted-foreground tabular-nums">{pending.length}</span>
        </h2>
        {pending.length === 0 ? (
          <p className="rounded-xl bg-surface px-5 py-4 text-[15px] text-muted-foreground">Nothing is waiting. New flags show up here as the reviewer posts them.</p>
        ) : (
          <ol className="flex flex-col gap-4">
            {pending.map((i) => (
              <Pending key={`${i.name}@${i.version}:${i.digest}`} item={i} onDone={() => void load()} />
            ))}
          </ol>
        )}
      </section>
      {decided.length > 0 && (
        <section aria-labelledby="decided" className="flex flex-col gap-3">
          <h2 id="decided" className="text-xl font-medium tracking-tight">
            Decided
          </h2>
          <ul className="divide-y rounded-xl border">
            {decided.map((i) => (
              <li key={`${i.name}@${i.version}:${i.digest}`} className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 px-4 py-3 text-[15px]">
                <Link href={`${packagePath(i.name)}?v=${encodeURIComponent(i.version)}`} className="font-mono underline-offset-4 hover:underline">
                  {i.name}@{i.version}
                </Link>
                <span className="text-sm text-muted-foreground">
                  {i.public.state === "confirmed" ? "confirmed" : "dismissed"} by {i.decidedBy ?? "unknown"}
                  {i.public.decidedAt ? `, ${ago(i.public.decidedAt)}` : ""}
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
