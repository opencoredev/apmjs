"use client";

// /publish: one prompt the person pastes into their coding agent, which publishes the package in front of it with the
// apm CLI (no MCP server), and the versions waiting for the person's approval, shown only when there are some.
//
// Direction: the home page's agent setup card is the reference (one primary copy action, everything else folded).
// One column; the approval list leads when something waits, because approving is the step only a person can do.
// The prompt is shown in full in a mono block with the person's scope picked out, so they can read what they paste.
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { ArrowRightIcon, ChevronRightIcon, KeyRoundIcon } from "lucide-react";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { CopyBlock, CopyGlyph, CopyStatus, useCopy } from "@/components/copy-button";
import { SignInPanel } from "@/components/sign-in-panel";
import { Account, call, StagedSummary, timeLeft } from "@/lib/account";
import { manualSteps, publishPrompt, type PublishTarget } from "@/lib/publish-prompt";

/** The versions waiting for approval: loaded, or failed to load (never shown as an empty list). */
type Waiting = { kind: "ok"; staged: StagedSummary[] } | { kind: "error"; message: string };

type State = { kind: "loading" } | { kind: "signed-out" } | { kind: "error"; message: string } | { kind: "ok"; account: Account; waiting: Waiting };

const StagedList = z.object({ staged: z.array(StagedSummary) });

const SESSION_ENDED = "Your session ended. Sign in again to see what is waiting.";

async function loadWaiting(): Promise<Waiting> {
  const s = await call("staged", StagedList);

  return s.kind === "ok" ? { kind: "ok", staged: s.value.staged } : { kind: "error", message: s.kind === "error" ? s.message : SESSION_ENDED };
}

/** The prompt as text, with each mention of the person's scope set brighter so they can see it is theirs. */
function PromptText({ text, scope }: { text: string; scope: string }) {
  const mark = `@${scope}`;

  return text.split(mark).map((part, i) => (
    <span key={i}>
      {i > 0 && <span className="text-foreground">{mark}</span>}
      {part}
    </span>
  ));
}

export function WaitingList({ staged }: { staged: StagedSummary[] }) {
  return (
    <section aria-labelledby="waiting" className="flex flex-col gap-3 rounded-xl bg-warn-soft p-4 sm:p-5">
      <div className="flex flex-col gap-1">
        <h2 id="waiting" className="text-[15px] leading-6 font-medium text-warn">
          {staged.length === 1 ? "1 version is waiting for your approval" : `${staged.length} versions are waiting for your approval`}
        </h2>
        <p className="text-[13px] leading-5 text-pretty text-muted-foreground">Nothing goes live until you approve it with your passkey or authenticator code.</p>
      </div>
      <ul className="flex flex-col divide-y overflow-hidden rounded-lg border bg-background">
        {staged.map((s) => (
          <li key={s.id}>
            <Link href={`/approve/${s.id}`} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-3 transition-colors hover:bg-muted/50">
              <span className="w-full min-w-0 font-mono text-[14px] [overflow-wrap:anywhere] sm:w-auto sm:flex-1">
                {s.package}@{s.version}
              </span>
              <span className="text-[13px] text-muted-foreground tabular-nums">
                by {s.publisher} · {timeLeft(s.expiresAt)}
              </span>
              <span className="inline-flex items-center gap-1 text-[13px] font-medium">
                Review
                <ArrowRightIcon className="size-3.5" aria-hidden />
              </span>
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function PromptCard({ target, primary }: { target: PublishTarget; primary: boolean }) {
  const prompt = publishPrompt(target);
  const copier = useCopy();

  return (
    <section aria-labelledby="agent-prompt" className="overflow-hidden rounded-xl border">
      <div className="flex flex-col gap-4 p-4 sm:flex-row sm:items-start sm:justify-between sm:gap-6 sm:p-5">
        <div className="flex min-w-0 flex-col gap-1">
          <h2 id="agent-prompt" className="text-[15px] leading-6 font-medium">
            Paste this into your coding agent
          </h2>
          <p className="max-w-[56ch] text-[13px] leading-5 text-pretty text-muted-foreground">
            Claude Code, Codex, Cursor or any agent with a shell. It gets the apm CLI, logs you in, names the package and uploads it. No MCP server needed.
          </p>
        </div>
        <Button size="lg" variant={primary ? "default" : "outline"} className="w-full sm:w-auto" onClick={() => copier.copy(prompt)}>
          <CopyGlyph copied={copier.state === "copied"} className="[&_svg]:text-current" />
          {copier.state === "copied" ? "Prompt copied" : "Copy prompt"}
        </Button>
      </div>
      <CopyStatus state={copier.state} className="px-4 pb-3 sm:px-5" manual="Couldn't copy automatically. Select the prompt below and copy it." />
      <pre
        tabIndex={0}
        aria-label="The prompt"
        className="max-h-80 overflow-y-auto border-t bg-surface/40 px-4 py-3.5 font-mono text-[12px] leading-5 whitespace-pre-wrap text-muted-foreground [overflow-wrap:anywhere] outline-none focus-visible:ring-3 focus-visible:ring-ring/50 sm:px-5 sm:text-[13px]"
      >
        <PromptText text={prompt} scope={target.scope} />
      </pre>
    </section>
  );
}

function ManualSteps({ target }: { target: PublishTarget }) {
  return (
    <details className="group">
      <summary className="inline-flex cursor-pointer list-none items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground [&::-webkit-details-marker]:hidden">
        <ChevronRightIcon className="size-4 transition-transform duration-150 group-open:rotate-90" aria-hidden />
        Publish from your own terminal instead
      </summary>
      <div className="mt-3 flex flex-col gap-3">
        <CopyBlock text={manualSteps(target)} label="Copy the commands" caption="The install script checks the binary's SHA-256 before it installs; read it first at /install. apm login prints a link: approve it in your browser." />
        <p className="text-[13px] leading-5 text-pretty text-muted-foreground">
          After apm login, <code className="font-mono text-foreground">npm publish</code> and <code className="font-mono text-foreground">bun publish</code> work too, with{" "}
          <code className="font-mono text-foreground">--registry {target.registry}</code>. They skip apm&apos;s local checks; the registry still runs its own.
        </p>
      </div>
    </details>
  );
}

export function PublishView({ registry, site }: { registry: string; site: string }) {
  const [state, setState] = useState<State>({ kind: "loading" });

  const load = useCallback(async () => {
    const [a, waiting] = await Promise.all([call("account", Account), loadWaiting()]);

    if (a.kind === "signed-out") return setState({ kind: "signed-out" });

    if (a.kind === "error") return setState({ kind: "error", message: a.message });

    setState({ kind: "ok", account: a.value, waiting });
  }, []);

  const refreshWaiting = useCallback(async () => {
    const waiting = await loadWaiting();

    setState((prev) => (prev.kind === "ok" ? { ...prev, waiting } : prev));
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // An agent uploads while this tab sits in the background: look again when the person comes back to it.
  useEffect(() => {
    const onVisible = () => {
      if (document.visibilityState === "visible") void refreshWaiting();
    };

    document.addEventListener("visibilitychange", onVisible);

    return () => document.removeEventListener("visibilitychange", onVisible);
  }, [refreshWaiting]);

  if (state.kind === "loading") return <div className="h-96 max-w-3xl animate-pulse rounded-2xl bg-muted" />;

  if (state.kind === "signed-out") {
    return (
      <SignInPanel next="/publish" title="Sign in to publish">
        <p className="text-[15px] leading-6 text-muted-foreground">You publish under your GitHub login, and you approve every version before it goes live.</p>
      </SignInPanel>
    );
  }

  if (state.kind === "error") {
    return (
      <div className="flex max-w-xl flex-col items-start gap-3">
        <p role="alert" className="text-bad">
          {state.message}
        </p>
        <Button variant="outline" onClick={() => void load()}>
          Try again
        </Button>
      </div>
    );
  }

  const { account: a, waiting } = state;

  return (
    <div className="flex max-w-3xl flex-col gap-8">
      <header className="flex flex-col gap-3">
        <div className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-2">
          <h1 className="text-[34px] leading-tight font-medium tracking-[-0.02em]">Publish a package</h1>
          {a.scope && (
            <Link href="/account/packages" className="inline-flex items-center gap-1 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground">
              Your packages
              <ArrowRightIcon className="size-3.5" aria-hidden />
            </Link>
          )}
        </div>
        <p className="text-[17px] leading-7 text-pretty text-muted-foreground">
          {a.scope ? (
            <>
              Your packages are named <code className="font-mono text-[15px] text-foreground">@{a.scope}/&lt;name&gt;</code>. Your agent uploads; you approve each version here before it goes live.
            </>
          ) : (
            "Your agent uploads; you approve each version here before it goes live."
          )}
        </p>
      </header>

      {waiting.kind === "error" ? (
        <div role="alert" className="flex flex-col items-start gap-3 rounded-xl bg-bad-soft px-4 py-3">
          <p className="text-[15px] leading-6 text-bad">Could not load the versions waiting for your approval. {waiting.message}</p>
          <Button variant="outline" className="bg-background" onClick={() => void refreshWaiting()}>
            Try again
          </Button>
        </div>
      ) : (
        waiting.staged.length > 0 && <WaitingList staged={waiting.staged} />
      )}

      {!a.scope ? (
        <div className="flex flex-col items-start gap-3 rounded-xl bg-warn-soft px-4 py-4">
          <p className="text-[15px] leading-6 text-warn">Your scope is your GitHub login, and your account has none yet. Link GitHub first.</p>
          <Link href="/account" className="inline-flex h-9 items-center rounded-lg bg-primary px-3 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/80">
            Go to your account
          </Link>
        </div>
      ) : (
        <>
          {!a.canPublish && (
            <div className="flex flex-col gap-3 rounded-xl bg-warn-soft p-4 sm:flex-row sm:items-center sm:justify-between sm:p-5">
              <div className="flex min-w-0 gap-3">
                <KeyRoundIcon className="mt-0.5 size-[18px] shrink-0 text-warn" aria-hidden />
                <div className="flex flex-col gap-0.5">
                  <p className="text-[15px] leading-6 font-medium text-warn">First, add a passkey or an authenticator app</p>
                  <p className="text-[13px] leading-5 text-pretty text-muted-foreground">You approve every version with one. Until you have one, the registry refuses uploads.</p>
                </div>
              </div>
              <Link
                href="/account"
                className="inline-flex h-9 shrink-0 items-center justify-center rounded-lg bg-primary px-3 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/80"
              >
                Set it up
              </Link>
            </div>
          )}
          {/* one primary action: setting up a factor, else approving what waits, else copying the prompt */}
          <PromptCard target={{ scope: a.scope, registry, site }} primary={a.canPublish && !(waiting.kind === "ok" && waiting.staged.length > 0)} />
          <ManualSteps target={{ scope: a.scope, registry, site }} />
        </>
      )}
    </div>
  );
}
