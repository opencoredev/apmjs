"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { z } from "zod";
import { Input } from "@/components/ui/input";
import { SignInPanel } from "@/components/sign-in-panel";
import { Account, call, StagedSummary, timeLeft } from "@/lib/account";
import { ExactPart, looksLikePackageName } from "@/lib/search-schema";
import { cn } from "@/lib/utils";

type State = { kind: "loading" } | { kind: "signed-out" } | { kind: "error"; message: string } | { kind: "ok"; account: Account; staged: StagedSummary[] };

type Check = { kind: "idle" } | { kind: "checking" } | { kind: "invalid" } | { kind: "done"; answer: ExactPart } | { kind: "failed" };

function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <li className="grid grid-cols-[2rem_minmax(0,1fr)] gap-x-3 gap-y-2">
      <span className="grid size-7 place-items-center rounded-full bg-secondary font-mono text-sm">{n}</span>
      <div className="flex min-w-0 flex-col gap-2">
        <h3 className="text-[15px] leading-7 font-medium">{title}</h3>
        {children}
      </div>
    </li>
  );
}

function Code({ children }: { children: string }) {
  return <pre className="overflow-x-auto rounded-lg bg-surface px-4 py-3 font-mono text-[13px] leading-6">{children}</pre>;
}

function NameCheck({ scope }: { scope: string }) {
  const [bare, setBare] = useState("");
  const [check, setCheck] = useState<Check>({ kind: "idle" });
  const full = `@${scope}/${bare}`;

  useEffect(() => {
    if (bare === "") return setCheck({ kind: "idle" });

    if (!looksLikePackageName(full)) return setCheck({ kind: "invalid" });
    setCheck({ kind: "checking" });
    const ctrl = new AbortController();

    const t = setTimeout(() => {
      fetch(`/api/names?q=${encodeURIComponent(full)}&part=exact`, { signal: ctrl.signal })
        .then(async (r) => {
          const parsed = ExactPart.safeParse(await r.json());
          setCheck(r.ok && parsed.success ? { kind: "done", answer: parsed.data } : { kind: "failed" });
        })
        .catch(() => {
          if (!ctrl.signal.aborted) setCheck({ kind: "failed" });
        });
    }, 200);

    return () => {
      clearTimeout(t);
      ctrl.abort();
    };
  }, [bare, full]);

  let line: { tone: "ok" | "bad" | "muted"; text: string } = { tone: "muted", text: "Lowercase letters, digits, dots, dashes and underscores." };

  if (check.kind === "checking") line = { tone: "muted", text: "Checking…" };

  if (check.kind === "invalid") line = { tone: "bad", text: "That is not a valid package name. Use lowercase letters, digits, dots, dashes and underscores." };

  if (check.kind === "failed") line = { tone: "bad", text: "Could not check the name right now. Try again in a moment." };

  if (check.kind === "done") {
    const a = check.answer;

    if (a.taken && a.owners.includes(scope)) line = { tone: "ok", text: `You already own ${full}${a.latest ? ` (latest ${a.latest.version})` : ""}. Publishing adds a new version.` };
    else if (a.taken) line = { tone: "bad", text: `${full} is taken${a.owners.length ? ` by ${a.owners.join(", ")}` : ""}.` };
    else line = { tone: "ok", text: `${full} is free. It is yours to publish.` };
  }

  return (
    <div className="flex flex-col gap-2">
      <label htmlFor="pkg-name" className="text-sm text-muted-foreground">
        Package name
      </label>
      <div className="flex h-11 max-w-xl items-center overflow-hidden rounded-lg border border-input focus-within:border-ring focus-within:ring-3 focus-within:ring-ring/50">
        <span className="flex h-full shrink-0 items-center bg-surface px-3 font-mono text-[15px] whitespace-nowrap text-muted-foreground">@{scope}/</span>
        <Input
          id="pkg-name"
          value={bare}
          onChange={(e) => setBare(e.target.value.trim().toLowerCase())}
          placeholder="my-package"
          autoComplete="off"
          spellCheck={false}
          className="h-full rounded-none border-0 font-mono text-[15px] focus-visible:ring-0"
        />
      </div>
      <p aria-live="polite" className={cn("text-sm", line.tone === "ok" ? "text-ok" : line.tone === "bad" ? "text-bad" : "text-muted-foreground")}>
        {line.text}
      </p>
    </div>
  );
}

export function PublishView() {
  const [state, setState] = useState<State>({ kind: "loading" });

  useEffect(() => {
    void Promise.all([call("account", Account), call("staged", z.object({ staged: z.array(StagedSummary) }))]).then(([a, s]) => {
      if (a.kind === "signed-out") return setState({ kind: "signed-out" });

      if (a.kind === "error") return setState({ kind: "error", message: a.message });
      setState({ kind: "ok", account: a.value, staged: s.kind === "ok" ? s.value.staged : [] });
    });
  }, []);

  if (state.kind === "loading") return <div className="h-96 animate-pulse rounded-2xl bg-muted" />;

  if (state.kind === "signed-out") {
    return (
      <SignInPanel next="/publish" title="Sign in to publish">
        <p className="text-[15px] leading-6 text-muted-foreground">Packages on apm are published under your GitHub login, and a person approves every version before it goes live.</p>
      </SignInPanel>
    );
  }

  if (state.kind === "error") return <p className="text-bad">{state.message}</p>;
  const { account: a, staged } = state;
  const scope = a.scope;

  return (
    <div className="flex max-w-3xl flex-col gap-10">
      <header className="flex flex-col gap-3">
        <h1 className="text-[34px] leading-tight font-medium tracking-[-0.02em]">Publish a package</h1>
        <p className="text-[17px] leading-7 text-pretty text-muted-foreground">
          New packages go under your scope{scope ? <>, <code className="font-mono text-foreground">@{scope}</code></> : null}. Every version waits for you to approve it with your passkey or authenticator app, so a leaked token or an agent cannot ship code on its own.
        </p>
      </header>

      {!scope && (
        <p className="rounded-xl bg-warn-soft px-4 py-3 text-[15px] text-warn">
          Your account has no scope yet.{" "}
          <Link href="/account" className="underline underline-offset-4">
            Link GitHub on your account page
          </Link>{" "}
          first: your scope is your GitHub login.
        </p>
      )}
      {scope && !a.canPublish && (
        <p className="rounded-xl bg-warn-soft px-4 py-3 text-[15px] text-warn">
          Set up 2FA or a passkey before you publish.{" "}
          <Link href="/account" className="underline underline-offset-4">
            Go to your account
          </Link>
        </p>
      )}

      <section className="flex flex-col gap-4">
        <h2 className="text-lg font-medium tracking-tight">Waiting for your approval</h2>
        {staged.length === 0 ? (
          <p className="text-[15px] text-muted-foreground">Nothing is waiting. Versions you or your agents upload show up here for 24 hours.</p>
        ) : (
          <ul className="flex flex-col divide-y rounded-xl border">
            {staged.map((s) => (
              <li key={s.id}>
                <Link href={`/approve/${s.id}`} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-3 transition-colors hover:bg-muted/50">
                  <span className="w-full min-w-0 font-mono text-[15px] [overflow-wrap:anywhere] sm:w-auto sm:flex-1">
                    {s.package}@{s.version}
                  </span>
                  <span className="text-sm text-muted-foreground">
                    by {s.publisher} · {timeLeft(s.expiresAt)}
                  </span>
                  <span className="text-sm font-medium">Review</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>

      {scope && (
        <section className="flex flex-col gap-4">
          <h2 className="text-lg font-medium tracking-tight">Check a name</h2>
          <NameCheck scope={scope} />
        </section>
      )}

      <section className="flex flex-col gap-5">
        <h2 className="text-lg font-medium tracking-tight">Publish with the CLI</h2>
        <ol className="flex flex-col gap-6">
          <Step n={1} title="Log in once">
            <Code>apm login</Code>
            <p className="text-sm leading-6 text-muted-foreground">It prints a link and a code and opens your browser. Approve the code there. npm, pnpm and bun use the same token.</p>
          </Step>
          <Step n={2} title="Name the package under your scope">
            <Code>{`// package.json\n"name": "@${scope ?? "your-github-login"}/my-package"`}</Code>
          </Step>
          <Step n={3} title="Publish">
            <Code>apm publish</Code>
            <p className="text-sm leading-6 text-muted-foreground">
              <code className="font-mono">bun publish</code> and <code className="font-mono">npm publish</code> work too. The version is uploaded but not live yet: the output shows a link to approve it.
            </p>
          </Step>
          <Step n={4} title="Approve it">
            <p className="text-sm leading-6 text-muted-foreground">
              Open the link, check the files and the score, and confirm with your passkey or authenticator code. If an agent published, it should give you the link. Unapproved versions expire after 24 hours.
            </p>
          </Step>
        </ol>
      </section>
    </div>
  );
}
