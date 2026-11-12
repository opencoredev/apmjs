"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScoreBadge } from "@/components/score-badge";
import { SignInPanel } from "@/components/sign-in-panel";
import { Account, AuthConfig, authClient, call, StagedDetail, timeLeft } from "@/lib/account";
import { cn } from "@/lib/utils";

type State =
  | { kind: "loading" }
  | { kind: "signed-out" }
  | { kind: "error"; message: string }
  | { kind: "ok"; staged: StagedDetail; account: Account; config: AuthConfig }
  | { kind: "decided"; status: "approved" | "rejected"; name: string; version: string };

function fmtSize(n: number): string {
  return n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} kB` : `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-[13px] text-muted-foreground">{label}</dt>
      <dd className="text-[15px] [overflow-wrap:anywhere]">{children}</dd>
    </div>
  );
}

const Decided = z.object({ ok: z.boolean(), status: z.enum(["approved", "rejected"]) });

function Confirm({ s, account, config, onDecided }: { s: StagedDetail; account: Account; config: AuthConfig; onDecided: (status: "approved" | "rejected") => void }) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState<"code" | "passkey" | "reject" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const canTotp = account.security.totp;
  const canPasskey = account.security.passkeys > 0 && config.passkeys;

  async function approve(body: { code?: string }, how: "code" | "passkey") {
    setBusy(how);
    setError(null);
    const r = await call(`staged/${s.id}/approve`, Decided, { method: "POST", body });
    setBusy(null);

    if (r.kind === "ok") return onDecided(r.value.status);
    setError(r.kind === "error" ? r.message : "Sign in again.");
  }

  async function withPasskey() {
    setBusy("passkey");
    setError(null);
    const p = await authClient().signIn.passkey();

    if (p.error) {
      setBusy(null);

      return setError(p.error.message ?? "The passkey check did not finish.");
    }

    await approve({}, "passkey");
  }

  async function reject() {
    setBusy("reject");
    const r = await call(`staged/${s.id}/reject`, Decided, { method: "POST", body: {} });
    setBusy(null);

    if (r.kind === "ok") return onDecided("rejected");
    setError(r.kind === "error" ? r.message : "Sign in again.");
  }

  if (!canTotp && !canPasskey) {
    return (
      <p className="rounded-xl bg-warn-soft px-4 py-3 text-[15px] text-warn">
        Approving needs 2FA or a passkey on your account.{" "}
        <Link href="/account" className="underline underline-offset-4">
          Set one up
        </Link>
        , then come back to this page.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-4 rounded-2xl border p-5 sm:p-6">
      <div className="flex flex-col gap-1">
        <h2 className="text-lg font-medium tracking-tight">Approve and publish</h2>
        <p className="text-[15px] leading-6 text-muted-foreground">
          {s.package}@{s.version} goes live for everyone who installs it. You cannot replace a version once it is published.
        </p>
      </div>
      <form
        onSubmit={(e) => {
          e.preventDefault();

          if (!/^\d{6}$/.test(code)) return setError("Enter the 6-digit code your app shows.");
          void approve({ code }, "code");
        }}
        className="flex flex-wrap items-end gap-2"
      >
        {canTotp && (
          <>
            <label className="flex flex-col gap-1.5 text-sm text-muted-foreground">
              Code from your authenticator app
              <Input
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="123456"
                className="h-10 w-40 font-mono text-base tracking-widest"
              />
            </label>
            <Button type="submit" size="lg" className="h-10 px-4" disabled={busy !== null}>
              {busy === "code" ? "Publishing…" : "Approve and publish"}
            </Button>
          </>
        )}
        {canPasskey && (
          <Button type="button" size="lg" variant={canTotp ? "outline" : "default"} className="h-10 px-4" disabled={busy !== null} onClick={() => void withPasskey()}>
            {busy === "passkey" ? "Waiting for passkey…" : "Approve with passkey"}
          </Button>
        )}
      </form>
      {error && (
        <p role="alert" className="text-sm text-bad">
          {error}
        </p>
      )}
      <div className="border-t pt-4">
        <Button variant="ghost" className="-ml-2.5 text-muted-foreground" disabled={busy !== null} onClick={() => void reject()}>
          {busy === "reject" ? "Rejecting…" : "Reject this version"}
        </Button>
      </div>
    </div>
  );
}

export function ApproveView() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [state, setState] = useState<State>({ kind: "loading" });

  const load = useCallback(async () => {
    const [s, a, c] = await Promise.all([call(`staged/${encodeURIComponent(id)}`, StagedDetail), call("account", Account), call("auth/config", AuthConfig)]);

    if (s.kind === "signed-out" || a.kind === "signed-out") return setState({ kind: "signed-out" });

    if (s.kind === "error") return setState({ kind: "error", message: s.message });

    if (a.kind === "error") return setState({ kind: "error", message: a.message });

    if (c.kind !== "ok") return setState({ kind: "error", message: "Could not load sign-in options." });
    setState({ kind: "ok", staged: s.value, account: a.value, config: c.value });
  }, [id]);

  useEffect(() => {
    void load();
  }, [load]);

  if (state.kind === "loading") return <div className="h-96 animate-pulse rounded-2xl bg-muted" />;

  if (state.kind === "signed-out") {
    return (
      <SignInPanel next={`/approve/${id}`} title="Sign in to review this version">
        <p className="text-[15px] leading-6 text-muted-foreground">A version was uploaded to apm and is waiting for its owner to approve it. Sign in as that owner to review it.</p>
      </SignInPanel>
    );
  }

  if (state.kind === "error") {
    return (
      <div className="flex max-w-xl flex-col gap-3">
        <h1 className="text-2xl font-medium tracking-tight">Cannot show this version</h1>
        <p className="text-[15px] text-muted-foreground">{state.message}</p>
        <Link href="/publish" className="text-[15px] underline underline-offset-4">
          See what is waiting for you
        </Link>
      </div>
    );
  }

  if (state.kind === "decided") {
    return (
      <div className="flex max-w-xl flex-col gap-3">
        <h1 className="text-[28px] font-medium tracking-tight">
          {state.status === "approved" ? `${state.name}@${state.version} is live` : `${state.name}@${state.version} was rejected`}
        </h1>
        <p className="text-[15px] text-muted-foreground">
          {state.status === "approved" ? "It installs with bun, npm and pnpm now." : "Nothing was published. The upload is deleted."}
        </p>
        {state.status === "approved" && (
          <Link href={`/package/${state.name}`} className="text-[15px] underline underline-offset-4">
            Open the package page
          </Link>
        )}
      </div>
    );
  }

  const { staged: s, account, config } = state;
  const pending = s.status === "pending" && Date.parse(s.expiresAt) > Date.now();
  const lost = s.score?.signals.filter((x) => x.points < 0) ?? [];
  const notes = s.score?.signals.filter((x) => x.points >= 0) ?? [];

  return (
    <div className="flex max-w-3xl flex-col gap-8">
      <header className="flex flex-col gap-3">
        <span className={cn("self-start rounded-md px-2 py-0.5 text-[13px] font-medium", pending ? "bg-warn-soft text-warn" : "bg-surface text-muted-foreground")}>
          {pending ? `Waiting for approval · ${timeLeft(s.expiresAt)}` : s.status === "pending" ? "Expired" : `This version was ${s.status}`}
        </span>
        <h1 className="font-mono text-[26px] leading-tight font-medium tracking-tight [overflow-wrap:anywhere] sm:text-[32px]">
          {s.package}@{s.version}
        </h1>
        {s.description && <p className="text-[17px] leading-7 text-muted-foreground">{s.description}</p>}
      </header>

      <dl className="grid grid-cols-2 gap-x-6 gap-y-4 rounded-2xl bg-surface p-5 sm:grid-cols-4">
        <Fact label="Uploaded by">{s.publisher}</Fact>
        <Fact label="Uploaded">{new Date(s.stagedAt).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}</Fact>
        <Fact label="Tag">{s.tag}</Fact>
        <Fact label={s.newPackage ? "Package" : "Current latest"}>{s.newPackage ? "New package" : (s.currentLatest ?? "none")}</Fact>
      </dl>

      {pending && <Confirm s={s} account={account} config={config} onDecided={(status) => setState({ kind: "decided", status, name: s.package, version: s.version })} />}

      <section className="flex flex-col gap-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-lg font-medium tracking-tight">apm score preview</h2>
          {s.score && <ScoreBadge score={s.score.score} grade={s.score.grade} />}
        </div>
        {!s.score ? (
          <p className="text-[15px] text-muted-foreground">No score: the tarball could not be analyzed.</p>
        ) : (
          <ul className="flex flex-col divide-y rounded-xl border">
            {lost.length === 0 && <li className="px-4 py-3 text-[15px] text-muted-foreground">No risk signals found.</li>}
            {lost.map((x) => (
              <li key={x.id} className="flex gap-4 px-4 py-3">
                <span className={cn("w-9 shrink-0 text-right font-mono text-[15px] tabular-nums", x.points <= -20 ? "text-bad" : "text-warn")}>{x.points}</span>
                <div className="min-w-0 flex-1">
                  <div className="text-[15px] leading-6">
                    <span className="font-mono">{x.id}</span> <span className="text-muted-foreground">{x.label}</span>
                  </div>
                  {x.evidence.slice(0, 4).map((ev) => (
                    <div key={ev} className="mt-1.5 border-l-2 pl-3 font-mono text-[12.5px] leading-5 text-muted-foreground [overflow-wrap:anywhere]">
                      {ev}
                    </div>
                  ))}
                </div>
              </li>
            ))}
            {notes.map((x) => (
              <li key={x.id} className="flex gap-4 px-4 py-2.5 text-sm text-muted-foreground">
                <span className="w-9 shrink-0 text-right font-mono tabular-nums">0</span>
                <span className="min-w-0">
                  <span className="font-mono text-foreground">{x.id}</span> {x.label}
                  {x.evidence[0] ? ` (${x.evidence[0]})` : ""}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="flex flex-col gap-4">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <h2 className="text-lg font-medium tracking-tight">Files</h2>
          <span className="text-sm text-muted-foreground">
            {s.files.length} files · {fmtSize(s.size)} packed
          </span>
        </div>
        <ul className="max-h-[420px] overflow-auto rounded-xl border font-mono text-[13px]">
          {s.files.map((f) => (
            <li key={f.path} className="flex justify-between gap-4 border-b px-4 py-2 last:border-b-0">
              <span className="min-w-0 [overflow-wrap:anywhere]">{f.path}</span>
              <span className="shrink-0 text-muted-foreground tabular-nums">{fmtSize(f.size)}</span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
