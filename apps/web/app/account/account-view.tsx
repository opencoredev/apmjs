"use client";

import Link from "next/link";
import QRCode from "qrcode";
import { useCallback, useEffect, useState } from "react";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SignInPanel } from "@/components/sign-in-panel";
import { Account, AuthConfig, authClient, authPost, call, linkProvider, PROVIDER_LABEL } from "@/lib/account";
import { cn } from "@/lib/utils";

type State = { kind: "loading" } | { kind: "signed-out" } | { kind: "error"; message: string } | { kind: "ok"; account: Account; config: AuthConfig };

function Section({ title, children, aside }: { title: string; children: React.ReactNode; aside?: React.ReactNode }) {
  return (
    <section className="flex flex-col gap-4 border-t pt-6">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="text-lg font-medium tracking-tight">{title}</h2>
        {aside}
      </div>
      {children}
    </section>
  );
}

function Status({ on, children }: { on: boolean; children: React.ReactNode }) {
  return <span className={cn("inline-flex h-6 items-center rounded-md px-2 text-[13px] font-medium", on ? "bg-ok-soft text-ok" : "bg-warn-soft text-warn")}>{children}</span>;
}

function fmt(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

const SixDigits = /^\d{6}$/;

function TotpSetup({ onDone }: { onDone: () => void }) {
  const [step, setStep] = useState<{ kind: "idle" } | { kind: "scan"; uri: string; secret: string; qr: string }>({ kind: "idle" });
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function start() {
    setBusy(true);
    setError(null);
    const r = await authPost("two-factor/enable", {});
    const uri = z.object({ totpURI: z.string() }).safeParse(r.body);
    if (!r.ok || !uri.success) {
      setError(r.message);
      setBusy(false);
      return;
    }
    const secret = new URL(uri.data.totpURI).searchParams.get("secret") ?? "";
    const qr = await QRCode.toDataURL(uri.data.totpURI, { margin: 1, width: 200 });
    setStep({ kind: "scan", uri: uri.data.totpURI, secret, qr });
    setBusy(false);
  }

  async function confirm(e: React.FormEvent) {
    e.preventDefault();
    if (!SixDigits.test(code)) return setError("Enter the 6-digit code your app shows.");
    setBusy(true);
    setError(null);
    const r = await authPost("two-factor/verify-totp", { code });
    setBusy(false);
    if (!r.ok) return setError("That code did not match. Check the time on your phone and try the next code.");
    onDone();
  }

  if (step.kind === "idle") {
    return (
      <div className="flex flex-col gap-2">
        <Button className="self-start" onClick={() => void start()} disabled={busy}>
          {busy ? "Starting…" : "Set up an authenticator app"}
        </Button>
        {error && <p className="text-sm text-bad">{error}</p>}
      </div>
    );
  }
  return (
    <form onSubmit={(e) => void confirm(e)} className="flex flex-col gap-4 rounded-xl bg-surface p-4 sm:flex-row sm:items-start sm:gap-6">
      {/* eslint-disable-next-line @next/next/no-img-element -- a data URL made in the browser */}
      <img src={step.qr} alt="QR code for your authenticator app" width={160} height={160} className="size-40 shrink-0 rounded-lg bg-white p-1" />
      <div className="flex min-w-0 flex-col gap-3">
        <p className="text-sm leading-6 text-muted-foreground">Scan this with an authenticator app (1Password, Google Authenticator, Authy). Or enter the key by hand:</p>
        <code className="font-mono text-[13px] [overflow-wrap:anywhere]">{step.secret.match(/.{1,4}/g)?.join(" ")}</code>
        <label className="flex flex-col gap-1.5 text-sm">
          Code from the app
          <Input value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" placeholder="123456" className="h-9 max-w-40 font-mono tracking-widest" />
        </label>
        <Button type="submit" className="self-start" disabled={busy}>
          {busy ? "Checking…" : "Turn on 2FA"}
        </Button>
        {error && <p className="text-sm text-bad">{error}</p>}
      </div>
    </form>
  );
}

function StepUp({ account, config, onDone }: { account: Account; config: AuthConfig; onDone: () => void }) {
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const until = account.security.verifiedAt ? Date.parse(account.security.verifiedAt) + 10 * 60_000 : 0;
  const active = until > Date.now();

  async function withCode(e: React.FormEvent) {
    e.preventDefault();
    if (!SixDigits.test(code)) return setError("Enter the 6-digit code your app shows.");
    setBusy(true);
    setError(null);
    const r = await call("verify", z.object({ ok: z.boolean() }), { method: "POST", body: { code } });
    setBusy(false);
    if (r.kind !== "ok") return setError(r.kind === "error" ? r.message : "Sign in again.");
    setCode("");
    onDone();
  }

  async function withPasskey() {
    setBusy(true);
    setError(null);
    const r = await authClient().signIn.passkey();
    setBusy(false);
    if (r.error) return setError(r.error.message ?? "The passkey check did not finish.");
    onDone();
  }

  const canTotp = account.security.totp;
  const canPasskey = account.security.passkeys > 0 && config.passkeys;
  if (!canTotp && !canPasskey) return <p className="text-sm text-muted-foreground">Set up 2FA or a passkey first.</p>;
  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm leading-6 text-muted-foreground">
        Revoke, restore, incident response and owner changes need a fresh check. Confirm here, then run the command within 10 minutes, or pass <code className="font-mono">--otp</code> to it.
        {active && <span className="text-foreground"> Confirmed until {new Date(until).toLocaleTimeString(undefined, { timeStyle: "short" })}.</span>}
      </p>
      <form onSubmit={(e) => void withCode(e)} className="flex flex-wrap items-center gap-2">
        {canTotp && (
          <>
            <Input
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="123456"
              aria-label="Code from your authenticator app"
              className="h-9 w-36 font-mono tracking-widest"
            />
            <Button type="submit" variant="outline" size="lg" disabled={busy}>
              Confirm with code
            </Button>
          </>
        )}
        {canPasskey && (
          <Button type="button" variant="outline" size="lg" disabled={busy} onClick={() => void withPasskey()}>
            Confirm with passkey
          </Button>
        )}
      </form>
      {error && <p className="text-sm text-bad">{error}</p>}
    </div>
  );
}

export function AccountView() {
  const [state, setState] = useState<State>({ kind: "loading" });
  const [note, setNote] = useState<string | null>(null);

  const load = useCallback(async () => {
    const [a, c] = await Promise.all([call("account", Account), call("auth/config", AuthConfig)]);
    if (a.kind === "signed-out") return setState({ kind: "signed-out" });
    if (a.kind === "error") return setState({ kind: "error", message: a.message });
    if (c.kind !== "ok") return setState({ kind: "error", message: c.kind === "error" ? c.message : "Could not load sign-in options." });
    setState({ kind: "ok", account: a.value, config: c.value });
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (state.kind === "loading") return <div className="h-96 animate-pulse rounded-2xl bg-muted" />;
  if (state.kind === "signed-out") return <SignInPanel next="/account" />;
  if (state.kind === "error") return <p className="text-bad">{state.message}</p>;
  const { account: a, config } = state;

  async function revoke(id: string) {
    const r = await call("account/tokens/revoke", z.object({ ok: z.boolean() }), { method: "POST", body: { id } });
    setNote(r.kind === "ok" ? "Token revoked. Anything using it stops working now." : r.kind === "error" ? r.message : "Sign in again.");
    await load();
  }

  async function addPasskey() {
    setNote(null);
    const r = await authClient().passkey.addPasskey({ name: `apm ${new Date().toLocaleDateString()}` });
    if (r?.error) setNote(r.error.message ?? "The passkey was not added.");
    await load();
  }

  async function signOut() {
    await authPost("sign-out", {});
    window.location.assign("/");
  }

  const linked = new Set(a.linked.map((l) => l.provider));
  const linkable = (["github", "vercel"] as const).filter((p) => config.providers[p] && !linked.has(p));
  const live = a.tokens.filter((t) => t.revokedAt === null && (t.expiresAt === null || Date.parse(t.expiresAt) > Date.now()));

  return (
    <div className="flex max-w-3xl flex-col gap-8">
      <header className="flex flex-wrap items-center gap-4">
        {a.image ? (
          // eslint-disable-next-line @next/next/no-img-element -- avatars come from GitHub/Vercel hosts
          <img src={a.image} alt="" className="size-14 rounded-full bg-muted" />
        ) : (
          <span className="grid size-14 place-items-center rounded-full bg-muted text-xl uppercase">{(a.scope ?? a.name).slice(0, 1)}</span>
        )}
        <div className="flex min-w-0 flex-1 flex-col">
          <h1 className="truncate text-[28px] leading-tight font-medium tracking-tight">{a.scope ? `@${a.scope}` : a.name || "Your account"}</h1>
          <span className="truncate text-[15px] text-muted-foreground">{a.email}</span>
        </div>
        <Button variant="outline" size="lg" onClick={() => void signOut()}>
          Sign out
        </Button>
      </header>

      {note && (
        <p role="status" className="rounded-lg bg-surface px-4 py-3 text-sm">
          {note}
        </p>
      )}

      <Section title="Your scope">
        {a.scope ? (
          <p className="text-[15px] leading-7 text-muted-foreground">
            New packages you publish are named <code className="font-mono text-foreground">@{a.scope}/&lt;name&gt;</code>. Your scope is your GitHub login
            {a.github && a.github !== a.scope ? ` (${a.github})` : ""}.{" "}
            <Link href="/publish" className="text-foreground underline underline-offset-4">
              Publish a package
            </Link>
          </p>
        ) : a.scopeTaken ? (
          <p className="text-[15px] leading-7 text-muted-foreground">
            Your GitHub login, <code className="font-mono text-foreground">{a.scopeTaken}</code>, is already the name of an older apm account, so it is not yours to publish under yet. Open a name dispute on GitHub (opencoredev/apmjs) and we will sort it out.
          </p>
        ) : (
          <div className="flex flex-col gap-3">
            <p className="text-[15px] leading-7 text-muted-foreground">You have no scope yet. Your scope is your GitHub login, so link GitHub before you publish.</p>
            {config.providers.github && (
              <Button className="self-start" onClick={() => void linkProvider("github", "/account").then((m) => m && setNote(m))}>
                Link GitHub
              </Button>
            )}
          </div>
        )}
      </Section>

      <Section title="Security" aside={a.canPublish ? <Status on>Ready to publish</Status> : <Status on={false}>Publishing needs 2FA or a passkey</Status>}>
        <div className="flex flex-col gap-5">
          <div className="flex flex-col gap-3">
            <div className="flex items-center gap-3">
              <span className="text-[15px] font-medium">Authenticator app (2FA)</span>
              <Status on={a.security.totp}>{a.security.totp ? "On" : "Off"}</Status>
            </div>
            {!a.security.totp && <TotpSetup onDone={() => void load()} />}
          </div>
          <div className="flex flex-col gap-3">
            <div className="flex items-center gap-3">
              <span className="text-[15px] font-medium">Passkeys</span>
              <Status on={a.security.passkeys > 0}>{a.security.passkeys === 0 ? "None" : `${a.security.passkeys} set up`}</Status>
            </div>
            {config.passkeys ? (
              <Button variant="outline" className="self-start" onClick={() => void addPasskey()}>
                Add a passkey
              </Button>
            ) : (
              <p className="text-sm text-muted-foreground">Passkeys need HTTPS. This registry is served over plain HTTP, so use an authenticator app here.</p>
            )}
          </div>
          <div className="flex flex-col gap-3">
            <span className="text-[15px] font-medium">Confirm it&apos;s you</span>
            <StepUp account={a} config={config} onDone={() => void load()} />
          </div>
        </div>
      </Section>

      <Section title="Linked accounts">
        <ul className="flex flex-col divide-y rounded-xl border">
          {a.linked.map((l) => (
            <li key={`${l.provider}:${l.accountId}`} className="flex items-center justify-between gap-3 px-4 py-3 text-[15px]">
              <span>{l.provider === "github" || l.provider === "vercel" ? PROVIDER_LABEL[l.provider] : l.provider}</span>
              <span className="text-sm text-muted-foreground">{l.provider === "github" && a.github ? a.github : "Linked"}</span>
            </li>
          ))}
        </ul>
        {linkable.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {linkable.map((p) => (
              <Button key={p} variant="outline" onClick={() => void linkProvider(p, "/account").then((m) => m && setNote(m))}>
                Link {PROVIDER_LABEL[p]}
              </Button>
            ))}
          </div>
        )}
      </Section>

      <Section title="Tokens" aside={<span className="text-sm text-muted-foreground">{live.length} active</span>}>
        {a.tokens.length === 0 ? (
          <p className="text-[15px] text-muted-foreground">
            No tokens yet. Run <code className="font-mono text-foreground">apm login</code> to get one for the CLI.
          </p>
        ) : (
          <ul className="flex flex-col divide-y rounded-xl border">
            {a.tokens.map((t) => {
              const revoked = t.revokedAt !== null;
              return (
                <li key={t.id} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-3">
                  <div className="flex min-w-0 flex-1 flex-col">
                    <span className={cn("text-[15px]", revoked && "text-muted-foreground line-through")}>{t.label}</span>
                    <span className="text-[13px] text-muted-foreground">
                      {t.scope === "publish" ? "Publishes go live at once" : "Publishes wait for your approval"} · created {fmt(t.createdAt)}
                      {revoked && t.revokedAt ? ` · revoked ${fmt(t.revokedAt)}` : ""}
                    </span>
                  </div>
                  {!revoked && (
                    <Button variant="destructive" size="sm" onClick={() => void revoke(t.id)}>
                      Revoke
                    </Button>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </Section>
    </div>
  );
}
