"use client";

import Link from "next/link";
import QRCode from "qrcode";
import { useCallback, useEffect, useState } from "react";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SignInPanel } from "@/components/sign-in-panel";
import {
  Account,
  AuthConfig,
  authClient,
  authPost,
  call,
  commandFromLink,
  commandText,
  linkProvider,
  PROVIDER_LABEL,
  proofHeaders,
  type FactorProof,
  type LiveAction,
} from "@/lib/account";
import { cn } from "@/lib/utils";

type State = { kind: "loading" } | { kind: "signed-out" } | { kind: "error"; message: string } | { kind: "ok"; account: Account; config: AuthConfig };

const NAME_DISPUTE_URL = "https://github.com/opencoredev/apmjs/issues/new?template=name-dispute.yml";

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

function hasFactor(a: Account): boolean {
  return a.security.totp || a.security.passkeys > 0;
}

/**
 * Asks for the factor the account already has: a code from the app (or a recovery code), or a passkey check.
 * `run` gets the proof and returns an error message, or null when it worked.
 */
function FactorPrompt({
  account,
  config,
  action,
  busyLabel,
  allowRecovery = false,
  run,
}: {
  account: Account;
  config: AuthConfig;
  action: string;
  busyLabel: string;
  allowRecovery?: boolean;
  run: (proof: FactorProof) => Promise<string | null>;
}) {
  const [mode, setMode] = useState<"totp" | "recovery">("totp");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState<"code" | "passkey" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const canTotp = account.security.totp;
  const canPasskey = account.security.passkeys > 0 && config.passkeys;

  async function withCode(e: React.FormEvent) {
    e.preventDefault();
    const value = code.trim();

    if (mode === "totp" && !SixDigits.test(value)) return setError("Enter the 6-digit code your app shows.");

    if (mode === "recovery" && !/^[A-Za-z0-9-]{6,64}$/.test(value)) return setError("Enter one of your recovery codes, like abcde-12345.");
    setBusy("code");
    setError(null);
    const message = await run({ kind: mode, code: value });
    setBusy(null);

    if (message) return setError(message);
    setCode("");
  }

  async function withPasskey() {
    setBusy("passkey");
    setError(null);
    const p = await authClient().signIn.passkey();

    if (p.error) {
      setBusy(null);

      return setError(p.error.message ?? "The passkey check did not finish.");
    }

    const message = await run({ kind: "passkey" });
    setBusy(null);

    if (message) setError(message);
  }

  return (
    <div className="flex flex-col gap-3">
      <form onSubmit={(e) => void withCode(e)} className="flex flex-wrap items-end gap-2">
        {canTotp && (
          <>
            <label className="flex flex-col gap-1.5 text-sm text-muted-foreground">
              {mode === "totp" ? "Code from your authenticator app" : "Recovery code"}
              <Input
                value={code}
                onChange={(e) => setCode(mode === "totp" ? e.target.value.replace(/\D/g, "").slice(0, 6) : e.target.value.slice(0, 64))}
                inputMode={mode === "totp" ? "numeric" : "text"}
                autoComplete={mode === "totp" ? "one-time-code" : "off"}
                spellCheck={false}
                placeholder={mode === "totp" ? "123456" : "abcde-12345"}
                aria-invalid={error !== null}
                className={cn("h-9 font-mono", mode === "totp" ? "w-36 tracking-widest" : "w-48")}
              />
            </label>
            <Button type="submit" variant="outline" size="lg" disabled={busy !== null}>
              {busy === "code" ? busyLabel : action}
            </Button>
          </>
        )}
        {canPasskey && (
          <Button type="button" variant="outline" size="lg" disabled={busy !== null} onClick={() => void withPasskey()}>
            {busy === "passkey" ? "Waiting for passkey…" : canTotp ? "Use passkey instead" : `${action} with passkey`}
          </Button>
        )}
      </form>
      {canTotp && allowRecovery && (
        <button
          type="button"
          className="self-start text-sm text-muted-foreground underline underline-offset-4 hover:text-foreground"
          onClick={() => {
            setMode(mode === "totp" ? "recovery" : "totp");
            setCode("");
            setError(null);
          }}
        >
          {mode === "totp" ? "Lost your phone? Use a recovery code" : "Use a code from your app instead"}
        </button>
      )}
      {error && (
        <p role="alert" className="text-sm text-bad">
          {error}
        </p>
      )}
    </div>
  );
}

/** The recovery codes, shown once right after 2FA is turned on. Exported for the rendering test. */
export function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  const text = `apm recovery codes\nEach code works once. Keep them somewhere safe, away from your phone.\n\n${codes.join("\n")}\n`;

  async function copy() {
    try {
      await navigator.clipboard.writeText(codes.join("\n"));
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  function download() {
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "apm-recovery-codes.txt";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="flex flex-col gap-4 rounded-xl border border-warn/40 bg-warn-soft/40 p-4 sm:p-5">
      <div className="flex flex-col gap-1">
        <h3 className="text-[15px] font-medium">Save your recovery codes</h3>
        <p className="text-sm leading-6 text-muted-foreground">
          2FA is on. If you lose your phone, each of these codes turns 2FA off once. This is the only time apm shows them.
        </p>
      </div>
      <ol className="grid grid-cols-1 gap-x-6 gap-y-1.5 rounded-lg bg-background px-4 py-3 font-mono text-[15px] tabular-nums min-[420px]:grid-cols-2">
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ol>
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" onClick={() => void copy()}>
          {copied ? "Copied" : "Copy codes"}
        </Button>
        <Button variant="outline" onClick={download}>
          Download .txt
        </Button>
      </div>
      <label className="flex items-start gap-2.5 text-[15px] leading-6">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} className="mt-1 size-4 accent-foreground" />
        I saved these codes somewhere safe
      </label>
      <Button className="self-start" disabled={!saved} onClick={onDone}>
        Done
      </Button>
    </div>
  );
}

/** Sets up an authenticator app; `onEnabled` gets the recovery codes to show once. */
function TotpSetup({ account, config, onEnabled }: { account: Account; config: AuthConfig; onEnabled: (recoveryCodes: string[]) => void }) {
  const [step, setStep] = useState<{ kind: "idle" } | { kind: "scan"; secret: string; qr: string; codes: string[] }>({ kind: "idle" });
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // An account with a passkey proves it before adding an authenticator app.
  const needsProof = hasFactor(account);

  async function start(proof: FactorProof | null): Promise<string | null> {
    setBusy(true);
    setError(null);
    const r = await authPost("two-factor/enable", {}, proof);
    const parsed = z.object({ totpURI: z.string(), backupCodes: z.array(z.string()) }).safeParse(r.body);

    if (!r.ok || !parsed.success) {
      setBusy(false);

      return r.message;
    }

    const secret = new URL(parsed.data.totpURI).searchParams.get("secret") ?? "";
    const qr = await QRCode.toDataURL(parsed.data.totpURI, { margin: 1, width: 200 });
    setStep({ kind: "scan", secret, qr, codes: parsed.data.backupCodes });
    setBusy(false);

    return null;
  }

  async function confirm(e: React.FormEvent) {
    e.preventDefault();

    if (step.kind !== "scan") return;

    if (!SixDigits.test(code)) return setError("Enter the 6-digit code your app shows.");
    setBusy(true);
    setError(null);
    const r = await authPost("two-factor/verify-totp", { code });
    setBusy(false);

    if (!r.ok) return setError(r.status === 429 ? r.message : "That code did not match. Check the time on your phone and try the next code.");
    onEnabled(step.codes);
  }

  if (step.kind === "idle") {
    if (needsProof) {
      return (
        <div className="flex flex-col gap-2">
          <p className="text-sm text-muted-foreground">Confirm with your passkey to add an authenticator app.</p>
          <FactorPrompt account={account} config={config} action="Set up" busyLabel="Starting…" run={(p) => start(p)} />
        </div>
      );
    }

    return (
      <div className="flex flex-col gap-2">
        <Button
          className="self-start"
          onClick={() => {
            void start(null).then((m) => m && setError(m));
          }}
          disabled={busy}
        >
          {busy ? "Starting…" : "Set up an authenticator app"}
        </Button>
        {error && <p className="text-sm text-bad">{error}</p>}
      </div>
    );
  }

  return (
    <form onSubmit={(e) => void confirm(e)} className="flex flex-col gap-4 rounded-xl bg-surface p-4 sm:flex-row sm:items-start sm:gap-6">
      {/* eslint-disable-next-line @next/next/no-img-element, shadcn/no-raw-colors -- a data URL made in the browser; a QR code needs a white quiet zone to scan in dark mode */}
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

/** Approves one CLI command that printed a link here. The CLI can then run that command once, within 10 minutes. */
function ConfirmCommand({ command, account, config, onDone }: { command: LiveAction; account: Account; config: AuthConfig; onDone: (message: string) => void }) {
  const text = commandText(command);

  return (
    <div className="flex flex-col gap-4 rounded-2xl border p-5 sm:p-6">
      <div className="flex flex-col gap-1.5">
        <h2 className="text-lg font-medium tracking-tight">Approve a command from your terminal</h2>
        <p className="text-[15px] leading-6 text-muted-foreground">This lets your CLI run this one command, once, in the next 10 minutes. Approve only if you just ran it.</p>
      </div>
      <code className="rounded-lg bg-surface px-4 py-3 font-mono text-[15px] [overflow-wrap:anywhere]">{text}</code>
      {hasFactor(account) ? (
        <FactorPrompt
          account={account}
          config={config}
          action="Approve command"
          busyLabel="Approving…"
          run={async (proof) => {
            if (proof.kind === "recovery") return "Use a code from your app or your passkey for this.";

            const r = await call("verify", z.object({ ok: z.boolean(), command: z.string(), until: z.string() }), {
              method: "POST",
              body: { command, ...(proof.kind === "totp" ? { code: proof.code } : { passkey: true }) },
            });

            if (r.kind === "ok") {
              onDone(`Approved. Run ${r.value.command} again before ${new Date(r.value.until).toLocaleTimeString(undefined, { timeStyle: "short" })}.`);

              return null;
            }

            return r.kind === "error" ? r.message : "Sign in again.";
          }}
        />
      ) : (
        <p className="text-sm text-muted-foreground">Set up 2FA or a passkey below first.</p>
      )}
    </div>
  );
}

function AddPasskey({ account, config, onDone }: { account: Account; config: AuthConfig; onDone: (note: string | null) => void }) {
  const [asking, setAsking] = useState(false);

  async function add(proof: FactorProof | null): Promise<string | null> {
    const r = await authClient().passkey.addPasskey({ name: `apm ${new Date().toLocaleDateString()}`, fetchOptions: { headers: proofHeaders(proof) } });

    if (r?.error) return r.error.message ?? "The passkey was not added.";
    setAsking(false);
    onDone(null);

    return null;
  }

  if (!config.passkeys) return <p className="text-sm text-muted-foreground">Passkeys need HTTPS. This registry is served over plain HTTP, so use an authenticator app here.</p>;

  if (!hasFactor(account)) {
    return (
      <Button variant="outline" className="self-start" onClick={() => void add(null).then((m) => m && onDone(m))}>
        Add a passkey
      </Button>
    );
  }

  if (!asking) {
    return (
      <Button variant="outline" className="self-start" onClick={() => setAsking(true)}>
        Add a passkey
      </Button>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <p className="text-sm text-muted-foreground">Confirm it&apos;s you before adding another passkey.</p>
      <FactorPrompt account={account} config={config} action="Add passkey" busyLabel="Adding…" run={(p) => add(p)} />
    </div>
  );
}

function TurnOffTotp({ account, config, onDone }: { account: Account; config: AuthConfig; onDone: (note: string) => void }) {
  const [open, setOpen] = useState(false);

  if (!open) {
    return (
      <Button variant="ghost" className="-ml-2.5 self-start text-muted-foreground" onClick={() => setOpen(true)}>
        Turn off 2FA
      </Button>
    );
  }

  return (
    <div className="flex flex-col gap-2 rounded-xl bg-surface p-4">
      <p className="text-sm leading-6 text-muted-foreground">
        Turning off 2FA needs your current code, a recovery code or your passkey. {account.security.passkeys === 0 && "Without 2FA or a passkey you cannot approve publishes."}
      </p>
      <FactorPrompt
        account={account}
        config={config}
        action="Turn off 2FA"
        busyLabel="Turning off…"
        allowRecovery
        run={async (proof) => {
          const r = await authPost("two-factor/disable", {}, proof);

          if (!r.ok) return r.message;
          onDone("2FA is off. Set it up again to get new recovery codes.");

          return null;
        }}
      />
    </div>
  );
}

export function AccountView() {
  const [state, setState] = useState<State>({ kind: "loading" });
  const [note, setNote] = useState<string | null>(null);
  const [command, setCommand] = useState<LiveAction | null>(null);
  const [linking, setLinking] = useState<"github" | "vercel" | null>(null);
  // Recovery codes from a setup that just finished: shown until the person says they saved them.
  const [recovery, setRecovery] = useState<string[] | null>(null);

  const load = useCallback(async () => {
    const [a, c] = await Promise.all([call("account", Account), call("auth/config", AuthConfig)]);

    if (a.kind === "signed-out") return setState({ kind: "signed-out" });

    if (a.kind === "error") return setState({ kind: "error", message: a.message });

    if (c.kind !== "ok") return setState({ kind: "error", message: c.kind === "error" ? c.message : "Could not load sign-in options." });
    setState({ kind: "ok", account: a.value, config: c.value });
  }, []);

  useEffect(() => {
    setCommand(commandFromLink(window.location.search));
    void load();
  }, [load]);

  if (state.kind === "loading") return <div className="h-96 animate-pulse rounded-2xl bg-muted" />;

  if (state.kind === "signed-out") return <SignInPanel next={`/account${typeof window === "undefined" ? "" : window.location.search}`} />;

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

  const { account: a, config } = state;

  async function revoke(id: string) {
    const r = await call("account/tokens/revoke", z.object({ ok: z.boolean() }), { method: "POST", body: { id } });
    setNote(r.kind === "ok" ? "Token revoked. Anything using it stops working now." : r.kind === "error" ? r.message : "Sign in again.");
    await load();
  }

  async function link(p: "github" | "vercel", proof: FactorProof | null): Promise<string | null> {
    return linkProvider(p, "/account", proof);
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

      {command && (
        <ConfirmCommand
          command={command}
          account={a}
          config={config}
          onDone={(message) => {
            setNote(message);
            setCommand(null);
            window.history.replaceState(null, "", "/account");
          }}
        />
      )}

      <Section title="Your scope">
        {a.scope ? (
          <div className="flex flex-col gap-3">
            <p className="text-[15px] leading-7 text-muted-foreground">
              New packages you publish are named <code className="font-mono text-foreground">@{a.scope}/&lt;name&gt;</code>.{" "}
              {a.githubRenamed ? null : "Your scope is your GitHub login. "}
              <Link href="/publish" className="text-foreground underline underline-offset-4">
                Publish a package
              </Link>
            </p>
            {a.githubRenamed && a.github && (
              <p className="rounded-xl bg-surface px-4 py-3 text-[15px] leading-7 text-muted-foreground">
                Your GitHub login is now <code className="font-mono text-foreground">{a.github}</code>. Your scope stays <code className="font-mono text-foreground">@{a.scope}</code>: a scope is
                permanent once claimed, and a GitHub rename does not move or free it. To move your packages to <code className="font-mono text-foreground">@{a.github.toLowerCase()}</code>,{" "}
                <a href={NAME_DISPUTE_URL} className="text-foreground underline underline-offset-4">
                  open a name dispute
                </a>
                .
              </p>
            )}
          </div>
        ) : a.scopeTaken ? (
          <p className="text-[15px] leading-7 text-muted-foreground">
            Your GitHub login, <code className="font-mono text-foreground">{a.scopeTaken}</code>, is already someone&apos;s apm scope. Scopes are permanent once claimed, even after a GitHub rename, so
            it is not yours to publish under.{" "}
            <a href={NAME_DISPUTE_URL} className="text-foreground underline underline-offset-4">
              Open a name dispute
            </a>{" "}
            if it should be.
          </p>
        ) : (
          <div className="flex flex-col gap-3">
            <p className="text-[15px] leading-7 text-muted-foreground">You have no scope yet. Your scope is your GitHub login, so link GitHub before you publish.</p>
            {config.providers.github && (
              <Button className="self-start" onClick={() => (hasFactor(a) ? setLinking("github") : void link("github", null).then((m) => m && setNote(m)))}>
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
            {recovery !== null ? (
              <RecoveryCodes codes={recovery} onDone={() => setRecovery(null)} />
            ) : a.security.totp ? (
              <TurnOffTotp
                account={a}
                config={config}
                onDone={(m) => {
                  setNote(m);
                  void load();
                }}
              />
            ) : (
              <TotpSetup
                account={a}
                config={config}
                onEnabled={(codes) => {
                  setRecovery(codes);
                  void load();
                }}
              />
            )}
          </div>
          <div className="flex flex-col gap-3">
            <div className="flex items-center gap-3">
              <span className="text-[15px] font-medium">Passkeys</span>
              <Status on={a.security.passkeys > 0}>{a.security.passkeys === 0 ? "None" : `${a.security.passkeys} set up`}</Status>
            </div>
            <AddPasskey
              account={a}
              config={config}
              onDone={(m) => {
                setNote(m);
                void load();
              }}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <span className="text-[15px] font-medium">Commands from your terminal</span>
            <p className="text-sm leading-6 text-muted-foreground">
              Revoke, restore, incident response and owner changes ask for <code className="font-mono">--otp</code>. Without it, the command prints a link to this page that approves that one command,
              once.
            </p>
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
        {linkable.length > 0 && linking === null && (
          <div className="flex flex-wrap gap-2">
            {linkable.map((p) => (
              <Button key={p} variant="outline" onClick={() => (hasFactor(a) ? setLinking(p) : void link(p, null).then((m) => m && setNote(m)))}>
                Link {PROVIDER_LABEL[p]}
              </Button>
            ))}
          </div>
        )}
        {linking !== null && (
          <div className="flex flex-col gap-2">
            <p className="text-sm text-muted-foreground">Confirm it&apos;s you before linking {PROVIDER_LABEL[linking]}: it becomes another way to sign in.</p>
            <FactorPrompt account={a} config={config} action={`Link ${PROVIDER_LABEL[linking]}`} busyLabel="Opening…" run={(p) => link(linking, p)} />
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
