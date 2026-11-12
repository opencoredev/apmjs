"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { AuthConfig, call, signIn, PROVIDER_LABEL } from "@/lib/account";

function GitHubMark() {
  return (
    <svg viewBox="0 0 16 16" aria-hidden className="size-4 fill-current">
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
    </svg>
  );
}

function VercelMark() {
  return (
    <svg viewBox="0 0 16 16" aria-hidden className="size-3.5 fill-current">
      <path d="M8 1L16 15H0L8 1Z" />
    </svg>
  );
}

/** GitHub and Vercel buttons, each shown only when the registry has that OAuth app configured. */
export function SignInPanel({ next, title = "Sign in to apm", children }: { next: string; title?: string; children?: React.ReactNode }) {
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const [busy, setBusy] = useState<"github" | "vercel" | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void call("auth/config", AuthConfig).then((r) => {
      if (r.kind === "ok") setConfig(r.value);
      else setError(r.kind === "error" ? r.message : "Could not load sign-in options.");
    });
  }, []);

  async function go(provider: "github" | "vercel") {
    setBusy(provider);
    setError(null);
    const failed = await signIn(provider, next);

    if (failed) {
      setError(failed);
      setBusy(null);
    }
  }

  const providers = config ? (["github", "vercel"] as const).filter((p) => config.providers[p]) : [];

  return (
    <section className="flex max-w-md flex-col gap-5 rounded-2xl border p-6 sm:p-8">
      <div className="flex flex-col gap-2">
        <h1 className="text-2xl font-medium tracking-tight">{title}</h1>
        {children ?? (
          <p className="text-[15px] leading-6 text-muted-foreground">
            Your apm scope is your GitHub login. You can sign in with Vercel, but you need to link GitHub before you can publish.
          </p>
        )}
      </div>
      <div className="flex flex-col gap-2.5">
        {config === null && error === null && <div className="h-10 animate-pulse rounded-lg bg-muted" />}
        {providers.map((p) => (
          <Button key={p} size="lg" variant={p === "github" ? "default" : "outline"} className="h-10 text-[15px]" disabled={busy !== null} onClick={() => void go(p)}>
            {p === "github" ? <GitHubMark /> : <VercelMark />}
            {busy === p ? "Opening…" : `Continue with ${PROVIDER_LABEL[p]}`}
          </Button>
        ))}
        {config !== null && providers.length === 0 && (
          <p className="rounded-lg bg-surface px-4 py-3 text-sm leading-6 text-muted-foreground">
            Sign-in is not set up on this registry yet: no GitHub or Vercel OAuth app is configured.
          </p>
        )}
      </div>
      {error && (
        <p role="alert" className="text-sm text-bad">
          {error}
        </p>
      )}
    </section>
  );
}
