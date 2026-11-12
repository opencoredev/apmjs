"use client";

// The control apm's reviewers (APM_ADMINS) get next to each piece of score evidence: dismiss it with a reason, or
// undo a dismissal. Everyone else sees nothing: the provider asks the registry once whether this website session
// belongs to a reviewer. Each action needs a fresh code from the authenticator app, or a passkey check, and the
// registry checks it again; this only decides what to show.
import { useRouter } from "next/navigation";
import { createContext, useContext, useEffect, useState } from "react";
import { z } from "zod";
import { authClient, call } from "@/lib/account";

/** What names one evidence item: the version's tarball digest, the scorer that cited it, the signal, file and line. */
export type EvidenceItem = { name: string; version: string; digest: string; scorer: string; signal: string; file: string; line: number };

const AdminContext = createContext(false);

export function EvidenceAdminProvider({ children }: { children: React.ReactNode }) {
  const [admin, setAdmin] = useState(false);

  useEffect(() => {
    let live = true;

    void call("evidence-admin/me", z.object({ admin: z.boolean() })).then((r) => {
      if (live && r.kind === "ok") setAdmin(r.value.admin);
    });

    return () => {
      live = false;
    };
  }, []);

  return <AdminContext value={admin}>{children}</AdminContext>;
}

type Factor = { kind: "code"; code: string } | { kind: "passkey" } | { kind: "error"; message: string };

const field = "h-9 min-w-0 rounded-md border border-inverse-border bg-inverse px-2.5 text-[13px] text-inverse-foreground placeholder:text-inverse-muted focus-visible:outline-2 focus-visible:outline-inverse-foreground";
const action = "inline-flex h-9 items-center rounded-md px-3 text-[13px] font-medium disabled:opacity-60";

type ControlProps = { item: EvidenceItem; mode: "dismiss" | "restore" };

/** "Dismiss" under a live item, "Undo" under a dismissed one; only for a reviewer, nothing for anyone else. */
export function EvidenceAdminControl(props: ControlProps) {
  return useContext(AdminContext) ? <AdminControl {...props} /> : null;
}

function AdminControl({ item, mode }: ControlProps) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [code, setCode] = useState("");
  const [usePasskey, setUsePasskey] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!open) {
    return (
      <button type="button" className="mt-1 font-sans text-[13px] text-inverse-muted underline underline-offset-4 hover:text-inverse-foreground" onClick={() => setOpen(true)}>
        {mode === "dismiss" ? "Dismiss this evidence" : "Undo dismissal"}
      </button>
    );
  }

  async function factor(): Promise<Factor> {
    if (!usePasskey) return /^\d{6}$/.test(code) ? { kind: "code", code } : { kind: "error", message: "Enter the 6-digit code from your authenticator app." };
    const p = await authClient().signIn.passkey();

    return p.error ? { kind: "error", message: p.error.message ?? "The passkey check did not finish." } : { kind: "passkey" };
  }

  async function submit() {
    if (mode === "dismiss" && reason.trim() === "") return setError("Say why this evidence is wrong; the reason is shown in public.");
    setBusy(true);
    setError(null);
    const f = await factor();

    if (f.kind === "error") {
      setBusy(false);

      return setError(f.message);
    }

    const proof = f.kind === "code" ? { code: f.code } : { passkey: true };
    const body = mode === "dismiss" ? { ...item, reason: reason.trim(), ...proof } : { ...item, ...proof };
    const r = await call(`evidence-admin/${mode}`, z.object({ ok: z.boolean() }), { method: "POST", body });

    setBusy(false);
    setCode("");

    if (r.kind === "ok") {
      setOpen(false);

      return router.refresh();
    }

    setError(r.kind === "error" ? r.message : "Sign in again.");
  }

  return (
    <div className="mt-2 flex flex-col gap-2 rounded-lg border border-inverse-border p-3 font-sans">
      <div className="flex flex-wrap items-center gap-2">
        {mode === "dismiss" && (
          <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why it is wrong (shown in public)" aria-label="Reason, shown in public" className={`${field} flex-1 basis-56`} />
        )}
        {!usePasskey && (
          <input
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
            inputMode="numeric"
            autoComplete="one-time-code"
            spellCheck={false}
            placeholder="2FA code"
            aria-label="Code from your authenticator app"
            className={`${field} w-28 font-mono tracking-widest`}
          />
        )}
        <button type="button" disabled={busy} onClick={() => void submit()} className={`${action} bg-inverse-foreground text-inverse`}>
          {busy ? "Saving…" : mode === "dismiss" ? "Dismiss" : "Undo"}
        </button>
        <button type="button" disabled={busy} onClick={() => setOpen(false)} className={`${action} text-inverse-muted hover:text-inverse-foreground`}>
          Cancel
        </button>
      </div>
      <button
        type="button"
        className="self-start text-[13px] text-inverse-muted underline underline-offset-4 hover:text-inverse-foreground"
        onClick={() => {
          setUsePasskey(!usePasskey);
          setError(null);
        }}
      >
        {usePasskey ? "Use a code from your authenticator app instead" : "Use your passkey instead"}
      </button>
      {error && (
        <p role="alert" className="text-[13px] text-inverse-bad">
          {error}
        </p>
      )}
    </div>
  );
}
