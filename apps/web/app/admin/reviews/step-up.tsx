"use client";

// One second factor for one named change: a 6-digit code from an authenticator app, or a passkey check made for exactly
// that change (lib/account.ts passkeyConfirmation). The queue uses it to open the decision window and to flip the switch.
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { passkeyConfirmation, type SessionAction } from "@/lib/account";

export type Proof = { code: string } | { confirmation: string };

export function StepUp({
  action,
  submitLabel,
  busyLabel,
  variant = "default",
  onProof,
  onCancel,
}: {
  action: SessionAction;
  submitLabel: string;
  busyLabel: string;
  variant?: "default" | "destructive" | "outline";
  /** Sends the change with this proof; resolves to an error to show, or null when it went through. */
  onProof: (proof: Proof) => Promise<string | null>;
  onCancel?: () => void;
}) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function send(proof: Proof) {
    setBusy(true);
    setError(null);
    const failed = await onProof(proof);

    setBusy(false);
    setCode("");

    if (failed !== null) setError(failed);
  }

  async function withPasskey() {
    setBusy(true);
    setError(null);
    const p = await passkeyConfirmation(action);

    if (p.kind === "error") {
      setBusy(false);

      return setError(p.message);
    }

    await send({ confirmation: p.id });
  }

  return (
    <div className="flex flex-col gap-2">
      <form
        className="flex flex-wrap items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault();

          if (!/^\d{6}$/.test(code)) return setError("Enter the 6-digit code from your authenticator app.");
          void send({ code });
        }}
      >
        <Input
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
          inputMode="numeric"
          autoComplete="one-time-code"
          spellCheck={false}
          placeholder="6-digit code"
          aria-label="Code from your authenticator app"
          className="h-9 w-36 font-mono tracking-wider"
        />
        <Button type="submit" size="lg" variant={variant} disabled={busy}>
          {busy ? busyLabel : submitLabel}
        </Button>
        <Button type="button" size="lg" variant="ghost" disabled={busy} onClick={() => void withPasskey()}>
          Use passkey
        </Button>
        {onCancel && (
          <Button type="button" size="lg" variant="ghost" disabled={busy} onClick={onCancel}>
            Cancel
          </Button>
        )}
      </form>
      {error && (
        <p role="alert" className="text-sm text-bad">
          {error}
        </p>
      )}
    </div>
  );
}
