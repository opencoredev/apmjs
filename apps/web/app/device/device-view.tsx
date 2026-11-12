"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SignInPanel } from "@/components/sign-in-panel";
import { Account, authPost, call } from "@/lib/account";

type State =
  | { kind: "loading" }
  | { kind: "signed-out" }
  | { kind: "enter" }
  | { kind: "confirm"; code: string; account: Account }
  | { kind: "done"; approved: boolean }
  | { kind: "error"; message: string };

const DeviceInfo = z.object({ user_code: z.string(), status: z.string() });

function clean(code: string): string {
  return code.toUpperCase().replace(/[^A-Z0-9]/g, "");
}

function pretty(code: string): string {
  return code.length === 8 ? `${code.slice(0, 4)}-${code.slice(4)}` : code;
}

export function DeviceView() {
  const params = useSearchParams();
  const fromUrl = clean(params.get("code") ?? params.get("user_code") ?? "");
  const [state, setState] = useState<State>({ kind: "loading" });
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);

  async function open(code: string) {
    const a = await call("account", Account);

    if (a.kind === "signed-out") return setState({ kind: "signed-out" });

    if (a.kind === "error") return setState({ kind: "error", message: a.message });
    // Opening the code while signed in ties it to this browser's session.
    const res = await fetch(`/api/auth/device?user_code=${encodeURIComponent(code)}`, { credentials: "same-origin" });
    const info = DeviceInfo.safeParse(await res.json().catch(() => null));

    if (!res.ok || !info.success) return setState({ kind: "error", message: "That code is not valid or has expired. Run apm login again for a new one." });

    if (info.data.status !== "pending") return setState({ kind: "error", message: "That code was already used. Run apm login again for a new one." });
    setState({ kind: "confirm", code, account: a.value });
  }

  useEffect(() => {
    if (fromUrl) void open(fromUrl);
    else
      void call("account", Account).then((a) => setState(a.kind === "signed-out" ? { kind: "signed-out" } : { kind: "enter" }));
    // eslint-disable-next-line react-hooks/exhaustive-deps -- run once for the code in the URL
  }, [fromUrl]);

  async function decide(approve: boolean) {
    if (state.kind !== "confirm") return;
    setBusy(true);
    const r = await authPost(approve ? "device/approve" : "device/deny", { userCode: state.code });
    setBusy(false);

    if (!r.ok) return setState({ kind: "error", message: r.message });
    setState({ kind: "done", approved: approve });
  }

  const back = `/device${fromUrl ? `?code=${fromUrl}` : ""}`;

  if (state.kind === "loading") return <div className="h-64 w-full max-w-md animate-pulse rounded-2xl bg-muted" />;

  if (state.kind === "signed-out") {
    return (
      <SignInPanel next={back} title="Sign in to log in the CLI">
        <p className="text-[15px] leading-6 text-muted-foreground">
          {fromUrl ? (
            <>
              Your terminal is waiting for the code <span className="font-mono text-foreground">{pretty(fromUrl)}</span>. Sign in, then approve it.
            </>
          ) : (
            "Sign in, then enter the code your terminal shows."
          )}
        </p>
      </SignInPanel>
    );
  }

  return (
    <section className="flex w-full max-w-md flex-col gap-5 rounded-2xl border p-6 sm:p-8">
      {state.kind === "enter" && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const c = clean(typed);

            if (c.length >= 6) {
              setState({ kind: "loading" });
              void open(c);
            }
          }}
          className="flex flex-col gap-4"
        >
          <h1 className="text-2xl font-medium tracking-tight">Log in the apm CLI</h1>
          <label className="flex flex-col gap-1.5 text-sm text-muted-foreground">
            Code from your terminal
            <Input value={typed} onChange={(e) => setTyped(e.target.value)} placeholder="ABCD-EFGH" autoComplete="off" className="h-11 font-mono text-lg tracking-widest uppercase" />
          </label>
          <Button type="submit" size="lg" className="h-10">
            Continue
          </Button>
        </form>
      )}
      {state.kind === "confirm" && (
        <>
          <div className="flex flex-col gap-2">
            <h1 className="text-2xl font-medium tracking-tight">Log in the apm CLI?</h1>
            <p className="text-[15px] leading-6 text-muted-foreground">Check that your terminal shows this code. Only approve a login you started.</p>
          </div>
          <div className="rounded-xl bg-surface py-4 text-center font-mono text-3xl tracking-[0.2em]">{pretty(state.code)}</div>
          {state.account.scope ? (
            <p className="text-[15px] leading-6 text-muted-foreground">
              The CLI gets a token for <span className="font-mono text-foreground">@{state.account.scope}</span>. It can install and upload versions, and every upload waits for you to approve it here.
            </p>
          ) : (
            <p className="rounded-lg bg-warn-soft px-4 py-3 text-sm text-warn">
              This account has no GitHub link yet, so the login will not get a token.{" "}
              <Link href="/account" className="underline underline-offset-4">
                Link GitHub first
              </Link>
              .
            </p>
          )}
          <div className="flex gap-2">
            <Button size="lg" className="h-10 flex-1" disabled={busy} onClick={() => void decide(true)}>
              Approve
            </Button>
            <Button size="lg" variant="outline" className="h-10 flex-1" disabled={busy} onClick={() => void decide(false)}>
              Deny
            </Button>
          </div>
        </>
      )}
      {state.kind === "done" && (
        <div className="flex flex-col gap-2">
          <h1 className="text-2xl font-medium tracking-tight">{state.approved ? "Done. Go back to your terminal." : "Login denied."}</h1>
          <p className="text-[15px] text-muted-foreground">{state.approved ? "apm login finishes on its own in a few seconds. You can close this tab." : "The terminal gets no token."}</p>
        </div>
      )}
      {state.kind === "error" && (
        <div className="flex flex-col gap-2">
          <h1 className="text-2xl font-medium tracking-tight">Could not log in the CLI</h1>
          <p className="text-[15px] text-muted-foreground">{state.message}</p>
        </div>
      )}
    </section>
  );
}
