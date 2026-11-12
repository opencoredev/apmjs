"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { Account, call } from "@/lib/account";

type State = { kind: "loading" } | { kind: "signed-out" } | { kind: "signed-in"; account: Account };

/** The header's sign-in control: "Sign in" when signed out, your scope (and pending approvals) when signed in. */
export function AccountButton() {
  const pathname = usePathname();
  const [state, setState] = useState<State>({ kind: "loading" });

  useEffect(() => {
    let live = true;
    void call("account", Account).then((r) => {
      if (!live) return;
      setState(r.kind === "ok" ? { kind: "signed-in", account: r.value } : { kind: "signed-out" });
    });
    return () => {
      live = false;
    };
  }, [pathname]);

  if (state.kind === "loading") return <span className="inline-block h-9 w-[76px]" aria-hidden />;
  if (state.kind === "signed-out") {
    const next = pathname && pathname !== "/signin" ? `?next=${encodeURIComponent(pathname)}` : "";
    return (
      <Link
        href={`/signin${next}`}
        className="inline-flex h-9 items-center rounded-full bg-primary px-4 text-[15px] font-medium text-primary-foreground transition-colors hover:bg-primary/85"
      >
        Sign in
      </Link>
    );
  }
  const a = state.account;
  const label = a.scope ? `@${a.scope}` : a.name || "Account";
  return (
    <Link
      href="/account"
      aria-current={pathname === "/account" ? "page" : undefined}
      aria-label={`Your account, ${label}${a.pending > 0 ? `, ${a.pending} waiting for approval` : ""}`}
      className="inline-flex h-9 max-w-[180px] items-center gap-2 rounded-full bg-secondary p-1 text-[15px] font-medium transition-colors hover:bg-muted sm:pr-3.5"
    >
      {a.image ? (
        // eslint-disable-next-line @next/next/no-img-element -- avatars come from GitHub/Vercel hosts
        <img src={a.image} alt="" className="size-7 rounded-full bg-muted" />
      ) : (
        <span className="grid size-7 place-items-center rounded-full bg-muted text-xs uppercase">{label.replace("@", "").slice(0, 1)}</span>
      )}
      <span className="hidden truncate sm:inline">{label}</span>
      {a.pending > 0 && (
        <span className="mr-1 rounded-full bg-warn-soft px-1.5 font-mono text-xs text-warn tabular-nums sm:mr-0" title={`${a.pending} version${a.pending === 1 ? "" : "s"} waiting for your approval`}>
          {a.pending}
        </span>
      )}
    </Link>
  );
}
