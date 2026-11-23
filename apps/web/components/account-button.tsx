"use client";

import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { Menu } from "@base-ui/react/menu";
import { Account, call } from "@/lib/account";

const MENU = [
  { href: "/account/packages", label: "Your packages" },
  { href: "/publish", label: "Publish" },
  { href: "/account", label: "Account and security" },
] as const;

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
      // Plain anchor so entering /signin from a tracked public page is a direct user-activated full navigation
      <a
        href={`/signin${next}`}
        className="inline-flex h-9 items-center rounded-full bg-primary px-4 text-[15px] font-medium text-primary-foreground transition-colors hover:bg-primary/85"
      >
        Sign in
      </a>
    );
  }

  const a = state.account;
  const label = a.scope ? `@${a.scope}` : a.name || "Account";

  return (
    <Menu.Root>
      <Menu.Trigger
        aria-label={`Your account, ${label}${a.pending > 0 ? `, ${a.pending} waiting for approval` : ""}`}
        className="inline-flex h-9 max-w-[180px] items-center gap-2 rounded-full bg-secondary p-1 text-[15px] font-medium transition-colors outline-none hover:bg-muted focus-visible:ring-3 focus-visible:ring-ring/50 data-[popup-open]:bg-muted sm:pr-3.5"
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
      </Menu.Trigger>
      <Menu.Portal>
        <Menu.Positioner side="bottom" align="end" sideOffset={8} className="isolate z-50 outline-none">
          <Menu.Popup className="flex min-w-52 origin-(--transform-origin) flex-col rounded-xl border bg-popover p-1 text-popover-foreground shadow-lg outline-none data-closed:animate-out data-closed:fade-out-0 motion-safe:data-closed:zoom-out-95 data-open:animate-in data-open:fade-in-0 motion-safe:data-open:zoom-in-95">
            {MENU.map((item) => (
              <Menu.LinkItem
                key={item.href}
                closeOnClick
                render={<a href={item.href} />}
                aria-current={pathname === item.href ? "page" : undefined}
                className="flex h-9 items-center justify-between gap-4 rounded-lg px-2.5 text-[14px] outline-none data-highlighted:bg-muted"
              >
                {item.label}
                {item.href === "/publish" && a.pending > 0 && <span className="rounded-full bg-warn-soft px-1.5 font-mono text-xs text-warn tabular-nums">{a.pending} waiting</span>}
              </Menu.LinkItem>
            ))}
          </Menu.Popup>
        </Menu.Positioner>
      </Menu.Portal>
    </Menu.Root>
  );
}
