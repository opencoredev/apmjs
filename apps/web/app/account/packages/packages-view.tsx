"use client";

// "Your packages": everything the signed-in person publishes (their scope and anything they own), each with its latest
// version, score, last publish and any version waiting for their approval. Scores render as the registry sends them.
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { ArrowRightIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ScoreBadge, StatusBadge } from "@/components/score-badge";
import { SignInPanel } from "@/components/sign-in-panel";
import { call, MyPackages, timeLeft, type MyPackage, type PendingVersion } from "@/lib/account";
import { ago } from "@/lib/format";

type State = { kind: "loading" } | { kind: "signed-out" } | { kind: "error"; message: string } | { kind: "ok"; packages: MyPackage[] };

/** A link to one waiting version's approval page, above the row's own link. */
function WaitingChip({ pending }: { pending: PendingVersion }) {
  return (
    <Link
      href={`/approve/${pending.id}`}
      className="relative z-10 inline-flex h-7 items-center gap-1 rounded-lg bg-warn-soft px-2 text-[13px] font-medium text-warn transition-colors hover:bg-warn-soft/70"
      title={`Approve within ${timeLeft(pending.expiresAt)}`}
    >
      <span className="font-mono">{pending.version}</span> waiting
      <ArrowRightIcon className="size-3.5" aria-hidden />
    </Link>
  );
}

export function PackageRow({ pkg }: { pkg: MyPackage }) {
  const [firstPending] = pkg.pending;
  // a name with no approved version has no package page yet: its row opens the approval instead
  const href = pkg.latest ? `/package/${pkg.name}` : firstPending ? `/approve/${firstPending.id}` : `/package/${pkg.name}`;

  return (
    <li className="relative flex flex-col gap-2 px-4 py-3.5 transition-colors hover:bg-muted/40 sm:flex-row sm:items-center sm:gap-4">
      <div className="flex min-w-0 flex-1 flex-col gap-0.5">
        <Link href={href} className="min-w-0 font-mono text-[15px] font-medium [overflow-wrap:anywhere] after:absolute after:inset-0">
          {pkg.name}
        </Link>
        <span className="text-[13px] text-muted-foreground tabular-nums">
          {pkg.latest ? (
            <>
              <span className="font-mono">{pkg.latest.version}</span>
              {pkg.lastPublishedAt && <> · published {ago(pkg.lastPublishedAt)}</>}
            </>
          ) : (
            "Not live yet: its first version is waiting for you"
          )}
        </span>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {pkg.pending.map((p) => (
          <WaitingChip key={p.id} pending={p} />
        ))}
        {pkg.latest && <StatusBadge status={pkg.latest.status} />}
        {pkg.latest && <ScoreBadge score={pkg.score?.score} grade={pkg.score?.grade} />}
      </div>
    </li>
  );
}

export function PackagesView() {
  const [state, setState] = useState<State>({ kind: "loading" });

  const load = useCallback(async () => {
    const r = await call("account/packages", MyPackages);

    if (r.kind === "signed-out") return setState({ kind: "signed-out" });

    setState(r.kind === "ok" ? { kind: "ok", packages: r.value.packages } : { kind: "error", message: r.message });
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (state.kind === "loading") return <div className="h-72 max-w-3xl animate-pulse rounded-2xl bg-muted" aria-label="Loading your packages" />;

  if (state.kind === "signed-out") {
    return (
      <SignInPanel next="/account/packages" title="Sign in to see your packages">
        <p className="text-[15px] leading-6 text-muted-foreground">Every package under your scope, and every one you own, with its latest version and score.</p>
      </SignInPanel>
    );
  }

  if (state.kind === "error") {
    return (
      <div className="flex max-w-xl flex-col items-start gap-3">
        <p role="alert" className="text-bad">
          Could not load your packages. {state.message}
        </p>
        <Button variant="outline" onClick={() => void load()}>
          Try again
        </Button>
      </div>
    );
  }

  const { packages } = state;
  const waiting = packages.reduce((n, p) => n + p.pending.length, 0);

  return (
    <div className="flex max-w-3xl flex-col gap-8">
      <header className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
        <div className="flex flex-col gap-2">
          <h1 className="text-[34px] leading-tight font-medium tracking-[-0.02em]">Your packages</h1>
          {packages.length > 0 && (
            <p className="text-[15px] text-muted-foreground tabular-nums">
              {packages.length === 1 ? "1 package" : `${packages.length} packages`}
              {waiting > 0 && <span className="text-warn"> · {waiting === 1 ? "1 version waiting for approval" : `${waiting} versions waiting for approval`}</span>}
            </p>
          )}
        </div>
        {packages.length > 0 && (
          <Link href="/publish" className="inline-flex items-center gap-1 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground">
            Publish another
            <ArrowRightIcon className="size-3.5" aria-hidden />
          </Link>
        )}
      </header>

      {packages.length === 0 ? (
        <div className="flex flex-col items-start gap-4 rounded-xl border border-dashed px-5 py-8">
          <div className="flex flex-col gap-1">
            <p className="text-[15px] font-medium">You have not published anything yet</p>
            <p className="text-[13px] leading-5 text-muted-foreground">Packages under your scope, and packages you own, show up here once you publish one.</p>
          </div>
          <Link href="/publish" className="inline-flex h-9 items-center rounded-lg bg-primary px-3 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/80">
            Publish a package
          </Link>
        </div>
      ) : (
        <ul className="flex flex-col divide-y overflow-hidden rounded-xl border">
          {packages.map((p) => (
            <PackageRow key={p.name} pkg={p} />
          ))}
        </ul>
      )}
    </div>
  );
}
