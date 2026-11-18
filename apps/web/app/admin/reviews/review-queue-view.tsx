"use client";

// The AI review queue for apm's reviewers (APM_ADMINS): every flag a person has not decided, as a triage list.
//
// Direction: Linear's triage inbox (one dense line per item, j/k to move, open in place) and GitHub's notification list
// (select, then act on the selection). The site's own tokens: muted text for facts, warn for "suspicious", bad for
// "malicious" and confirming. The switch sits on top with its consequence spelled out, because it changes what every
// agent is told. No card per item, no form per item: the decision controls live in the one row that is open.
//
// One factor (code or passkey) unlocks decisions for this session for a few minutes (the registry's decision window);
// the switch always asks again. Findings arrive redacted from the registry and are masked again in FindingList.
import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ChevronRightIcon, LockIcon, LockOpenIcon } from "lucide-react";
import { z } from "zod";
import { FindingList } from "@/components/finding-list";
import { SignInPanel } from "@/components/sign-in-panel";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { call } from "@/lib/account";
import { ago } from "@/lib/format";
import { packagePath } from "@/lib/package-route";
import { BULK_LIMIT, dismissInBatches, itemKey, moveFocus, Queue, verdictOf, windowLeft, type BatchAnswer, type QueueItem, type SwitchState } from "@/lib/review-queue";
import { coverageText, notReadText } from "@/lib/review-schema";
import { compactCount } from "@/lib/review-status";
import { StepUp } from "./step-up";

type State = { kind: "loading" } | { kind: "signed-out" } | { kind: "error"; message: string } | { kind: "ok"; queue: Queue };

const Ok = z.object({ ok: z.boolean() });

const errorOf = (r: Awaited<ReturnType<typeof call>>): string | null => (r.kind === "ok" ? null : r.kind === "error" ? r.message : "Sign in again.");

const TONE = { bad: "bg-bad-soft text-bad", warn: "bg-warn-soft text-warn", muted: "bg-surface text-muted-foreground" } as const;

function VerdictChip({ item }: { item: QueueItem }) {
  const v = verdictOf(item);

  return <span className={`inline-flex h-6 items-center rounded-md px-1.5 text-[12.5px] font-medium whitespace-nowrap ${TONE[v.tone]}`}>{v.label}</span>;
}

/** The current second: re-renders a countdown once a second while `on`. */
function useNow(on: boolean): number {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (!on) return;
    const t = setInterval(() => setNow(Date.now()), 1000);

    return () => clearInterval(t);
  }, [on]);

  return now;
}

// ---------- the switch ----------
function SwitchPanel({ state, waiting, onChanged }: { state: SwitchState; waiting: number; onChanged: () => void }) {
  const [open, setOpen] = useState(false);
  const next = !state.hold;
  const who = state.source === "set" && state.changedBy ? `Set ${state.hold ? "on" : "off"} by ${state.changedBy}${state.changedAt ? `, ${ago(state.changedAt)}` : ""}.` : `The deploy's default (${state.defaultHold ? "on" : "off"}); nobody has changed it.`;

  return (
    <section aria-labelledby="switch" className={`flex flex-col gap-3 rounded-xl border px-4 py-4 sm:px-5 ${state.hold ? "" : "border-warn/40 bg-warn-soft/40"}`}>
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
        <div className="flex max-w-xl min-w-0 flex-col gap-1">
          <h2 id="switch" className="flex items-center gap-2 text-[17px] font-medium">
            AI flags hold installs
            <span className={`inline-flex h-6 items-center rounded-md px-1.5 text-[12.5px] font-semibold ${state.hold ? "bg-foreground text-background" : "bg-warn text-background"}`}>{state.hold ? "ON" : "OFF"}</span>
          </h2>
          <p className="text-[15px] leading-6 text-pretty text-muted-foreground">
            {state.hold
              ? `A flagged version is review-first for agents until someone here decides. ${waiting === 0 ? "Nothing is held now." : `${waiting} ${waiting === 1 ? "version is" : "versions are"} held now.`}`
              : "Flags are a note only: agents are told an AI review flagged the version and a person has not looked yet, and they install it."}{" "}
            Confirmed-malicious versions stay blocked either way.
          </p>
          <p className="text-[13px] text-muted-foreground">{who}</p>
        </div>
        {!open && (
          <Button size="lg" variant={state.hold ? "outline" : "default"} onClick={() => setOpen(true)}>
            {state.hold ? "Turn off" : "Turn on"}
          </Button>
        )}
      </div>
      {open && (
        <div className="flex flex-col gap-2 border-t pt-3">
          <p className="text-sm leading-6 text-pretty">
            {next
              ? "Turning it on makes every open flag review-first again on the next request."
              : `Turning it off takes effect on the next request: ${waiting === 1 ? "the 1 flagged version" : `all ${waiting} flagged versions`} stop holding installs. Confirm it's you.`}
          </p>
          <StepUp
            action={{ kind: "review-switch", hold: next }}
            submitLabel={next ? "Turn on" : "Turn off"}
            busyLabel="Saving…"
            onCancel={() => setOpen(false)}
            onProof={async (proof) => {
              const failed = errorOf(await call("review-admin/switch", Ok, { method: "POST", body: { hold: next, ...proof } }));

              if (failed === null) {
                setOpen(false);
                onChanged();
              }

              return failed;
            }}
          />
        </div>
      )}
    </section>
  );
}

// ---------- the decision window ----------
function UnlockBar({ until, windowMs, onChanged }: { until: string | null; windowMs: number; onChanged: () => void }) {
  const now = useNow(until !== null);
  const left = windowLeft(until, now);
  const minutes = Math.round(windowMs / 60_000);

  if (left !== null) {
    return (
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl bg-surface px-4 py-2.5 text-sm">
        <span className="flex items-center gap-2">
          <LockOpenIcon className="size-4 text-muted-foreground" aria-hidden />
          Decisions unlocked for this session · <span className="font-mono tabular-nums">{left}</span> left
        </span>
        <Button size="sm" variant="ghost" onClick={() => void call("review-admin/lock", Ok, { method: "POST", body: {} }).then(onChanged)}>
          Lock now
        </Button>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2 rounded-xl bg-surface px-4 py-3">
      <p className="flex items-center gap-2 text-sm">
        <LockIcon className="size-4 text-muted-foreground" aria-hidden />
        Decisions are locked. Confirm it&apos;s you once to confirm and dismiss for {minutes} minutes in this browser session.
      </p>
      <StepUp
        action={{ kind: "review-unlock" }}
        submitLabel={`Unlock for ${minutes} minutes`}
        busyLabel="Unlocking…"
        variant="outline"
        onProof={async (proof) => {
          const failed = errorOf(await call("review-admin/unlock", z.object({ ok: z.boolean(), until: z.string() }), { method: "POST", body: proof }));

          if (failed === null) onChanged();

          return failed;
        }}
      />
    </div>
  );
}

// ---------- one open row ----------
function Details({ item, unlocked, onDone }: { item: QueueItem; unlocked: boolean; onDone: () => void }) {
  const [note, setNote] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState<"confirm" | "dismiss" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const files = item.private.notRead.flatMap((n) => (n.kind === "file" ? [notReadText(n)] : []));
  const noteId = `note-${itemKey(item)}`;

  async function decide(decision: "confirm" | "dismiss") {
    setBusy(decision);
    setError(null);
    const failed = errorOf(await call("review-admin/decide", Ok, { method: "POST", body: { name: item.name, version: item.version, digest: item.digest, decision, note: note.trim() } }));

    setBusy(null);

    if (failed === null) return onDone();
    setError(failed);
  }

  return (
    <div className="flex flex-col gap-4 border-t bg-surface/40 px-4 py-4 sm:pl-13">
      {item.private.summary && (
        <p className="text-[15px] leading-6 text-pretty">
          <span className="text-muted-foreground">Model&apos;s summary: </span>
          {item.private.summary}
        </p>
      )}
      {item.private.findings.length > 0 && <FindingList findings={item.private.findings} name={item.name} version={item.version} />}
      <p className="text-[13px] leading-5 text-pretty text-muted-foreground">
        {coverageText(item.public.coverage)}
        {item.public.coverage.previousVersion ? ` from ${item.public.coverage.previousVersion}` : ""} · {item.public.model} · answers: {item.private.attempts.map((a) => a.result).join(", ")}
        {files.length > 0 ? ` · not read: ${files.slice(0, 6).join(", ")}${files.length > 6 ? "…" : ""}` : ""} ·{" "}
        <Link href={`${packagePath(item.name)}?v=${encodeURIComponent(item.version)}`} className="text-foreground underline-offset-4 hover:underline">
          Package page
        </Link>
      </p>
      <div className="flex flex-col gap-2 border-t pt-4">
        <label htmlFor={noteId} className="text-sm font-medium">
          Public note <span className="font-normal text-muted-foreground">· shown on the package page next to your decision</span>
        </label>
        <Input id={noteId} value={note} onChange={(e) => setNote(e.target.value)} placeholder="e.g. Reordered alphabet, same 64 characters; not malicious." className="h-9" />
        {confirming ? (
          <div className="flex flex-col gap-2 rounded-lg border border-bad/30 bg-bad-soft/50 px-3 py-3">
            <p className="text-sm leading-6 text-pretty">
              Confirm <span className="font-mono">{item.name}@{item.version}</span> is malicious? It is blocked for everyone at once, and the findings and your note become public.
            </p>
            <div className="flex flex-wrap gap-2">
              <Button size="lg" variant="destructive" disabled={busy !== null} onClick={() => void decide("confirm")}>
                {busy === "confirm" ? "Confirming…" : "Confirm malicious"}
              </Button>
              <Button size="lg" variant="ghost" disabled={busy !== null} onClick={() => setConfirming(false)}>
                Cancel
              </Button>
            </div>
          </div>
        ) : (
          <div className="flex flex-wrap items-center gap-2">
            <Button size="lg" variant="outline" disabled={!unlocked || busy !== null} onClick={() => void decide("dismiss")}>
              {busy === "dismiss" ? "Dismissing…" : "Dismiss flag"}
            </Button>
            <Button size="lg" variant="destructive" disabled={!unlocked || busy !== null} onClick={() => setConfirming(true)}>
              Confirm malicious…
            </Button>
            {!unlocked && <span className="text-sm text-muted-foreground">Unlock decisions above first.</span>}
          </div>
        )}
        {error && (
          <p role="alert" className="text-sm text-bad">
            {error}
          </p>
        )}
      </div>
    </div>
  );
}

// ---------- bulk ----------
function BulkBar({ selected, unlocked, onClear, onDone }: { selected: QueueItem[]; unlocked: boolean; onClear: () => void; onDone: () => void }) {
  const [note, setNote] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const n = selected.length;

  async function dismiss() {
    setBusy(true);
    setError(null);

    // the route takes at most BULK_LIMIT flags a request: "Select all" on a long queue goes in several
    const r = await dismissInBatches({
      items: selected.map((i) => ({ name: i.name, version: i.version, digest: i.digest })),
      send: async (batch): Promise<BatchAnswer> => {
        const answer = await call("review-admin/dismiss", z.object({ ok: z.boolean(), dismissed: z.number() }), { method: "POST", body: { items: batch, note: note.trim() } });

        return answer.kind === "ok" ? { kind: "ok", dismissed: answer.value.dismissed } : { kind: "error", message: errorOf(answer) ?? "The registry did not answer." };
      },
    });

    setBusy(false);

    if (r.kind === "ok") {
      setConfirming(false);
      setNote("");

      return onDone();
    }

    setError(r.dismissed > 0 ? `Dismissed ${r.dismissed}, then stopped: ${r.message}` : r.message);

    // what went through leaves the list; the rest stays selected
    if (r.dismissed > 0) onDone();
  }

  return (
    <div className="sticky bottom-3 z-20 flex flex-col gap-2 rounded-xl border bg-background px-4 py-3 shadow-lg">
      {confirming ? (
        <>
          <p className="text-sm leading-6 text-pretty">
            Dismiss {n} {n === 1 ? "flag" : "flags"}? {n === 1 ? "It stops" : "They stop"} holding installs at once, and each package page says a person checked it
            {note.trim() ? ", with your note" : ""}.{n > BULK_LIMIT ? ` They go in ${Math.ceil(n / BULK_LIMIT)} batches of up to ${BULK_LIMIT}.` : ""}
          </p>
          <div className="flex flex-wrap gap-2">
            <Button size="lg" disabled={busy} onClick={() => void dismiss()}>
              {busy ? "Dismissing…" : `Dismiss ${n}`}
            </Button>
            <Button size="lg" variant="ghost" disabled={busy} onClick={() => setConfirming(false)}>
              Cancel
            </Button>
          </div>
        </>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium tabular-nums">{n} selected</span>
          <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Public note for all (optional)" aria-label="Public note, shown on each package page" className="h-9 min-w-0 flex-1 basis-56" />
          <Button size="lg" disabled={!unlocked} onClick={() => setConfirming(true)}>
            Dismiss selected
          </Button>
          <Button size="lg" variant="ghost" onClick={onClear}>
            Clear
          </Button>
        </div>
      )}
      {!unlocked && <p className="text-[13px] text-muted-foreground">Unlock decisions above to dismiss.</p>}
      {error && (
        <p role="alert" className="text-sm text-bad">
          {error}
        </p>
      )}
    </div>
  );
}

// ---------- the list ----------
function Row({
  item,
  index,
  open,
  selected,
  onToggle,
  onSelect,
  buttonRef,
}: {
  item: QueueItem;
  index: number;
  open: boolean;
  selected: boolean;
  onToggle: () => void;
  onSelect: (on: boolean) => void;
  buttonRef: (el: HTMLButtonElement | null) => void;
}) {
  const label = `${item.name}@${item.version}`;

  return (
    <div className="flex items-stretch">
      <label className="flex shrink-0 cursor-pointer items-center py-2.5 pr-1 pl-4">
        <input type="checkbox" checked={selected} onChange={(e) => onSelect(e.target.checked)} aria-label={`Select ${label}`} className="size-4 accent-foreground" />
      </label>
      <button
        ref={buttonRef}
        type="button"
        data-row={index}
        aria-expanded={open}
        onClick={onToggle}
        className="grid min-w-0 flex-1 grid-cols-[1rem_minmax(0,1fr)_auto] items-center gap-x-2 gap-y-0.5 py-2.5 pr-4 pl-2 text-left outline-none focus-visible:bg-muted sm:grid-cols-[1rem_minmax(0,15rem)_6.5rem_4.5rem_4.5rem_minmax(0,1fr)] sm:gap-x-3"
      >
        <ChevronRightIcon className={`size-4 text-muted-foreground transition-transform ${open ? "rotate-90" : ""}`} aria-hidden />
        <span className="truncate font-mono text-[14px] font-medium">{label}</span>
        <span className="justify-self-end sm:justify-self-start">
          <VerdictChip item={item} />
        </span>
        <span className="col-start-2 text-[13px] text-muted-foreground tabular-nums sm:col-start-auto sm:text-right">
          {item.weeklyDownloads === null ? "–" : `${compactCount(item.weeklyDownloads)}/wk`}
          <span className="sm:hidden"> · {ago(item.reviewedAt)}</span>
        </span>
        <span className="hidden text-right text-[13px] text-muted-foreground tabular-nums sm:block">
          <time dateTime={item.reviewedAt} suppressHydrationWarning>
            {ago(item.reviewedAt)}
          </time>
        </span>
        <span className="col-span-2 col-start-2 truncate text-[13.5px] text-muted-foreground sm:col-span-1 sm:col-start-auto">{item.summaryLine || "No summary"}</span>
      </button>
    </div>
  );
}

/** The decided reviews and every change of the switch, newest first: who did what, and when. */
function Decided({ decided, history }: { decided: QueueItem[]; history: SwitchState["history"] }) {
  type Line = { key: string; at: string; item: QueueItem | null; text: string };

  const lines: Line[] = [
    ...decided.map((i): Line => ({ key: `d:${itemKey(i)}`, at: i.public.decidedAt ?? i.reviewedAt, item: i, text: `${i.public.state === "confirmed" ? "confirmed" : "dismissed"} by ${i.decidedBy ?? "unknown"}` })),
    ...history.map((h, n): Line => ({ key: `s:${n}:${h.at}`, at: h.at, item: null, text: `AI flags hold installs turned ${h.hold ? "on" : "off"} by ${h.by}` })),
  ].sort((a, b) => b.at.localeCompare(a.at));

  if (lines.length === 0) return null;

  return (
    <section aria-labelledby="decided" className="flex flex-col gap-3">
      <h2 id="decided" className="text-lg font-medium tracking-tight">
        Decided
      </h2>
      <ul className="divide-y rounded-xl border">
        {lines.map((l) => (
          <li key={l.key} className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 px-4 py-2.5 text-[14px]">
            {l.item ? (
              <Link href={`${packagePath(l.item.name)}?v=${encodeURIComponent(l.item.version)}`} className="font-mono underline-offset-4 hover:underline">
                {l.item.name}@{l.item.version}
              </Link>
            ) : (
              <span className="font-medium">Switch</span>
            )}
            <span className="text-[13px] text-muted-foreground">
              {l.text}, {ago(l.at)}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function ReviewQueueView() {
  const [state, setState] = useState<State>({ kind: "loading" });
  const [open, setOpen] = useState<string | null>(null);
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const rows = useRef<(HTMLButtonElement | null)[]>([]);
  const focused = useRef(-1);

  const load = useCallback(async () => {
    const r = await call("review-admin/queue", Queue);

    if (r.kind === "ok") {
      setState({ kind: "ok", queue: r.value });
      // a decided item leaves the list: drop it from the selection, and close it if it was open
      const keys = new Set(r.value.pending.map(itemKey));

      setSelected((s) => new Set([...s].filter((k) => keys.has(k))));
      setOpen((o) => (o !== null && keys.has(o) ? o : null));
    } else if (r.kind === "signed-out") setState({ kind: "signed-out" });
    else setState({ kind: "error", message: r.message });
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const queue = state.kind === "ok" ? state.queue : null;
  const pending = useMemo(() => queue?.pending ?? [], [queue]);
  const now = useNow(queue?.unlockedUntil != null);
  const unlocked = windowLeft(queue?.unlockedUntil ?? null, now) !== null;
  const chosen = pending.filter((i) => selected.has(itemKey(i)));

  const toggleSelect = (key: string, on: boolean) => setSelected((s) => (on ? new Set([...s, key]) : new Set([...s].filter((k) => k !== key))));

  function onKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
    if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement || e.metaKey || e.ctrlKey || e.altKey) return;
    const at = rows.current.findIndex((el) => el === document.activeElement);
    const current = at >= 0 ? at : focused.current;
    const next = moveFocus({ key: e.key, at: current, count: pending.length });

    if (next !== null) {
      e.preventDefault();
      focused.current = next;
      rows.current[next]?.focus();

      return;
    }

    const item = current >= 0 ? pending[current] : undefined;

    if (!item) return;

    if (e.key === "x") {
      e.preventDefault();
      toggleSelect(itemKey(item), !selected.has(itemKey(item)));
    } else if (e.key === "Escape") setOpen(null);
  }

  if (state.kind === "loading") return <div className="h-96 animate-pulse rounded-2xl bg-muted" />;

  if (state.kind === "signed-out") return <SignInPanel next="/admin/reviews" title="Sign in to see the review queue" />;

  if (state.kind === "error") return <p className="rounded-xl bg-surface px-5 py-4 text-muted-foreground">{state.message}</p>;
  const q = state.queue;
  const allSelected = pending.length > 0 && chosen.length === pending.length;

  // one ref per row on screen: a decided item leaves no stale button behind for j/k to land on
  rows.current.length = pending.length;

  return (
    <div className="flex max-w-5xl flex-col gap-6">
      <header className="flex flex-col gap-2">
        <h1 className="text-[28px] leading-tight font-medium tracking-tight sm:text-4xl">AI review queue</h1>
        <p className="max-w-3xl text-[15px] leading-6 text-pretty text-muted-foreground">
          Versions an AI review flagged that nobody here has decided yet, most downloaded first. The public sees &ldquo;Under review&rdquo; and the{" "}
          <Link href="/reviews" className="text-foreground underline-offset-4 hover:underline">
            list of waiting versions
          </Link>
          , never the findings, until you confirm. Quoted secrets are masked.
        </p>
      </header>
      {q.flagsHold && <SwitchPanel state={q.flagsHold} waiting={pending.length} onChanged={() => void load()} />}
      <UnlockBar until={q.unlockedUntil} windowMs={q.windowMs} onChanged={() => void load()} />
      <section aria-labelledby="pending" className="flex flex-col gap-3">
        <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
          <h2 id="pending" className="text-lg font-medium tracking-tight">
            Waiting <span className="text-muted-foreground tabular-nums">{pending.length}</span>
          </h2>
          <p className="hidden text-[13px] text-muted-foreground sm:block">
            <kbd className="font-mono">j</kbd>/<kbd className="font-mono">k</kbd> move · <kbd className="font-mono">Enter</kbd> open · <kbd className="font-mono">x</kbd> select ·{" "}
            <kbd className="font-mono">Esc</kbd> close
          </p>
        </div>
        {pending.length === 0 ? (
          <p className="rounded-xl bg-surface px-5 py-4 text-[15px] text-muted-foreground">Nothing is waiting. New flags show up here as the reviewer posts them.</p>
        ) : (
          <div onKeyDown={onKeyDown} className="overflow-hidden rounded-xl border">
            <div className="flex items-center gap-3 border-b bg-surface/60 py-2 pr-4 pl-4 text-[12.5px] text-muted-foreground">
              <input
                type="checkbox"
                checked={allSelected}
                onChange={(e) => setSelected(e.target.checked ? new Set(pending.map(itemKey)) : new Set())}
                aria-label="Select every waiting version"
                className="size-4 accent-foreground"
              />
              <span className="hidden flex-1 grid-cols-[1rem_minmax(0,15rem)_6.5rem_4.5rem_4.5rem_minmax(0,1fr)] gap-x-3 pl-2 sm:grid">
                <span />
                <span>Package</span>
                <span>Model said</span>
                <span className="text-right">Downloads</span>
                <span className="text-right">Flagged</span>
                <span>Summary</span>
              </span>
              <span className="sm:hidden">Select all</span>
            </div>
            <ol className="divide-y">
              {pending.map((item, i) => {
                const key = itemKey(item);
                const isOpen = open === key;

                return (
                  <li key={key} className={selected.has(key) ? "bg-muted/50" : ""}>
                    <Row
                      item={item}
                      index={i}
                      open={isOpen}
                      selected={selected.has(key)}
                      onToggle={() => {
                        focused.current = i;
                        setOpen(isOpen ? null : key);
                      }}
                      onSelect={(on) => toggleSelect(key, on)}
                      buttonRef={(el) => {
                        rows.current[i] = el;
                      }}
                    />
                    {isOpen && <Details item={item} unlocked={unlocked} onDone={() => void load()} />}
                  </li>
                );
              })}
            </ol>
          </div>
        )}
      </section>
      {chosen.length > 0 && <BulkBar selected={chosen} unlocked={unlocked} onClear={() => setSelected(new Set())} onDone={() => void load()} />}
      <Decided decided={q.decided} history={q.flagsHold?.history ?? []} />
    </div>
  );
}
