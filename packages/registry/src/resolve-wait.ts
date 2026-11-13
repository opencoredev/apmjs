// How long GET /-/apm/v1/resolve waits for queued analyses before it answers, on its own so the website's tests can
// check their timeouts against it without loading the registry (apps/web/lib/agent/resolve-budget.test.ts).

/** About 20 s, polling the database each second: what the CLI's resolve waits by default, inside its 60 s timeout. */
export const RESOLVE_WAIT = { maxMs: 20_000, pollMs: 1_000 } as const;

/** The query parameter a caller sets to wait less: whole milliseconds, 0 to RESOLVE_WAIT.maxMs. */
export const WAIT_PARAM = "wait";

export type WaitParse = { kind: "ok"; maxMs: number } | { kind: "invalid"; error: string };

/** `wait`: absent means RESOLVE_WAIT.maxMs; a caller may only shorten it, never wait longer than the registry would. */
export function parseWait(raw: string | null): WaitParse {
  if (raw === null) return { kind: "ok", maxMs: RESOLVE_WAIT.maxMs };
  const n = /^\d{1,6}$/.test(raw) ? Number(raw) : Number.NaN;

  if (!Number.isInteger(n)) return { kind: "invalid", error: `wait must be a whole number of milliseconds from 0 to ${RESOLVE_WAIT.maxMs} (got "${raw}")` };

  return { kind: "ok", maxMs: Math.min(n, RESOLVE_WAIT.maxMs) };
}
