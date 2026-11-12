// The lifecycle of a published version: active → yanked ⇄ active, and active/yanked → revoke-pending → revoked,
// with restore taking a revoked version back down to yanked. One table of transitions, so every route that
// changes a version's state agrees on what is allowed. XState would add a runtime for six states and no timers
// it could own (the 24h window is data in Postgres, matured by reads and the cron), so this stays a pure function.
import type { VersionStatus } from "./db.ts";

const HOUR = 3_600_000;
export const DAY = 24 * HOUR;

/** A revoke of an old or depended-on version waits this long before it becomes final. */
export const PENDING_MS = DAY;

/** Revokes of versions younger than this take effect at once. */
export const FRESH_MS = 72 * HOUR;

export type LifecycleEvent =
  | { kind: "yank" }
  | { kind: "unyank" }
  /** An owner revokes. `final` when the version is fresh (the malware case) or the caller forces it. */
  | { kind: "revoke"; final: boolean }
  /** A second owner revokes a version another owner left pending. */
  | { kind: "confirm" }
  | { kind: "restore" };

export type Transition =
  | { kind: "move"; to: VersionStatus }
  /** Already in the state the event asks for; nothing changes. */
  | { kind: "same" }
  | { kind: "refuse"; reason: "revoked-beats-yank" | "not-yanked" | "not-revoked" | "already-pending" };

export function transition(from: VersionStatus, event: LifecycleEvent): Transition {
  switch (event.kind) {
    case "yank":
      if (from === "revoked" || from === "revoke-pending") return { kind: "refuse", reason: "revoked-beats-yank" };

      return from === "yanked" ? { kind: "same" } : { kind: "move", to: "yanked" };
    case "unyank":
      return from === "yanked" ? { kind: "move", to: "active" } : { kind: "refuse", reason: "not-yanked" };
    case "revoke":
      if (from === "revoked") return { kind: "same" };

      if (from === "revoke-pending") return { kind: "refuse", reason: "already-pending" };

      return { kind: "move", to: event.final ? "revoked" : "revoke-pending" };
    case "confirm":
      if (from === "revoked") return { kind: "same" };

      return from === "revoke-pending" ? { kind: "move", to: "revoked" } : { kind: "refuse", reason: "not-revoked" };
    case "restore":
      return from === "revoked" || from === "revoke-pending" ? { kind: "move", to: "yanked" } : { kind: "refuse", reason: "not-revoked" };
    default: {
      const _exhaustive: never = event;

      return _exhaustive;
    }
  }
}

/** The state a version is in at `now`: a pending revoke older than the window is final even before the cron writes it. */
export function effectiveStatus(v: { status: VersionStatus; status_at: number | null }, now: number): VersionStatus {
  if (v.status === "revoke-pending" && v.status_at !== null && v.status_at <= now - PENDING_MS) return "revoked";

  return v.status;
}

/** A version record with its effective status applied. */
export function atTime<V extends { status: VersionStatus; status_at: number | null }>(v: V, now: number): V {
  const status = effectiveStatus(v, now);

  return status === v.status ? v : { ...v, status };
}
