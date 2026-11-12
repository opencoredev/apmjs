// A package page asks for a version's answers (the AI review, an older version's score) before the package answer
// says which version it shows, so neither waits for the other. The early answer is used only when it is about the
// shown version and says no more than the package answer allows: a version the package answer reports revoked or
// revoke-pending is shown only from a redacted answer, so an early answer read before a revoke is read again. Nothing
// is kept: each is a registry read of this view, which the registry decides on then.
import type { Fetched } from "./registry-fetch";

/**
 * The version a page shows, as the package answer reports it: "withheld" when it is revoked or its revoke is pending,
 * "unknown" when the answer's version list (the newest 200) does not include it, so nothing says it is still active.
 */
export type Shown = { version: string; status: "active" | "withheld" | "unknown" };

/** A revoked version, or one whose revoke is pending: the registry shows none of its source (its withheld.ts). */
export function isWithheld(status: string): boolean {
  return status === "revoked" || status === "revoke-pending";
}

/**
 * `version` as the package answer reports it. `redacted` is the package answer's own score for that version saying it
 * is withheld (the latest version's score), which counts even when the version list does not list it.
 */
export function shownOf(versions: readonly { version: string; status: string }[], version: string, redacted = false): Shown {
  const listed = versions.find((v) => v.version === version);

  if (redacted || (listed !== undefined && isWithheld(listed.status))) return { version, status: "withheld" };

  return { version, status: listed === undefined ? "unknown" : "active" };
}

/**
 * The answer for `shown`: `early` (asked for `asked`, a version or a dist-tag) when it names that version and is at
 * least as restrictive as the package answer (redacted unless the package answer lists the version as active), is a 404 for exactly that
 * version, or says the registry could not be read (a second read would double the wait in an outage); else what
 * `read` answers for it.
 */
export async function answerFor<T extends { version: string; redacted: boolean }>(input: {
  early: Promise<Fetched<T>>;
  asked: string;
  shown: Shown;
  read: () => Promise<Fetched<T>>;
}): Promise<Fetched<T>> {
  const early = await input.early;

  switch (early.kind) {
    case "ok":
      // read before a revoke the package answer has seen, or about a version it does not list: the registry is asked
      // again for exactly that version, and redacts it if it is withheld now
      return early.value.version === input.shown.version && (early.value.redacted || input.shown.status === "active") ? early : input.read();
    case "missing":
      return input.asked === input.shown.version ? early : input.read();
    case "unavailable":
      return early;
    default: {
      const _exhaustive: never = early;

      return _exhaustive;
    }
  }
}

/** The version a page's `?v=` asks for: its first value, or undefined when there is none. */
export function askedVersion(v: string | string[] | undefined): string | undefined {
  const asked = Array.isArray(v) ? v[0] : v;

  return asked === undefined || asked === "" ? undefined : asked;
}
