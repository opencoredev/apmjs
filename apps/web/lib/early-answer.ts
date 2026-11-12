// A package page asks for a version's answers (the AI review, an older version's score) before the package answer
// says which version it shows, so neither waits for the other. The early answer is used only when it turns out to be
// about the shown version; otherwise the page reads the answer for that version. Nothing is kept: each is a registry
// read of this view, which the registry decides on then.
import type { Fetched } from "./registry-fetch";

/**
 * The answer for `version`: `early` (asked for `asked`, a version or a dist-tag) when it names that version, is a 404
 * for exactly that version, or says the registry could not be read (a second read would double the wait in an
 * outage); else what `read` answers for it.
 */
export async function answerFor<T extends { version: string }>(input: {
  early: Promise<Fetched<T>>;
  asked: string;
  version: string;
  read: () => Promise<Fetched<T>>;
}): Promise<Fetched<T>> {
  const early = await input.early;

  if (early.kind === "ok" && early.value.version === input.version) return early;

  if (early.kind === "missing" && input.asked === input.version) return early;

  if (early.kind === "unavailable") return early;

  return input.read();
}

/** The version a page's `?v=` asks for: its first value, or undefined when there is none. */
export function askedVersion(v: string | string[] | undefined): string | undefined {
  const asked = Array.isArray(v) ? v[0] : v;

  return asked === undefined || asked === "" ? undefined : asked;
}
