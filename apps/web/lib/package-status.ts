// Does this package (or this file of a version) exist, and can the registry be read? Asked by proxy.ts before a
// package page renders, because the page's status code is decided before its content streams. Both answers come from
// the edge cache once known: packages are never deleted and a version's files never change, so a yes is kept, and a
// package the proxy had to look up is left in the cache for the page that renders next. A version can still be
// revoked, so a file's cached yes counts only while the version's permission to be shown is a few seconds old.
import { z } from "zod";
import { lookup, POLICIES, store } from "./edge-cache";
import { askServable, confirmServable, fetchJson, logUnavailable, REGISTRY_TIMEOUT_MS, type Fetched } from "./registry-fetch";
import { fileApiPath, packageApiPath, REGISTRY, servableKey } from "./registry-url";

/** "refused": the registry deliberately won't show it (a revoked version's 410, an unreadable tarball's 422); the page explains why. */
export type Status = "ok" | "missing" | "refused" | "unavailable";

const Exists = z.object({ name: z.string() });

/** What a cached yes is stored as. */
const YES = "1";

export async function packageStatus(name: string, signal?: AbortSignal): Promise<Status> {
  const url = `${REGISTRY}${packageApiPath(name)}`;
  const known = `${url}#exists`;

  if (await lookup(known, POLICIES.exists)) return "ok";
  // the same URL and cache entry as the page's getPackage: the page renders from this answer
  const result = await fetchJson({ url, schema: Exists, signal, cache: POLICIES.package });

  if (result.kind === "ok") store(known, YES, POLICIES.exists);
  else if (result.kind === "unavailable" && !signal?.aborted) logUnavailable(packageApiPath(name), result.reason);

  return result.kind;
}

/** A HEAD's answer as a Status: a 410 or 422 is the registry's decision, not an outage. */
function statusOf(result: Fetched<null>): Status {
  if (result.kind !== "unavailable") return result.kind;

  return result.reason.kind === "status" && (result.reason.status === 410 || result.reason.status === 422) ? "refused" : "unavailable";
}

/** Does this version have this file? A HEAD request: the registry answers with the status and no body. A 404 also means the package or the version is not there. */
export async function fileStatus(input: { name: string; version: string; path: string }, signal?: AbortSignal): Promise<Status> {
  const url = `${REGISTRY}${fileApiPath(input)}`;
  const known = `${url}#exists`;
  // that the file exists never changes, so it is kept; that the version may be shown is asked with a HEAD unless one
  // said yes in the last few seconds. A file not yet known to exist is always asked about: the version's permission
  // says nothing about this path.
  const exists = await lookup(known, POLICIES.versionFile);
  const check = { url, servable: servableKey(input), signal, timeoutMs: REGISTRY_TIMEOUT_MS * 2 };
  const status = statusOf(exists ? await confirmServable(check) : await askServable(check));

  if (status === "ok" && !exists) store(known, YES, POLICIES.versionFile);

  return status;
}
