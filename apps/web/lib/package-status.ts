// Does this package (or this file of a version) exist, and can the registry be read? Asked by proxy.ts before a
// package page renders, because the page's status code is decided before its content streams. Both are HEAD requests:
// the registry answers with a status and builds no answer. Only that something exists is kept in the edge cache:
// packages are never deleted and a version's paths never change. Whether a version's source may be shown is never
// kept: the page reads it from the registry on every view, and the registry refuses a revoked version then (a 410 the
// page explains).
import { lookup, POLICIES, store } from "./edge-cache";
import { headStatus, logUnavailable, REGISTRY_TIMEOUT_MS, type Fetched } from "./registry-fetch";
import { fileApiPath, packageApiPath, REGISTRY } from "./registry-url";

/** "refused": the registry deliberately won't show it (a revoked version's 410, an unreadable tarball's 422); the page explains why. */
export type Status = "ok" | "missing" | "refused" | "unavailable";

/** What a cached yes is stored as. */
const YES = "1";

/**
 * Does the registry know this package, here or on npm? A HEAD of the package answer: the registry looks the name up
 * and stops there, so it neither builds the answer nor analyses the latest version; the page reads the answer itself.
 */
export async function packageStatus(name: string, signal?: AbortSignal): Promise<Status> {
  const url = `${REGISTRY}${packageApiPath(name)}`;
  const known = `${url}#exists`;

  if (await lookup(known, POLICIES.exists)) return "ok";
  const result = await headStatus({ url, signal });

  if (result.kind === "ok") store(known, YES, POLICIES.exists);
  else if (result.kind === "unavailable" && !signal?.aborted) logUnavailable(packageApiPath(name), result.reason);

  return result.kind;
}

/** A HEAD's answer as a Status: a 410 or 422 is the registry's decision, not an outage. */
function statusOf(result: Fetched<null>): Status {
  if (result.kind !== "unavailable") return result.kind;

  return result.reason.kind === "status" && (result.reason.status === 410 || result.reason.status === 422) ? "refused" : "unavailable";
}

/**
 * Does this version have this file? A HEAD request: the registry answers with the status and no body. A 404 also
 * means the package or the version is not there. A path known to exist is not asked about again; the page's own read
 * of the file is what the registry refuses when the version was revoked since.
 */
export async function fileStatus(input: { name: string; version: string; path: string }, signal?: AbortSignal): Promise<Status> {
  const url = `${REGISTRY}${fileApiPath(input)}`;
  const known = `${url}#exists`;

  if (await lookup(known, POLICIES.fileExists)) return "ok";
  const status = statusOf(await headStatus({ url, signal, timeoutMs: REGISTRY_TIMEOUT_MS * 2 }));

  if (status === "ok") store(known, YES, POLICIES.fileExists);

  return status;
}
