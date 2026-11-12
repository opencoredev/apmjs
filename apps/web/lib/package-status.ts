// Does this package (or this file of a version) exist, and can the registry be read? Asked by proxy.ts before a
// package page renders, because the page's status code is decided before its content streams. Both answers come from
// the edge cache once known: packages are never deleted and a version's files never change, so a yes is kept, and a
// package the proxy had to look up is left in the cache for the page that renders next.
import { z } from "zod";
import { lookup, POLICIES, store } from "./edge-cache";
import { classifyStatus, fetchJson, logUnavailable, REGISTRY_TIMEOUT_MS, withTimeout } from "./registry-fetch";
import { registryFetch } from "./registry-transport";
import { fileApiPath, packageApiPath, REGISTRY } from "./registry-url";

export type Status = "ok" | "missing" | "unavailable";

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

/** Does this version have this file? A HEAD request: the registry answers with the status and no body. A 404 also means the package or the version is not there. */
export async function fileStatus(input: { name: string; version: string; path: string }, signal?: AbortSignal): Promise<Status> {
  const url = `${REGISTRY}${fileApiPath(input)}`;
  const known = `${url}#exists`;

  if (await lookup(known, POLICIES.versionFile)) return "ok";

  try {
    const res = await registryFetch(url, { method: "HEAD", cache: "no-store", signal: withTimeout(REGISTRY_TIMEOUT_MS * 2, signal) });

    await res.body?.cancel();
    const status = classifyStatus(res.status);

    if (status === "ok") store(known, YES, POLICIES.versionFile);

    return status;
  } catch {
    return "unavailable";
  }
}
