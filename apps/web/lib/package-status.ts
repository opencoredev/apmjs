// Does this package exist, and can the registry be read? Asked by proxy.ts before a package page renders.
import { z } from "zod";
import { classifyStatus, fetchJson, logUnavailable, REGISTRY_TIMEOUT_MS, withTimeout, type Fetched } from "./registry-fetch";
import { registryFetch } from "./registry-transport";
import { encodeName, fileApiPath, REGISTRY } from "./registry-url";

const Exists = z.object({ name: z.string() });

export async function packageStatus(name: string, signal?: AbortSignal): Promise<Fetched<{ name: string }>> {
  const result = await fetchJson({ url: `${REGISTRY}-/apm/v1/packages/${encodeName(name)}`, schema: Exists, signal });

  if (result.kind === "unavailable" && !signal?.aborted) logUnavailable(`-/apm/v1/packages/${encodeName(name)}`, result.reason);

  return result;
}

/** Does this version have this file? A HEAD request: the registry answers with the status and no body. */
export async function fileStatus(input: { name: string; version: string; path: string }, signal?: AbortSignal): Promise<"ok" | "missing" | "unavailable"> {
  try {
    const res = await registryFetch(`${REGISTRY}${fileApiPath(input)}`, { method: "HEAD", cache: "no-store", signal: withTimeout(REGISTRY_TIMEOUT_MS * 2, signal) });

    await res.body?.cancel();

    return classifyStatus(res.status);
  } catch {
    return "unavailable";
  }
}
