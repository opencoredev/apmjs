// Does this package exist, and can the registry be read? Asked by proxy.ts before a package page renders.
import { z } from "zod";
import { fetchJson, logUnavailable, type Fetched } from "./registry-fetch";
import { encodeName, REGISTRY } from "./registry-url";

const Exists = z.object({ name: z.string() });

export async function packageStatus(name: string, signal?: AbortSignal): Promise<Fetched<{ name: string }>> {
  const result = await fetchJson({ url: `${REGISTRY}-/apm/v1/packages/${encodeName(name)}`, schema: Exists, signal });

  if (result.kind === "unavailable" && !signal?.aborted) logUnavailable(`-/apm/v1/packages/${encodeName(name)}`, result.reason);

  return result;
}
