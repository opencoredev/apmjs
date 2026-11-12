// How server code reaches the registry. Inside the website Worker it goes through the REGISTRY service binding:
// Workers on one Cloudflare account cannot fetch each other's public URLs, and a binding skips the network hop.
// Everywhere else (next dev, next start, the unit tests) it is plain fetch to the URL.
import { getCloudflareContext } from "@opennextjs/cloudflare";
import { z } from "zod";

type RegistryBinding = { fetch: (request: Request) => Promise<Response> };

const ServiceBinding = z.object({ fetch: z.instanceof(Function) });

/** The REGISTRY service binding when this runs inside the website Worker, else null. */
function binding(): RegistryBinding | null {
  let env: CloudflareEnv;

  try {
    env = getCloudflareContext().env;
  } catch {
    // not on Cloudflare: there is no request context to read bindings from
    return null;
  }

  const registry = env.REGISTRY;

  return registry !== undefined && ServiceBinding.safeParse(registry).success ? registry : null;
}

/** fetch() for registry URLs. The URL's path and query reach the registry Worker unchanged either way. */
export function registryFetch(input: string | URL, init: RequestInit = {}): Promise<Response> {
  const service = binding();

  return service ? service.fetch(new Request(input.toString(), init)) : fetch(input, init);
}
