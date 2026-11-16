// GET /api/build: which deploy run uploaded this website version (lib/build-identity.ts), for the deploy's smoke check.
// connection() makes it a request-time route under Cache Components (next.config.ts), so it is never prerendered.
import { getCloudflareContext } from "@opennextjs/cloudflare";
import { connection } from "next/server";
import { buildIdentity } from "@/lib/build-identity";

export async function GET(): Promise<Response> {
  await connection();
  let env: CloudflareEnv | null = null;

  try {
    env = getCloudflareContext().env;
  } catch {
    // not on Cloudflare: no bindings, so no build to report
  }

  return buildIdentity(env);
}
