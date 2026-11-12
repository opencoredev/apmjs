// /llms.txt: what apm is and where an agent goes next (llmstxt.org). Static: prerendered at build.
import { LLMS_TXT } from "@/lib/agent/llms";

export function GET(): Response {
  return new Response(LLMS_TXT, { headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "public, max-age=3600" } });
}
