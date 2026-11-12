// Reads what an install verdict needs (the registry's resolve answer with its dependency walk, then the AI review of
// the version it picked) and returns the verdict. Shared by GET /api/explain and the explain_install MCP tool. Both
// reads skip every cache (see AgentSource): a version confirmed malicious a second ago must not get "install".
import { looksLikePackageName } from "../search-schema";
import type { AgentSource } from "./source";
import { explainInstall, reviewInput, type Verdict } from "./verdict";

/** "zod", "zod@^4", "@scope/name@1.2.3" → name and range; null when the name can't be a package name. */
export function parsePackageSpec(spec: string): { name: string; range: string | null } | null {
  const s = spec.trim();
  const at = s.lastIndexOf("@");
  const name = (at > 0 ? s.slice(0, at) : s).toLowerCase();
  const range = at > 0 ? s.slice(at + 1).trim() : "";

  if (!looksLikePackageName(name) || range.length > 256) return null;

  return { name, range: range === "" ? null : range };
}

export async function explainFor(input: { name: string; range: string | null; source: AgentSource }): Promise<Verdict> {
  const { name, range, source } = input;
  const resolve = await source.resolve({ name, range: range ?? "latest" });
  // only an "ok" resolve reads the review; the other verdicts never look at it
  const review = resolve.kind === "ok" ? reviewInput(await source.review({ name, version: resolve.version })) : ({ kind: "unreadable" } as const);

  return explainInstall({ name, range, resolve, review });
}
