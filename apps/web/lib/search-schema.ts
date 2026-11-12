// Shapes the web app's own /api routes return. The route handlers build them from registry
// answers on the server; the browser parses them again with the same schemas.
import { z } from "zod";
import "./zod-csp";

const Score = z.object({ score: z.number(), grade: z.string() });

export const SearchHit = z.object({
  name: z.string(),
  version: z.string(),
  description: z.string(),
  date: z.string().nullable(),
  source: z.enum(["local", "npm"]),
  /** Only present when the registry already stored an analysis for this version. */
  score: Score.nullable(),
  weeklyDownloads: z.number().nullable(),
});

export type SearchHit = z.infer<typeof SearchHit>;

export const SearchAnswer = z.object({
  query: z.string(),
  hits: z.array(SearchHit),
  total: z.number(),
  /** npm did not answer; the hits are this registry's only. */
  upstreamFailed: z.boolean(),
});

export type SearchAnswer = z.infer<typeof SearchAnswer>;

const NameReason = z.object({ name: z.string(), reason: z.string() });

export const ExactPart = z.object({
  query: z.string(),
  valid: z.boolean(),
  taken: z.boolean(),
  source: z.string().nullable(),
  unknown: z.boolean().default(false),
  available: z.boolean(),
  owners: z.array(z.string()),
  latest: z.object({ version: z.string(), score: z.number().nullable(), grade: z.string().nullable() }).nullable(),
  description: z.string().nullable(),
  conflicts: z.array(NameReason),
});

export type ExactPart = z.infer<typeof ExactPart>;

export const LookalikePart = z.object({
  query: z.string(),
  valid: z.boolean(),
  lookalikes: z.array(NameReason),
  similar: z.array(NameReason),
});

export type LookalikePart = z.infer<typeof LookalikePart>;

export const AlternativesPart = z.object({
  query: z.string(),
  valid: z.boolean(),
  /** The signed-in user's scope the suggestions were checked under; null when nobody is signed in. */
  scope: z.string().nullable().default(null),
  // `checked: false` marks a placeholder (`@you/...`) nobody could check
  suggestions: z.array(z.object({ name: z.string(), available: z.boolean(), taken: z.boolean(), unknown: z.boolean().default(false), checked: z.boolean().default(true) })),
});

export type AlternativesPart = z.infer<typeof AlternativesPart>;

/** What the "Free alternatives" slot shows: checked free names, or scoped placeholders to sign in for. */
export type AlternativesView = { kind: "free"; scope: string | null; names: string[] } | { kind: "sign-in"; names: string[] } | { kind: "none" };

const MAX_ALTERNATIVES = 4;

/**
 * Picks what to suggest. Under the GitHub-scope policy the registry suggests only scoped names (a bare name always
 * means the npm package): under the signed-in scope, checked, or under `@you/` for a visitor, unchecked.
 */
export function alternativesView(answer: AlternativesPart): AlternativesView {
  const free = answer.suggestions.filter((s) => s.checked && s.available).map((s) => s.name);

  if (free.length > 0) return { kind: "free", scope: answer.scope, names: free.slice(0, MAX_ALTERNATIVES) };
  const placeholders = answer.suggestions.filter((s) => !s.checked).map((s) => s.name);

  return placeholders.length > 0 ? { kind: "sign-in", names: placeholders.slice(0, MAX_ALTERNATIVES) } : { kind: "none" };
}

export type NamePart = "exact" | "lookalike" | "alternatives";

export type NamePartAnswer = { exact: ExactPart; lookalike: LookalikePart; alternatives: AlternativesPart };

/** Mapped by part, so indexing with a generic part keeps the schema tied to that part's answer. */
export const NAME_PART_SCHEMAS: { [P in NamePart]: z.ZodType<NamePartAnswer[P]> } = { exact: ExactPart, lookalike: LookalikePart, alternatives: AlternativesPart };

export function isNamePart(s: string | null): s is NamePart {
  return s === "exact" || s === "lookalike" || s === "alternatives";
}

// Same rule as the registry's name check, so the UI only asks about strings that can be package names.
const NAME_RE = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;

export function looksLikePackageName(q: string): boolean {
  return q.length > 0 && q.length <= 214 && NAME_RE.test(q);
}
