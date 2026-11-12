// Which cached answers quote a version's source, and how to take it out. A package's latest score and an older
// version's score cite evidence lines; a confirmed AI review shows excerpts. After a revoke the registry sends these
// redacted (packages/registry/src/withheld.ts), so a copy cached before the revoke must not outlive the version's
// permission: lib/registry-fetch.ts reads such a copy again once that permission is a few seconds old.
// No "server-only": proxy.ts and the unit tests import it.
import { z } from "zod";
import type { JsonValue, SourceGate } from "./registry-fetch";
import { servableKey } from "./registry-url";

const Evidence = z.object({ evidence: z.array(z.string()) });

/** The part of a score these checks read; `redacted` came with the revoke redaction, an older registry leaves it out. */
const ScoreQuotes = z.object({ redacted: z.boolean().optional(), signals: z.array(Evidence), dismissed: z.array(Evidence).optional() });

type ScoreQuotes = z.infer<typeof ScoreQuotes>;

const quotesEvidence = (s: ScoreQuotes): boolean => [...s.signals, ...(s.dismissed ?? [])].some((e) => e.evidence.length > 0);

// the registry's evidence formats (packages/core/src/score.ts): `lib/a.js:4: <line>`, `package.json scripts.x: <script>`
const CITED_LINE = /^([^\s:][^:\n]*?):(\d+)(?=: |$)/;
const QUOTES_AFTER_CITE = /^(package\.json scripts\.[^:\s]+|binding\.gyp): /;

/** One evidence line cut to what it cites, as the registry cuts a revoked version's (withheld.ts). */
export function evidenceWithoutSource(evidence: string): string {
  const line = CITED_LINE.exec(evidence);

  if (line?.[1] && line[2]) return `${line[1]}:${line[2]}`;

  return QUOTES_AFTER_CITE.exec(evidence)?.[1] ?? evidence;
}

/** A score's evidence and dismissed evidence cut to what each line cites. */
function scoreWithoutSource<S extends { signals: { evidence: string[] }[]; dismissed: { evidence: string[] }[] }>(score: S): S {
  const cut = <E extends { evidence: string[] }>(e: E): E => ({ ...e, evidence: e.evidence.map(evidenceWithoutSource) });

  return { ...score, signals: score.signals.map(cut), dismissed: score.dismissed.map(cut) };
}

const PackageQuotes = z.object({ name: z.string(), latest: z.string().nullable(), score: ScoreQuotes.nullable() });

/**
 * What a package answer quotes: its latest version's score evidence. proxy.ts reads the same URL with a smaller schema,
 * and passes this too, so its read records what the registry said for the page that renders next.
 */
export function packageQuotes(json: JsonValue): ReturnType<SourceGate<unknown>["quotes"]> {
  const p = PackageQuotes.safeParse(json);

  // a redacted answer says the version is revoked even when nothing is left to quote
  if (!p.success || p.data.latest === null || !p.data.score || (p.data.score.redacted !== true && !quotesEvidence(p.data.score))) return null;

  return { key: servableKey({ name: p.data.name, version: p.data.latest }), redacted: p.data.score.redacted };
}

/** A package answer: its latest version's score evidence. */
export function packageGate<T extends { score: { signals: { evidence: string[] }[]; dismissed: { evidence: string[] }[] } | null }>(): SourceGate<T> {
  return { quotes: packageQuotes, withoutSource: (value) => (value.score ? { ...value, score: scoreWithoutSource(value.score) } : value) };
}

const VersionScoreQuotes = ScoreQuotes.extend({ name: z.string(), version: z.string() });

/** One version's full score. */
export function scoreGate<T extends { signals: { evidence: string[] }[]; dismissed: { evidence: string[] }[] }>(): SourceGate<T> {
  return {
    quotes: (json) => {
      const s = VersionScoreQuotes.safeParse(json);

      if (!s.success || (s.data.redacted !== true && !quotesEvidence(s.data))) return null;

      return { key: servableKey(s.data), redacted: s.data.redacted };
    },
    withoutSource: scoreWithoutSource,
  };
}

const Quoting = z.object({ excerpt: z.string().optional(), quote: z.string().optional() });
const Findings = z.object({ findings: z.array(Quoting) }).nullable();
const ReviewQuotes = z.object({ name: z.string(), version: z.string(), redacted: z.boolean().optional(), review: Findings, private: Findings.optional() });

/** One version's AI review: the excerpts its findings show. */
export function reviewGate<T extends { review: { findings: { excerpt: string }[] } | null; private: { findings: { excerpt: string }[] } | null }>(): SourceGate<T> {
  const cut = <F extends { findings: { excerpt: string }[] }>(part: F): F => ({ ...part, findings: part.findings.map((f) => ({ ...f, excerpt: "" })) });

  return {
    quotes: (json) => {
      const r = ReviewQuotes.safeParse(json);

      if (!r.success) return null;
      const findings = [...(r.data.review?.findings ?? []), ...(r.data.private?.findings ?? [])];

      if (r.data.redacted !== true && !findings.some((f) => (f.excerpt ?? "") !== "" || (f.quote ?? "") !== "")) return null;

      return { key: servableKey(r.data), redacted: r.data.redacted };
    },
    withoutSource: (value) => ({ ...value, review: value.review ? cut(value.review) : null, private: value.private ? cut(value.private) : null }),
  };
}
