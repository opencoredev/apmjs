// Typed client for the apm registry API. Responses are parsed here, at the network boundary.
import { z } from "zod";
import type { Config } from "./config.ts";

// confidence arrived with apm-score-v4; older answers asserted every signal
export const SignalSchema = z.object({ id: z.string(), label: z.string(), points: z.number(), evidence: z.array(z.string()), confidence: z.enum(["confirmed", "possible"]).default("confirmed") });

/** What the package can do (apm-score-v10): listed with the score, never scored on its own. Older scorers send none. */
export const CapabilitySchema = z.object({
  id: z.string(),
  label: z.string(),
  status: z.enum(["declared", "undeclared", "not-declared", "unused"]),
  basis: z.enum(["code", "text", "possible", "none"]),
  declared: z.string().optional(),
  evidence: z.array(z.string()),
  outside: z.array(z.string()).optional(),
});

export const ReportSchema = z.object({
  score: z.number(),
  grade: z.string(),
  signals: z.array(SignalSchema),
  capabilities: z.array(CapabilitySchema).default([]),
  notChecked: z.array(z.string()).optional(),
  facts: z.record(z.string(), z.unknown()).optional(),
});

export type Capability = z.infer<typeof CapabilitySchema>;
export type Signal = z.infer<typeof SignalSchema>;
export type Report = z.infer<typeof ReportSchema>;

/** `revokeReason`: the owner's words, for a revoked or revoke-pending version (older registries put them in `reason`). */
const Skipped = z.array(z.object({ version: z.string(), reason: z.string(), revokeReason: z.string().nullish() }));
const UncheckedDep = z.object({ dependency: z.string(), reason: z.string(), via: z.array(z.string()) });

const DepRef = z.object({ name: z.string(), version: z.string() });

/** The AI review standing of every dependency the walk checked (older registries send none). */
export const TreeReviews = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("off") }),
  z.object({ kind: z.literal("on"), confirmed: z.array(DepRef), underReview: z.array(DepRef), pending: z.array(DepRef), noAnswer: z.array(DepRef) }),
]);

/** `packages`: every name@version the registry's walk checked (older registries send none). `unchecked` is the total. */
export const Tree = z
  .object({ unchecked: z.number(), uncheckedDeps: z.array(UncheckedDep).default([]), packages: z.array(DepRef).default([]), reviews: TreeReviews.optional() })
  .loose();

export const ResolveOk = z.object({ name: z.string(), version: z.string(), report: ReportSchema.nullable(), skipped: Skipped, source: z.string().optional(), tree: Tree.optional() });
export const ResolveFail = z.object({ error: z.string(), name: z.string(), version: z.null(), skipped: Skipped });
export type ResolveOk = z.infer<typeof ResolveOk>;

export const ScoreResponse = ReportSchema.extend({
  name: z.string(),
  version: z.string(),
  status: z.string(),
  publishedAt: z.string(),
  publishedBy: z.string(),
  previous: z.object({ version: z.string(), score: z.number(), grade: z.string() }).nullable(),
  changes: z.array(z.string()),
});
export type ScoreResponse = z.infer<typeof ScoreResponse>;

export const NameResponse = z.object({
  query: z.string(),
  valid: z.boolean(),
  taken: z.boolean(),
  available: z.boolean(),
  owners: z.array(z.string()),
  latest: z.object({ version: z.string(), score: z.number().nullable(), grade: z.string().nullable() }).nullable(),
  conflicts: z.array(z.object({ name: z.string(), reason: z.string() })),
  similar: z.array(z.object({ name: z.string(), reason: z.string() })).optional(),
  suggestions: z.array(z.object({ name: z.string(), available: z.boolean(), taken: z.boolean() })),
});

export const Advisory = z.object({ title: z.string(), severity: z.string(), vulnerable_versions: z.string(), url: z.string().optional() }).loose();
export const BulkResponse = z.record(z.string(), z.array(Advisory));
export const ScanResponse = z.object({
  advisories: z.array(z.object({ package: z.string(), version: z.string(), level: z.string(), description: z.string() })),
  unchecked: z.array(z.object({ package: z.string(), version: z.string(), reason: z.string() })).default([]),
});
export const AuditResponse = z.object({ advisories: BulkResponse, unavailable: z.array(z.string()) });

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly body: unknown,
  ) {
    super(message);
  }
}

function errorText(body: unknown, status: number): string {
  if (typeof body === "object" && body !== null && "error" in body && typeof body.error === "string") return body.error;
  return `HTTP ${status}`;
}

/** A registry answer before it is parsed: its HTTP status and its JSON body (null when it had none). */
export type RawAnswer = { status: number; body: unknown };

export class Api {
  constructor(readonly cfg: Config) {}

  private headers(json: boolean): Record<string, string> {
    return {
      accept: "application/json",
      ...(json ? { "content-type": "application/json" } : {}),
      ...(this.cfg.token ? { authorization: `Bearer ${this.cfg.token}` } : {}),
    };
  }

  async raw(path: string, init: { method?: string; body?: unknown } = {}): Promise<RawAnswer> {
    const res = await fetch(`${this.cfg.registry}${path}`, {
      method: init.method ?? "GET",
      headers: this.headers(init.body !== undefined),
      ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
      signal: AbortSignal.timeout(60_000),
    });
    const text = await res.text();
    let body: unknown = text;
    try {
      body = JSON.parse(text);
    } catch {
      // not JSON
    }
    return { status: res.status, body };
  }

  async get<T>(path: string, schema: z.ZodType<T>): Promise<T> {
    const r = await this.raw(path);
    if (r.status !== 200) throw new ApiError(r.status, errorText(r.body, r.status), r.body);
    return schema.parse(r.body);
  }

  async post<T>(path: string, body: unknown, schema: z.ZodType<T>): Promise<T> {
    const r = await this.raw(path, { method: "POST", body });
    if (r.status !== 200 && r.status !== 201) throw new ApiError(r.status, errorText(r.body, r.status), r.body);
    return schema.parse(r.body);
  }
}

export function encodeName(name: string): string {
  return name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}

/** Splits "name@range" (scoped names keep their leading @). */
export function parseSpec(spec: string): { name: string; range: string | null } {
  const at = spec.lastIndexOf("@");
  if (at > 0) return { name: spec.slice(0, at), range: spec.slice(at + 1) || null };
  return { name: spec, range: null };
}
