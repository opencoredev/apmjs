// Browser-side client for sign-in and the account routes. The registry serves both; next.config.ts
// rewrites /api/auth/* and /-/apm/v1/* to it, so cookies stay on this origin. Responses are parsed here.
"use client";

import { createAuthClient } from "better-auth/react";
import { passkeyClient } from "@better-auth/passkey/client";
import { z } from "zod";
import "./zod-csp";

function makeClient() {
  return createAuthClient({ baseURL: window.location.origin, plugins: [passkeyClient()] });
}

let client: ReturnType<typeof makeClient> | null = null;

/** Better Auth's browser client, made on first use (it needs window.location). Used for passkeys. */
export function authClient(): ReturnType<typeof makeClient> {
  client ??= makeClient();

  return client;
}

export const AuthConfig = z.object({
  providers: z.object({ github: z.boolean(), vercel: z.boolean() }),
  passkeys: z.boolean(),
});

export type AuthConfig = z.infer<typeof AuthConfig>;

export const Account = z.object({
  scope: z.string().nullable(),
  scopeTaken: z.string().nullable().default(null),
  github: z.string().nullable(),
  /** The GitHub login changed after the scope was claimed. The scope stays. */
  githubRenamed: z.boolean().default(false),
  name: z.string(),
  email: z.string(),
  image: z.string().nullable(),
  linked: z.array(z.object({ provider: z.string(), accountId: z.string() })),
  security: z.object({ totp: z.boolean(), passkeys: z.number() }),
  canPublish: z.boolean(),
  tokens: z.array(
    z.object({ id: z.string(), label: z.string(), scope: z.string(), createdAt: z.string(), expiresAt: z.string().nullable(), revokedAt: z.string().nullable() }),
  ),
  pending: z.number(),
});

export type Account = z.infer<typeof Account>;

export const StagedSummary = z.object({
  id: z.string(),
  package: z.string(),
  version: z.string(),
  publisher: z.string(),
  tag: z.string(),
  stagedAt: z.string(),
  expiresAt: z.string(),
  status: z.enum(["pending", "approved", "rejected", "expired"]),
  url: z.string(),
});

export type StagedSummary = z.infer<typeof StagedSummary>;

// confidence arrived with apm-score-v4; older answers asserted every signal
const Signal = z.object({ id: z.string(), label: z.string(), points: z.number(), evidence: z.array(z.string()), confidence: z.enum(["confirmed", "possible"]).default("confirmed") });

export type Signal = z.infer<typeof Signal>;

export const StagedDetail = StagedSummary.extend({
  newPackage: z.boolean(),
  currentLatest: z.string().nullable(),
  description: z.string(),
  size: z.number(),
  /** The tarball's sha512, in npm's integrity format. */
  integrity: z.string(),
  files: z.array(z.object({ path: z.string(), size: z.number() })),
  score: z.object({ score: z.number(), grade: z.string(), signals: z.array(Signal), notChecked: z.array(z.string()).default([]) }).nullable(),
  floor: z.number(),
  analysis: z.enum(["complete", "incomplete"]),
  /** "typed": the person types the package name to approve (incomplete analysis or a score under the floor). */
  confirmation: z.discriminatedUnion("kind", [z.object({ kind: z.literal("plain") }), z.object({ kind: z.literal("typed"), reason: z.string() })]),
});

export type StagedDetail = z.infer<typeof StagedDetail>;

export const StagedFile = z.object({ path: z.string(), size: z.number(), binary: z.boolean(), truncated: z.boolean(), text: z.string().nullable() });

export type StagedFile = z.infer<typeof StagedFile>;

export type Loaded<T> = { kind: "ok"; value: T } | { kind: "signed-out" } | { kind: "error"; status: number; message: string };

function messageOf(body: unknown, status: number): string {
  if (typeof body === "object" && body !== null) {
    if ("message" in body && typeof body.message === "string") return body.message;

    if ("error" in body && typeof body.error === "string") return body.error;
  }

  return `The registry answered ${status}.`;
}

/** GET or POST a /-/apm/v1 route with the session cookie and parse the answer. */
export async function call<T>(path: string, schema: z.ZodType<T>, init: { method?: "GET" | "POST"; body?: unknown } = {}): Promise<Loaded<T>> {
  let res: Response;

  try {
    res = await fetch(`/-/apm/v1/${path}`, {
      method: init.method ?? "GET",
      credentials: "same-origin",
      headers: init.body !== undefined ? { "content-type": "application/json" } : {},
      ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
    });
  } catch {
    return { kind: "error", status: 0, message: "Could not reach the registry. Check your connection and try again." };
  }

  const text = await res.text();
  let body: unknown = text;

  try {
    body = JSON.parse(text);
  } catch {
    // not JSON
  }

  if (res.status === 401 && init.method !== "POST") return { kind: "signed-out" };

  if (!res.ok) return { kind: "error", status: res.status, message: messageOf(body, res.status) };
  const parsed = schema.safeParse(body);

  return parsed.success ? { kind: "ok", value: parsed.data } : { kind: "error", status: res.status, message: "The registry sent an answer this page does not understand." };
}

/** A second factor for an account change: a code from the app, a recovery code, or the passkey check just made. */
export type FactorProof = { kind: "totp"; code: string } | { kind: "recovery"; code: string } | { kind: "passkey" };

/** The header the registry reads a factor proof from on account changes. */
export function proofHeaders(proof: FactorProof | null): Headers {
  const headers = new Headers();

  if (proof !== null) headers.set("x-apm-second-factor", proof.kind === "passkey" ? "passkey" : `${proof.kind}:${proof.code.trim()}`);

  return headers;
}

/** POST to Better Auth's own routes. */
export async function authPost(path: string, body: unknown, proof: FactorProof | null = null): Promise<{ ok: boolean; status: number; body: unknown; message: string }> {
  let res: Response;

  try {
    const headers = proofHeaders(proof);

    headers.set("content-type", "application/json");
    res = await fetch(`/api/auth/${path}`, { method: "POST", credentials: "same-origin", headers, body: JSON.stringify(body) });
  } catch {
    return { ok: false, status: 0, body: null, message: "Could not reach the registry. Check your connection and try again." };
  }

  const text = await res.text();
  let parsed: unknown = text;

  try {
    parsed = JSON.parse(text);
  } catch {
    // not JSON
  }

  return { ok: res.ok, status: res.status, body: parsed, message: messageOf(parsed, res.status) };
}

export async function signIn(provider: "github" | "vercel", next: string): Promise<string | null> {
  const r = await authPost("sign-in/social", { provider, callbackURL: next, errorCallbackURL: "/signin?error=1", disableRedirect: true });
  const url = typeof r.body === "object" && r.body !== null && "url" in r.body && typeof r.body.url === "string" ? r.body.url : null;

  if (!r.ok || !url) return r.message;
  window.location.assign(url);

  return null;
}

export async function linkProvider(provider: "github" | "vercel", next: string, proof: FactorProof | null = null): Promise<string | null> {
  const r = await authPost("link-social", { provider, callbackURL: next, disableRedirect: true }, proof);
  const url = typeof r.body === "object" && r.body !== null && "url" in r.body && typeof r.body.url === "string" ? r.body.url : null;

  if (!r.ok || !url) return r.message;
  window.location.assign(url);

  return null;
}

/** A CLI command a person approves on the website, once. Mirrors the registry's LiveAction (packages/registry/src/actions.ts). */
const Name = z.string().min(1).max(214);
const Version = z.string().min(1).max(256);
const DeprecateChange = z.object({ version: Version, message: z.string().max(1024).nullable() });

export const LiveAction = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("revoke"), name: Name, version: Version }),
  z.object({ kind: z.literal("restore"), name: Name, version: Version }),
  z.object({ kind: z.literal("yank"), name: Name, version: Version }),
  z.object({ kind: z.literal("unyank"), name: Name, version: Version }),
  z.object({ kind: z.literal("dist-tag"), name: Name, tag: z.string().min(1).max(128), version: Version.nullable() }),
  z.object({ kind: z.literal("deprecate"), name: Name, changes: z.array(DeprecateChange).min(1).max(1000) }),
  z.object({ kind: z.literal("incident"), since: z.string().min(1).max(64), dryRun: z.boolean() }),
  z.object({ kind: z.literal("owner-add"), name: Name, user: z.string().min(1).max(64) }),
  z.object({ kind: z.literal("owner-remove"), name: Name, user: z.string().min(1).max(64) }),
]);

export type LiveAction = z.infer<typeof LiveAction>;

export function commandText(a: LiveAction): string {
  switch (a.kind) {
    case "revoke":
    case "restore":
    case "yank":
    case "unyank":
      return `apm ${a.kind} ${a.name}@${a.version}`;
    case "dist-tag":
      return a.version === null ? `npm dist-tag rm ${a.name} ${a.tag}` : `npm dist-tag add ${a.name}@${a.version} ${a.tag}`;
    case "deprecate":
      return [...a.changes]
        .sort((x, y) => (x.version < y.version ? -1 : x.version > y.version ? 1 : 0))
        .map((c) => `npm deprecate ${a.name}@${c.version} ${JSON.stringify(c.message ?? "")}`)
        .join(" && ");
    case "incident":
      return `apm incident --since ${a.since}${a.dryRun ? " --dry-run" : ""}`;
    case "owner-add":
      return `apm owner add ${a.user} ${a.name}`;
    case "owner-remove":
      return `apm owner rm ${a.user} ${a.name}`;
    default: {
      const _exhaustive: never = a;

      return _exhaustive;
    }
  }
}

/** The command named in an account page link (`?confirm=<base64url JSON>`), or null. */
export function commandFromLink(search: string): LiveAction | null {
  const raw = new URLSearchParams(search).get("confirm");

  if (!raw) return null;

  try {
    const b64 = raw.replace(/-/g, "+").replace(/_/g, "/");
    const json: unknown = JSON.parse(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)));
    const parsed = LiveAction.safeParse(json);

    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

export const PROVIDER_LABEL: Record<"github" | "vercel", string> = { github: "GitHub", vercel: "Vercel" };

export function timeLeft(iso: string, now: number = Date.now()): string {
  const ms = Date.parse(iso) - now;

  if (ms <= 0) return "expired";
  const h = Math.floor(ms / 3_600_000);
  const m = Math.floor((ms % 3_600_000) / 60_000);

  return h > 0 ? `${h}h ${m}m left` : `${m}m left`;
}
