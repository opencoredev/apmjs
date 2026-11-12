// Score evidence an apm reviewer dismisses. Some confirmed signals are false (a credential file named in a deny
// list, WebAssembly counted as obfuscation); the fix is a person's decision for that exact content, not a looser
// rule. A reviewer (APM_ADMINS), signed in on the website and with a fresh code or passkey check, dismisses one
// evidence item: the version's tarball digest, the scorer that cited it, the signal, the file and the line. The
// score is recomputed without it wherever it is read (db.ts applies dismissals as versions load), the dismissal and
// its undo go into the package's public log, and nothing carries over to other bytes, versions or scorers.
import { Effect } from "effect";
import type * as SqlClient from "effect/sql/SqlClient";
import { z } from "zod";
import { DISMISSABLE, evidenceAt, parseAnalysis } from "@apm/core";
import { reportFor } from "./apm.ts";
import type { Auth } from "./auth.ts";
import { Clock } from "./clock.ts";
import { RegistryConfig } from "./config.ts";
import { Store, type DismissalKey } from "./db.ts";
import type { AuthError, HttpFailure, StoreError } from "./errors.ts";
import { fail, json, parseBody } from "./http.ts";
import { checkOrigin, resolveVersion, viewerOf, type SessionViewer, type Viewer } from "./review.ts";
import type { Caller } from "./server.ts";
import { ProofFields, secondFactor } from "./step-up.ts";

const MAX_BODY_BYTES = 16 * 1024;

const Item = {
  name: z.string().min(1).max(214),
  version: z.string().min(1).max(256),
  digest: z.string().min(1).max(200),
  scorer: z.string().min(1).max(64),
  signal: z.string().min(1).max(64),
  file: z.string().min(1).max(1024),
  line: z.number().int().min(1),
};

const DismissBody = z.object({ ...Item, reason: z.string().trim().min(1, "Say why this evidence is wrong.").max(2000), ...ProofFields });

const RestoreBody = z.object({ ...Item, note: z.string().trim().max(2000).default(""), ...ProofFields });

type ItemInput = z.infer<z.ZodObject<typeof Item>>;

function adminsOf(admins: readonly string[]): ReadonlySet<string> {
  return new Set(admins.flatMap((a) => (a.trim() === "" ? [] : [a.trim().toLowerCase()])));
}

/** One of apm's reviewers, on the website. A token never counts: a stolen CLI or CI token must not change a score. */
const isAdmin = (v: Viewer) =>
  Effect.gen(function* () {
    const { admins } = yield* RegistryConfig;

    return v.kind === "user" && v.via.kind === "session" && v.githubLogin !== null && adminsOf(admins).has(v.githubLogin);
  });

/**
 * The version an item belongs to, checked against what the registry holds now: the digest is this version's, the
 * scorer is the one that scored these bytes, and the item is evidence that score cites (`dismissed` says whether a
 * reviewer has already dismissed it).
 */
const checkItem = (d: ItemInput) =>
  Effect.gen(function* () {
    if (!DISMISSABLE.has(d.signal)) return { kind: "refused", res: fail(422, "Only code evidence (shell, network, credential, eval, obfuscation) can be dismissed.") } as const;
    const got = yield* resolveVersion(d.name, d.version);

    if (got.digest !== d.digest) return { kind: "refused", res: fail(409, "This version's tarball has a different digest; reload the page.") } as const;
    const analysis = parseAnalysis(got.version.score);

    if (!analysis) return { kind: "refused", res: fail(409, "This version has not been scored yet.") } as const;

    if (analysis.scorer !== d.scorer) return { kind: "refused", res: fail(409, `This version is scored by ${analysis.scorer} now; reload the page.`) } as const;

    const cites = (e: string): boolean => {
      const at = evidenceAt(e);

      return at !== null && at.file === d.file && at.line === d.line;
    };

    const signal = analysis.signals.find((s) => s.id === d.signal);
    const live = signal !== undefined && [...signal.evidence, ...(signal.more ?? []), ...(signal.fallback ?? [])].some(cites);
    const dismissed = (analysis.dismissed ?? []).some((x) => x.signal === d.signal && x.file === d.file && x.line === d.line);

    return { kind: "ok", version: got.version, live, dismissed } as const;
  });

const keyOf = (d: ItemInput): DismissalKey => ({ package: d.name, version: d.version, digest: d.digest, scorer: d.scorer, signal: d.signal, file: d.file, line: d.line });

/** The version's score as it reads now, dismissals applied. */
const scoreNow = (name: string, version: string) =>
  Effect.gen(function* () {
    const got = yield* resolveVersion(name, version);
    const r = reportFor(got.version, yield* (yield* Clock).now);

    return r ? { score: r.score, grade: r.grade } : null;
  });

const dismissResponse = (req: Request, viewer: SessionViewer) =>
  Effect.gen(function* () {
    const d = yield* parseBody(req, DismissBody, MAX_BODY_BYTES);
    const item = yield* checkItem(d);

    if (item.kind === "refused") return item.res;

    if (item.dismissed) return fail(409, "This evidence is already dismissed.");

    if (!item.live) return fail(404, "This version's score cites no such evidence.");
    // a dismissal changes a public score: a fresh code or passkey check for exactly this item
    yield* secondFactor({ session: viewer.via.session, body: d, purpose: `evidence:${JSON.stringify(["dismiss", d.name, d.version, d.digest, d.scorer, d.signal, d.file, d.line])}` });
    const store = yield* Store;
    const at = yield* (yield* Clock).now;
    const by = viewer.githubLogin ?? viewer.user.name;
    const added = yield* store.addDismissal({ ...keyOf(d), reason: d.reason, by, at });

    if (!added) return fail(409, "This evidence is already dismissed.");
    yield* store.addEvent({
      package: d.name,
      kind: "evidence-dismissed",
      actor: by,
      at,
      detail: { version: d.version, digest: d.digest, scorer: d.scorer, signal: d.signal, file: d.file, line: d.line, reason: d.reason },
    });

    return json({ ok: true, score: yield* scoreNow(d.name, d.version) });
  });

const restoreResponse = (req: Request, viewer: SessionViewer) =>
  Effect.gen(function* () {
    const d = yield* parseBody(req, RestoreBody, MAX_BODY_BYTES);
    const item = yield* checkItem(d);

    if (item.kind === "refused") return item.res;

    if (!item.dismissed) return fail(404, "This evidence is not dismissed.");
    yield* secondFactor({ session: viewer.via.session, body: d, purpose: `evidence:${JSON.stringify(["restore", d.name, d.version, d.digest, d.scorer, d.signal, d.file, d.line])}` });
    const store = yield* Store;
    const at = yield* (yield* Clock).now;
    const by = viewer.githubLogin ?? viewer.user.name;
    const undone = yield* store.restoreDismissal({ ...keyOf(d), by, at });

    if (!undone) return fail(404, "This evidence is not dismissed.");
    yield* store.addEvent({
      package: d.name,
      kind: "evidence-restored",
      actor: by,
      at,
      detail: { version: d.version, digest: d.digest, scorer: d.scorer, signal: d.signal, file: d.file, line: d.line, reason: undone.reason, note: d.note === "" ? null : d.note },
    });

    return json({ ok: true, score: yield* scoreNow(d.name, d.version) });
  });

/** `/-/apm/v1/evidence-admin/…`: whether the viewer is a reviewer, and the dismiss and undo actions. */
export const evidenceRoute = (
  req: Request,
  url: URL,
  caller: Caller,
): Effect.Effect<Response | null, HttpFailure | StoreError | AuthError, Store | SqlClient.SqlClient | Clock | RegistryConfig | Auth> =>
  Effect.gen(function* () {
    const p = url.pathname;

    if (!p.startsWith("/-/apm/v1/evidence-admin/")) return null;
    const viewer = yield* viewerOf(req, caller);
    const admin = yield* isAdmin(viewer);

    if (p === "/-/apm/v1/evidence-admin/me" && req.method === "GET") return json({ admin }, 200, { "cache-control": "no-store" });

    if (viewer.kind !== "user") return fail(401, "Sign in first.");

    if (!admin || viewer.via.kind !== "session") {
      return fail(403, viewer.via.kind === "token" ? "Evidence is dismissed on the website only: sign in there. Tokens cannot change a score." : "Only apm's reviewers can dismiss evidence.");
    }

    const session: SessionViewer = { ...viewer, via: viewer.via };

    if (req.method !== "POST") return fail(404, "Not found");
    yield* checkOrigin(req, viewer);

    if (p === "/-/apm/v1/evidence-admin/dismiss") return yield* dismissResponse(req, session);

    if (p === "/-/apm/v1/evidence-admin/restore") return yield* restoreResponse(req, session);

    return fail(404, "Not found");
  });
