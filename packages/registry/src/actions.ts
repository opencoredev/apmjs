// Live-state changes a person can authorize one at a time: what a CLI confirmation on the website names,
// and what a staging token needs a fresh code for. One shape, one canonical key per action, and every
// parameter that changes what the command does is part of both: a confirmation of one command never
// authorizes another (another time range, a real run after a preview, another deprecation message).
import { z } from "zod";

const Name = z.string().min(1).max(214);
const Version = z.string().min(1).max(256);

/** One version's new deprecation message; null takes the deprecation off. */
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

/** An incident's `since` as one canonical ISO string, so "2026-11-01" and "2026-11-01T00:00:00.000Z" are the same command. */
export function canonicalSince(since: string): string {
  const t = Date.parse(since);

  return Number.isNaN(t) ? since : new Date(t).toISOString();
}

function sortedChanges(changes: readonly z.infer<typeof DeprecateChange>[]): [string, string | null][] {
  return changes.map((c): [string, string | null] => [c.version, c.message]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
}

/** The stored key of an action: equal keys mean the same command. */
export function actionKey(a: LiveAction): string {
  switch (a.kind) {
    case "revoke":
    case "restore":
    case "yank":
    case "unyank":
      return JSON.stringify([a.kind, a.name, a.version]);
    case "dist-tag":
      return JSON.stringify([a.kind, a.name, a.tag, a.version]);
    case "deprecate":
      return JSON.stringify([a.kind, a.name, sortedChanges(a.changes)]);
    case "incident":
      return JSON.stringify([a.kind, canonicalSince(a.since), a.dryRun]);
    case "owner-add":
    case "owner-remove":
      return JSON.stringify([a.kind, a.name, a.user]);
    default: {
      const _exhaustive: never = a;

      return _exhaustive;
    }
  }
}

/** The command a person sees when they confirm the action. */
export function commandLine(a: LiveAction): string {
  switch (a.kind) {
    case "revoke":
    case "restore":
    case "yank":
    case "unyank":
      return `apm ${a.kind} ${a.name}@${a.version}`;
    case "dist-tag":
      return a.version === null ? `npm dist-tag rm ${a.name} ${a.tag}` : `npm dist-tag add ${a.name}@${a.version} ${a.tag}`;
    case "deprecate":
      return sortedChanges(a.changes)
        .map(([version, message]) => `npm deprecate ${a.name}@${version} ${JSON.stringify(message ?? "")}`)
        .join(" && ");
    case "incident":
      return `apm incident --since ${canonicalSince(a.since)}${a.dryRun ? " --dry-run" : ""}`;
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

/** The website link that confirms exactly this command. */
export function confirmUrl(webUrl: string, a: LiveAction): string {
  return `${webUrl}account?confirm=${Buffer.from(JSON.stringify(a)).toString("base64url")}`;
}

// ---------- website actions a second factor confirms ----------
// A code or passkey check on the website confirms exactly one of these, from one session: the change, and every
// parameter that decides what it does. The change spends a confirmation only when its own key is the same.

const Digest = z.string().min(1).max(200);

/** One evidence item: the version's exact tarball digest, the scorer that cited it, the signal, the file and the line. */
export const EvidenceKey = z.object({
  name: Name,
  version: Version,
  digest: Digest,
  scorer: z.string().min(1).max(64),
  signal: z.string().min(1).max(64),
  file: z.string().min(1).max(1024),
  line: z.number().int().min(1),
});

export type EvidenceKey = z.infer<typeof EvidenceKey>;

/** Why a reviewer dismisses an item: shown in public. */
export const DismissReason = z.string().trim().min(1, "Say why this evidence is wrong; the reason is shown in public.").max(2000);

/** Why a reviewer undoes a dismissal: shown in public next to the dismissal's reason. */
export const RestoreReason = z.string().trim().min(1, "Say why you are undoing this dismissal; the reason is shown in public.").max(2000);

/** The account changes that add or remove a way in (auth.ts's gated Better Auth routes). */
export const ACCOUNT_CHANGES = ["link-social", "two-factor/enable", "two-factor/disable", "passkey/verify-registration"] as const;

export type AccountChange = (typeof ACCOUNT_CHANGES)[number];

export function isAccountChange(path: string): path is AccountChange {
  return ACCOUNT_CHANGES.some((c) => c === path);
}

export const ReviewDecision = z.object({
  name: Name,
  version: Version,
  digest: Digest,
  decision: z.enum(["confirm", "dismiss"]),
  note: z.string().trim().max(2000).default(""),
});

export const SessionAction = z.discriminatedUnion("kind", [
  /** Approving one staged upload; the row behind an id never changes. */
  z.object({ kind: z.literal("approve"), id: z.string().min(1).max(64) }),
  /** Confirming one CLI command on the website, which the CLI may then run once. */
  z.object({ kind: z.literal("cli-confirm"), command: LiveAction }),
  ReviewDecision.extend({ kind: z.literal("review-decision") }),
  EvidenceKey.extend({ kind: z.literal("evidence-dismiss"), reason: DismissReason }),
  EvidenceKey.extend({ kind: z.literal("evidence-restore"), reason: RestoreReason }),
  z.object({ kind: z.literal("account"), change: z.enum(ACCOUNT_CHANGES) }),
]);

export type SessionAction = z.infer<typeof SessionAction>;

/** The stored key of a website action: equal keys mean the same change with the same parameters. */
export function sessionActionKey(a: SessionAction): string {
  switch (a.kind) {
    case "approve":
      return JSON.stringify([a.kind, a.id]);
    case "cli-confirm":
      return JSON.stringify([a.kind, actionKey(a.command)]);
    case "review-decision":
      return JSON.stringify([a.kind, a.name, a.version, a.digest, a.decision, a.note]);
    case "evidence-dismiss":
    case "evidence-restore":
      return JSON.stringify([a.kind, a.name, a.version, a.digest, a.scorer, a.signal, a.file, a.line, a.reason]);
    case "account":
      return JSON.stringify([a.kind, a.change]);
    default: {
      const _exhaustive: never = a;

      return _exhaustive;
    }
  }
}
