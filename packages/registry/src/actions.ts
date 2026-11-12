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
