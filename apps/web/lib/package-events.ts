// One line per entry of a package's public log, as the package page shows it after the actor's name.
import { z } from "zod";
import type { PackageEvent } from "./registry";

/** The item a dismissal or its undo names, as the log shows it: "credential-access evidence (index.js:1)". */
const EvidenceDetail = z.object({ signal: z.string(), file: z.string(), line: z.number() });

/**
 * An undo's detail. Since undos need a reason, `reason` is the undo's and `dismissal.reason` the dismissal's. An
 * older entry kept the dismissal's reason in `reason` and an optional `note` for the undo.
 */
const RestoreDetail = z.union([
  z.object({ reason: z.string(), dismissal: z.object({ reason: z.string() }) }).transform((d) => ({ undo: d.reason, dismissed: d.dismissal.reason })),
  z.object({ reason: z.string(), note: z.string().nullish() }).transform((d) => ({ undo: d.note ?? "", dismissed: d.reason })),
]);

/** The detail fields an entry's line reads; one that is missing or not text reads as "". */
const Text = z.string().catch("");
const Detail = z.object({ version: Text, reason: Text, message: Text, user: Text, tag: Text }).catch({ version: "", reason: "", message: "", user: "", tag: "" });

function evidenceCited(e: PackageEvent): string {
  const d = EvidenceDetail.safeParse(e.detail);

  return d.success ? `${d.data.signal} evidence (${d.data.file}:${d.data.line})` : "evidence";
}

/** What an undo says: why it was undone, and why the item had been dismissed. */
function restoredReasons(e: PackageEvent): string {
  const d = RestoreDetail.safeParse(e.detail);

  if (!d.success) return "";
  const undo = d.data.undo === "" ? "" : `: ${d.data.undo}`;

  return `${undo} (it had been dismissed: ${d.data.dismissed})`;
}

export function describeEvent(e: PackageEvent): string {
  const d = Detail.parse(e.detail);
  const v = d.version;
  const why = d.reason || d.message;
  const reason = why ? `: ${why}` : "";

  switch (e.kind) {
    case "publish":
      return `published ${v}`;
    case "yank":
      return `yanked ${v}${reason}`;
    case "unyank":
      return `restored ${v} to active`;
    case "revoke":
      return `revoked ${v}${reason}`;
    case "revoke-pending":
      return `started revoking ${v}${reason}`;
    case "restore":
      return `downgraded revoke of ${v} to a yank${reason}`;
    case "deprecate":
      return `deprecated ${v}${reason}`;
    case "owner-add":
      return `added owner ${d.user}`;
    case "owner-remove":
      return `removed owner ${d.user}`;
    case "dist-tag":
      return `tagged ${v} as ${d.tag}`;
    case "evidence-dismissed":
      return `dismissed ${evidenceCited(e)} in ${v}${reason}`;
    case "evidence-restored":
      return `restored ${evidenceCited(e)} in ${v}${restoredReasons(e)}`;
    default:
      return e.kind;
  }
}
