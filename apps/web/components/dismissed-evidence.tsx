// Evidence an apm reviewer dismissed stays on the version page: struck through, with the reason and the date, and,
// for a reviewer, the control that undoes it.
import { EvidenceAdminControl, type EvidenceItem } from "@/components/evidence-admin";
import type { Dismissed } from "@/lib/registry";

/** A dismissed item, still shown: struck through, with the reviewer's reason and the date. */
export function DismissedEvidence({ d, item }: { d: Dismissed; item: EvidenceItem | null }) {
  const day = new Date(d.at).toISOString().slice(0, 10);

  return (
    <div className="mt-2 border-l-2 border-inverse-border pl-3">
      {d.evidence.slice(0, 1).map((ev) => (
        <div key={ev} className="font-mono text-[12.5px] leading-5 text-inverse-muted line-through decoration-inverse-muted [overflow-wrap:anywhere]">
          {ev}
        </div>
      ))}
      <p className="mt-0.5 text-[13px] leading-5 text-pretty text-inverse-foreground">
        Dismissed by an apm reviewer: {d.reason} <span className="text-inverse-muted">({day})</span>
      </p>
      {item && <EvidenceAdminControl item={item} mode="restore" />}
    </div>
  );
}

