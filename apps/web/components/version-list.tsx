"use client";

// Version history on the package page. Phones show the newest few, wider screens a dozen, and one button
// opens the rest, so the facts and the readme stay near the top.
import Link from "next/link";
import { useState } from "react";
import { ChevronDownIcon } from "lucide-react";
import { cn } from "cn";
import { ScoreBadge, StatusBadge } from "@/components/score-badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { PackageInfo } from "@/lib/registry";

/** A version row with its age already worded on the server, so hydration matches. */
export type VersionRow = PackageInfo["versions"][number] & { when: string };

/** Rows shown before "Show all", below the lg breakpoint and from it on. */
export const VERSIONS_SHOWN = { phone: 5, wide: 12 } as const;

export function VersionList({ rows, packageHref, current }: { rows: VersionRow[]; packageHref: string; current: string | null }) {
  const [open, setOpen] = useState(false);
  const shown = open ? rows : rows.slice(0, VERSIONS_SHOWN.wide);
  const hiddenOnPhone = rows.length > VERSIONS_SHOWN.phone;
  const hiddenWide = rows.length > VERSIONS_SHOWN.wide;

  return (
    <div className="overflow-hidden rounded-xl border">
      <Table>
        <TableHeader className="bg-surface">
          <TableRow className="hover:bg-transparent">
            <TableHead className="h-10 pl-4 font-normal text-muted-foreground">Version</TableHead>
            <TableHead className="hidden h-10 font-normal text-muted-foreground sm:table-cell">Published</TableHead>
            <TableHead className="hidden h-10 font-normal text-muted-foreground sm:table-cell">By</TableHead>
            <TableHead className="h-10 pr-4 text-right font-normal text-muted-foreground">Score</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {shown.map((v, i) => (
            <TableRow key={v.version} className={cn("hover:bg-surface/60", !open && i >= VERSIONS_SHOWN.phone && "max-lg:hidden")}>
              <TableCell className="py-3 pl-4 whitespace-normal">
                <div className="flex flex-wrap items-center gap-2">
                  <Link
                    href={`${packageHref}?v=${encodeURIComponent(v.version)}`}
                    aria-current={v.version === current ? "page" : undefined}
                    className={cn("font-mono text-[15px] underline-offset-4 hover:underline aria-[current=page]:font-semibold", v.status !== "active" && "text-muted-foreground line-through")}
                  >
                    {v.version}
                  </Link>
                  <StatusBadge status={v.status} />
                  {v.deprecated && <span className="text-xs text-muted-foreground">deprecated</span>}
                </div>
                {v.statusReason && <div className="mt-1 text-sm text-muted-foreground">{v.statusReason}</div>}
                <div className="mt-0.5 text-xs text-muted-foreground sm:hidden">
                  {v.when} by <span className="font-mono">{v.publishedBy}</span>
                </div>
              </TableCell>
              <TableCell className="hidden py-3 text-muted-foreground sm:table-cell">{v.when}</TableCell>
              <TableCell className="hidden py-3 font-mono text-[13px] text-muted-foreground sm:table-cell">{v.publishedBy}</TableCell>
              <TableCell className="py-3 pr-4 text-right">
                <ScoreBadge score={v.score} grade={v.grade} unscorable={Boolean(v.unscorable)} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {hiddenOnPhone && (
        <button
          type="button"
          aria-expanded={open}
          onClick={() => setOpen((o) => !o)}
          className={cn(
            "flex min-h-11 w-full items-center justify-center gap-1.5 border-t bg-surface px-4 py-2.5 text-sm font-medium transition-colors hover:bg-secondary",
            !hiddenWide && "lg:hidden",
          )}
        >
          {open ? "Show fewer versions" : `Show all ${rows.length} versions`}
          <ChevronDownIcon className={cn("size-4 text-muted-foreground transition-transform", open && "rotate-180")} aria-hidden />
        </button>
      )}
    </div>
  );
}
