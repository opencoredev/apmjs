// The package's homepage, repository and issue tracker as plain links. package-links.ts has already dropped
// anything that isn't an http(s) URL; the rel keeps a publisher's link from passing ranking or the opener.
import { CircleDotIcon, CodeIcon, GlobeIcon } from "lucide-react";
import { EXTERNAL_REL } from "@/lib/readme";
import type { PackageLink, PackageLinkKind } from "@/lib/package-links";

const ICONS: Record<PackageLinkKind, typeof GlobeIcon> = { homepage: GlobeIcon, repository: CodeIcon, issues: CircleDotIcon };

export function PackageLinks({ links, className }: { links: readonly PackageLink[]; className?: string }) {
  if (links.length === 0) return null;

  return (
    <ul aria-label="Links" className={`flex flex-wrap gap-x-5 gap-y-1 text-sm ${className ?? ""}`}>
      {links.map((l) => {
        const Icon = ICONS[l.kind];

        return (
          <li key={l.kind} className="min-w-0 max-w-full">
            <a href={l.href} rel={EXTERNAL_REL} title={`${l.label}: ${l.href}`} className="group inline-flex min-h-8 max-w-full items-center gap-1.5 text-muted-foreground transition-colors hover:text-foreground">
              <Icon className="size-4 shrink-0" aria-hidden />
              <span className="shrink-0">{l.label}</span>
              <span className="min-w-0 truncate font-mono text-[13px] text-foreground/80 underline-offset-4 group-hover:underline">{l.display}</span>
            </a>
          </li>
        );
      })}
    </ul>
  );
}
