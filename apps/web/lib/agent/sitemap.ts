// The sitemap's entries: the site's own pages, the popular packages, and the packages with recent activity on
// this registry (the pages people have just been sent to). Pure; app/sitemap.ts reads the recent feed.
import { canonicalPackagePath, POPULAR_PACKAGES, siteUrl } from "./site";

export type SitemapEntry = { url: string; lastModified?: Date; changeFrequency: "daily" | "weekly" | "monthly"; priority: number };

/** At most this many recent packages, so one busy hour can't crowd the file. */
export const MAX_RECENT = 100;

export function sitemapEntries(input: { recent: readonly { package: string; at: string }[]; now: Date }): SitemapEntry[] {
  const pages: SitemapEntry[] = [
    { url: siteUrl("/"), lastModified: input.now, changeFrequency: "daily", priority: 1 },
    { url: siteUrl("/docs"), changeFrequency: "weekly", priority: 0.8 },
    { url: siteUrl("/compare"), changeFrequency: "monthly", priority: 0.6 },
  ];

  const seen = new Set<string>();
  const packages: SitemapEntry[] = [];

  for (const p of POPULAR_PACKAGES) {
    seen.add(p.name);
    packages.push({ url: siteUrl(canonicalPackagePath(p.name)), changeFrequency: "daily", priority: 0.7 });
  }

  for (const e of input.recent) {
    if (seen.has(e.package) || seen.size >= POPULAR_PACKAGES.length + MAX_RECENT) continue;
    seen.add(e.package);
    const at = new Date(e.at);

    packages.push({ url: siteUrl(canonicalPackagePath(e.package)), lastModified: Number.isNaN(at.getTime()) ? undefined : at, changeFrequency: "daily", priority: 0.5 });
  }

  return [...pages, ...packages];
}
