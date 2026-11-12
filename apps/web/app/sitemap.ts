// /sitemap.xml: the site's pages, the popular packages, and the packages with recent activity or scored lately.
import type { MetadataRoute } from "next";
import { connection } from "next/server";
import { sitemapPackages } from "@/lib/agent/registry-source";
import { sitemapEntries } from "@/lib/agent/sitemap";

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  // request time only: at build the registry is not there, and a prerender would freeze an empty list
  await connection();

  return sitemapEntries({ recent: await sitemapPackages(), now: new Date() });
}
