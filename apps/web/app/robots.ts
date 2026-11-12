// /robots.txt: everything may be crawled. The signed-in pages (/account, /approve, /admin, /device) send
// X-Robots-Tag: noindex instead (next.config.ts), which a crawler can only see if it may fetch them.
import type { MetadataRoute } from "next";
import { siteUrl } from "@/lib/agent/site";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [{ userAgent: "*", allow: "/" }],
    sitemap: siteUrl("/sitemap.xml"),
    host: siteUrl(""),
  };
}
