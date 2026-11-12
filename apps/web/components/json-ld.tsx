import { jsonLdText, type JsonLdDocument } from "@/lib/agent/seo";

/** Structured data for search engines. A data block, not a script, so the CSP does not apply to it. */
export function JsonLd({ data }: { data: JsonLdDocument }) {
  return <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: jsonLdText(data) }} />;
}
