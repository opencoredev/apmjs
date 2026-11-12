// Per-page metadata (title, description, canonical URL, Open Graph and Twitter cards) and the JSON-LD the pages
// embed. Pure, so the pages and the tests share it.
import type { Metadata } from "next";
import { canonicalPackagePath, SITE_URL, siteUrl } from "./site";

export const SITE_NAME = "apm";

export const SITE_TITLE = "apm: check npm packages before you install them";

export const SITE_DESCRIPTION =
  "A package registry in front of npm. Every version gets a security score with the cited line behind every lost point, new versions wait 24 hours, and bad ones can be yanked or revoked. Works with bun, npm and pnpm.";

/** Search engines show about this many characters of a description. */
const DESCRIPTION_CHARS = 158;

export function clip(text: string, max = DESCRIPTION_CHARS): string {
  const flat = text.replace(/\s+/g, " ").trim();

  if (flat.length <= max) return flat;
  const cut = flat.slice(0, max - 1);
  const space = cut.lastIndexOf(" ");

  return `${(space > max * 0.6 ? cut.slice(0, space) : cut).replace(/[\s,.;:]+$/, "")}…`;
}

/** Title, description, canonical URL and the social cards for one page. `image` is a site path such as /og. */
export function pageMetadata(input: { title: string; description: string; path: string; image?: string; imageAlt?: string; type?: "website" | "article"; noindex?: boolean }): Metadata {
  const description = clip(input.description);
  const image = { url: input.image ?? "/og", width: 1200, height: 630, alt: input.imageAlt ?? SITE_TITLE };

  return {
    title: input.title,
    description,
    alternates: { canonical: input.path },
    openGraph: { type: input.type ?? "website", siteName: SITE_NAME, url: input.path, title: input.title, description, images: [image] },
    twitter: { card: "summary_large_image", title: input.title, description, images: [image.url] },
    robots: input.noindex ? { index: false, follow: true } : undefined,
  };
}

/** What the package page's metadata needs to know. */
export type PackageMeta = { name: string; description: string; latest: string | null; score: { score: number; grade: string } | null };

export function packageMetadata(p: PackageMeta): Metadata {
  const scoreText = p.score ? `apm security score ${p.score.score}/100 (grade ${p.score.grade})` : "not scored by apm yet";
  const title = `${p.name}${p.latest ? ` ${p.latest}` : ""}: ${p.score ? `score ${p.score.score}/100 (${p.score.grade})` : "security score"} · apm`;
  const short = p.description ? clip(p.description, 90) : "";
  const lead = short === "" ? "" : /[.!?…]$/.test(short) ? `${short} ` : `${short}. `;

  return {
    ...pageMetadata({
      title,
      description: `${lead}${p.name}${p.latest ? ` ${p.latest}` : ""} is ${scoreText}. See every risk signal with its cited line, the AI review and how to install it.`,
      path: canonicalPackagePath(p.name),
      image: `/og${canonicalPackagePath(p.name).slice("/package".length)}`,
      imageAlt: `${p.name} on apm: ${scoreText}`,
    }),
    // the Markdown view of the same page, for agents
    alternates: { canonical: canonicalPackagePath(p.name), types: { "text/markdown": `${canonicalPackagePath(p.name)}.md` } },
  };
}

/** The home page's WebSite JSON-LD, with the search box as a SearchAction. */
export function websiteJsonLd() {
  return {
    "@context": "https://schema.org",
    "@type": "WebSite",
    name: SITE_NAME,
    alternateName: "apmjs",
    url: `${SITE_URL}/`,
    description: SITE_DESCRIPTION,
    potentialAction: {
      "@type": "SearchAction",
      target: { "@type": "EntryPoint", urlTemplate: `${SITE_URL}/?q={search_term_string}` },
      "query-input": "required name=search_term_string",
    },
  };
}

/**
 * A package page's SoftwareSourceCode JSON-LD. Only fields the registry answer actually holds: a field it lacks is
 * undefined, which JSON.stringify leaves out.
 */
export function packageJsonLd(p: PackageMeta & { license: string | null; repository: string | null; homepage: string | null; maintainers: string[] }) {
  return {
    "@context": "https://schema.org",
    "@type": "SoftwareSourceCode",
    name: p.name,
    url: siteUrl(canonicalPackagePath(p.name)),
    description: p.description ? clip(p.description, 300) : undefined,
    version: p.latest ?? undefined,
    programmingLanguage: "JavaScript",
    runtimePlatform: "Node.js",
    license: p.license ?? undefined,
    codeRepository: p.repository ?? undefined,
    sameAs: p.homepage ?? undefined,
    maintainer: p.maintainers.length > 0 ? p.maintainers.slice(0, 5).map((name) => ({ "@type": "Person", name })) : undefined,
    additionalProperty: p.score ? { "@type": "PropertyValue", name: "apm security score", value: p.score.score, maxValue: 100, description: `grade ${p.score.grade}` } : undefined,
    isPartOf: { "@type": "WebSite", name: SITE_NAME, url: `${SITE_URL}/` },
  };
}

export type JsonLdDocument = ReturnType<typeof websiteJsonLd> | ReturnType<typeof packageJsonLd>;

/** JSON-LD as a script body: `<` escaped so publisher text can't close the script element. */
export function jsonLdText(data: JsonLdDocument): string {
  return JSON.stringify(data).replace(/</g, "\\u003c");
}
