// A package readme as React elements: Markdown and the HTML GitHub allows in it, sanitized on the server.
// Readmes are publisher-written, so they are untrusted. The pipeline (unified, remark, rehype) works on
// syntax trees in plain JavaScript, with no DOM, so it runs the same in the Worker, under next dev and in tests.
//
// 1. remark-parse + remark-gfm read Markdown with GitHub's tables, task lists, autolinks and footnotes.
// 2. remark-rehype + rehype-raw turn it into an HTML tree and parse inline HTML (parse5) into that tree.
// 3. rehype-slug gives headings ids, so a readme's own table of contents works.
// 4. rehype-sanitize applies GitHub's allow-list (hast-util-sanitize's default schema, narrowed below): no
//    script, style, iframe, object, form or SVG; no on* handlers, style or target attributes; href only
//    http, https or mailto; src only http or https; every id and name prefixed with "user-content-".
// 5. rewriteTree, on the sanitized tree: relative URLs resolve into the GitHub repository or are dropped,
//    images load over https only, external links get rel="nofollow noopener noreferrer ugc", in-page
//    links follow the prefixed ids, and headings move two levels down to sit under the page's h2.
// 6. hast-util-to-jsx-runtime builds React elements from the tree, so the page never sets inner HTML.
import type { Element, ElementContent, Properties, Root, RootContent } from "hast";
import { toJsxRuntime } from "hast-util-to-jsx-runtime";
import type { ReactElement } from "react";
import { Fragment, jsx, jsxs } from "react/jsx-runtime";
import rehypeRaw from "rehype-raw";
import rehypeSanitize, { defaultSchema, type Options as SanitizeSchema } from "rehype-sanitize";
import rehypeSlug from "rehype-slug";
import remarkGfm from "remark-gfm";
import remarkParse from "remark-parse";
import remarkRehype from "remark-rehype";
import { unified } from "unified";
import { z } from "zod";
import type { GithubRepo } from "./repository";

/** Prefixed onto every id and name in a readme, so `<h2 id="readme">` can't take over the page's own anchors. */
export const ID_PREFIX = "user-content-";

export const EXTERNAL_REL = "nofollow noopener noreferrer ugc";

// Attributes GitHub's schema allows that have no use in a rendered readme and can confuse keyboard users.
const DROPPED_GLOBAL = new Set(["accessKey", "tabIndex", "action", "method", "encType", "accept", "acceptCharset", "longDesc"]);

const SCHEMA: SanitizeSchema = {
  ...defaultSchema,
  clobberPrefix: ID_PREFIX,
  protocols: { ...defaultSchema.protocols, href: ["http", "https", "mailto"], src: ["http", "https"], cite: ["http", "https"] },
  attributes: {
    ...defaultSchema.attributes,
    "*": (defaultSchema.attributes?.["*"] ?? []).filter((a) => Array.isArray(a) || !DROPPED_GLOBAL.has(a)),
    img: ["alt", "src", "width", "height", "align", "title"],
    source: ["srcSet", "media", "type", "width", "height"],
  },
  // Stripped with their contents; anything else not on the list is unwrapped and keeps only its text.
  strip: ["script", "style", "template", "noscript", "iframe", "object", "embed", "svg", "math", "title", "textarea", "select"],
};

// Footnote ids come out bare here; rehype-sanitize prefixes them like every other id.
const processor = unified()
  .use(remarkParse)
  .use(remarkGfm)
  .use(remarkRehype, { allowDangerousHtml: true, clobberPrefix: "" })
  .use(rehypeRaw)
  .use(rehypeSlug)
  .use(rehypeSanitize, SCHEMA);

const SCHEME = /^([a-z][a-z0-9+.-]*):/i;

type UrlUse = "link" | "image";

/** Resolves a repo-relative path to GitHub: raw bytes for images, the blob page for links. Null when it climbs out of the repo. */
function inRepo(path: string, repo: GithubRepo, use: UrlUse): string | null {
  const root = use === "image" ? `https://raw.githubusercontent.com/${repo.owner}/${repo.repo}/HEAD/` : `https://github.com/${repo.owner}/${repo.repo}/blob/HEAD/`;
  // A leading slash means the repository root on GitHub; anything else is relative to the package's folder.
  const fromRoot = path.startsWith("/");
  const base = fromRoot || repo.directory === "" ? root : `${root}${repo.directory}/`;
  let resolved: URL;

  try {
    resolved = new URL(fromRoot ? path.slice(1) : path, base);
  } catch {
    return null;
  }

  return resolved.href.startsWith(root) && resolved.href !== root ? resolved.href : null;
}

/** The URL a readme's link or image may use on this page, or null to drop it. Runs after sanitizing. */
export function safeUrl(raw: string, repo: GithubRepo | null, use: UrlUse): string | null {
  const value = raw.trim();

  if (value === "") return null;

  if (value.startsWith("#")) {
    if (use === "image") return null;
    const id = value.slice(1);

    return id === "" || id.startsWith(ID_PREFIX) ? value : `#${ID_PREFIX}${id}`;
  }

  // Protocol-relative and backslash forms name another host; browsers read "\\" like "//".
  const absolute = /^[/\\]{2}/.test(value) ? `https:${value}` : SCHEME.test(value) ? value : null;

  if (absolute === null) return repo ? inRepo(value, repo, use) : null;
  let url: URL;

  try {
    url = new URL(absolute);
  } catch {
    return null;
  }

  if (use === "image") {
    // The page's CSP lets images load from https only; most image hosts serve both.
    if (url.protocol === "http:") url.protocol = "https:";

    return url.protocol === "https:" ? url.href : null;
  }

  return url.protocol === "https:" || url.protocol === "http:" || url.protocol === "mailto:" ? url.href : null;
}

function stringProp(props: Properties, key: string): string | null {
  const v = z.string().safeParse(props[key]);

  return v.success ? v.data : null;
}

/** srcset candidates ("url 2x, url 300w") with each URL made safe; candidates that can't be are left out. */
function safeSrcSet(raw: string, repo: GithubRepo | null): string | null {
  const kept = raw
    .split(",")
    .map((c) => c.trim().split(/\s+/))
    .flatMap(([url, ...descriptor]) => {
      const safe = url ? safeUrl(url, repo, "image") : null;

      return safe ? [[safe, ...descriptor].join(" ")] : [];
    });

  return kept.length > 0 ? kept.join(", ") : null;
}

const HEADING = /^h([1-6])$/;

/** One sanitized element, rewritten for this page; null removes it. */
function rewriteElement(el: Element, repo: GithubRepo | null): Element | null {
  const props = el.properties;

  if (el.tagName === "img") {
    const src = safeUrl(stringProp(props, "src") ?? "", repo, "image");

    if (src === null) return null;
    el.properties = { ...props, src, loading: "lazy", decoding: "async", referrerPolicy: "no-referrer" };
  } else if (el.tagName === "source") {
    const srcSet = safeSrcSet(stringProp(props, "srcSet") ?? "", repo);

    if (srcSet === null) return null;
    el.properties = { ...props, srcSet };
  } else if (el.tagName === "a") {
    const raw = stringProp(props, "href");
    const href = raw === null ? null : safeUrl(raw, repo, "link");
    const next: Properties = { ...props };

    delete next.href;

    if (href !== null) {
      next.href = href;

      if (!href.startsWith("#")) next.rel = EXTERNAL_REL.split(" ");
    }

    el.properties = next;
  } else {
    const level = HEADING.exec(el.tagName)?.[1];

    if (level) {
      const n = Number(level);
      const className = Array.isArray(props.className) ? props.className : [];

      el.tagName = `h${Math.min(n + 2, 6)}`;
      el.properties = { ...props, className: [...className, `readme-h${n}`] };
    }
  }

  el.children = rewriteChildren(el.children, repo);

  return el;
}

function rewriteChildren<T extends ElementContent | RootContent>(children: T[], repo: GithubRepo | null): T[] {
  return children.flatMap((c) => {
    if (c.type !== "element") return [c];
    const out = rewriteElement(c, repo);

    return out ? [c] : [];
  });
}

/** The sanitized, rewritten tree for a readme. Exported for tests; the page uses renderReadme. */
export function readmeTree(markdown: string, repo: GithubRepo | null): Root {
  const tree = processor.runSync(processor.parse(markdown));

  tree.children = rewriteChildren(tree.children, repo);

  return tree;
}

/** The readme as React elements, ready to render inside `.readme`. */
export function renderReadme(markdown: string, repo: GithubRepo | null): ReactElement {
  return toJsxRuntime(readmeTree(markdown, repo), { Fragment, jsx, jsxs, passKeys: true });
}

/**
 * The first `limit` characters of a readme, cut at a paragraph break (else a line break) near the limit, so
 * the preview ends on a whole block. Unclosed code fences and HTML tags are closed by the parsers.
 */
export function cutReadme(markdown: string, limit: number): string {
  if (markdown.length <= limit) return markdown;
  const head = markdown.slice(0, limit);
  const floor = limit * 0.75;
  const paragraph = head.lastIndexOf("\n\n");

  if (paragraph >= floor) return head.slice(0, paragraph);
  const line = head.lastIndexOf("\n");

  return line >= floor ? head.slice(0, line) : head;
}
