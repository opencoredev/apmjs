// A package readme as React elements: Markdown and the HTML GitHub allows in it, sanitized on the server.
// Readmes are publisher-written, so they are untrusted. The pipeline (unified, remark, rehype) works on
// syntax trees in plain JavaScript, with no DOM, so it runs the same in the Worker, under next dev and in tests.
//
// 0. measureSource reads the text once, without parsing, and over-estimates how deeply it nests and how many
//    nodes it makes. The parsers and React recurse once per level, and workerd's stack is far smaller than
//    Bun's, so a readme past MAX_DEPTH or MAX_NODES is shown as escaped text instead (see renderReadme).
// 1. remark-parse + remark-gfm read Markdown with GitHub's tables, task lists, autolinks and footnotes.
// 2. remark-rehype + rehype-raw turn it into an HTML tree and parse inline HTML (parse5) into that tree.
// 3. rehype-slug gives headings ids, so a readme's own table of contents works. Every id and name is noted
//    here, before sanitizing, so in-page links can follow them (step 5).
// 4. rehype-sanitize applies GitHub's allow-list (hast-util-sanitize's default schema, narrowed below): no
//    script, style, iframe, object, form or SVG; no on* handlers, style or target attributes; href only
//    http, https or mailto; src only http or https; every id and name prefixed with "user-content-".
//    The sanitized tree is measured again, so nothing the source check missed reaches React.
// 5. rewriteTree, on the sanitized tree and without recursion: relative URLs resolve into the GitHub
//    repository or are dropped, images load over https only, external links get rel="nofollow noopener
//    noreferrer ugc", in-page links follow the ids from step 3, and headings move two levels down to sit
//    under the page's h2.
// 6. hast-util-to-jsx-runtime builds React elements from the tree, so the page never sets inner HTML.
//
// Anything that throws on the way falls back to the escaped source and logs one line; the page still renders.
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

/**
 * The deepest a readme may nest (HTML elements, blockquotes, list markers and indentation, counted together)
 * and still be rendered. Real readmes stay under 20; workerd overflows its stack at about 1,500 levels.
 */
export const MAX_DEPTH = 100;

/** The most nodes a readme may make and still be rendered. A 20,000-character preview of ordinary Markdown makes a few thousand. */
export const MAX_NODES = 30_000;

// The sanitized tree's own limit. One list level is two elements (ul, li) and a paragraph adds one, so this
// sits well above MAX_DEPTH; it catches nesting the source check can't see, such as emphasis inside emphasis.
const MAX_TREE_DEPTH = 4 * MAX_DEPTH;

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
const toHtmlTree = unified().use(remarkParse).use(remarkGfm).use(remarkRehype, { allowDangerousHtml: true, clobberPrefix: "" }).use(rehypeRaw).use(rehypeSlug);

const sanitizer = unified().use(rehypeSanitize, SCHEMA);

/** How deeply a readme nests and how many nodes it has. */
export type Extent = { depth: number; nodes: number };

// Elements a parser closes by itself when the next one starts (<p>, <li>, <td> …) and elements with no
// content (<br>, <img> …): neither adds a level, so the source check doesn't count them.
const NO_DEPTH = new Set(
  ["p", "li", "dt", "dd", "tr", "td", "th", "thead", "tbody", "tfoot", "colgroup", "caption", "option", "optgroup", "rb", "rt", "rp", "rtc"].concat(
    ["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"],
  ),
);

// An HTML start or end tag. [^<>]* stops at the next bracket, so the scan stays linear.
const TAG = /<(\/?)([A-Za-z][A-Za-z0-9-]*)[^<>]*>/g;

// A list marker at the cursor: -, * or +, or up to nine digits and . or ), then a space, a tab or the line's end.
const LIST_MARKER = /(?:[-*+]|\d{1,9}[.)])(?=[ \t]|$)/y;

/**
 * The containers that open a line: each > and list marker is a level, and every two columns of indentation
 * another. The space after a > and the spaces after a list marker belong to the marker, so they don't count.
 */
function lineDepth(line: string): number {
  let markers = 0;
  let columns = 0;
  let i = 0;

  while (i < line.length) {
    const c = line[i];

    if (c === " ") {
      columns += 1;
      i += 1;
    } else if (c === "\t") {
      columns += 4;
      i += 1;
    } else if (c === ">") {
      markers += 1;
      i += line[i + 1] === " " ? 2 : 1;
    } else {
      LIST_MARKER.lastIndex = i;
      const marker = LIST_MARKER.exec(line);

      if (marker === null) break;
      markers += 1;
      i += marker[0].length;

      for (let gap = 0; gap < 4 && line[i] === " "; gap += 1) i += 1;
    }
  }

  return markers + Math.floor(columns / 2);
}

/**
 * An over-estimate of a readme's nesting and size, read in one pass before any parser sees it: HTML start
 * tags still open, plus the blockquotes, list markers and indentation that open each line. Over-counting only
 * shows a readme as text; under-counting is caught by the sanitized tree's check and the fallback.
 */
export function measureSource(markdown: string): Extent {
  let open = 0;
  let depth = 0;
  let nodes = 0;

  for (const line of markdown.split("\n")) {
    const containers = lineDepth(line);

    nodes += 1 + containers;
    depth = Math.max(depth, open + containers);

    for (const tag of line.matchAll(TAG)) {
      nodes += 1;
      const name = (tag[2] ?? "").toLowerCase();

      // "<div/>" opens a div: HTML ignores the slash on anything but a void element.
      if (NO_DEPTH.has(name)) continue;
      open = tag[1] === "/" ? Math.max(0, open - 1) : open + 1;
      depth = Math.max(depth, open + containers);
    }
  }

  return { depth, nodes };
}

type Parent = Root | Element;

/** Every node under `tree` with its element depth, visited from an explicit stack so no depth can overflow. */
function walk(tree: Root, visit: (node: RootContent | ElementContent, depth: number) => void): void {
  const stack: { node: Parent; depth: number }[] = [{ node: tree, depth: 0 }];

  for (let top = stack.pop(); top; top = stack.pop()) {
    for (const child of top.node.children) {
      visit(child, top.depth + 1);

      if (child.type === "element") stack.push({ node: child, depth: top.depth + 1 });
    }
  }
}

function measureTree(tree: Root): Extent {
  const extent: Extent = { depth: 0, nodes: 0 };

  walk(tree, (node, depth) => {
    extent.nodes += 1;
    extent.depth = Math.max(extent.depth, depth);
  });

  return extent;
}

const SCHEME = /^([a-z][a-z0-9+.-]*):/i;

type UrlUse = "link" | "image";

/** Where in-page links may point: each id or name as the readme wrote it, mapped to the id it has after sanitizing. */
type Anchors = { sanitized: ReadonlyMap<string, string>; present: ReadonlySet<string> };

type Rewrite = { repo: GithubRepo | null; anchors: Anchors };

function stringProp(props: Properties, key: string): string | null {
  const v = z.string().safeParse(props[key]);

  return v.success ? v.data : null;
}

/** Each id and name in a tree: as written before sanitizing, or as they ended up after. */
function anchorNames(tree: Root): string[] {
  const names: string[] = [];

  walk(tree, (node) => {
    if (node.type !== "element") return;

    for (const key of ["id", "name"]) {
      const value = stringProp(node.properties, key);

      if (value) names.push(value);
    }
  });

  return names;
}

/** A fragment link's target: the sanitized id of what the readme named, else the id as written if it exists after sanitizing, else prefixed so it can't reach the page's own anchors. */
function fragmentTarget(id: string, anchors: Anchors): string {
  return anchors.sanitized.get(id) ?? (anchors.present.has(id) || id.startsWith(ID_PREFIX) ? id : `${ID_PREFIX}${id}`);
}

/** Resolves a repo-relative path to GitHub: raw bytes for images, the blob page for links. Null when it climbs out of the repo. */
function inRepo(path: string, repo: GithubRepo, use: UrlUse): string | null {
  const root = use === "image" ? `https://raw.githubusercontent.com/${repo.owner}/${repo.repo}/HEAD/` : `https://github.com/${repo.owner}/${repo.repo}/blob/HEAD/`;
  // A leading slash means the repository root on GitHub; anything else is relative to the package's folder.
  const fromRoot = path.startsWith("/");
  // Each folder name is encoded, so a # or ? in one is part of the path, not a fragment or query that cuts the base short.
  const directory = repo.directory.split("/").map(encodeURIComponent).join("/");
  const base = fromRoot || repo.directory === "" ? root : `${root}${directory}/`;
  let resolved: URL;

  try {
    resolved = new URL(fromRoot ? path.slice(1) : path, base);
  } catch {
    return null;
  }

  return resolved.href.startsWith(root) && resolved.href !== root ? resolved.href : null;
}

/** The URL a readme's link or image may use on this page, or null to drop it. Runs after sanitizing. */
function safeUrl(raw: string, rewrite: Rewrite, use: UrlUse): string | null {
  const value = raw.trim();

  if (value === "") return null;

  if (value.startsWith("#")) {
    if (use === "image") return null;
    const id = value.slice(1);

    return id === "" ? value : `#${fragmentTarget(id, rewrite.anchors)}`;
  }

  // Protocol-relative and backslash forms name another host; browsers read "\\" like "//".
  const absolute = /^[/\\]{2}/.test(value) ? `https:${value}` : SCHEME.test(value) ? value : null;

  if (absolute === null) return rewrite.repo ? inRepo(value, rewrite.repo, use) : null;
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

/** One srcset candidate as written: its URL and its descriptors (none, or "2x", "300w" …). */
export type SrcSetCandidate = { url: string; descriptors: string[] };

const isSpace = (c: string | undefined): boolean => c === " " || c === "\t" || c === "\n" || c === "\r" || c === "\f";

/**
 * A srcset split by the HTML grammar: a URL runs to the next whitespace (so it may contain commas), then
 * descriptors run to the next comma outside parentheses. A URL that ends in commas has no descriptors.
 */
export function parseSrcSet(raw: string): SrcSetCandidate[] {
  const candidates: SrcSetCandidate[] = [];
  let i = 0;

  while (i < raw.length) {
    while (i < raw.length && (isSpace(raw[i]) || raw[i] === ",")) i += 1;

    if (i >= raw.length) break;
    const start = i;

    while (i < raw.length && !isSpace(raw[i])) i += 1;
    let end = i;

    while (end > start && raw[end - 1] === ",") end -= 1;

    if (end < i) {
      candidates.push({ url: raw.slice(start, end), descriptors: [] });
      continue;
    }

    const from = i;
    let parens = 0;

    while (i < raw.length && (raw[i] !== "," || parens > 0)) {
      if (raw[i] === "(") parens += 1;
      else if (raw[i] === ")" && parens > 0) parens -= 1;
      i += 1;
    }

    const descriptors = raw.slice(from, i).trim();

    candidates.push({ url: raw.slice(start, end), descriptors: descriptors === "" ? [] : descriptors.split(/\s+/) });
    i += 1;
  }

  return candidates;
}

// A width ("300w", a positive integer) or a pixel density ("2x", "1.5x", "1e1x", above zero).
const WIDTH = /^[1-9]\d*w$/;
const DENSITY = /^(?:\d+(?:\.\d+)?|\.\d+)(?:[eE][+-]?\d+)?x$/;

function validDescriptors(descriptors: string[]): boolean {
  const [only, ...rest] = descriptors;

  if (only === undefined) return true;

  return rest.length === 0 && (WIDTH.test(only) || (DENSITY.test(only) && Number(only.slice(0, -1)) > 0));
}

/** srcset candidates with each whole URL made safe; a candidate whose URL or descriptor can't be is left out. */
function safeSrcSet(raw: string, rewrite: Rewrite): string | null {
  const kept = parseSrcSet(raw).flatMap(({ url, descriptors }) => {
    const safe = validDescriptors(descriptors) ? safeUrl(url, rewrite, "image") : null;

    return safe ? [[safe, ...descriptors].join(" ")] : [];
  });

  return kept.length > 0 ? kept.join(", ") : null;
}

const HEADING = /^h([1-6])$/;

/** Rewrites one sanitized element's own properties for this page; false removes the element. */
function rewriteElement(el: Element, rewrite: Rewrite): boolean {
  const props = el.properties;

  if (el.tagName === "img") {
    const src = safeUrl(stringProp(props, "src") ?? "", rewrite, "image");

    if (src === null) return false;
    el.properties = { ...props, src, loading: "lazy", decoding: "async", referrerPolicy: "no-referrer" };
  } else if (el.tagName === "source") {
    const srcSet = safeSrcSet(stringProp(props, "srcSet") ?? "", rewrite);

    if (srcSet === null) return false;
    el.properties = { ...props, srcSet };
  } else if (el.tagName === "a") {
    const raw = stringProp(props, "href");
    const href = raw === null ? null : safeUrl(raw, rewrite, "link");
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

  return true;
}

/** Rewrites every element in the tree for this page, from an explicit stack so no depth can overflow. */
function rewriteTree(tree: Root, rewrite: Rewrite): void {
  const stack: Parent[] = [tree];

  const keep = <T extends RootContent | ElementContent>(children: T[]): T[] =>
    children.filter((child) => {
      if (child.type !== "element") return true;
      const kept = rewriteElement(child, rewrite);

      if (kept) stack.push(child);

      return kept;
    });

  for (let parent = stack.pop(); parent; parent = stack.pop()) {
    if (parent.type === "root") parent.children = keep(parent.children);
    else parent.children = keep(parent.children);
  }
}

/** Why a readme is shown as its source instead of rendered. */
export type FallbackReason = "too_deep" | "too_many_nodes" | "render_failed";

export type ReadmeTree = { kind: "rendered"; tree: Root } | { kind: "fallback"; reason: Exclude<FallbackReason, "render_failed">; extent: Extent };

function overLimit(extent: Extent, maxDepth: number): ReadmeTree | null {
  if (extent.depth > maxDepth) return { kind: "fallback", reason: "too_deep", extent };

  if (extent.nodes > MAX_NODES) return { kind: "fallback", reason: "too_many_nodes", extent };

  return null;
}

/** The sanitized, rewritten tree for a readme, or why it is too deep or too large to render. May throw; renderReadme catches. */
export function readmeTree(markdown: string, repo: GithubRepo | null): ReadmeTree {
  const early = overLimit(measureSource(markdown), MAX_DEPTH);

  if (early) return early;
  const raw = toHtmlTree.runSync(toHtmlTree.parse(markdown));
  const written = anchorNames(raw);
  const tree = sanitizer.runSync(raw);
  const late = overLimit(measureTree(tree), MAX_TREE_DEPTH);

  if (late) return late;
  const anchors: Anchors = { sanitized: new Map(written.map((name) => [name, `${ID_PREFIX}${name}`])), present: new Set(anchorNames(tree)) };

  rewriteTree(tree, { repo, anchors });

  return { kind: "rendered", tree };
}

const FALLBACK_NOTE: Record<FallbackReason, string> = {
  too_deep: "This readme nests too deeply to render here, so it is shown as text.",
  too_many_nodes: "This readme is too large to render here, so it is shown as text.",
  render_failed: "This readme could not be rendered here, so it is shown as text.",
};

/** The readme's source as escaped text under a note saying why, logged as one structured line. */
function fallback(markdown: string, reason: FallbackReason, detail: Record<string, string | number>): ReactElement {
  console.error(JSON.stringify({ event: "readme_fallback", reason, chars: markdown.length, ...detail }));

  return jsxs("div", {
    className: "readme-fallback",
    children: [jsx("p", { className: "text-sm text-muted-foreground", children: FALLBACK_NOTE[reason] }), jsx("pre", { children: markdown })],
  });
}

/** The readme as React elements, ready to render inside `.readme`. Never throws: a readme that can't be rendered is shown as text. */
export function renderReadme(markdown: string, repo: GithubRepo | null): ReactElement {
  try {
    const result = readmeTree(markdown, repo);

    if (result.kind === "fallback") return fallback(markdown, result.reason, result.extent);

    return toJsxRuntime(result.tree, { Fragment, jsx, jsxs, passKeys: true });
  } catch (error) {
    return fallback(markdown, "render_failed", { error: error instanceof Error ? `${error.name}: ${error.message}` : "non-error thrown" });
  }
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
