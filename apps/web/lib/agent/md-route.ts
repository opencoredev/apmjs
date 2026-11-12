// Which /package/... requests ask for the Markdown view: /package/<name>.md, or /package/<name>?format=md.
// A file of a version (/package/zod/v/4.1.0/file/README.md) is never one. Pure, so proxy.ts and the tests share it.
import { parsePackageRoute } from "../package-route";

export type MarkdownRoute = { name: string; version: string | null };

/** The package and version a request names for the Markdown view, or null when it asks for the HTML page or a file. */
export function markdownRoute(url: { pathname: string; searchParams: URLSearchParams }): MarkdownRoute | null {
  if (!url.pathname.startsWith("/package/")) return null;
  const segs = url.pathname.slice("/package/".length).split("/");

  if (segs.length > 1 && segs.at(-1) === "") segs.pop();
  const last = segs.at(-1) ?? "";
  const suffix = last.endsWith(".md") && last.length > ".md".length;
  const asked = url.searchParams.get("format") === "md";

  if (!suffix && !asked) return null;
  const route = parsePackageRoute(suffix ? [...segs.slice(0, -1), last.slice(0, -".md".length)] : segs);

  if (route?.kind !== "package") return null;

  return { name: route.name, version: url.searchParams.get("v") };
}

/** The internal route that renders it. */
export function markdownApiPath(route: MarkdownRoute): string {
  const query = route.version ? `?v=${encodeURIComponent(route.version)}` : "";

  return `/api/package-md/${route.name.split("/").map(encodeURIComponent).join("/")}${query}`;
}
