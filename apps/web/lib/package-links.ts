// A package's homepage, repository and issue tracker, from its latest version's manifest. Publishers write these
// fields, so each becomes a link only when it is a plain http(s) URL with no credentials in it; anything else
// (javascript:, data:, a bare word) is dropped, never shown as a link.
import { githubRepo, type RepositoryField } from "./repository";

export type PackageLinkKind = "homepage" | "repository" | "issues";

export type PackageLink = { kind: PackageLinkKind; label: string; href: string; display: string };

/** The longest manifest URL apm turns into a link. */
const MAX_URL_CHARS = 2048;

const LABELS: Record<PackageLinkKind, string> = { homepage: "Homepage", repository: "Repository", issues: "Issues" };

/** The URL when `raw` is an absolute http or https URL without a username or password; null for anything else. */
export function safeHttpUrl(raw: string | null | undefined): string | null {
  const text = raw?.trim() ?? "";

  if (text === "" || text.length > MAX_URL_CHARS) return null;
  let url: URL;

  try {
    url = new URL(text);
  } catch {
    return null;
  }

  if ((url.protocol !== "https:" && url.protocol !== "http:") || url.username !== "" || url.password !== "") return null;

  return url.href;
}

/**
 * Where a repository field opens in a browser: GitHub repositories (any spelling npm accepts) at the repo, or the
 * package's folder in a monorepo, and any other host when its URL is http(s) once git's "git+" and ".git" are off.
 */
export function repositoryUrl(field: RepositoryField | null | undefined): string | null {
  const gh = githubRepo(field);

  if (gh) return `https://github.com/${gh.owner}/${gh.repo}${gh.directory ? `/tree/HEAD/${gh.directory.split("/").map(encodeURIComponent).join("/")}` : ""}`;

  return safeHttpUrl(field?.url.trim().replace(/^git\+/, "").replace(/\.git$/, ""));
}

/** A URL as people read it: host without "www.", then the path, without a trailing slash. */
function displayOf(href: string): string {
  const url = new URL(href);
  const path = url.pathname === "/" ? "" : url.pathname.replace(/\/$/, "");

  return `${url.hostname.replace(/^www\./, "")}${path}`;
}

/** Without its fragment, so "https://github.com/o/r#readme" and "https://github.com/o/r" count as one place. */
const sansHash = (href: string) => href.split("#")[0] ?? href;

const ORDER: readonly PackageLinkKind[] = ["homepage", "repository", "issues"];

/**
 * The package's links in a fixed order (homepage, repository, issues), unsafe ones dropped. A homepage that is
 * only the repository again ("https://github.com/o/r#readme" is common) is dropped in favour of the repository.
 */
export function packageLinks(input: { homepage: string | null | undefined; repository: RepositoryField | null | undefined; bugs: string | null | undefined }): PackageLink[] {
  const hrefs: Record<PackageLinkKind, string | null> = { homepage: safeHttpUrl(input.homepage), repository: repositoryUrl(input.repository), issues: safeHttpUrl(input.bugs) };

  if (hrefs.homepage !== null && hrefs.repository !== null && sansHash(hrefs.homepage) === sansHash(hrefs.repository)) hrefs.homepage = null;
  // a monorepo package's link opens its folder, but reads as the repository: github.com/react/react
  const gh = githubRepo(input.repository);
  const repoDisplay = gh ? `github.com/${gh.owner}/${gh.repo}` : null;

  return ORDER.flatMap((kind) => {
    const href = hrefs[kind];

    if (href === null) return [];

    return [{ kind, label: LABELS[kind], href, display: kind === "repository" && repoDisplay ? repoDisplay : displayOf(href) }];
  });
}
