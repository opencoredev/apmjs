// Where a package's readme points when it uses a relative link or image: its GitHub repository.
// npm writes "repository" many ways; only GitHub is resolved, since its raw and blob URLs are stable.
import { z } from "zod";

/** A GitHub repository, and the folder inside it the package lives in ("" for the root). */
export type GithubRepo = { owner: string; repo: string; directory: string };

/** The registry's normalized `repository` field: the manifest's url and optional directory. */
export const RepositoryField = z.object({ url: z.string(), directory: z.string().nullable() });

export type RepositoryField = z.infer<typeof RepositoryField>;

const PART = /^[A-Za-z0-9._-]+$/;

// git+https://github.com/o/r.git, git://github.com/o/r, git@github.com:o/r.git, https://github.com/o/r/tree/main/x
const HOSTED = /^(?:git\+)?(?:https?:\/\/|git:\/\/|ssh:\/\/|git\+ssh:\/\/)?(?:[^@/]+@)?(?:www\.)?github\.com[/:]([^/]+)\/([^/#?]+)/i;

// github:o/r and the bare o/r shorthand npm also accepts
const SHORTHAND = /^(?:github:)?([^/:]+)\/([^/#?:]+)$/;

/** A repo-relative folder with no "..", no leading or trailing slashes; null when it tries to leave the repo. */
function cleanDirectory(raw: string | null): string | null {
  const parts = (raw ?? "").split("/").filter((p) => p !== "" && p !== ".");

  return parts.some((p) => p === "..") ? null : parts.join("/");
}

/** The GitHub repository a package names, or null for another host or a value apm can't read. */
export function githubRepo(field: RepositoryField | null | undefined): GithubRepo | null {
  if (!field) return null;
  const url = field.url.trim();
  const m = HOSTED.exec(url) ?? SHORTHAND.exec(url);
  const owner = m?.[1];
  const repo = m?.[2]?.replace(/\.git$/i, "");
  const directory = cleanDirectory(field.directory);

  if (!owner || !repo || !PART.test(owner) || !PART.test(repo) || directory === null) return null;

  return { owner, repo, directory };
}
