// The apm CLI's downloads on the website's own origin, served from the stage's CLI bucket (R2, binding CLI; created by
// packages/infra/alchemy.run.ts and filled by packages/infra/release-cli.ts):
//
//   /install                     the install script (install.sh), text/plain, cached 5 minutes
//   /cli/releases.txt            every released binary: version, platform, SHA-256; cached 5 minutes
//   /cli/<version>/apm-<target>  a binary, immutable, served only once <version>/SHA256SUMS exists (released)
//   /cli/<version>/SHA256SUMS    that version's checksums, immutable
//
// proxy.ts answers these before Next.js routes anything, and the OpenNext Worker returns that answer as it is, so a
// binary (about 100 MB, past what Worker static assets take) streams from R2 without passing through the Next server.

/** What the handler reads of an R2 object: the size and ETag, and for GET its body. */
type CliObjectHead = { size: number; httpEtag: string };

type CliObject = CliObjectHead & { body: ReadableStream };

/** The part of an R2 bucket binding the handler uses. */
export type CliBucket = { get(key: string): Promise<CliObject | null>; head(key: string): Promise<CliObjectHead | null> };

/**
 * A CLI path: the R2 key it reads and what it is. A binary also names its version's SHA256SUMS, the marker
 * release-cli.ts writes once every binary of the version is uploaded: until it exists the version is not released.
 */
export type CliPath = { key: string; kind: "script" | "index" | "sums" } | { key: string; kind: "binary"; released: string };

const VERSIONED = /^\/cli\/(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)\/(apm-[a-z0-9-]+|SHA256SUMS)$/;

/** The CLI download a path names, or null when it names none (Next.js then routes it as usual). */
export function cliPath(pathname: string): CliPath | null {
  if (pathname === "/install") return { key: "install.sh", kind: "script" };

  if (pathname === "/cli/releases.txt") return { key: "cli/releases.txt", kind: "index" };
  const m = VERSIONED.exec(pathname);

  if (m === null) return null;

  const key = `cli/${m[1]}/${m[2]}`;

  return m[2] === "SHA256SUMS" ? { key, kind: "sums" } : { key, kind: "binary", released: `cli/${m[1]}/SHA256SUMS` };
}

/** Whether a path is under the CLI's routes at all: one cliPath does not name is answered 404 here, not by Next.js. */
export function isCliRoute(pathname: string): boolean {
  return pathname === "/install" || pathname.startsWith("/cli/");
}

const SHORT = "public, max-age=300";
const IMMUTABLE = "public, max-age=31536000, immutable";

function headersFor(path: CliPath, object: CliObjectHead): Headers {
  const binary = path.kind === "binary";

  return new Headers({
    "content-type": binary ? "application/octet-stream" : "text/plain; charset=utf-8",
    "content-length": String(object.size),
    etag: object.httpEtag,
    "cache-control": path.kind === "script" || path.kind === "index" ? SHORT : IMMUTABLE,
    "x-content-type-options": "nosniff",
  });
}

function text(status: number, body: string, extra: Record<string, string> = {}): Response {
  return new Response(`${body}\n`, { status, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", ...extra } });
}

/**
 * The answer for a CLI route. `bucket` is null when this Worker has no CLI binding (a deploy from before the bucket
 * existed): 503, so a missing binding is never mistaken for a missing release.
 */
export async function cliDownload(input: { pathname: string; method: string; bucket: CliBucket | null }): Promise<Response> {
  if (input.method !== "GET" && input.method !== "HEAD") return text(405, "method not allowed", { allow: "GET, HEAD" });
  const path = cliPath(input.pathname);

  if (path === null) return text(404, "not found");

  if (input.bucket === null) return text(503, "apm CLI downloads are not available on this deployment");

  // a binary is served, and cached for a year, only once its version is released: a release cut short before
  // SHA256SUMS may upload that version's binaries again, so until then the URL answers an uncached 404
  if (path.kind === "binary" && (await input.bucket.head(path.released)) === null) return text(404, "this apm version is not released");

  if (input.method === "HEAD") {
    const head = await input.bucket.head(path.key);

    return head === null ? missing(path) : new Response(null, { status: 200, headers: headersFor(path, head) });
  }

  const object = await input.bucket.get(path.key);

  return object === null ? missing(path) : new Response(object.body, { status: 200, headers: headersFor(path, object) });
}

function missing(path: CliPath): Response {
  return text(404, path.kind === "script" ? "no apm CLI release is published on this site yet" : "not found");
}
