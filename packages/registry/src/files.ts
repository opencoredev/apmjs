// One file of a published version, as text, for the website's file view (evidence links open it at a line).
// GET /-/apm/v1/file/<name>/<version>?path=<path in the tarball>              the whole file, up to 1 MB
// GET /-/apm/v1/file/<name>/<version>?path=<path>&line=<n>&context=<k>        lines n-k to n+k, any size
// GET /-/apm/v1/readme/<name>/<version>                                       the README npm would pick
//
// The bytes come from the same verified tarball the install routes serve: a local version's blob is checked
// against its sha512 integrity, an upstream one is fetched and checked by Upstream.tarball. The path is looked up
// in the parsed entry list, never joined onto anything, so "../" and friends can only name an entry that exists.
// Answers are cached in the blob store under the tarball's digest: one index of paths and sizes, and one
// object per path read, so a repeat costs one or two small reads instead of inflating the tarball again.
import { Effect, Option } from "effect";
import { z } from "zod";
import { readTarball, type TarEntry } from "@apm/core";
import { WORKER_MAX_UNPACKED_BYTES } from "./analysis.ts";
import { Blobs } from "./blobs.ts";
import { Store, type VersionRecord } from "./db.ts";
import { refuse } from "./errors.ts";
import { sha256Hex, sha512 } from "./hash.ts";
import { json } from "./http.ts";
import { countLines, ExcerptLine, isUtf8, pickReadme, sliceLines } from "./file-text.ts";
import { splitPath, versionOf } from "./server.ts";
import { digestLabel, digestOf, Upstream, type UpstreamPackage } from "./upstream.ts";
import { isWithheld } from "./withheld.ts";

/** The largest file the view returns. Larger files are reported with their size, not sent. */
export const MAX_FILE_VIEW_BYTES = 1024 * 1024;

/** Longer `path` parameters name no file in any tarball apm reads. */
const MAX_PATH_CHARS = 1024;

const PREFIX = "/-/apm/v1/file/";
const README_PREFIX = "/-/apm/v1/readme/";

/** What the blob store keeps per tarball: every entry's path and size, duplicates included. */
const FileIndex = z.object({ entries: z.array(z.object({ path: z.string(), size: z.number() })) });

type FileIndex = z.infer<typeof FileIndex>;

/** What it keeps per path read. */
const FileBody = z.discriminatedUnion("kind", [z.object({ kind: z.literal("text"), text: z.string() }), z.object({ kind: z.literal("binary") })]);

type FileBody = z.infer<typeof FileBody>;

type Found = { kind: "local"; v: VersionRecord } | { kind: "upstream"; v: VersionRecord; pkg: UpstreamPackage; upstream: Upstream["Service"] };

/** Text when the bytes are valid UTF-8, whatever they contain; binary otherwise. */
export function fileBody(data: Uint8Array): FileBody {
  try {
    return { kind: "text", text: new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(data) };
  } catch {
    return { kind: "binary" };
  }
}

const indexKey = (label: string) => `files/${label}/index.json`;
const bodyKey = (label: string, path: string) => `files/${label}/${sha256Hex(path)}.json`;

const readCached = <S extends z.ZodType>(key: string, schema: S) =>
  Effect.gen(function* () {
    const got = yield* (yield* Blobs).bytes(key);

    if (Option.isNone(got)) return null;
    let raw: unknown;

    try {
      raw = JSON.parse(new TextDecoder().decode(got.value));
    } catch {
      return null;
    }

    const parsed = schema.safeParse(raw);

    return parsed.success ? parsed.data : null;
  });

const writeCached = (key: string, value: FileIndex | FileBody | LineCount | Block) => Effect.flatMap(Blobs, (b) => b.put(key, new TextEncoder().encode(JSON.stringify(value))));

/** The version, local first, then upstream. */
const findVersion = (name: string, version: string) =>
  Effect.gen(function* () {
    if (yield* (yield* Store).getPackage(name)) {
      const v = yield* versionOf(name, version);

      return v ? ({ kind: "local", v } satisfies Found) : null;
    }

    const upstream = yield* Effect.serviceOption(Upstream);

    if (Option.isNone(upstream)) return null;
    const probe = yield* upstream.value.probe(name);

    switch (probe.kind) {
      case "found": {
        const v = probe.pkg.versions.find((x) => x.version === version);

        return v ? ({ kind: "upstream", v, pkg: probe.pkg, upstream: upstream.value } satisfies Found) : null;
      }

      case "absent":
        return null;
      case "unknown":
        return yield* Effect.fail(refuse(503, "The upstream registry could not be reached."));
      default: {
        const _exhaustive: never = probe;

        return _exhaustive;
      }
    }
  });

/** The version's tarball, checked against its checksum, parsed into entries. */
const entriesOf = (found: Found) =>
  Effect.gen(function* () {
    let bytes: Uint8Array;

    if (found.kind === "local") {
      const blob = yield* (yield* Blobs).bytes(found.v.tarball_key);

      if (Option.isNone(blob)) return yield* Effect.fail(refuse(404, "Tarball missing"));

      if (sha512(blob.value).integrity !== found.v.integrity) return yield* Effect.fail(refuse(409, "The stored tarball no longer matches its checksum."));
      bytes = blob.value;
    } else {
      const got = yield* found.upstream.tarball(found.pkg, found.v.version);

      switch (got.kind) {
        case "absent":
          return yield* Effect.fail(refuse(404, `${found.pkg.name}@${found.v.version} is not published upstream.`));
        case "unavailable":
          return yield* Effect.fail(refuse(502, `Upstream tarball unavailable: ${got.reason}.`));
        case "ok":
          bytes = got.bytes;
          break;
        default: {
          const _exhaustive: never = got;

          return _exhaustive;
        }
      }
    }

    try {
      return readTarball(bytes, WORKER_MAX_UNPACKED_BYTES);
    } catch {
      return yield* Effect.fail(refuse(422, "apm can't read this version's tarball."));
    }
  });

/** The answer: the file's text, or why it isn't sent. */
type FileAnswer = { name: string; version: string; path: string; size: number } & (FileBody | { kind: "too-large"; limit: number });

/** One version's tarball as the file routes see it: checked, indexed, and its entries inflated at most once. */
type Opened = {
  label: string;
  index: FileIndex;
  /** The parsed entries; inflates the tarball on first use (the index may have come from the cache). */
  entries: ReturnType<typeof entriesOf>;
};

/** Refuses a revoked version, checks it has a checksum, and reads (or builds and caches) its index of paths. */
const open = (input: { found: Found; name: string }) =>
  Effect.gen(function* () {
    const { found, name } = input;
    const v = found.v;

    if (isWithheld(v.status)) return yield* Effect.fail(refuse(410, `${name}@${v.version} was revoked: ${v.status_reason ?? "no reason given"}`));
    const digest = digestOf(v);

    if (!digest) return yield* Effect.fail(refuse(422, "This version has no checksum, so its tarball cannot be verified."));
    const label = digestLabel(digest);
    let inflated: TarEntry[] | null = null;

    const entries = Effect.gen(function* () {
      inflated ??= yield* entriesOf(found);

      return inflated;
    });

    let index = yield* readCached(indexKey(label), FileIndex);

    if (!index) {
      index = { entries: (yield* entries).map((e) => ({ path: e.path, size: e.data.length })) };
      yield* writeCached(indexKey(label), index);
    }

    return { label, index, entries } satisfies Opened;
  });

/** The one entry named exactly `path` in the index: a 404 when there is none, a 422 when there are two. */
const entryAt = (input: { opened: Opened; name: string; version: string; path: string }) => {
  const { opened, name, version, path } = input;
  const hits = opened.index.entries.filter((e) => e.path === path);
  const hit = hits[0];

  if (!hit) return Effect.fail(refuse(404, `${name}@${version} has no file ${path}.`));

  if (hits.length > 1) return Effect.fail(refuse(422, `${path} appears more than once in ${name}@${version}'s tarball, so apm can't say which one gets installed.`));

  return Effect.succeed(hit);
};

/** The inflated bytes of the entry named `path` (already known to be in the index exactly once). */
const bytesAt = (input: { opened: Opened; name: string; version: string; path: string }) =>
  Effect.gen(function* () {
    const entry = (yield* input.opened.entries).find((e) => e.path === input.path);

    if (!entry) return yield* Effect.fail(refuse(404, `${input.name}@${input.version} has no file ${input.path}.`));

    return entry.data;
  });

const wholeFile = (input: { opened: Opened; name: string; version: string; path: string }) =>
  Effect.gen(function* () {
    const { opened, name, version, path } = input;
    const hit = yield* entryAt(input);
    const head = { name, version, path, size: hit.size };

    if (hit.size > MAX_FILE_VIEW_BYTES) return { ...head, kind: "too-large", limit: MAX_FILE_VIEW_BYTES } satisfies FileAnswer;
    let body = yield* readCached(bodyKey(opened.label, path), FileBody);

    if (!body) {
      body = fileBody(yield* bytesAt(input));
      yield* writeCached(bodyKey(opened.label, path), body);
    }

    return { ...head, ...body } satisfies FileAnswer;
  });

const answerFor = (input: { found: Found; name: string; path: string }) =>
  Effect.gen(function* () {
    const opened = yield* open(input);

    return yield* wholeFile({ opened, name: input.name, version: input.found.v.version, path: input.path });
  });

// ---------------------------------------------------------------------------------------------------------------
// Excerpts: ?path=...&line=N&context=K returns lines N-K to N+K of a file of any size the tarball caps allow, so
// a citation into a 20 MB bundle can be checked. Lines are numbered as the scorer numbers them (split on "\n",
// a trailing newline makes no extra line). One line longer than MAX_EXCERPT_LINE_BYTES is cut there and reports
// its full length. The answer is assembled from blocks of BLOCK_LINES lines cached per digest, path and block,
// so the cache holds at most one copy of a file however many ranges are asked for.

/** The most lines asked for on each side of `line`. */
export const MAX_EXCERPT_CONTEXT = 100;

/** Lines on each side of `line` when `context` is left out. */
export const DEFAULT_EXCERPT_CONTEXT = 20;

/** The most bytes of one line an excerpt returns (minified bundles put a whole program on one line). */
export const MAX_EXCERPT_LINE_BYTES = 4096;

const BLOCK_LINES = 100;

/** What the blob store keeps per path for excerpts: whether it is text, and how many lines it has. */
const LineCount = z.discriminatedUnion("kind", [z.object({ kind: z.literal("text"), lines: z.number() }), z.object({ kind: z.literal("binary") })]);

type LineCount = z.infer<typeof LineCount>;

const Block = z.object({ lines: z.array(ExcerptLine) });

type Block = z.infer<typeof Block>;

// the block size and line cap are in the key, so changing either never serves blocks cut the old way
const countKey = (label: string, path: string) => `files/${label}/${sha256Hex(path)}.lines.json`;
const blockKey = (label: string, path: string, block: number) => `files/${label}/${sha256Hex(path)}.b${BLOCK_LINES}x${MAX_EXCERPT_LINE_BYTES}-${block}.json`;

type ExcerptAnswer = { name: string; version: string; path: string; size: number } & (
  | { kind: "excerpt"; line: number; totalLines: number; from: number; to: number; lines: ExcerptLine[] }
  | { kind: "binary" }
);

const excerptFor = (input: { found: Found; name: string; path: string; line: number; context: number }) =>
  Effect.gen(function* () {
    const { name, path, line, context } = input;
    const version = input.found.v.version;
    const opened = yield* open(input);
    const hit = yield* entryAt({ opened, name, version, path });
    const head = { name, version, path, size: hit.size };
    let count: LineCount | null = yield* readCached(countKey(opened.label, path), LineCount);

    if (!count) {
      const data = yield* bytesAt({ opened, name, version, path });

      count = isUtf8(data) ? { kind: "text", lines: countLines(data) } : { kind: "binary" };
      yield* writeCached(countKey(opened.label, path), count);
    }

    if (count.kind === "binary") return { ...head, kind: "binary" } satisfies ExcerptAnswer;
    const total = count.lines;

    if (line > total) return yield* Effect.fail(refuse(416, `${path} has ${total} ${total === 1 ? "line" : "lines"}; there is no line ${line}.`, { lines: total }));
    const from = Math.max(1, line - context);
    const to = Math.min(total, line + context);
    const lines: ExcerptLine[] = [];

    for (let block = Math.floor((from - 1) / BLOCK_LINES); block <= Math.floor((to - 1) / BLOCK_LINES); block += 1) {
      let cached: Block | null = yield* readCached(blockKey(opened.label, path, block), Block);

      if (!cached) {
        const data = yield* bytesAt({ opened, name, version, path });

        cached = { lines: sliceLines({ data, from: block * BLOCK_LINES + 1, to: Math.min(total, (block + 1) * BLOCK_LINES), maxLineBytes: MAX_EXCERPT_LINE_BYTES }) };
        yield* writeCached(blockKey(opened.label, path, block), cached);
      }

      lines.push(...cached.lines.filter((l) => l.n >= from && l.n <= to));
    }

    return { ...head, kind: "excerpt", line, totalLines: total, from, to, lines } satisfies ExcerptAnswer;
  });

// ---------------------------------------------------------------------------------------------------------------
// Readmes: GET /-/apm/v1/readme/<name>/<version> answers the version's README from its tarball, for packages whose
// packument carries none. It is picked the way npm picks one when it fills in a manifest's readme
// (@npmcli/package-json): files at the package root matching README or README.* (any case), where the first
// with a markdown-like extension wins, else a file named exactly README.

const readmeFor = (input: { found: Found; name: string }) =>
  Effect.gen(function* () {
    const opened = yield* open(input);
    const version = input.found.v.version;
    const path = pickReadme(opened.index.entries.map((e) => e.path));

    if (path === null) return yield* Effect.fail(refuse(404, `${input.name}@${version} has no readme file.`));

    return yield* wholeFile({ opened, name: input.name, version, path });
  });

/** A whole number in a query parameter, or null when it is absent; a failure when it is something else. */
const wholeParam = (input: { url: URL; name: string; min: number; max: number }) => {
  const raw = input.url.searchParams.get(input.name);

  if (raw === null) return Effect.succeed(null);
  const n = /^\d{1,9}$/.test(raw) ? Number(raw) : Number.NaN;

  return n >= input.min && n <= input.max ? Effect.succeed(n) : Effect.fail(refuse(400, `${input.name} must be a whole number from ${input.min} to ${input.max}.`));
};

/** What a file request asks for: the whole file, or the lines around one. */
type Wanted = { kind: "file" } | { kind: "excerpt"; line: number; context: number };

const target = (url: URL, prefix: string) =>
  Effect.gen(function* () {
    const sp = splitPath(`/${url.pathname.slice(prefix.length)}`);
    const version = sp?.rest[0];

    if (!sp || version === undefined || sp.rest.length !== 1) return yield* Effect.fail(refuse(404, "Not found"));

    return { name: sp.name, version };
  });

const fileTarget = (url: URL) =>
  Effect.gen(function* () {
    const t = yield* target(url, PREFIX);
    const path = url.searchParams.get("path");

    if (!path || path.length > MAX_PATH_CHARS || path.includes("\0")) return yield* Effect.fail(refuse(400, `Name the file with ?path=, at most ${MAX_PATH_CHARS} characters.`));
    const line = yield* wholeParam({ url, name: "line", min: 1, max: 999_999_999 });
    const context = yield* wholeParam({ url, name: "context", min: 0, max: MAX_EXCERPT_CONTEXT });

    if (line === null && context !== null) return yield* Effect.fail(refuse(400, "context needs a line."));
    const wanted: Wanted = line === null ? { kind: "file" } : { kind: "excerpt", line, context: context ?? DEFAULT_EXCERPT_CONTEXT };

    return { ...t, path, wanted };
  });

/** The version a route names, or a 404. */
const versionNamed = (t: { name: string; version: string }) =>
  Effect.gen(function* () {
    const found = yield* findVersion(t.name, t.version);

    return found ?? (yield* Effect.fail(refuse(404, `${t.name}@${t.version} not found.`)));
  });

/**
 * GET or HEAD /-/apm/v1/file/<name>/<version>?path=...[&line=N[&context=K]] and /-/apm/v1/readme/<name>/<version>;
 * null for any other request.
 */
export const fileRoute = (req: Request, url: URL) => {
  const isFile = url.pathname.startsWith(PREFIX);

  if ((!isFile && !url.pathname.startsWith(README_PREFIX)) || (req.method !== "GET" && req.method !== "HEAD")) return Effect.succeed(null);
  const bodyless = (res: Response): Response => (req.method === "HEAD" ? new Response(null, { status: res.status, headers: res.headers }) : res);

  return Effect.gen(function* () {
    let answer: FileAnswer | ExcerptAnswer;

    if (isFile) {
      const t = yield* fileTarget(url);
      const found = yield* versionNamed(t);

      answer = t.wanted.kind === "file" ? yield* answerFor({ found, name: t.name, path: t.path }) : yield* excerptFor({ found, name: t.name, path: t.path, ...t.wanted });
    } else {
      const t = yield* target(url, README_PREFIX);

      answer = yield* readmeFor({ found: yield* versionNamed(t), name: t.name });
    }

    // the bytes behind a digest never change; a version can still be revoked, so shared caches recheck soon
    return bodyless(json(answer, 200, { "cache-control": "public, max-age=300" }));
  }).pipe(Effect.catchTag("HttpFailure", (f) => Effect.succeed(bodyless(json({ error: f.error, ...f.extra }, f.status)))));
};
