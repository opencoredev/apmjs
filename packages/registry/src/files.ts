// One file of a published version, as text, for the website's file view (evidence links open it at a line).
// GET /-/apm/v1/file/<name>/<version>?path=<path in the tarball>              the whole file, up to 1 MB
// GET /-/apm/v1/file/<name>/<version>?path=<path>&line=<n>&context=<k>        lines n-k to n+k, any size
// GET /-/apm/v1/readme/<name>/<version>                                       the README npm would pick
//
// The bytes come from the same verified tarball the install routes serve: a local version's blob is checked
// against its sha512 integrity, an upstream one is fetched and checked by Upstream.tarball. An upstream tarball too
// large to hold (over 32 MiB to download or 48 MiB to unpack, next's) is read as a stream that holds only the file
// asked for, up to MAX_STREAMED_FILE_BYTES, and checked byte for byte against its sha512 before any of it is used
// (streamed-analysis.ts, readOneFile). The path is looked up
// in the parsed entry list, never joined onto anything, so "../" and friends can only name an entry that exists.
// Answers are cached in the blob store under the tarball's digest: one index of paths and sizes, and one
// object per path read, so a repeat costs one or two small reads instead of inflating the tarball again.
import { pageProbe, pageScores } from "./kept-package.ts";
import { Clock } from "./clock.ts";
import { RequestMemory } from "./memory.ts";
import { Effect, Option } from "effect";
import { z } from "zod";
import { ArchiveError, readTarball, type TarEntry } from "@apm/core";
import { WORKER_MAX_UNPACKED_BYTES } from "./analysis.ts";
import { Blobs } from "./blobs.ts";
import { Store, type VersionRecord } from "./db.ts";
import { refuse, type BlobError } from "./errors.ts";
import { DeadlinePassed } from "./deadline.ts";
import { sha256Hex, sha512 } from "./hash.ts";
import { json } from "./http.ts";
import { countLines, ExcerptLine, isUtf8, pickReadme, sliceLines } from "./file-text.ts";
import { splitPath, versionOf } from "./server.ts";
import { digestLabel, digestOf, Upstream, type UpstreamPackage } from "./upstream.ts";
import { isWithheld } from "./withheld.ts";
import { MAX_STREAMED_FILE_BYTES, readOneFile } from "./streamed-analysis.ts";
import { escapedLength } from "./walk-catalog.ts";

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

/**
 * A failed read or write of the view's cache is logged and otherwise ignored: its copies are rebuilt from the verified
 * tarball, so R2 answering late or with an error of its own costs a rebuild, not the answer. Before, a cache read past
 * R2_GET_MS (a HEAD of a file, 2026-11-24) and R2's 10001 errors (a readme, 2026-11-22) each made the view a 500,
 * though the tarball's own cached copy already treated them as a miss (upstream.ts, cacheRead).
 */
const cacheFailed = (e: BlobError) => Effect.sync(() => console.warn(JSON.stringify({ level: "warn", event: "file-cache", error: e.cause instanceof DeadlinePassed ? "late" : "failed", operation: e.operation })));

const readCached = <S extends z.ZodType>(key: string, schema: S) =>
  Effect.gen(function* () {
    const got = yield* (yield* Blobs).bytes(key).pipe(Effect.catchTag("BlobError", (e) => Effect.as(cacheFailed(e), Option.none())));

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

const writeCached = (key: string, value: FileIndex | FileBody | LineCount | Block) =>
  Effect.flatMap(Blobs, (b) => b.put(key, new TextEncoder().encode(JSON.stringify(value)))).pipe(Effect.catchTag("BlobError", cacheFailed));

/** The version, local first, then upstream. */
const findVersion = (name: string, version: string) =>
  Effect.gen(function* () {
    const need = { kind: "version", version } as const;
    // the package row, or an upstream package's kept summary and its scores with only this version's analysis whole, in
    // one round trip (Store.fileRead): next's analyses whole are 5 MB, and a file view reads none of them. A local
    // package's versions are not in it: the one asked for is read on its own, its state as of now (versionOf)
    const row = yield* (yield* Store).fileRead({ name, at: yield* (yield* Clock).now, scores: pageScores(need) });

    if (row.kind === "local") {
      const v = yield* versionOf(name, version);

      return v ? ({ kind: "local", v } satisfies Found) : null;
    }

    const upstream = yield* Effect.serviceOption(Upstream);

    if (Option.isNone(upstream)) return null;
    // the kept summary names the version's tarball and checksum when it holds the version (kept-package.ts)
    const probe = yield* pageProbe({ upstream: upstream.value, name, need, lease: yield* RequestMemory, first: { kind: "read", kept: row.kept, analyses: row.analyses, whole: row.whole } });

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

/** A version's entries: whole for a tarball held whole; for one read as a stream, only `want` held (`notHeld` the rest). */
type Entries = { files: TarEntry[]; notHeld: ReadonlySet<TarEntry> };

/** An upstream tarball too large to hold, read as a stream that holds only `want`, verified against its sha512. */
const streamedEntries = (found: Extract<Found, { kind: "upstream" }>, want: string | null) =>
  Effect.gen(function* () {
    const digest = digestOf(found.v);

    if (!digest) return yield* Effect.fail(refuse(422, "This version has no checksum, so its tarball cannot be verified."));
    // charged to the request's own lease, which stays open until the answer is built and handed to the response: the
    // entries are read again for the index, the body and their cached copies after the read ends (review of e8616ca,
    // finding 3: a child lease released here left a 625 KB index built and written with nothing charged for it)
    const memory = yield* RequestMemory;

    const open = () =>
      Effect.runPromise(found.upstream.openTarball(found.pkg, found.v.version).pipe(Effect.catchTag("BlobError", () => Effect.succeed({ kind: "unavailable", reason: "the blob store could not be read", retryable: true } as const))));

    const read = yield* Effect.promise(() => readOneFile({ open, digest, want, memory }));

    if (read.kind === "failed") return yield* Effect.fail(refuse(read.status, read.status === 502 ? `Upstream tarball unavailable: ${read.reason}.` : `${read.reason}.`));

    return { files: read.tarball.files, notHeld: read.tarball.notHeld } satisfies Entries;
  });

/** The version's tarball, checked against its checksum, parsed into entries; `want` is the one file the caller reads. */
const entriesOf = (found: Found, want: string | null) =>
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
        case "too-large":
          return yield* streamedEntries(found, want);
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
      return { files: readTarball(bytes, WORKER_MAX_UNPACKED_BYTES), notHeld: new Set() } satisfies Entries;
    } catch (e) {
      // an upstream tarball under the download cap that unpacks past what is held whole: read as a stream too
      if (found.kind === "upstream" && e instanceof ArchiveError && e.kind === "too-large") return yield* streamedEntries(found, want);

      return yield* Effect.fail(refuse(422, "apm can't read this version's tarball."));
    }
  });

/** The answer: the file's text, or why it isn't sent. */
type FileAnswer = { name: string; version: string; path: string; size: number } & (FileBody | { kind: "too-large"; limit: number });

/** One version's tarball as the file routes see it: checked, indexed, and its entries inflated at most once. */
type Opened = {
  label: string;
  index: FileIndex;
  /**
   * The parsed entries with `want` held; inflates the tarball on first use (the index may have come from the cache).
   * A tarball held whole is read once per request; one read as a stream once per file asked for.
   */
  entries: (want: string | null) => ReturnType<typeof entriesOf>;
};

/**
 * Charges `bytes` to the request's lease before what they stand for is built (an index, a file body, their JSON),
 * or answers 503 when the registry has no room for them: they stay charged until the request ends.
 */
const charged = (bytes: number, what: string) =>
  Effect.gen(function* () {
    if (!(yield* RequestMemory).take(bytes)) return yield* Effect.fail(refuse(503, `The registry has no memory to spare for this ${what} now; try again shortly.`));
  });

/**
 * An upper bound on JSON text before it is written: its UTF-16 units, the UTF-8 bytes they encode to, and whether a
 * unit may be past 0xFF (V8 then holds the whole text at two bytes a unit, else one).
 */
type JsonText = { units: number; utf8: number; wide: boolean };

/** What writing the text holds at once: the JSON string and its encoded copy (writeCached). */
const textBytes = (t: JsonText): number => (t.wide ? 2 : 1) * t.units + t.utf8;

/** `s` as a JSON string: its quotes, and each unit as JSON escapes it (escapedLength: six for a control or surrogate). */
function addString(t: JsonText, s: string): void {
  t.units += 2;
  t.utf8 += 2;

  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const e = escapedLength(c);

    t.units += e;
    // an escape is ASCII; a unit written as itself takes one to three bytes (a surrogate pair four, under its 12)
    t.utf8 += e > 1 || c < 0x80 ? e : c < 0x800 ? 2 : 3;

    if (c > 0xff) t.wide = true;
  }
}

/**
 * The UTF-8 text `data` holds, as a JSON string, without decoding it: an ASCII byte is one unit as JSON escapes it,
 * and every other byte at most one unit and one byte (valid UTF-8 has no lone surrogate, so none is escaped).
 */
function addUtf8(t: JsonText, data: Uint8Array): void {
  t.units += 2;
  t.utf8 += 2;

  for (const b of data) {
    if (b < 0x80) {
      const e = escapedLength(b);

      t.units += e;
      t.utf8 += e;
    } else {
      t.units += 1;
      t.utf8 += 1;
      t.wide = true;
    }
  }
}

/** Each entry of an index: its object and array slot (the path is the entry's own string), and `{"path":,"size":}` with the longest size. */
const INDEX_ENTRY_BYTES = 96;

const INDEX_ENTRY_TEXT = 40;

/**
 * What the index of `paths` holds while it is built and written: its entries, and its JSON text and encoded copy
 * with every path as JSON escapes it (review of 8249989: four bytes a character undercounted a path of controls,
 * which JSON writes six characters for one).
 */
function indexBytes(paths: readonly string[]): number {
  const t: JsonText = { units: 16, utf8: 16, wide: false };

  for (const p of paths) {
    addString(t, p);
    t.units += INDEX_ENTRY_TEXT;
    t.utf8 += INDEX_ENTRY_TEXT;
  }

  return paths.length * INDEX_ENTRY_BYTES + textBytes(t);
}

/**
 * What a file body of `data` holds while it is built and written: its decoded text (a unit for each byte at most),
 * and the body's JSON text and encoded copy with the text as JSON escapes it.
 */
function bodyBytes(data: Uint8Array): number {
  const t: JsonText = { units: 32, utf8: 32, wide: false };

  addUtf8(t, data);

  return (t.wide ? 2 : 1) * data.length + 64 + textBytes(t);
}

/** Refuses a revoked version, checks it has a checksum, and reads (or builds and caches) its index of paths. */
/** `want`: the one file the request reads, so a tarball read as a stream holds it while it builds the index. */
const open = (input: { found: Found; name: string; want?: string | null }) =>
  Effect.gen(function* () {
    const { found, name } = input;
    const v = found.v;

    if (isWithheld(v.status)) return yield* Effect.fail(refuse(410, `${name}@${v.version} was revoked: its files are not shown.`, { revoked: true, revokeReason: v.status_reason ?? "no reason given" }));
    const digest = digestOf(v);

    if (!digest) return yield* Effect.fail(refuse(422, "This version has no checksum, so its tarball cannot be verified."));
    const label = digestLabel(digest);
    let inflated: Entries | null = null;

    const entries = (want: string | null) =>
      Effect.gen(function* () {
        // a whole read serves every path; a streamed one only the path it held
        if (inflated !== null && (inflated.notHeld.size === 0 || inflated.files.some((f) => f.path === want && !inflated?.notHeld.has(f)))) return inflated;
        inflated = yield* entriesOf(found, want);

        return inflated;
      });

    let index = yield* readCached(indexKey(label), FileIndex);

    if (!index) {
      const read = yield* entries(input.want ?? null);

      // the index and its JSON, charged before they are built
      yield* charged(indexBytes(read.files.map((e) => e.path)), "file index");
      // each entry's size, which a streamed read keeps for the files it did not hold
      index = { entries: read.files.map((e) => ({ path: e.path, size: e.size })) };
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
    const read = yield* input.opened.entries(input.path);
    const entry = read.files.find((e) => e.path === input.path);

    if (!entry) return yield* Effect.fail(refuse(404, `${input.name}@${input.version} has no file ${input.path}.`));

    // a file over what a streamed read holds of one file is said to be, never shown from its first bytes
    if (read.notHeld.has(entry)) return yield* Effect.fail(refuse(413, `${input.path} is ${(entry.size / 1_000_000).toFixed(1)} MB; from a tarball this large apm reads at most ${MAX_STREAMED_FILE_BYTES / (1024 * 1024)} MiB of one file.`));

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
      const data = yield* bytesAt(input);

      // the decoded text, its JSON and that JSON's encoded copy, charged before any is built
      yield* charged(bodyBytes(data), "file");
      body = fileBody(data);
      yield* writeCached(bodyKey(opened.label, path), body);
    }

    return { ...head, ...body } satisfies FileAnswer;
  });

const answerFor = (input: { found: Found; name: string; path: string }) =>
  Effect.gen(function* () {
    const opened = yield* open({ ...input, want: input.path });

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
    const opened = yield* open({ ...input, want: input.path });
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

    // the bytes behind a digest never change and are kept in the blob store; whether they may be shown is read from
    // the database on every request, so no cache downstream keeps the answer (a revoke refuses the very next one)
    return bodyless(json(answer, 200, { "cache-control": "no-store" }));
  }).pipe(Effect.catchTag("HttpFailure", (f) => Effect.succeed(bodyless(json({ error: f.error, ...f.extra }, f.status)))));
};
