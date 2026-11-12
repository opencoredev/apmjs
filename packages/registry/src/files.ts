// One file of a published version, as text, for the website's file view (evidence links open it at a line).
// GET /-/apm/v1/file/<name>/<version>?path=<path in the tarball>
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
import { splitPath, versionOf } from "./server.ts";
import { digestLabel, digestOf, Upstream, type UpstreamPackage } from "./upstream.ts";

/** The largest file the view returns. Larger files are reported with their size, not sent. */
export const MAX_FILE_VIEW_BYTES = 1024 * 1024;

/** Longer `path` parameters name no file in any tarball apm reads. */
const MAX_PATH_CHARS = 1024;

const PREFIX = "/-/apm/v1/file/";

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

const writeCached = (key: string, value: FileIndex | FileBody) => Effect.flatMap(Blobs, (b) => b.put(key, new TextEncoder().encode(JSON.stringify(value))));

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

const answerFor = (input: { found: Found; name: string; path: string }) =>
  Effect.gen(function* () {
    const { found, name, path } = input;
    const v = found.v;

    if (v.status === "revoked" || v.status === "revoke-pending") return yield* Effect.fail(refuse(410, `${name}@${v.version} was revoked: ${v.status_reason ?? "no reason given"}`));
    const digest = digestOf(v);

    if (!digest) return yield* Effect.fail(refuse(422, "This version has no checksum, so its tarball cannot be verified."));
    const label = digestLabel(digest);
    let entries: TarEntry[] | null = null;
    let index = yield* readCached(indexKey(label), FileIndex);

    if (!index) {
      entries = yield* entriesOf(found);
      index = { entries: entries.map((e) => ({ path: e.path, size: e.data.length })) };
      yield* writeCached(indexKey(label), index);
    }

    const hits = index.entries.filter((e) => e.path === path);
    const hit = hits[0];
    const absent = refuse(404, `${name}@${v.version} has no file ${path}.`);

    if (!hit) return yield* Effect.fail(absent);

    if (hits.length > 1) return yield* Effect.fail(refuse(422, `${path} appears more than once in ${name}@${v.version}'s tarball, so apm can't say which one gets installed.`));
    const head = { name, version: v.version, path, size: hit.size };

    if (hit.size > MAX_FILE_VIEW_BYTES) return { ...head, kind: "too-large", limit: MAX_FILE_VIEW_BYTES } satisfies FileAnswer;
    let body = yield* readCached(bodyKey(label, path), FileBody);

    if (!body) {
      entries ??= yield* entriesOf(found);
      const entry = entries.find((e) => e.path === path);

      if (!entry) return yield* Effect.fail(absent);
      body = fileBody(entry.data);
      yield* writeCached(bodyKey(label, path), body);
    }

    return { ...head, ...body } satisfies FileAnswer;
  });

const target = (url: URL) => {
  const sp = splitPath(`/${url.pathname.slice(PREFIX.length)}`);
  const version = sp?.rest[0];
  const path = url.searchParams.get("path");

  if (!sp || version === undefined || sp.rest.length !== 1) return Effect.fail(refuse(404, "Not found"));

  if (!path || path.length > MAX_PATH_CHARS || path.includes("\0")) return Effect.fail(refuse(400, `Name the file with ?path=, at most ${MAX_PATH_CHARS} characters.`));

  return Effect.succeed({ name: sp.name, version, path });
};

/** GET or HEAD /-/apm/v1/file/<name>/<version>?path=...; null for any other request. */
export const fileRoute = (req: Request, url: URL) => {
  if (!url.pathname.startsWith(PREFIX) || (req.method !== "GET" && req.method !== "HEAD")) return Effect.succeed(null);
  const bodyless = (res: Response): Response => (req.method === "HEAD" ? new Response(null, { status: res.status, headers: res.headers }) : res);

  return Effect.gen(function* () {
    const t = yield* target(url);
    const found = yield* findVersion(t.name, t.version);

    if (!found) return yield* Effect.fail(refuse(404, `${t.name}@${t.version} not found.`));
    const answer = yield* answerFor({ found, name: t.name, path: t.path });

    // the bytes behind a digest never change; a version can still be revoked, so shared caches recheck soon
    return bodyless(json(answer, 200, { "cache-control": "public, max-age=300" }));
  }).pipe(Effect.catchTag("HttpFailure", (f) => Effect.succeed(bodyless(json({ error: f.error }, f.status)))));
};
