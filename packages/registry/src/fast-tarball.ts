// The tarball of a package only npm has, served without reading its packument. A published npm tarball never changes
// for a name and version, and every client checks it against the integrity in the packument it was given, so serving
// one needs only what can refuse it, read fresh on every request before any byte goes out:
//
// - the database, in one statement (Store.tarballRead): whether the name is published here (then server.ts answers
//   it, as before), whether an apm reviewer confirmed this version's tarball malicious (410, as before), and whether it
//   needs queueing for analysis;
// - the install block list in R2 (blocklist.ts), which is never less strict than the database: a version on it is
//   refused here too (the packument route does not read it while the database answers, so this only adds refusals);
// - npm's document for the one version (Upstream.versionOf, a few KiB, kept in the isolate for the upstream TTL like
//   the packument it replaces here): the version exists upstream now, where its tarball is and what it must hash to.
//
// The three run at once. The bytes then come straight from npm, passed on as they arrive and hashed on the way
// against the version's checksum (verifiedStream): nothing is held, kept in R2 or shared between requests, so a
// request with credentials is served the same way and no copy can outlive a block. Before this, every download read
// and parsed the whole packument (tens of MB for next or typescript) and made about five database round trips, and a
// tarball up to 32 MiB was downloaded whole before its first byte was sent (npm install of 81 packages: about 1.3 s a
// tarball with production's 75 ms round trip; scripts/perf/npm-install-bench.ts).
//
// A package published here goes to the protocol route (server.ts), as before. Anything else this path is not sure of
// goes to the packument route it replaces, which answers it as it always has: `~safe` (its policy needs scores), a
// file name that is not the one apm's packuments link (`<name>-<version>.tgz`), a version npm's document does not
// confirm or could not be read for, one with no checksum, a block list that cannot be read or names the package as
// published here, and an upstream tarball that could not be opened (that route may still have the bytes in R2).
import { Effect, Option, Result } from "effect";
import { isValidVersion } from "@apm/core";
import { Analysis, REQUEUE_AFTER_MS } from "./analysis.ts";
import { Blocklist, verdictFor, type BlocklistBody } from "./blocklist.ts";
import { Clock } from "./clock.ts";
import { confirmedText } from "./confirmed.ts";
import { Store } from "./db.ts";
import { digestLabel, digestOf } from "./digest.ts";
import { fail } from "./http.ts";
import { tarballBase } from "./server.ts";
import { passTarball, type UpstreamApi } from "./upstream.ts";

const TARBALL_HEADERS = { "content-type": "application/octet-stream" } as const;

/** The version a tarball file names, when it is exactly the file apm's packuments link for `name`; null otherwise. */
export function versionOfFile(name: string, file: string): string | null {
  const prefix = `${tarballBase(name)}-`;

  if (!file.startsWith(prefix) || !file.endsWith(".tgz")) return null;
  const version = file.slice(prefix.length, -".tgz".length);

  // the route this replaces takes the same shape (server.ts, the tarball regex); anything else goes to it
  return isValidVersion(version) && /^(.*)-(\d+\.\d+\.\d+.*)\.tgz$/.test(file) ? version : null;
}

/**
 * The install block list's entries, as this path uses them: an empty list when none was ever written (the database,
 * read on the same request, is the authority; the list only adds blocks), null when it could not be read or this
 * registry keeps none, which sends the request to the packument route.
 */
const blockList = Effect.gen(function* () {
  const blocklist = yield* Effect.serviceOption(Blocklist);

  if (Option.isNone(blocklist)) return null;
  const read = yield* Effect.result(blocklist.value.read);

  if (Result.isFailure(read)) return null;

  switch (read.success.kind) {
    case "ok":
      return read.success.list;
    case "missing":
      return EMPTY_LIST;
    case "unreadable":
      return null;
    default: {
      const _exhaustive: never = read.success;

      return _exhaustive;
    }
  }
});

const EMPTY_LIST: BlocklistBody = { format: 1, syncedAt: null, local: [], confirmed: [] };

/**
 * What the fast path came to: its answer; "local", a package published here, which the protocol route (server.ts)
 * answers; or "packument", for the packument route to answer as it always has.
 */
export type FastTarball = { kind: "answer"; response: Response } | { kind: "local" } | { kind: "packument" };

const PACKUMENT: FastTarball = { kind: "packument" };

/**
 * The fast path's answer. The bytes are public, but an answer to a request with credentials, a refusal included, is
 * marked so no shared cache keeps it (withPrivacyHeaders leaves tarball paths alone).
 */
function answered(req: Request, response: Response): FastTarball {
  if (!req.headers.has("authorization") && !req.headers.has("cookie")) return { kind: "answer", response };
  const headers = new Headers(response.headers);

  headers.set("cache-control", "private, no-store");
  headers.set("vary", "Authorization, Cookie");

  return { kind: "answer", response: new Response(response.body, { status: response.status, statusText: response.statusText, headers }) };
}

/** A GET or HEAD of `/<name>/-/<file>` for a package npm has, answered from npm's tarball when nothing refuses it. */
export const fastTarball = (input: { req: Request; name: string; file: string; upstream: UpstreamApi }) =>
  Effect.gen(function* () {
    const { req, name, file, upstream } = input;
    const version = versionOfFile(name, file);

    if (version === null) return PACKUMENT;
    const store = yield* Store;
    const at = yield* Effect.flatMap(Clock, (c) => c.now);

    // npm's tarball is not asked for until these pass: a version refused here is never fetched (opening it while they
    // ran saved about 30 ms a tarball in the bench, and asked npm for the bytes of versions apm refuses)
    const [read, npm, list] = yield* Effect.all([store.tarballRead({ name, version, queuedSince: at - REQUEUE_AFTER_MS }), upstream.versionOf(name, version), blockList], {
      concurrency: "unbounded",
    });

    if (read.local) return { kind: "local" } satisfies FastTarball;

    if (npm.kind !== "found" || list === null) return PACKUMENT;
    const digest = digestOf(npm);

    if (digest === null) return PACKUMENT;
    const label = digestLabel(digest);
    const verdict = verdictFor(list, name);

    // confirmed malicious by an apm reviewer, in the database or on the block list: gone like a revoked version, before
    // anything is downloaded
    if (read.confirmed.includes(label) || (verdict.kind === "upstream" && verdict.confirmed.some((e) => e.version === version && e.digest === label))) {
      return answered(req, fail(410, confirmedText(name, version), { confirmed: true }));
    }

    // published here by the list (a publish whose transaction may still be committing): the packument route decides
    if (verdict.kind === "local") return PACKUMENT;
    // scoring a download happens off the request path, as before: queued unless it is scored, decided or queued already
    const queue = read.decided || read.queued ? Effect.void : Effect.flatMap(Analysis, (a) => a.enqueue(name, version));
    const [opened, queued] = yield* Effect.all([upstream.openTarballUrl(npm.tarball), Effect.result(queue)], { concurrency: "unbounded" });

    if (Result.isFailure(queued)) {
      // an answer left unread would hold its connection
      if (opened.kind === "open") yield* Effect.promise(() => opened.res.body?.cancel() ?? Promise.resolve());

      return yield* Effect.fail(queued.failure);
    }

    if (opened.kind !== "open") return PACKUMENT;
    const served = passTarball(opened.res, digest);
    const headers = new Headers(TARBALL_HEADERS);

    if (served.length !== null) headers.set("content-length", String(served.length));

    if (req.method === "HEAD") {
      yield* Effect.promise(() => served.body.cancel());

      return answered(req, new Response(null, { headers }));
    }

    return answered(req, new Response(served.body, { headers }));
  });
