// The tarball of a package only npm has, served without reading its packument. A published npm tarball never changes
// for a name and version, and every client checks it against the integrity in the packument it was given, so serving
// one needs only what can refuse it, read before any byte goes out:
//
// - the database, in one statement (Store.tarballRead), read fresh on every request: whether the name is published
//   here (then server.ts answers it, as before), whether an apm reviewer confirmed this version's tarball malicious
//   (410, as before), and whether it needs queueing for analysis. This is the check that sees a block at once;
// - the install block list in R2 (blocklist.ts), which is never less strict than the database: a version on it is
//   refused here too (the packument route does not read it while the database answers, so this only adds refusals).
//   It is this isolate's read of it from the last BLOCKLIST_RECENT_MS (Blocklist.recent): every write that blocks
//   something adds it to the list before its transaction commits, so what the list adds beyond the database read on
//   this same request is only a block still committing, and a read seconds old is as good for that. It is waited for
//   at most EDGE_READ_DEADLINE_MS (300 ms); past it the database decides alone (blockListWithin);
// - npm's document for the one version (Upstream.versionOf, a few KiB, kept in the isolate for the upstream TTL; npm's
//   own CDN keeps it too, so asking for it from a Worker is a cache hit in the same data center): the version exists
//   upstream, where its tarball is and what it must hash to;
// - what the OSSF malicious-packages feed lists of the name (osv.ts, advisoriesFor: one small OSV query per name, kept
//   in the isolate and the data center's cache): a listed version is refused with a 403 that cites its MAL- id.
//
// The four run at once. Once nothing refuses the version:
//
// - a request without credentials is answered with a redirect to npm's own tarball URL (only on the upstream's or
//   npm's origin), never kept by any cache. The client downloads npm's bytes from npm's CDN and checks them against the
//   integrity apm's install document gave it, which is npm's own (upstreamPackument). npm, pnpm and bun follow the
//   redirect and none of their lockfiles names npm's URL (npm's records apm's), so a later install from the lockfile
//   comes back here and is checked again; scripts/perf/npm-install-bench.ts checks all three on every run (yarn is not
//   checked there). Streaming the bytes through the Worker cost seconds on big tarballs (next's 43.7 MB took
//   2.2 to 3.4 s through production against npm's 0.45 s) and Worker CPU on every download;
// - a request with credentials is never sent elsewhere: some clients would send its Authorization along. It gets
//   npm's bytes through the Worker, opened as soon as npm's document and the block list are known and the list does
//   not refuse it, while the database statement is still running (the slowest of the three: about 60 ms against 30
//   for opening npm's answer in the bench). Nothing is sent before the database has answered: a version it refuses
//   gets its refusal and the opened answer is cancelled unread. So npm may be asked for the bytes of a version the
//   database refuses, but only one the block list did not know of yet: one confirmed in the last few seconds, or
//   published here in them. The bytes come straight from npm, passed on as they arrive and hashed on the way against
//   the version's checksum (verifiedStream), with the last bytes held back: nothing is held, kept in R2 or shared
//   between requests, and no copy can outlive a block.
//
// Before round one, every download read and parsed the whole packument (tens of MB for next or typescript) and made
// about five database round trips, and a tarball up to 32 MiB was downloaded whole before its first byte was sent.
//
// With APM_INSTALL_CHECKS=edge, a request without credentials from a client that checks tarballs is first asked of this
// isolate's edge view (edge-checks.ts): a name it clears is redirected to npm with no database statement, and its
// analysis is asked about after the answer (queueDownload). Anything the view does not clear takes the path above.
//
// A package published here goes to the protocol route (server.ts), as before. Anything else this path is not sure of
// goes to the packument route it replaces, which answers it as it always has: `~safe` (its policy needs scores), a
// file name that is not the one apm's packuments link (`<name>-<version>.tgz`), a version npm's document does not
// confirm or could not be read for, one with no checksum, a block list that cannot be read or names the package as
// published here, and an upstream tarball that could not be opened (that route may still have the bytes in R2).
import { Duration, Effect, Exit, Fiber, Option, Result } from "effect";
import { isValidVersion } from "@apm/core";
import { Analysis, REQUEUE_AFTER_MS } from "./analysis.ts";
import { Blocklist, verdictFor, type BlocklistBody } from "./blocklist.ts";
import { Clock } from "./clock.ts";
import { RegistryConfig, type RegistrySettings } from "./config.ts";
import { confirmedText } from "./confirmed.ts";
import { Store } from "./db.ts";
import { digestLabel, digestOf, type Digest } from "./digest.ts";
import { EDGE_READ_DEADLINE_MS, EdgeChecks, type AskOutcome } from "./edge-checks.ts";
import { fail } from "./http.ts";
import { listedTarballText, listedVersionsOf } from "./osv.ts";
import { tarballBase } from "./server.ts";
import { timed, timingOrNull, type TimingApi } from "./timing.ts";
import { passTarball, type OpenedUpstream, type UpstreamApi, type UpstreamVersion } from "./upstream.ts";

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
  const read = yield* Effect.result(blocklist.value.recent);

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
 * The block list as blockList reads it, waited for at most EDGE_READ_DEADLINE_MS (300 ms), as an edge view's read is.
 * Past it the database's statement on this request decides alone, as it does for the install document: the list only
 * adds blocks whose transaction is still committing (EMPTY_LIST adds none). So a slow R2 read never holds an answer.
 */
const blockListWithin = (deadlineMs: number) => Effect.map(Effect.timeoutOption(blockList, Duration.millis(deadlineMs)), (read) => Option.getOrElse(read, () => EMPTY_LIST));

/**
 * What the fast path came to: its answer; "local", a package published here, which the protocol route (server.ts)
 * answers; or "packument", for the packument route to answer as it always has.
 */
export type FastTarball = { kind: "answer"; response: Response } | { kind: "local" } | { kind: "packument" };

/** Where npm itself serves tarballs: the only origin a client is redirected to. */
const NPM_TARBALLS = "https://registry.npmjs.org/";

/**
 * Whether `url` is npm's own tarball URL for exactly `name@version`. A mirror's or any other link is streamed and
 * checked here instead: after a redirect the client follows any further hops itself, with none of apm's checks.
 */
export function isNpmTarball(url: string, name: string, version: string, base: string = NPM_TARBALLS): boolean {
  return url === `${base}${name}/-/${tarballBase(name)}-${version}.tgz`;
}

/** The base a checked tarball request may be redirected under: npm's, or the configured upstream's when set to. */
function redirectBase(settings: RegistrySettings): string | null {
  if (settings.tarballRedirects === "upstream") return settings.upstreamUrl;

  return settings.upstreamUrl === NPM_TARBALLS ? NPM_TARBALLS : null;
}

/**
 * Clients redirected to npm's own tarball: npm, pnpm and yarn 1, which check a downloaded tarball against the install
 * document's dist.integrity or shasum on every install. Yarn 2 and later trust their own cache checksum, which a first
 * install has not got, so they and every unnamed client get npm's bytes checked here. Bun checks integrity too, but
 * Bun 1.4.x sometimes never sends one queued request after following a 302 and waits forever ("waiting for 1 tasks";
 * reproduced against a bare 302 registry with no apm code, 2026-11-18), so Bun is streamed, not redirected. A client
 * that only claims to be one of these skips apm's check of bytes sent to itself, nothing more.
 */
const CHECKING_CLIENT = /^(?:npm\/|pnpm\/|yarn\/1\.)/i;

export function checksTarballs(req: Request): boolean {
  return CHECKING_CLIENT.test(req.headers.get("user-agent") ?? "");
}

const PACKUMENT: FastTarball = { kind: "packument" };

/**
 * The fast path's answer. The bytes are public, but an answer to a request with credentials, a refusal included, is
 * marked so no shared cache keeps it (withPrivacyHeaders leaves tarball paths alone).
 */
function answered(req: Request, response: Response, timing: TimingApi | null): FastTarball {
  // the answer of a package only npm has: its phases may go to anyone (timing.ts)
  timing?.expose();

  if (!req.headers.has("authorization") && !req.headers.has("cookie")) return { kind: "answer", response };
  const headers = new Headers(response.headers);

  headers.set("cache-control", "private, no-store");
  headers.set("vary", "Authorization, Cookie");

  return { kind: "answer", response: new Response(response.body, { status: response.status, statusText: response.statusText, headers }) };
}

/** What npm's document says this path may serve: the version's tarball URL and checksum, or null to leave it to the packument route. */
type Servable = { tarball: string; digest: Digest } | null;

function servableOf(npm: UpstreamVersion): Servable {
  if (npm.kind !== "found") return null;
  const digest = digestOf(npm);

  return digest === null ? null : { tarball: npm.tarball, digest };
}

/** Whether the block list refuses this version here: confirmed malicious, or the name published on apm. */
function listRefuses(list: BlocklistBody, name: string, version: string, digest: Digest): boolean {
  const verdict = verdictFor(list, name);
  const label = digestLabel(digest);

  return verdict.kind === "local" || verdict.confirmed.some((e) => e.version === version && e.digest === label);
}

/**
 * Lets go of an early open that is not served: the fiber is stopped (openTarballUrl cancels an answer that comes after
 * that) and an answer it already had is cancelled unread, so no connection to npm is left open. The caller does not
 * wait for any of it.
 */
const discard = (opening: Fiber.Fiber<OpenedUpstream | null>): Effect.Effect<void> =>
  Effect.asVoid(
    Effect.forkDetach(
      Effect.gen(function* () {
        yield* Fiber.interrupt(opening);
        const done = opening.pollUnsafe();
        const opened = done !== undefined && Exit.isSuccess(done) ? done.value : null;

        if (opened?.kind === "open") yield* Effect.promise(() => opened.res.body?.cancel().catch(() => undefined) ?? Promise.resolve());
      }),
    ),
  );

/**
 * The redirect to npm's tarball answered from this isolate's edge view (edge-checks.ts), with no database statement
 * before it: only for a request without credentials from a client that checks the tarball itself, when the view says
 * nothing refuses the name and npm's document links its own URL. Null for the database path to answer, as before.
 */
const edgeRedirect = (input: { req: Request; name: string; version: string; upstream: UpstreamApi; timing: TimingApi | null }) =>
  Effect.gen(function* () {
    const { req, name, version, upstream, timing } = input;
    const edge = yield* Effect.serviceOption(EdgeChecks);

    if (Option.isNone(edge) || req.headers.has("authorization") || req.headers.has("cookie") || !checksTarballs(req)) return null;
    const base = redirectBase(yield* RegistryConfig);

    if (base === null) return null;
    const checksStart = performance.now();
    // npm's document and what the OSSF feed lists of the name are read beside the view: the database path reads them
    // too, from this isolate's caches then
    const [verdict, npm, listed] = yield* Effect.all([timed(timing, "edge")(edge.value.verdict(name)), upstream.versionOf(name, version), listedVersionsOf(name, [version])], { concurrency: "unbounded" });

    timing?.add("checks", performance.now() - checksStart);

    if (verdict.kind !== "clear") return null;
    const listedHere = listed.get(version);

    // listed by the OSSF malicious-packages feed: refused, as on the database path (osv.ts)
    if (listedHere) return answered(req, fail(403, listedTarballText(listedHere), { knownMalicious: listedHere }), timing);
    const servable = servableOf(npm);

    if (servable === null || !isNpmTarball(servable.tarball, name, version, base)) return yield* Effect.as(edge.value.declined, null);

    // the view decides only while it is young enough now, after npm's document was read: else the database path
    if (!(yield* edge.value.stillClear(verdict))) return null;
    // scoring a download happens off the request path, as on the database path, and after this answer
    yield* edge.value.downloaded({ name, version });

    return answered(req, new Response(null, { status: 302, headers: { location: servable.tarball, "cache-control": "no-store" } }), timing);
  });

/** A GET or HEAD of `/<name>/-/<file>` for a package npm has, answered from npm's tarball when nothing refuses it. */
export const fastTarball = (input: { req: Request; name: string; file: string; upstream: UpstreamApi }) =>
  Effect.gen(function* () {
    const { req, name, file, upstream } = input;
    const version = versionOfFile(name, file);

    if (version === null) return PACKUMENT;
    const fromEdge = yield* edgeRedirect({ req, name, version, upstream, timing: yield* timingOrNull });

    if (fromEdge !== null) return fromEdge;
    const store = yield* Store;
    const at = yield* Effect.flatMap(Clock, (c) => c.now);
    const timing = yield* timingOrNull;
    const checksStart = performance.now();
    // npm's document and the block list are read on fibers of their own, and npm's tarball is opened once both are
    // known and the list does not refuse it, while the database statement below still runs; each is interrupted when
    // this request ends, so a check that fails here stops them
    const listing = yield* Effect.forkChild(timed(timing, "blocklist")(blockListWithin(EDGE_READ_DEADLINE_MS)));
    const document = yield* Effect.forkChild(upstream.versionOf(name, version));
    // what the OSSF malicious-packages feed lists of the name (osv.ts), from this isolate's or the data center's copy
    // when one is young enough
    const feed = yield* Effect.forkChild(listedVersionsOf(name, [version]));
    // a request without credentials is sent to npm's own URL once nothing refuses it, so nothing is opened for it here;
    // one with credentials is never sent elsewhere (its Authorization would follow it there in some clients), and gets
    // npm's bytes through this Worker, opened early
    const credentialed = req.headers.has("authorization") || req.headers.has("cookie");

    const opening = credentialed
      ? yield* Effect.forkChild(
          Effect.gen(function* () {
            const [list, npm] = [yield* Fiber.join(listing), servableOf(yield* Fiber.join(document))];

            if (list === null || npm === null || listRefuses(list, name, version, npm.digest)) return null;

            return yield* upstream.openTarballUrl(npm.tarball);
          }),
        )
      : null;

    const letGo = opening === null ? Effect.void : discard(opening);
    const read = yield* Effect.onError(store.tarballRead({ name, version, queuedSince: at - REQUEUE_AFTER_MS }), () => letGo);
    const list = yield* Fiber.join(listing);
    const npm = yield* Fiber.join(document);
    const listedHere = (yield* Fiber.join(feed)).get(version);

    timing?.add("checks", performance.now() - checksStart);

    // what follows answers with npm's bytes only through `serve`; every other way out lets the early open go
    const refuse = (outcome: FastTarball) => Effect.as(letGo, outcome);

    if (read.local) return yield* refuse({ kind: "local" });

    // listed by the OSSF malicious-packages feed: refused before any byte is sent, a version npm has since removed
    // included (osv.ts)
    if (listedHere) return yield* refuse(answered(req, fail(403, listedTarballText(listedHere), { knownMalicious: listedHere }), timing));
    const servable = servableOf(npm);

    if (servable === null || list === null) return yield* refuse(PACKUMENT);
    const { digest } = servable;
    const label = digestLabel(digest);
    const verdict = verdictFor(list, name);

    // confirmed malicious by an apm reviewer, in the database or on the block list: gone like a revoked version, before
    // any byte is sent
    if (read.confirmed.includes(label) || (verdict.kind === "upstream" && verdict.confirmed.some((e) => e.version === version && e.digest === label))) {
      return yield* refuse(answered(req, fail(410, confirmedText(name, version), { confirmed: true }), timing));
    }

    // published here by the list (a publish whose transaction may still be committing): the packument route decides
    if (verdict.kind === "local") return yield* refuse(PACKUMENT);
    // scoring a download happens off the request path, as before: queued unless it is scored, decided or queued already
    const queue = read.decided || read.queued ? Effect.void : Effect.flatMap(Analysis, (a) => a.enqueue(name, version));

    // sent to npm: the version passed every check above, and the client downloads npm's own bytes from npm's own URL,
    // checking them against the integrity apm's install document carries, which is npm's (upstreamPackument). The
    // redirect is never kept by a cache, so the next request is checked again
    const base = redirectBase(yield* RegistryConfig);

    if (opening === null && base !== null && checksTarballs(req) && isNpmTarball(servable.tarball, name, version, base)) {
      yield* queue;

      return answered(req, new Response(null, { status: 302, headers: { location: servable.tarball, "cache-control": "no-store" } }), timing);
    }

    const open = opening === null ? upstream.openTarballUrl(servable.tarball) : Fiber.join(opening);
    const [opened, queued] = yield* Effect.all([open, Effect.result(queue)], { concurrency: "unbounded" });

    if (Result.isFailure(queued)) {
      // an answer left unread would hold its connection
      if (opened?.kind === "open") yield* Effect.promise(() => opened.res.body?.cancel() ?? Promise.resolve());

      return yield* Effect.fail(queued.failure);
    }

    if (opened?.kind !== "open") return PACKUMENT;
    const served = passTarball(opened.res, digest);
    const headers = new Headers(TARBALL_HEADERS);

    if (served.length !== null) headers.set("content-length", String(served.length));

    if (req.method === "HEAD") {
      yield* Effect.promise(() => served.body.cancel());

      return answered(req, new Response(null, { headers }), timing);
    }

    return answered(req, new Response(served.body, { headers }), timing);
  });

/**
 * What a download answered from the edge view does after its answer (worker.ts runs it on services of its own): the
 * statement the database path reads before its answer (Store.tarballRead), then the version queued for analysis unless
 * it is published here, scored, decided or queued already, as on the database path. "failed" when the queue refused
 * the version, so the edge asks again after a few seconds instead of a minute.
 */
export const queueDownload = (input: { name: string; version: string }) =>
  Effect.gen(function* () {
    const at = yield* Effect.flatMap(Clock, (c) => c.now);
    const read = yield* (yield* Store).tarballRead({ ...input, queuedSince: at - REQUEUE_AFTER_MS });

    if (read.local || read.decided || read.queued) return "asked" satisfies AskOutcome;
    const queued = yield* (yield* Analysis).enqueue(input.name, input.version);

    return queued ? ("asked" satisfies AskOutcome) : ("failed" satisfies AskOutcome);
  });
