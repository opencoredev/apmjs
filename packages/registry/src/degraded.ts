// The install routes while Postgres cannot be reached (db-health.ts): packuments and tarballs of npm's packages are
// served from npm as the normal routes serve them, minus anything that needs the database, and everything else is
// refused with a 503 that says why. What is refused without the database comes from the block list in R2
// (blocklist.ts): a package published on apm is refused (its versions and owners live only in Postgres), and a version
// an apm reviewer confirmed malicious is left out of its packument and its tarball answers 410, as in normal operation.
// Scores live in the database, so none is sent: every packument says scores are unknown (`_apmDegraded`, and the
// x-apm-scores header). The ~safe view filters by score, so it is refused. Nothing is queued for analysis.
import { Effect, Option, Result } from "effect";
import { SERVED_EXTRA_CHARS, SERVED_VERSION_WEIGHT, UPSTREAM_RETRY_AFTER_S, upstreamPackument, upstreamSource, versionsAndTags } from "./apm.ts";
import { Blocklist, verdictFor } from "./blocklist.ts";
import { Clock } from "./clock.ts";
import { RegistryConfig } from "./config.ts";
import { confirmedAmong, confirmedText } from "./confirmed.ts";
import { fail, json, routePath, streamedJson, streamWeight } from "./http.ts";
import { advisoriesOf, listedAmong, listedTarballText, noticeHeaders } from "./osv.ts";
import { RequestMemory } from "./memory.ts";
import { getRouteOf } from "./routes.ts";
import { splitPath, tarballVersion } from "./server.ts";
import { scoredPackage, Upstream } from "./upstream.ts";

/** The header every answer made without the database carries, with why. */
export const DEGRADED_HEADER = "x-apm-degraded";

/** The header that says the answer carries no scores because none could be read. */
export const SCORES_HEADER = "x-apm-scores";

/** The reason every degraded answer gives, in its header and body. */
export const DATABASE_UNAVAILABLE = "database-unavailable";

/** The GET routes a package manager needs to install: these are answered without the database when it is down. */
const INSTALL_ROUTES: ReadonlySet<string> = new Set(["packument", "tarball", "ping"]);

/** Whether `req` is one the install routes answer while the database is down. */
export function isInstallRead(req: Request): boolean {
  if (req.method !== "GET" && req.method !== "HEAD") return false;
  const route = getRouteOf(new URL(req.url).pathname);

  return route !== null && INSTALL_ROUTES.has(route);
}

function marked(res: Response): Response {
  const headers = new Headers(res.headers);
  headers.set(DEGRADED_HEADER, DATABASE_UNAVAILABLE);

  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

/** The 503 for anything the registry cannot answer safely without its database: the reason, and when to ask again. */
export function unavailable(detail: string): Response {
  return marked(
    json(
      { error: `apm's database is unavailable, so the registry cannot answer this safely: ${detail}. Installs of npm packages keep working; try again shortly.`, degraded: true, reason: DATABASE_UNAVAILABLE },
      503,
      { "retry-after": String(UPSTREAM_RETRY_AFTER_S), "cache-control": "no-store" },
    ),
  );
}

/** What the install routes answer while the database is down. `cause` is why it is taken as down, for the log. */
export const degradedRoute = (req: Request) =>
  Effect.gen(function* () {
    const url = new URL(req.url);
    const { path, viaSafe } = routePath(url.pathname);
    const route = getRouteOf(url.pathname);

    if (route === "ping") return marked(json({}));

    if (viaSafe) return unavailable("the ~safe view filters versions by their scores, which live in the database");
    const blocklist = yield* Effect.serviceOption(Blocklist);

    if (Option.isNone(blocklist)) return unavailable("this registry keeps no block list");
    const read = yield* Effect.result(blocklist.value.read);

    if (Result.isFailure(read)) return unavailable("its block list could not be read either");

    if (read.success.kind !== "ok") return unavailable("its block list has not been written from the database yet");
    const list = read.success.list;
    const syncedAt = list.syncedAt;

    if (syncedAt === null) return unavailable("its block list has not been written from the database yet");
    const sp = splitPath(path);

    if (!sp) return unavailable("this path names no package");
    const verdict = verdictFor(list, sp.name);

    if (verdict.kind === "local") return unavailable(`${sp.name} is published on apm, and its versions live only in that database`);
    const upstream = Option.getOrNull(yield* Effect.serviceOption(Upstream));

    if (upstream === null) return unavailable("this registry proxies no upstream");
    const lease = yield* RequestMemory;
    const listed = yield* upstream.listing(sp.name, lease);

    if (listed.kind === "unknown") return marked(json({ error: `The upstream registry could not be read for ${sp.name}. Try again shortly.` }, 503, { "retry-after": String(UPSTREAM_RETRY_AFTER_S) }));

    if (listed.kind === "absent") return marked(fail(404, "Not found"));
    const probe = scoredPackage(listed.pkg, { scores: new Map(), unscorable: new Map() });

    if (probe.kind !== "found") return marked(fail(404, "Not found"));
    const src = upstreamSource(probe.pkg);
    const confirmed = confirmedAmong(verdict.confirmed, src.versions);
    // the OSSF malicious-packages feed needs no database: its versions are withheld here too (osv.ts)
    const advisories = yield* advisoriesOf(src.name);

    if (sp.rest[0] === "-" && sp.rest[1]) {
      const version = tarballVersion(src.name, sp.rest[1]);

      if (!version) return marked(fail(404, "Not found"));

      if (confirmed.has(version)) return marked(fail(410, confirmedText(src.name, version), { confirmed: true }));
      const listedHere = listedAmong(src.name, advisories, [version]).get(version);

      if (listedHere) return marked(fail(403, listedTarballText(listedHere), { knownMalicious: listedHere }));
      const got = yield* Effect.result(upstream.serve(src.pkg, version));

      if (Result.isFailure(got)) return unavailable("the tarball could not be read from the blob store");

      switch (got.success.kind) {
        case "absent":
          return marked(fail(404, `${src.name}@${version} is not published upstream.`));
        case "unavailable":
          return marked(fail(502, `Upstream tarball unavailable: ${got.success.reason}.`));
        case "ok": {
          const bytes = got.success.bytes;

          return marked(new Response(req.method === "HEAD" ? null : bytes, { headers: { "content-type": "application/octet-stream", "content-length": String(bytes.length) } }));
        }

        case "stream": {
          const stream = got.success;
          const headers = new Headers({ "content-type": "application/octet-stream" });

          if (stream.length !== null) headers.set("content-length", String(stream.length));

          if (req.method === "HEAD") {
            yield* Effect.promise(() => stream.body.cancel());

            return marked(new Response(null, { headers }));
          }

          return marked(new Response(stream.body, { headers }));
        }

        default: {
          const _exhaustive: never = got.success;

          return _exhaustive;
        }
      }
    }

    if (sp.rest.length > 0) return marked(fail(404, "Not found"));
    const abbreviated = (req.headers.get("accept") ?? "").includes("application/vnd.npm.install-v1+json");

    const headers = {
      "content-type": abbreviated ? "application/vnd.npm.install-v1+json; charset=utf-8" : "application/json",
      "cache-control": "no-cache",
      [DEGRADED_HEADER]: DATABASE_UNAVAILABLE,
      [SCORES_HEADER]: "unknown",
      ...noticeHeaders(src.name, advisories),
    };

    if (req.method === "HEAD") return new Response(null, { status: 200, headers });
    const dev = abbreviated ? null : yield* upstream.devDependencies(src.name, lease);
    const longest = src.pkg.serveCost.maxPieceChars + (dev?.maxPieceChars ?? 0) + SERVED_EXTRA_CHARS;

    if (!lease.take(src.pkg.serveCost.versionDocs + src.versions.length * SERVED_VERSION_WEIGHT + streamWeight(longest))) {
      return marked(json({ error: `The upstream registry could not be read for ${sp.name}. Try again shortly.` }, 503, { "retry-after": String(UPSTREAM_RETRY_AFTER_S) }));
    }

    const at = yield* (yield* Clock).now;
    const { baseUrl } = yield* RegistryConfig;
    const withheld = listedAmong(src.name, advisories, versionsAndTags(src));
    const body = upstreamPackument({ base: baseUrl, src, abbreviated, view: null, at, confirmed, listed: withheld, devDependencies: dev?.byVersion ?? null });

    // read by apm's CLI and by people: these versions carry no score because none could be read, not because none exists
    body._apmDegraded = { reason: DATABASE_UNAVAILABLE, scores: "unknown", blocklistSyncedAt: new Date(syncedAt).toISOString() };

    return streamedJson(body, "versions", headers, { onDone: lease.retain() });
  });
