// The smoke check's read-only probes of install verdicts and the OSSF malicious-packages feed: the website's explain of
// a large package, and a version the feed lists, which explain refuses and the registry withholds and refuses. Each read
// is bounded in time and size and checks that the answer is the view it asked for, of the package it asked about; an
// explain that answers with a transient state is asked again a bounded number of times. The fetch is injected, so the
// unit tests (test/smoke-probes.test.ts) need no network.
import { z } from "zod";
import { tarballPath } from "./smoke-commands.ts";

export type Fetch = (url: string, init: { headers: Record<string, string>; signal: AbortSignal; redirect: "follow" | "manual" }) => Promise<Response>;

export type Check = { ok: boolean; name: string; detail: string };

export type ProbeDeps = { fetch: Fetch; registry: string; web: string; sleep?: (ms: number) => Promise<void> };

/** The most of one answer a probe reads: explain and these packuments are tens of kilobytes. */
export const BODY_CAP = 2 * 1024 * 1024;

export const REGISTRY_MS = 15_000;

/** A cold explain of next takes about 10 s; three attempts, 5 s apart, all inside a minute. */
export const EXPLAIN = { attemptMs: 30_000, deadlineMs: 60_000, attempts: 3, backoffMs: 5_000 } as const;

/** A known-good large package: analysed, scored 98, with a dependency tree the explain walks whole. */
export const LARGE = { name: "next", version: "16.4.6" } as const;

/**
 * The user agent of an npm client. The registry redirects a tarball request from npm, pnpm or yarn 1 to npm's own URL
 * once its checks pass (registry fast-tarball.ts) and streams every other client's, so the refusal is probed as both.
 */
export const NPM_CLIENT = "npm/10.9.2 node/v22.12.0 linux x64 workspaces/false";

/** OSV MAL-2026-20430 lists ugent_uws 10.9.9 to 10.9.11; npm still serves them, 10.9.11 as latest, beside a clean 9.0.0. */
export const OSSF_LISTED = { name: "ugent_uws", version: "10.9.11", id: "MAL-2026-20430" } as const;

/** failure: why there is no usable answer, a transport failure (none in time, or the connection failed) or one over BODY_CAP. */
export type Got<T> = { status: number | null; media: string | null; text: string; data: T | null; failure: "transport" | "over-cap" | null };

function parsed<T>(schema: z.ZodType<T>, text: string): T | null {
  try {
    const p = schema.safeParse(JSON.parse(text));

    return p.success ? p.data : null;
  } catch {
    return null;
  }
}

/**
 * A GET, bounded: the answer must start and finish within `timeoutMs`, and its body is read once, up to BODY_CAP. Status
 * null when there is no usable answer (none in time, or one over the cap), the text then saying why; data is the body read
 * as `schema`, null when it is not that. With `manual`, a redirect is the answer, not followed.
 */
export async function boundedGet<T>(fetch: Fetch, url: string, input: { timeoutMs: number; schema: z.ZodType<T>; accept?: string; userAgent?: string; manual?: boolean }): Promise<Got<T>> {
  const signal = AbortSignal.timeout(input.timeoutMs);
  // the deadline also stops a body read the fetch does not tie to the signal
  const stopped = new Promise<never>((_, reject) => signal.addEventListener("abort", () => reject(new Error(`no answer within ${input.timeoutMs} ms`)), { once: true }));
  let cancel: (() => Promise<void>) | undefined;

  stopped.catch(() => undefined);

  const plain = { accept: input.accept ?? "application/json", "cache-control": "no-cache" };
  const headers = input.userAgent === undefined ? plain : { ...plain, "user-agent": input.userAgent };

  try {
    const res = await Promise.race([fetch(url, { headers, signal, redirect: input.manual ? "manual" : "follow" }), stopped]);
    const media = res.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase() ?? null;
    const chunks: Uint8Array[] = [];
    let size = 0;

    const body = res.body?.getReader();

    cancel = body ? () => body.cancel() : undefined;

    if (body) {
      for (let next = await Promise.race([body.read(), stopped]); !next.done; next = await Promise.race([body.read(), stopped])) {
        size += next.value.length;

        if (size > BODY_CAP) {
          await body.cancel();

          return { status: null, media, text: `the answer is over ${BODY_CAP} bytes`, data: null, failure: "over-cap" };
        }

        chunks.push(next.value);
      }
    }

    const text = new TextDecoder().decode(Buffer.concat(chunks));

    return { status: res.status, media, text, data: parsed(input.schema, text), failure: null };
  } catch (e) {
    await cancel?.().catch(() => undefined);

    return { status: null, media: null, text: e instanceof Error ? e.message : String(e), data: null, failure: "transport" };
  }
}

/** What a failed read says: the status, media type and the start of the answer, or why none came. */
const answerOf = (r: Got<unknown>): string => (r.status === null ? `no answer: ${r.text}` : `HTTP ${r.status} ${r.media ?? "no media type"} ${r.text.slice(0, 160)}`);

const Explained = z.object({
  verdict: z.string(),
  name: z.string(),
  range: z.string(),
  version: z.string().nullable(),
  score: z.object({ score: z.number() }).nullable(),
  reasons: z.array(z.string()),
  notes: z.array(z.object({ kind: z.string(), text: z.string() })),
});

type Explanation = z.infer<typeof Explained>;

/**
 * An answer worth asking again: none in time or a failed connection, rate-limited, a server error, apm could not say, or
 * the version is still being analysed. An answer over the cap is not: asking again would read as much.
 */
function transient(got: Got<Explanation>): boolean {
  if (got.failure === "transport" || got.status === 429 || (got.status !== null && got.status >= 500)) return true;

  return got.data !== null && (got.data.verdict === "unknown" || got.data.notes.some((n) => n.kind === "not-scored" && /still analysing/.test(n.text)));
}

/** The website's explain of `name@version`, asked again while the answer is transient, within EXPLAIN's bounds. */
async function explain(deps: ProbeDeps, name: string, version: string): Promise<{ got: Got<Explanation>; attempts: number; seconds: string }> {
  const sleep = deps.sleep ?? Bun.sleep;
  const t0 = Date.now();
  const end = t0 + EXPLAIN.deadlineMs;

  for (let attempts = 1; ; attempts++) {
    const got = await boundedGet(deps.fetch, `${deps.web}api/explain?package=${encodeURIComponent(`${name}@${version}`)}`, { timeoutMs: Math.max(1, Math.min(EXPLAIN.attemptMs, end - Date.now())), schema: Explained });

    if (!transient(got) || attempts >= EXPLAIN.attempts || end - Date.now() <= EXPLAIN.backoffMs) return { got, attempts, seconds: ((Date.now() - t0) / 1000).toFixed(1) };
    await sleep(EXPLAIN.backoffMs);
  }
}

/** Whether an explain answer is about `name@version`, as asked. */
const about = (d: Explanation | null, name: string, version: string): d is Explanation => d !== null && d.name === name && d.range === version && d.version === version;

/** Explain of a known-good large package answers install, for that version, with its score (a 503 on next went unnoticed). */
export async function largeExplain(deps: ProbeDeps): Promise<Check> {
  const { name, version } = LARGE;
  const { got, attempts, seconds } = await explain(deps, name, version);
  const d = got.data;
  const ok = got.status === 200 && about(d, name, version) && d.verdict === "install" && d.score !== null;

  return { ok, name: `explain answers install for a large package (${name}@${version}), scored`, detail: `${d ? `verdict ${d.verdict}, ${d.name}@${d.version}, score ${d.score?.score ?? "none"}` : answerOf(got)}, ${attempts} attempt${attempts === 1 ? "" : "s"}, ${seconds} s` };
}

const Refused = z.object({ error: z.string() });

const Packument = z.object({ name: z.string(), versions: z.record(z.string(), z.object({ version: z.string() })), "dist-tags": z.record(z.string(), z.string()) });

// semver.org's regular expression for a valid version
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

/**
 * The OSSF-listed version: explain says do-not-install citing its id, the registry refuses its tarball with a 403 citing
 * it (registry osv.ts listedTarballText) to the default client and to npm, a redirect failing either, and each packument view, answered as the view asked for and for this package,
 * leaves it out of its versions while still listing a valid one, and tags as latest a version it lists.
 */
export async function ossfListed(deps: ProbeDeps): Promise<Check[]> {
  const { name, version, id } = OSSF_LISTED;
  const out: Check[] = [];
  const { got: explained, attempts } = await explain(deps, name, version);
  const d = explained.data;
  const cited = d?.reasons.some((r) => r.includes(id)) === true;

  out.push({ ok: explained.status === 200 && about(d, name, version) && d.verdict === "do-not-install" && cited, name: `explain says do-not-install for an OSSF-listed version (${name}@${version}), citing ${id}`, detail: d ? `verdict ${d.verdict}, ${d.name}@${d.version}, ${cited ? "cites" : "does not cite"} ${id}, ${attempts} attempt${attempts === 1 ? "" : "s"}` : answerOf(explained) });

  for (const [client, userAgent] of [["the default client", undefined], ["npm", NPM_CLIENT]] as const) {
    const tarball = await boundedGet(deps.fetch, `${deps.registry}${name}/-/${name}-${version}.tgz`, { timeoutMs: REGISTRY_MS, schema: Refused, userAgent, manual: true });
    const refused = tarball.status === 403 && tarball.data?.error.includes(id) === true;

    out.push({ ok: refused, name: `the registry refuses its tarball to ${client} with 403, citing ${id}`, detail: refused ? `HTTP 403, ${tarball.data?.error.slice(0, 120)}` : answerOf(tarball) });
  }

  for (const [view, accept] of [["full", "application/json"], ["install", "application/vnd.npm.install-v1+json"]] as const) {
    const r = await boundedGet(deps.fetch, `${deps.registry}${name}`, { timeoutMs: REGISTRY_MS, schema: Packument, accept });
    const p = r.data;
    const listed = p ? Object.keys(p.versions) : [];
    const valid = p ? listed.filter((v) => SEMVER.test(v) && p.versions[v]?.version === v) : [];
    const latest = p?.["dist-tags"].latest;
    const ok = r.status === 200 && r.media === accept && p?.name === name && !listed.includes(version) && valid.length > 0 && latest !== undefined && valid.includes(latest);

    out.push({ ok, name: `the registry's ${view} packument of ${name} withholds ${version}: not in versions, not latest`, detail: p ? `${r.media ?? "no media type"}, name ${p.name}, versions ${listed.slice(0, 8).join(", ") || "none"}, latest ${latest ?? "none"}` : answerOf(r) });
  }

  return out;
}

const INSTALL_VIEW = "application/vnd.npm.install-v1+json";

const SafePackument = z.object({ name: z.string(), versions: z.record(z.string(), z.object({ version: z.string(), dist: z.object({ tarball: z.string() }) })), "dist-tags": z.record(z.string(), z.string()) });

/**
 * The registry's ~safe install packument of a known-good large package answers 200, as that view and for that package:
 * on 2026-11-26 every ~safe packument of next answered 503 (the registry read its whole history of analyses as one row,
 * which the database connection dropped), and nothing probed it. Every version it lists is under its own key with its
 * tarball at exactly the registry's ~safe URL for it, and latest is one of them. It may list none: the view hides what apm read only in part, as it reads
 * next@16.4.6, so how many pass is the stage's data, not the route's health.
 */
export async function safeLarge(deps: ProbeDeps): Promise<Check> {
  const { name } = LARGE;
  const r = await boundedGet(deps.fetch, `${deps.registry}~safe/${name}`, { timeoutMs: REGISTRY_MS, schema: SafePackument, accept: INSTALL_VIEW });
  const p = r.data;
  const docs = p ? Object.entries(p.versions) : [];
  const inView = docs.every(([key, doc]) => doc.version === key && doc.dist.tarball === `${deps.registry}~safe/${tarballPath(name, key)}`);
  const latest = p?.["dist-tags"].latest;
  const tagged = docs.length === 0 || (latest !== undefined && p !== null && Object.hasOwn(p.versions, latest));
  const ok = r.status === 200 && r.media === INSTALL_VIEW && p?.name === name && inView && tagged;

  return {
    ok,
    name: `the registry's ~safe install packument of ${name} answers 200, every version it lists served from ~safe`,
    detail: p ? `HTTP ${r.status ?? "none"}, ${r.media ?? "no media type"}, name ${p.name}, ${docs.length} versions${inView ? "" : " (one outside ~safe)"}, latest ${latest ?? "none"}` : answerOf(r),
  };
}
