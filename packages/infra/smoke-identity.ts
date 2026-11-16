// Which version answers the smoke check: the registry's GET /-/ping and the website's GET /api/build carry the
// answering version's build id (APM_BUILD, stamped by deploy.ts) in x-apm-build. Behaviour alone cannot tell a new
// version from an old one that still serves the same answers, so smoke.ts asks for the build before its behavioural
// checks (waiting, for a bounded time, while Cloudflare moves traffic to the new version) and again after them (with
// no waiting). Every request asks past any cache: a query string of its own and Cache-Control: no-cache.
//
// The docs Worker is assets-only: it runs no code to answer with a build, and Cloudflare keeps no variables on its
// versions, so its identity is not checked (docs/DEPLOY.md, "What each deploy uploads and records").
import { randomUUID } from "node:crypto";
import { z } from "zod";

export const BUILD_HEADER = "x-apm-build";

export const SmokeStage = z.enum(["staging", "production"]);

export type SmokeStage = z.infer<typeof SmokeStage>;

/** The workers.dev subdomain smoke.ts falls back to when deploy.ts does not pass the one it resolved. */
const FALLBACK_SUBDOMAIN = "leoisadev";

function flag(argv: readonly string[], name: string): string | null {
  const at = argv.indexOf(name);
  const value = at >= 0 ? argv[at + 1] : undefined;

  return value === undefined || value.startsWith("--") ? null : value;
}

/** smoke.ts's arguments: --stage, and from deploy.ts --build (the run's build id) and --subdomain (the account's). */
export function parseSmokeArgs(argv: readonly string[]) {
  return {
    stage: SmokeStage.parse(flag(argv, "--stage") ?? "staging"),
    build: flag(argv, "--build"),
    subdomain: flag(argv, "--subdomain") ?? process.env.WORKERS_SUBDOMAIN ?? FALLBACK_SUBDOMAIN,
  };
}

/** The stage's public addresses: production's own domains, staging's workers.dev ones. */
export function smokeTargets(stage: SmokeStage, subdomain: string) {
  if (stage === "production") return { registry: "https://registry.apmjs.dev/", web: "https://apmjs.dev/", docs: "https://docs.apmjs.dev/" };

  return {
    registry: `https://apmjs-registry-${stage}.${subdomain}.workers.dev/`,
    web: `https://apmjs-web-${stage}.${subdomain}.workers.dev/`,
    docs: `https://apmjs-docs-${stage}.${subdomain}.workers.dev/`,
  };
}

/** The build one uncached request to `url` says answered it; null when the answer has no build header or none came. */
async function answeringBuild(url: string): Promise<{ build: string | null; status: string }> {
  const u = new URL(url);

  u.searchParams.set("apm-build-check", randomUUID());

  try {
    const res = await fetch(u, { cache: "no-store", headers: { "cache-control": "no-cache" }, redirect: "manual", signal: AbortSignal.timeout(15_000) });

    await res.body?.cancel();

    return { build: res.headers.get(BUILD_HEADER), status: `HTTP ${res.status}` };
  } catch (e) {
    return { build: null, status: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * Whether `url` answers with `expected` in `consecutive` uncached requests in a row. A wrong answer starts the count
 * again while `deadlineMs` lasts, and fails it after: a deadline of 0 allows no wrong answer at all.
 */
export async function confirmBuild(input: { name: string; url: string; expected: string; consecutive: number; deadlineMs: number; intervalMs?: number }): Promise<{ ok: boolean; detail: string }> {
  const end = Date.now() + input.deadlineMs;
  const interval = input.intervalMs ?? 2_000;
  let streak = 0;
  let asked = 0;

  for (;;) {
    const answer = await answeringBuild(input.url);

    asked += 1;

    if (answer.build === input.expected) {
      streak += 1;

      if (streak >= input.consecutive) return { ok: true, detail: `${input.name} answered build ${input.expected} ${streak} times in a row (${asked} asked)` };
    } else {
      streak = 0;

      if (Date.now() >= end) {
        const said = answer.build === null ? `no build (${answer.status})` : `build ${answer.build}`;

        return { ok: false, detail: `${input.name} answered ${said}, not this run's ${input.expected} (${asked} asked)` };
      }
    }

    await Bun.sleep(interval);
  }
}
