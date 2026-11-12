// apm on Cloudflare, as one Alchemy stack: the registry Worker with its R2 bucket, analysis queue and Hyperdrive
// in front of Neon, and the website Worker. Stages: "staging" serves on workers.dev; "production" on apmjs.dev.
// Secrets arrive as environment variables from deploy.ts, which reads them from ~/.config/apmjs.
import { resolve } from "node:path";
import * as Cloudflare from "@alchemy.run/cloudflare";
import * as Alchemy from "alchemy";
import * as Config from "effect/Config";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import { COMPATIBILITY_DATE, COMPATIBILITY_FLAGS } from "../registry/scripts/compat.ts";

const PRODUCTION = { registry: "registry.apmjs.dev", web: "apmjs.dev", docs: "docs.apmjs.dev" } as const;

export default Alchemy.Stack(
  "apmjs",
  { providers: Cloudflare.providers(), state: Alchemy.localState() },
  Effect.gen(function* () {
    const stage = yield* Alchemy.Stage;
    const production = stage === "production";
    const subdomain = yield* Config.String("WORKERS_SUBDOMAIN");
    const registryName = `apmjs-registry-${stage}`;
    const webName = `apmjs-web-${stage}`;
    const registryUrl = production ? `https://${PRODUCTION.registry}/` : `https://${registryName}.${subdomain}.workers.dev/`;
    const webUrl = production ? `https://${PRODUCTION.web}/` : `https://${webName}.${subdomain}.workers.dev/`;
    const docsName = `apmjs-docs-${stage}`;
    const docsUrl = production ? `https://${PRODUCTION.docs}/` : `https://${docsName}.${subdomain}.workers.dev/`;

    const neon = new URL(Redacted.value(yield* Config.Redacted("NEON_URL")));
    const database = yield* Config.String("APM_DATABASE");

    const blobs = yield* Cloudflare.R2.Bucket("Blobs", { name: `apmjs-blobs-${stage}` });
    const analysis = yield* Cloudflare.Queues.Queue("Analysis", { name: `apmjs-analysis-${stage}` });

    const postgres = yield* Cloudflare.Hyperdrive.Connection("Postgres", {
      name: `apmjs-${stage}`,
      origin: {
        scheme: "postgres",
        host: neon.hostname,
        port: 5432,
        database,
        user: decodeURIComponent(neon.username),
        password: Redacted.make(decodeURIComponent(neon.password)),
      },
      // Version state changes at any time (yank, revoke), so nothing the registry reads may come from a cache.
      caching: { disabled: true },
    });

    // the AI review (docs/AI-REVIEW.md) is on when deploy.ts found this stage's reviewer token; only its sha256 is sent
    const reviewTokenHash = yield* Config.withDefault(Config.String("REVIEW_TOKEN_HASH"), "");
    const admins = yield* Config.withDefault(Config.String("APM_ADMINS"), "");
    const review = Object.fromEntries(reviewTokenHash === "" ? [] : [["APM_REVIEW_TOKEN_HASH", reviewTokenHash], ["APM_ADMINS", admins]]);

    const registry = yield* Cloudflare.Worker("Registry", {
      name: registryName,
      main: yield* Config.withDefault(Config.String("APM_REGISTRY_BUNDLE"), resolve(import.meta.dirname, "../registry/dist/worker.js")),
      bundle: false,
      compatibility: { date: COMPATIBILITY_DATE, flags: [...COMPATIBILITY_FLAGS] },
      env: {
        HYPERDRIVE: postgres,
        BLOBS: blobs,
        ANALYSIS_QUEUE: analysis,
        APM_REGISTRY_URL: registryUrl,
        APM_PUBLIC_URL: webUrl,
        APM_UPSTREAM: "https://registry.npmjs.org/",
        APM_NAME_POLICY: "scoped",
        APM_LEGACY_AUTH: "0",
        APM_AUTH_SECRET: yield* Config.Redacted("AUTH_SECRET"),
        APM_GITHUB_CLIENT_ID: yield* Config.String("GITHUB_CLIENT_ID"),
        APM_GITHUB_CLIENT_SECRET: yield* Config.Redacted("GITHUB_CLIENT_SECRET"),
        ...review,
      },
      // Writes down pending revokes past 24h and expired staged versions; reads already treat them as final.
      crons: ["*/10 * * * *"],
      observability: { enabled: true, logs: { enabled: true, invocationLogs: true } },
      // staging has no custom domain: undefined leaves workers.dev as the only address
      domain: production ? PRODUCTION.registry : undefined,
    });

    yield* Cloudflare.Queues.Consumer("AnalysisConsumer", {
      queueId: analysis.queueId,
      scriptName: registry.workerName,
      settings: { batchSize: 5, maxRetries: 3, maxWaitTimeMs: 1000, retryDelay: 30 },
    });

    // The website: Next.js through OpenNext. Its route handlers forward /api/auth/* and /-/apm/v1/* to the registry,
    // so sign-in cookies live on the website's origin.
    const website = yield* Cloudflare.Website.Nextjs("Web", {
      name: webName,
      rootDir: resolve(import.meta.dirname, "../../apps/web"),
      // REGISTRY is a service binding: Workers on one account cannot reach each other's public URLs
      env: { REGISTRY: registry, APM_REGISTRY: registryUrl },
      openNext: { buildCommand: "bun run build" },
      observability: { enabled: true, logs: { enabled: true, invocationLogs: true } },
      domain: production ? PRODUCTION.web : undefined,
    });

    // The docs (apps/docs, Blume): static HTML served by an assets-only Worker, so no Worker code is uploaded.
    // drop-trailing-slash serves /quickstart without redirecting to /quickstart/, as Blume's deployment guide asks.
    const docs = yield* Cloudflare.Website.StaticSite("Docs", {
      name: docsName,
      cwd: resolve(import.meta.dirname, "../../apps/docs"),
      command: "bun run build",
      outdir: "dist",
      assets: { htmlHandling: "drop-trailing-slash", notFoundHandling: "404-page" },
      observability: { enabled: true, logs: { enabled: true, invocationLogs: true } },
      domain: production ? PRODUCTION.docs : undefined,
    });

    return { registry: registryUrl, web: webUrl, docs: docsUrl, registryWorker: registry.url, webWorker: website.url, docsWorker: docs.url };
  }),
);
