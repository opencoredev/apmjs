# Architecture

apm runs on Cloudflare: two Workers, one Postgres on Neon, one R2 bucket and one queue, declared together in an Alchemy stack. This page says what each part does, how a request moves through the registry, and why it is built this way.

## The parts

```
 npm, bun, pnpm, apm CLI ──────────────▶ registry Worker  (registry.apmjs.dev)
                                            │  Effect program over request-scoped services
 browser ──▶ website Worker (apmjs.dev)     ├─ Store ────▶ Hyperdrive ──▶ Neon Postgres 18
             Next.js via OpenNext ──────────┤                         (packages, versions, accounts,
             REGISTRY service binding       │                          Better Auth, second-factor ledger)
                                            ├─ Blobs ────▶ R2 bucket (tarballs by sha512)
                                            ├─ Upstream ─▶ registry.npmjs.org
                                            ├─ Analysis ─▶ analysis queue ──▶ same Worker's queue()
                                            ├─ Review ◀── apps/reviewer (pulls AI review jobs over HTTPS)
                                            └─ cron every 10 min: write down matured revokes, expire staged versions
```

| Package | What it is |
| --- | --- |
| `packages/core` | The score engine, tarball reader, name and dependency parsers. Plain TypeScript, no I/O. |
| `packages/registry` | The registry Worker. `src/worker.ts` is the entry; `scripts/build.ts` bundles it. |
| `packages/infra` | The Alchemy stack (`alchemy.run.ts`), the deploy script and the smoke check. |
| `apps/web` | The website: Next.js 16 with shadcn, built with OpenNext and deployed as a Worker. |
| `packages/cli`, `packages/bun-scanner` | The `apm` CLI and the Bun security scanner. They talk HTTP to the registry. |

## A registry request

1. `worker.ts` parses the Worker's environment with a zod schema (bindings, vars, secrets). A misconfigured Worker answers 500 and logs why; legacy password auth on a public https URL without `APM_ALLOW_LEGACY_IN_PROD` answers 503 to every request.
2. It builds the request's services as Effect layers (`servicesFor`) and runs `router.ts`.
3. The router picks a route module: `review.ts` (the AI review queue and views, when it is on), `account.ts` (sign-in, device login, confirmations, staged approvals), `apm.ts` (scores, resolve, scan, audit, yank and revoke, the upstream proxy), and `server.ts` (the npm protocol: packuments, tarballs, publish, dist-tags, search).
4. A route returns a `Response` or fails with a typed error. `HttpFailure` becomes its JSON error body; `StoreError`, `BlobError`, `AuthError` and `QueueError` become a 500 and one structured log line with the operation that failed.

The layers live for one request. `Store` opens one Postgres connection through Hyperdrive and closes it when the request ends; Hyperdrive pools the connections to Neon. Better Auth is built on first use, so routes that never touch sign-in never pay for it.

### Services

| Service | File | Job |
| --- | --- | --- |
| `Store` | `db.ts` | Every table, through `@effect/sql-pg`. Rows are parsed with zod schemas at this boundary. Includes the second-factor ledger. |
| `Blobs` | `blobs.ts` | Tarball bytes in R2, keyed `sha512/<hex>`. A staged tarball that gets approved keeps its object; identical bytes share one. |
| `Upstream` | `upstream.ts` | Reads npm: packuments, search, scope checks, advisories, and tarballs fetched only from the upstream's origin, verified against the published checksum and cached in R2. |
| `Analysis` | `analysis.ts` | Scores upstream versions: a few small tarballs per request inline, the rest on the queue. |
| `Auth` | `auth.ts` | Better Auth (GitHub, Vercel, TOTP, passkeys, device flow) on the same Postgres, with apm's own route allow-list and second-factor checks. |
| `Clock` | `clock.ts` | The registry's time (`now`) and the wall clock codes are checked against (`wallNow`). |
| `RegistryConfig` | `config.ts` | Public URLs, the upstream, the name policy and legacy auth. |
| `ReviewConfig` | `review.ts` | Present only when `APM_REVIEW_TOKEN_HASH` is set: the AI review's service token hash, admins and limits. Its routes and hooks do nothing without it. |
| `ReleaseHooks` | `hooks.ts` | Listeners for "a version went live" and "an upstream packument was fetched". `worker.ts` wires the AI review queue to them. |

### Data

The schema is SQL in `packages/registry/migrations`, applied in order by `scripts/migrate.ts` and recorded in `apm_migrations`. Times are milliseconds in `bigint` columns; manifests, scores and dist-tags are `jsonb`. Better Auth's tables come from its own generator (`0002_better_auth.sql`).

Publishing is one transaction that creates or locks the package row, rechecks ownership, inserts the version (the primary key decides a race: the loser gets 409 and its blob is dropped when nothing else uses it), moves dist-tags and logs the event. Approving a staged version decides the staged row and commits the version in the same transaction.

### Version states

`lifecycle.ts` holds the transitions between `active`, `yanked`, `revoke-pending` and `revoked` as one pure function, so every route agrees on what a yank, unyank, revoke, second-owner confirmation and restore may do. A pending revoke becomes final 24 hours after it started. Reads apply that rule themselves (`effectiveStatus`), so a matured revoke is a 410 the moment its window closes; the cron writes it down and logs the event later. Staged versions expire the same way. This keeps the test clock authoritative and costs no extra write on install traffic. XState would add a runtime for six states and no timer it could own, so it isn't used.

### Scoring npm packages

The score endpoint, `~safe`, resolve and scan need a score now. A request analyzes at most eight upstream tarballs of at most 4 MB itself; anything else is sent to the analysis queue and reads as "not scored yet" (scan lists it as unchecked, `~safe` hides it, resolve skips it). The queue consumer is the same Worker's `queue()` handler, which fetches, verifies, analyzes and stores. `analysis_jobs` keeps one version from being queued twice within ten minutes.

A Worker has 128 MB of memory, so the registry caps what it reads: upstream downloads at 32 MB, inflated tarballs at 48 MB, publish bodies at 32 MB and JSON API bodies at 5 MB. A package over those caps is refused (publish) or left unscored (upstream), never passed.

Analyses of npm versions are keyed by tarball digest and scorer version, so a re-published tarball or a new scorer never reuses an old answer.

### AI release review

`review.ts` keeps the review-job queue and results in Postgres (`0004_reviews_and_password_lockout.sql`). The model never runs on Cloudflare: the reviewer process (`apps/reviewer`) runs next to the model on the owner's tailnet, leases jobs with a service token (`SELECT ... FOR UPDATE SKIP LOCKED`, so two reviewers never get the same job), downloads tarballs from the registry, and posts results back. The Worker stores only the token's sha256.

Two hooks fill the queue. After a publish or an approval commits, the version is queued on the request's own connection. When an upstream packument is fetched (not on a cache hit), the enqueue policy runs after the response through `ctx.waitUntil`, on its own Postgres connection, because the request's connection closes with the request. The `review_seen` high-water mark is claimed in one statement, so two isolates that fetched the same packument queue its new versions once. See `docs/AI-REVIEW.md`.

### Sign-in and second factors

Better Auth handles OAuth, sessions, TOTP enrolment, passkeys and the device flow. The registry exposes only the Better Auth routes the website uses, and gates the ones that change how someone signs in behind the existing factor (the `x-apm-second-factor` header). apm checks codes itself, against a ledger in Postgres: one attempt budget per account across TOTP and recovery codes, each TOTP time step accepted once, a passkey check spent on one action from the session that made it, and a website confirmation of one named CLI command used once within ten minutes. Because the ledger is in Postgres, every Worker isolate sees the same budget.

### The website

The website is Next.js 16 with shadcn, built by OpenNext through Alchemy's `Website.Nextjs`. `proxy.ts` forwards `/api/auth/*` and `/-/apm/v1/*` to the registry so the session cookie lives on the website's origin, and server components read the registry for package pages and search. Both go through `lib/registry-transport.ts`: inside the Worker that is the `REGISTRY` service binding, because Workers on one account can't fetch each other's public URLs and a binding skips the network hop; under `next dev` it is plain HTTP to `APM_REGISTRY`.

## Tests

The acceptance suite (`tests/acceptance`, 220 tests) drives real `bun`, `npm` and `pnpm` and the `apm` CLI against the registry exactly as it ships:

- `packages/registry/scripts/build.ts` bundles the Worker with rolldown and the Cloudflare plugin set Alchemy uses. The deploy uploads `dist/worker.js` as built (`bundle: false`); the suite runs `dist/worker-test.js`, which imports that entry and adds three test controls.
- Miniflare runs the bundle in workerd with R2, the analysis queue and its consumer, and Hyperdrive simulated locally. Hyperdrive points at a real Postgres 18 cluster the suite starts with `initdb` (`tests/acceptance/postgres.ts`), or at `APM_TEST_DATABASE_URL`. Each registry gets a copy of one migrated template database.
- A small proxy in front of Miniflare stamps the test's clocks on every request (`x-apm-test-now`, `x-apm-test-totp-now`), so tests keep moving time with `clock += DAY` while stock clients make the requests. The test entry honours those headers, `/__test/mint` and `/__test/blobs` only for callers holding a per-run secret that the deployed Worker never has.

Why not PGlite: Miniflare's Hyperdrive simulation connects over TCP, so PGlite would need its socket server, which serves one connection at a time, while a request here can hold two (the store and Better Auth) and the queue consumer runs in parallel. PGlite is also not Postgres 18. This machine has Postgres 18 installed, CI installs it from PGDG, and Neon runs 18, so the suite tests the same SQL that production runs. Why not `wrangler dev`: Miniflare's API starts in well under a second per registry, takes bindings as plain options and needs no config file per test.

`packages/registry/test` holds the second-factor unit tests; they run against a fresh Postgres database through the real `Store`. `packages/infra/smoke.ts` checks a deployed stage with stock clients.

## Rat Stack

The project follows [Rat Stack](https://ratstack.sh) where it applies: Effect 4.1.2 services with typed errors, `@effect/sql-pg` 4.1.2, Alchemy 2.0.0-beta.85 declaring every cloud resource in one TypeScript program, everything on Cloudflare, exact version pins. Where it differs, and why:

| Rat Stack | apm | Why |
| --- | --- | --- |
| Foldkit UI | Next.js and shadcn | The owner's call: the website already exists and works. |
| Effect-native Workers (`Cloudflare.Worker(..., Effect.gen(...))`) | A plain module Worker running an Effect program | The bundle the suite tests is byte for byte the bundle Alchemy uploads, and it runs under Miniflare without Alchemy's dev runtime. |
| Effect `Schema` at boundaries | zod | The repo, the CLI, the website and the other workers' code all use zod 4. Effect errors are `Data.TaggedError`. |
| pnpm, TypeScript 7 | bun, TypeScript 5.9 | The acceptance suite drives bun and the repo is a bun workspace; the website's toolchain is on TypeScript 5. |
| Alchemy state in a Cloudflare state store | Alchemy's local state (`packages/infra/.alchemy`) | The deploy token has no Secrets Store permission, which the Cloudflare store needs. See [DEPLOY.md](./DEPLOY.md). |
| XState for lifecycles | A transition function | See [Version states](#version-states). |
