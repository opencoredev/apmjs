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
3. The router picks a route module: `review.ts` (the AI review queue and views, when it is on), `account.ts` (sign-in, device login, confirmations, staged approvals), `files.ts` (one file of a version as text, for the website's file view), `apm.ts` (scores, resolve, scan, audit, yank and revoke, the upstream proxy), and `server.ts` (the npm protocol: packuments, tarballs, publish, dist-tags, search).
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

Publishing is one transaction that creates or locks the package row, rechecks ownership, writes the tarball to R2, inserts the version (the primary key decides a race: the loser gets 409 and its blob is dropped when nothing else uses it), moves dist-tags and logs the event. Approving a staged version decides the staged row and commits the version in the same transaction. A staged upload is inserted in one transaction that takes an advisory lock, rechecks that nothing waits for the same name@version and that the per-account and per-package quotas still allow it; the byte quota counts the tarball plus the manifest, readme and score the row keeps. A rejected or expired upload keeps only its audit fields. Uploads and cleanup share each blob key's advisory lock: an upload holds it shared from writing the object to inserting the row that points at it, and deleting an unused blob holds it exclusively while it checks for references, so an expiry sweep never deletes the object a re-upload of the same bytes just wrote. Every change to an existing package (yank, revoke, restore, dist-tags, deprecation, owners, incident response) takes the package row lock first and checks ownership under it, so an owner removed while a change waits cannot finish it. Wrong passwords are counted with one upsert before the hash check, so concurrent guesses all count. Per-user answers get `Cache-Control: private, no-store` and `Vary: Authorization, Cookie` in `worker.ts`, whichever route made them.

### Version states

`lifecycle.ts` holds the transitions between `active`, `yanked`, `revoke-pending` and `revoked` as one pure function, so every route agrees on what a yank, unyank, revoke, second-owner confirmation and restore may do. A pending revoke becomes final 24 hours after it started. Reads apply that rule themselves (`effectiveStatus`), so a matured revoke is a 410 the moment its window closes; the cron writes it down and logs the event later. Staged versions expire the same way. This keeps the test clock authoritative and costs no extra write on install traffic. XState would add a runtime for six states and no timer it could own, so it isn't used.

### Scoring npm packages

The score endpoint, `~safe`, resolve and scan need a score now. A request analyzes at most eight upstream tarballs of at most 4 MB itself; anything else is sent to the analysis queue and reads as "not scored yet" (scan lists it as unchecked, `~safe` hides it, resolve skips it). The queue consumer is the same Worker's `queue()` handler, which fetches, verifies, analyzes and stores. `analysis_jobs` keeps one version from being queued twice within ten minutes; when the queue refuses the job, that reservation is dropped so the next request queues it. A job whose upstream failed in a way that may pass (a network error, a 5xx or 429, bytes that failed their checksum, a packument it could not fetch) is handed back with `message.retry()`; only a version the upstream no longer lists, or one apm can never read, is acked unscored.

A Worker has 128 MB of memory, so the registry caps what it reads: upstream downloads at 32 MB, inflated tarballs at 48 MB, publish bodies at 32 MB and JSON API bodies at 5 MB. Request bodies are read through a counting reader that cancels the stream at the cap, so a body with no or a false `Content-Length` is not buffered first. A tarball's `package.json`, which is the manifest apm stores and serves, is capped at 1 MB. A local tarball is checked against its published sha512 before it is served. A package over those caps is refused (publish) or left unscored (upstream), never passed.

Analyses of npm versions are keyed by tarball digest and scorer version, so a re-published tarball or a new scorer never reuses an old answer.

### The file view

Every score citation and AI review finding on the website links to the file it names, opened at the cited line. `files.ts` answers `GET /-/apm/v1/file/<name>/<version>?path=...` from the same verified tarball the install routes serve (a local blob checked against its sha512 integrity, an upstream one through `Upstream.tarball`). The path is matched against the parsed entry list, never joined onto a directory, so `../` names nothing. Files that are not valid UTF-8 are reported with their size and not sent; a revoked version answers 410. Answers are cached in R2 under the tarball's digest: one index of paths and sizes, and one object per path read. The website renders the text as text only, in blocks of 200 lines that skip layout while off screen, and shows bidi controls and other hidden characters as visible markers.

The whole-file answer stops at 1 MB, but a citation can point into a 20 MB bundle, so `?path=...&line=N&context=K` returns lines N−K to N+K (K at most 100) of a file of any size the tarball caps allow, with their real line numbers. A line longer than 4 KB (a minified bundle) is cut on a character boundary and reports its full length. Excerpts are built from blocks of 100 lines cached in R2 per digest, path and block, plus one line count per path, so however many ranges are asked for, the cache holds at most one copy of the file. A line past the end answers 416 with the line count. Evidence links carry the line in the query as well as the fragment (`?line=12#L12`), because the server only sees the query: a file over 1 MB opens as an excerpt of about 40 lines around the cited one, highlighted, with "Show more" controls that fetch 100 lines at a time.

`GET /-/apm/v1/readme/<name>/<version>` answers the README in a version's tarball, picked the way npm picks one (a root `README` or `README.*` file, any case; the first with a markdown-like extension in path order, else one named exactly `README`), through the same checks and caps as the file view. The package page uses it when npm's packument carries no readme, and says "No readme published" when neither has one. The page also links the latest version's `homepage`, `repository` and `bugs`, but only http(s) URLs without credentials, with the same `rel` as readme links.

### AI release review

`review.ts` keeps the review-job queue and results in Postgres (`0004_reviews_and_password_lockout.sql`). The model never runs on Cloudflare: the reviewer process (`apps/reviewer`) runs next to the model on the owner's tailnet, leases jobs with a service token (`SELECT ... FOR UPDATE SKIP LOCKED`, so two reviewers never get the same job), downloads tarballs from the registry, and posts results back. The Worker stores only the token's sha256.

Two hooks fill the queue. After a publish or an approval commits, the version is queued on the request's own connection. When an upstream packument is fetched (not on a cache hit), the enqueue policy runs after the response through `ctx.waitUntil`, on its own Postgres connection, because the request's connection closes with the request. The `review_seen` high-water mark is claimed in the same transaction that inserts the jobs, so two isolates that fetched the same packument queue its new versions once, and a failed insert leaves them unseen for the next fetch. The download count the policy needs is fetched before that transaction. See `docs/AI-REVIEW.md`.

### Sign-in and second factors

Better Auth handles OAuth, sessions, TOTP enrolment, passkeys and the device flow. The registry exposes only the Better Auth routes the website uses, and gates the ones that change how someone signs in behind the existing factor (the `x-apm-second-factor` header). apm checks codes itself, against a ledger in Postgres: one attempt budget per account across TOTP and recovery codes, each TOTP time step accepted once, and a website confirmation of one named CLI command used once within ten minutes. Because the ledger is in Postgres, every Worker isolate sees the same budget.

Every second factor on the website is bound to one action (`0007_action_confirmations.sql`). `actions.ts` gives each website action one canonical key that holds every parameter deciding what it does: the staged upload's id, the CLI command, the review decision and its note, the evidence item and the reason, the sign-in setting. A code, or a passkey check, issues a confirmation for that key and the session that made it (`POST /-/apm/v1/factor/confirm`), and the change spends a confirmation only when its own key and session match, once, within five minutes. A passkey check answers a WebAuthn challenge the registry made for one named action (`POST /-/apm/v1/factor/passkey-challenge`) and is verified against the account's own passkeys; Better Auth's passkey sign-in makes a session and no confirmation. A code sent with the change itself is issued and spent on that change in the same request. The website-only routes (approvals, confirmations, review decisions, evidence dismissals, token revocation and the gated sign-in settings) refuse a request without the website's `Origin` (`origin.ts`); routes that take a token do not look at it.

### The website

The website is Next.js 16 with shadcn, built by OpenNext through Alchemy's `Website.Nextjs`. `proxy.ts` forwards `/api/auth/*` and `/-/apm/v1/*` to the registry so the session cookie lives on the website's origin, and server components read the registry for package pages and search. Both go through `lib/registry-transport.ts`: inside the Worker that is the `REGISTRY` service binding, because Workers on one account can't fetch each other's public URLs and a binding skips the network hop; under `next dev` it is plain HTTP to `APM_REGISTRY`.

A package's readme is publisher-written, so `lib/readme.ts` renders it on the server through unified (remark-gfm, rehype-raw, rehype-sanitize with GitHub's allow-list) into React elements, never inner HTML. Relative links and images resolve into the package's GitHub repository (the `repository` field of the package answer) or are dropped, images load over https only, external links get `rel="nofollow noopener noreferrer ugc"`, and every id is prefixed with `user-content-`.

## How `apm add` makes the package manager install what apm checked

`apm add` asks the registry to resolve and score a package, then runs your package manager (bun, npm, pnpm or yarn) to install the exact version. The check only means something if the package manager then installs the same bytes from the same registry, for the package and for everything under it. Two things can break that:

- A config file sends a scope to another registry. A project `.npmrc` line like `@someone:registry=https://elsewhere/` applies to every package in that scope, including dependencies several levels down.
- A lockfile pins a package to another registry's tarball. bun, npm and pnpm reuse a locked `resolved` URL and integrity even when told a different registry, so a committed lockfile can bring in bytes apm never saw.

`apm add` closes both, in this order:

1. **Bind every scope in the tree.** The resolve answer lists every package the registry walked under the added ones (`tree.packages`). apm pins each scope among them, plus the added packages' own scopes, to the checked registry: `--registry` and `--@scope:registry` flags for npm and pnpm, and the matching `npm_config_*`/`BUN_CONFIG_REGISTRY` variables in the child environment. If an `.npmrc`, `bunfig.toml` or `.yarnrc.yml` sends one of those scopes elsewhere, apm refuses before it installs anything.
2. **Check the added packages' existing lockfile entries.** An entry for an added name@version whose integrity differs from what the checked registry serves is refused before anything is fetched.
3. **Install with scripts held back.** bun, npm and pnpm run with `--ignore-scripts`, so no `preinstall`, `install` or `postinstall` script runs yet.
4. **Verify every installed node.** apm reads the lockfile the install wrote (`bun.lock`, `package-lock.json` or `pnpm-lock.yaml`, or npm's and pnpm's copy in `node_modules` when the project lockfile is off), walks it from the added packages to every package under them, and compares each node's integrity with the one the checked registry serves for that name@version. Git, file and link dependencies are not on a registry; the resolve step already lists them as not checked.
5. **Then run the scripts, or undo the install.** If every node matches, apm runs the held-back scripts: `npm rebuild <packages with install scripts>`, `pnpm rebuild --pending`, and for bun, which only runs scripts while installing a package, it removes those packages' directories and runs `bun install --frozen-lockfile` from the verified lockfile. Each package manager's own script policy still applies (bun's `trustedDependencies`, pnpm's `onlyBuiltDependencies`). If any node does not match, apm puts `package.json` and the lockfile back, removes the unverified packages from `node_modules`, names each one, and exits non-zero. Their scripts never ran.

If apm cannot read the lockfile after the install, it refuses and does not run the scripts.

Limits:

- yarn gets steps 1 and 2 only. apm does not read `yarn.lock`, so yarn installs run their scripts as usual.
- `apm x` (bunx, npx, pnpm dlx) gets step 1 only. Those tools install into their own cache with no project lockfile to verify.
- The tree walk stops after 300 packages; anything past that is listed as not checked, and only the lockfile verification in step 4 covers it.

## Tests

The acceptance suite (`tests/acceptance`, 309 tests) drives real `bun`, `npm` and `pnpm` and the `apm` CLI against the registry exactly as it ships:

- `packages/registry/scripts/build.ts` bundles the Worker with rolldown and the Cloudflare plugin set Alchemy uses. The deploy uploads `dist/worker.js` as built (`bundle: false`); the suite runs `dist/worker-test.js`, which imports that entry and adds test-only controls.
- Miniflare runs the bundle in workerd with R2, the analysis queue and its consumer, and Hyperdrive simulated locally. Hyperdrive points at a real Postgres 18 cluster the suite starts with `initdb` (`tests/acceptance/postgres.ts`), or at `APM_TEST_DATABASE_URL`. Each registry gets a copy of one migrated template database.
- A small proxy in front of Miniflare stamps the test's clocks on every request (`x-apm-test-now`, `x-apm-test-totp-now`), so tests keep moving time with `clock += DAY` while stock clients make the requests. The test entry honours those headers, `/__test/mint`, `/__test/blobs`, `/__test/sweep` (the cron's sweep at the test clock), `/__test/analysis-job` (the queue consumer on one job, reporting ack or retry), `x-apm-test-queue: fail` (an analysis queue that refuses every send) and `x-apm-test-fault: event-insert` (every public-log insert fails inside Postgres) only for callers holding a per-run secret that the deployed Worker never has. Tests that race a request against a lock open their own Postgres connection to the registry's database.

Why not PGlite: Miniflare's Hyperdrive simulation connects over TCP, so PGlite would need its socket server, which serves one connection at a time, while a request here can hold two (the store and Better Auth) and the queue consumer runs in parallel. PGlite is also not Postgres 18. This machine has Postgres 18 installed, CI installs it from PGDG, and Neon runs 18, so the suite tests the same SQL that production runs. Why not `wrangler dev`: Miniflare's API starts in well under a second per registry, takes bindings as plain options and needs no config file per test.

`packages/registry/test` holds the second-factor, body-limit and migration-lock unit tests; the database ones run against a fresh Postgres database through the real `Store`. `packages/infra/test` checks that `deploy.ts plan` changes nothing. `packages/infra/smoke.ts` checks a deployed stage with stock clients.

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
