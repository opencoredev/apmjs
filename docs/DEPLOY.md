# Deploying apm

apm deploys with one command per stage. `packages/infra/deploy.ts` builds the registry Worker, creates and migrates the stage's Neon database, then runs the Alchemy stack in `packages/infra/alchemy.run.ts`, which creates or updates everything on Cloudflare and builds the website.

| Stage | Registry | Website | Neon database |
| --- | --- | --- | --- |
| `staging` | `https://apmjs-registry-staging.<subdomain>.workers.dev/` | `https://apmjs-web-staging.<subdomain>.workers.dev/` | `apmjs_staging` |
| `production` | `https://registry.apmjs.dev/` | `https://apmjs.dev/` | `neondb` |

`<subdomain>` is the account's workers.dev subdomain; deploy.ts reads it from the Cloudflare API.

## Before the first deploy

The deploy reads its secrets from `~/.config/apmjs` (set `APM_SECRETS_DIR` to use another folder). Keep every file mode `0600`; nothing in the repo holds a secret.

| File | Contents |
| --- | --- |
| `cloudflare-token` | A Cloudflare API token with Workers, R2, Hyperdrive, Queues, Observability and Tail on the account, and DNS, routes, SSL and settings on the `apmjs.dev` zone. |
| `cloudflare.env` | `CLOUDFLARE_ACCOUNT_ID=...` |
| `neon-url` | The Neon connection string (the direct endpoint, not `-pooler`). The role needs `CREATEDB` for the staging database. |
| `github-oauth.env` | `APM_GITHUB_CLIENT_ID=...` and `APM_GITHUB_CLIENT_SECRET=...` |
| `review-token-<stage>` | Optional. The AI reviewer's service token for that stage; when the file exists the deploy turns the AI review on and sends only its sha256 (`APM_REVIEW_TOKEN_HASH`). The reviewer process gets the same token. See `docs/AI-REVIEW.md`. |
| `review.env` | Optional. `APM_ADMINS=login,login`: GitHub logins that may confirm or dismiss flagged reviews. |
| `auth-secret-<stage>` | Made by the first deploy of a stage. It signs sessions and encrypts TOTP secrets: changing it signs everyone out and breaks every authenticator app set up so far. Back it up. |

The GitHub OAuth app needs each stage's callback URL: `<website>/api/auth/callback/github`, so `https://apmjs.dev/api/auth/callback/github` and `https://apmjs-web-staging.<subdomain>.workers.dev/api/auth/callback/github`.

Bun 1.4 runs everything; Alchemy's CLI runs under Bun too.

## Deploy

```sh
bun install
bun packages/infra/deploy.ts plan   --stage staging      # what would change; changes nothing
bun packages/infra/deploy.ts deploy --stage staging
bun packages/infra/smoke.ts --stage staging              # check it with stock clients
```

`deploy` prints the stage's URLs. The smoke check runs `bun add` and `npm install` of real npm packages through the registry, `apm add` against a low-score package (it must refuse) and a clean one, a staged `npm publish` approved with a TOTP code and then installed, and `bun audit`. On staging it signs in as a check account (`apm-staging-check`) that it creates in the staging database, because GitHub sign-in needs a person at a browser; everything after sign-in runs the deployed code. It never makes that account on production.

## Production cutover

1. Confirm the zone is on Cloudflare: `dig NS apmjs.dev +short` must print `etta.ns.cloudflare.com` and `norman.ns.cloudflare.com`.
2. `bun packages/infra/deploy.ts deploy --stage production`. The stack attaches `registry.apmjs.dev` and `apmjs.dev` to the Workers as custom domains; Alchemy creates the DNS records and certificates.
3. Check: `curl https://registry.apmjs.dev/-/ping`, open `https://apmjs.dev`, then repeat the stock-client checks by hand or with `bun packages/infra/smoke.ts --stage production` (which skips the staged publish).
4. Sign in with GitHub on `https://apmjs.dev/signin` to confirm the OAuth callback.

## What the stack creates

Per stage: the R2 bucket `apmjs-blobs-<stage>`, the queue `apmjs-analysis-<stage>` and its consumer (the registry Worker, batches of 5, 3 retries), the Hyperdrive config `apmjs-<stage>` with caching off (version states change at any time), the Workers `apmjs-registry-<stage>` (with a cron every 10 minutes) and `apmjs-web-<stage>`, and in production the two custom domains. Workers Logs is on for both Workers.

## State

Alchemy keeps what it deployed in `packages/infra/.alchemy/` on the machine that deploys (gitignored). Back that folder up after each deploy. If it is lost, `bun packages/infra/deploy.ts deploy --stage <stage> --adopt` adopts the existing resources instead of creating new ones. Moving state to Alchemy's Cloudflare state store (`Cloudflare.state()`) needs a token with Secrets Store permission; then CI can deploy too.

## Migrations

Migrations are SQL files in `packages/registry/migrations`, applied in order, each once, inside a transaction, before the Workers update. A run holds a Postgres advisory lock for its whole length, so two runs against one database take turns and the second finds nothing to do. `plan` only lists a missing database, pending migrations and a missing auth secret; `deploy` creates and applies them. They only move forward. Write a new numbered file for every schema change; never edit one that has been applied to staging or production. A deploy whose code needs a new migration applies it first, so the old Worker runs briefly against the new schema: keep changes additive, and drop old columns or tables one release later.

## Rolling back

Deploy the previous commit. The database stays on the newer schema, which is why migrations stay additive.

## Local development

`bun run registry` runs the registry Worker bundle in Miniflare on `http://127.0.0.1:4873/` against a throwaway Postgres (from `initdb`, or `APM_TEST_DATABASE_URL`). Point the website at it with `APM_REGISTRY=http://127.0.0.1:4873/ bun run dev` in `apps/web`. Nothing persists between runs.

## Worker variables

The registry Worker reads these (`packages/registry/src/worker.ts` parses them):

| Variable | Meaning |
| --- | --- |
| `HYPERDRIVE`, `BLOBS`, `ANALYSIS_QUEUE` | The Hyperdrive, R2 and queue bindings. |
| `APM_REGISTRY_URL` | The registry's public URL (tarball links). |
| `APM_PUBLIC_URL` | The website's URL: sign-in callbacks, approval links, the device page. |
| `APM_UPSTREAM` | The registry to proxy, or `off`. |
| `APM_UPSTREAM_TTL_MS` | How long an upstream answer is trusted (default 60000). |
| `APM_NAME_POLICY` | `scoped` (production) or `open`. |
| `APM_LEGACY_AUTH`, `APM_ALLOW_LEGACY_IN_PROD` | npm password accounts. Off in production; on a public https URL they also need the override. |
| `APM_AUTH_SECRET` | Secret. See `auth-secret-<stage>` above. |
| `APM_GITHUB_CLIENT_ID`, `APM_GITHUB_CLIENT_SECRET` | The GitHub OAuth app. Without them the GitHub button is hidden. |
| `APM_VERCEL_CLIENT_ID`, `APM_VERCEL_CLIENT_SECRET` | The Vercel OAuth app. Not set yet, so the Vercel button stays hidden. |
| `APM_REVIEW_TOKEN_HASH` | sha256 (hex) of the AI reviewer's service token. Turns the AI review on. |
| `APM_ADMINS` | GitHub logins that may confirm or dismiss flagged reviews. |
| `APM_REVIEW_POPULAR_WEEKLY`, `APM_NPM_DOWNLOADS_URL`, `APM_REVIEW_LEASE_MS`, `APM_REVIEW_REQUESTS_PER_HOUR`, `APM_REVIEW_MAX_ATTEMPTS` | AI review tuning; defaults in `review.ts`. |

The website Worker gets `REGISTRY` (a service binding to the registry Worker) and `APM_REGISTRY`.
