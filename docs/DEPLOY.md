# Deploying apm

apm deploys with one command per stage. `packages/infra/deploy.ts` builds the registry Worker, creates and migrates the stage's Neon database, then runs the Alchemy stack in `packages/infra/alchemy.run.ts`, which creates or updates everything on Cloudflare and builds the website and the docs site.

| Stage | Registry | Website | Docs | Neon database |
| --- | --- | --- | --- | --- |
| `staging` | `https://apmjs-registry-staging.<subdomain>.workers.dev/` | `https://apmjs-web-staging.<subdomain>.workers.dev/` | `https://apmjs-docs-staging.<subdomain>.workers.dev/` | `apmjs_staging` |
| `production` | `https://registry.apmjs.dev/` | `https://apmjs.dev/` | `https://docs.apmjs.dev/` | `neondb` |

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
| `debug-token-<stage>` | Optional. A token for reading the registry's full `Server-Timing` (every metric with its count): send it as the `x-apm-debug` header. The deploy sends only its sha256 (`APM_DEBUG_TOKEN_HASH`); without the file no caller gets the header. |
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

`deploy` prints the stage's URLs. The smoke check installs real npm packages through the registry with bun and npm from committed lockfiles (`packages/infra/smoke-fixtures/`: `bun install --frozen-lockfile` and `npm ci`, scripts off, every tarball checked against the lockfile's integrity, so a registry answer cannot add a dependency or run its code), checks that the registry's metadata resolves each locked version to that integrity at exactly the tarball URL the locked install fetches, with exactly the dependencies the lockfile records for it, and that `latest` names a version the metadata lists, runs `apm add` against a low-score package (three 0.187.0, which has no dependencies, so no cooldown can refuse it: the default must warn and install it, `--strict` must refuse it; a failed check prints apm's whole output) and a clean one, a staged `npm publish` approved with a TOTP code (live means the metadata lists that version with the packed tarball's integrity at its tarball URL, tagged `latest`) and then installed with `npm ci` from a lockfile holding the integrity of the tarball the check packed, and `bun audit` of a locked project whose install must pass first. No install it runs executes an install script. To change a probe's packages, regenerate its lockfile against registry.npmjs.org and let `packages/infra/test/smoke-commands.test.ts` check it: it refuses a fixture with anything but exact registry versions and integrity. That check runs after the lockfile is written, so it cannot stop what the regeneration itself runs. npm's lock computation can run a git dependency's `prepare` even with `--package-lock-only --ignore-scripts` (`tests/acceptance/ignore-scripts-git.test.ts` reproduces it), so a dependency that resolves to a git repository runs its code before anything checks the lock. Regenerate an npm lockfile (`npm install --package-lock-only --ignore-scripts`) only in a disposable environment with no credentials: a fresh container or VM with no `~/.npmrc` token, SSH key or agent, cloud or apm secrets and no checkout of this repo beyond the probe's directory, thrown away afterwards. A bun lockfile can be regenerated in place with `bun install --lockfile-only --ignore-scripts`: in the same acceptance tests bun computes a lockfile with scripts ignored (`bun add --lockfile-only --ignore-scripts`) and runs no git dependency's `prepare`. On staging it signs in as a check account (`apm-staging-check`) that it creates in the staging database, because GitHub sign-in needs a person at a browser; everything after sign-in runs the deployed code. It never makes that account on production.

### Order

Migrations run first, then Alchemy updates the registry Worker, then the website. The website's `REGISTRY` service binding makes it depend on the registry, and Alchemy starts a resource only after everything it depends on has finished, and not at all when one failed. The order matters for revocation: the registry is the only thing that decides whether a version's source (files, excerpts, readmes, review quotes, score evidence) may be shown, and the website shows whatever it answers. A website deployed on its own against an older registry fails closed: it requires the `redacted` and `readmeVersion` fields that only a registry with the allowlist redaction sends, and shows "registry unavailable" where it would have shown the answer.

### Install checks

What the registry checks before it answers an install read of a package only npm has is set per deploy: `--install-checks database` (the default; one database statement per request) or `--install-checks edge` (each isolate's read of the R2 block list, no statement; `packages/registry/src/edge-checks.ts`, and `docs/ARCHITECTURE.md`, "Install checks answered in the data center"). `APM_INSTALL_CHECKS=edge` in the environment does the same; the flag wins. The deploy's first line says which it used.

Edge views are safe only while every registry version that can publish holds the publish fence: a first publish puts its name on the block list and waits 8 s before its transaction, so no view without the name still answers when the name exists. Every build from this one on holds the fence in either mode; older builds do not. A Worker deploy is not atomic (old versions keep serving for a while, and a publish can still be running on one), so turn edge views on in two deploys:

1. Phase 1: deploy this build, or any later one, in database mode, saying so: `bun packages/infra/deploy.ts deploy --stage <stage> --install-checks database`. Its first line must say `install checks database`.
2. Phase 2: once it is the only version serving (`bun packages/infra/rollback.ts list --stage <stage>` shows one live deployment at 100% and no older one, and a few minutes have passed for publishes in flight on the old one), deploy again with `--install-checks edge`.

Each run's line in the release record keeps the mode it deployed (`installChecks`), written only once the registry's live version is confirmed to carry that `APM_INSTALL_CHECKS`, and `rollback.ts list` shows it beside each registry build (`install checks database` or `edge`; a line from before the field is a build with no edge mode, shown as `database`).

To go back: first deploy in database mode (or roll back to a build of this line that `rollback.ts list` shows with `install checks database`), wait until that is the only version serving, and only then roll back to a build without the fence. Rolling back from an edge deploy straight to a build without the fence leaves edge readers serving while fence-less publishes run.

Each isolate in edge mode logs an `edge-checks` line once a minute in Workers Logs: how many requests it cleared, how many fell back and why (`published-here`, `confirmed`, `no-view`, `slow-read`, `expired`, `unservable`), its R2 reads and Cache API copies, failed reads, and skipped, late or failed analysis asks. Each request is counted once, as it was answered (a clearance that aged out before the answer counts only as `expired`), so the fallback share is the fallback counts over the fallbacks plus `clear`. These lines go to Workers Logs only; nothing of them is sent to Databuddy.

## Production cutover

1. Confirm the zone is on Cloudflare: `dig NS apmjs.dev +short` must print `etta.ns.cloudflare.com` and `norman.ns.cloudflare.com`.
2. `bun packages/infra/deploy.ts deploy --stage production`. The stack attaches `registry.apmjs.dev`, `apmjs.dev` and `docs.apmjs.dev` to the Workers as custom domains; Alchemy creates the DNS records and certificates.
3. Check: `curl https://registry.apmjs.dev/-/ping`, open `https://apmjs.dev` and `https://docs.apmjs.dev`, then repeat the stock-client checks by hand or with `bun packages/infra/smoke.ts --stage production` (which skips the staged publish).
4. Sign in with GitHub on `https://apmjs.dev/signin` to confirm the OAuth callback.

## What the stack creates

Per stage: the R2 bucket `apmjs-blobs-<stage>` (tarballs under `sha512/`, file views under `files/`, and under `state/` the install block list and the queue probe's last record), the R2 bucket `apmjs-cli-<stage>` (the CLI's binaries and install script, bound to the website as `CLI`; see [The apm CLI](#the-apm-cli)), the queue `apmjs-analysis-<stage>` and its consumer (the registry Worker, batch size 1, maxConcurrency 1, 5 retries), the Hyperdrive config `apmjs-<stage>` with caching off (version states change at any time), the Workers `apmjs-registry-<stage>` (with a cron every 10 minutes) and `apmjs-web-<stage>`, the assets-only Worker `apmjs-docs-<stage>` (the Blume build of `apps/docs`, no Worker code), and in production the three custom domains. Workers Logs is on for all three.

## State

Alchemy keeps what it deployed in `packages/infra/.alchemy/` on the machine that deploys (gitignored). Back that folder up after each deploy. If it is lost, `bun packages/infra/deploy.ts deploy --stage <stage> --adopt` adopts the existing resources instead of creating new ones. Moving state to Alchemy's Cloudflare state store (`Cloudflare.state()`) needs a token with Secrets Store permission; then CI can deploy too.

## Migrations

Migrations are SQL files in `packages/registry/migrations`, applied in order, each once, inside a transaction, before the Workers update. A run holds a Postgres advisory lock for its whole length, so two runs against one database take turns and the second finds nothing to do. `plan` only lists a missing database, pending migrations and a missing auth secret; `deploy` creates and applies them. They only move forward. Write a new numbered file for every schema change; never edit one that has been applied to staging or production. A deploy whose code needs a new migration applies it first, so the old Worker runs briefly against the new schema: keep changes additive, and drop old columns or tables one release later.

A migration that the previous release's code still runs correctly against (a new table or index, a nullable column) says so with a `-- apm:rollback-safe` line in its leading comment, optionally followed by why (`-- apm:rollback-safe: a new table nothing older reads`). Only then may `rollback.ts` put older Workers back after it ran; without the marker it refuses.

## Rolling back

### Scope

- **Where:** every production and staging deploy, and every rollback, runs on evo-1 from `/home/leo/code/apmjs`, through `packages/infra/deploy.ts` or `packages/infra/rollback.ts`.
- **Unsupported:** deploying from another machine, from another clone, or through the Cloudflare dashboard (a dashboard edit, a dashboard rollback, `wrangler deploy`). Such a deploy is in no release record. `rollback.ts` then refuses to change any Worker running it, or to go back to it, but it can still confuse which build is current. Don't do it, and if it happened, run `rollback.ts list` and decide by hand.
- **The lock is machine-local** (below): it keeps runs on evo-1 apart, not runs anywhere else.
- **Nothing rolls back on its own:** a failed deploy prints the command to run.

### The release lock

One exclusive lock covers every change to apm's Workers and database. The incident agent's helper uses the same lock; this is the contract agreed with it.

- **The lock:** an exclusive `flock(LOCK_EX|LOCK_NB)` on `/home/leo/.config/apmjs/release.lock` (`~/.config/apmjs/release.lock` for whoever runs it). The `APM_RELEASE_LOCK` environment variable overrides the path, and `deploy.ts`, `rollback.ts` and `release-lock.ts` honour it.
- **Busy means refused:** a run that finds it held changes nothing, prints who holds it and exits with code 6. Nothing waits for it, and nothing releases it on a timer.
- **Held for the whole run:**
  - `deploy.ts deploy` takes it before anything else (secrets, migrations, builds) and holds it through the upload, the smoke check and the release record;
  - `rollback.ts ... --yes` takes it before it reads anything and holds it through the rollback;
  - `deploy.ts plan`, `rollback.ts list` and runs without `--yes` change nothing and take no lock.
- **Held by the children that change things:** Alchemy's upload and the smoke check hold it with the run, so killing `deploy.ts` while Alchemy is still uploading leaves the lock held until Alchemy ends.
- **No other way in:** no environment variable or record makes a run the holder. Every run takes the lock itself.
- **The holder record:** `release.lock.json` next to the lock records `pid`, `started`, `command`, `sha` (the checkout's git SHA) and `stage`, and is removed when the run ends. It only describes the holder; whether the lock is held is always the kernel's answer.

How it is held (`packages/infra/release-lock.ts`): Bun's standard library has no `flock`, so a run opens the lock file and has util-linux's `flock(1)` lock that open file description: `flock -n 3`, with the descriptor handed to it as its fd 3. A flock belongs to the open file description, not to a process, so the lock stays held while any process has that description open. That is the run itself and every child it starts through `lockedSpawn`, which hands the same description to the child as its fd 3 (Bun closes other descriptors in children). evo-1 has `flock` from util-linux 2.41.

A small CLI reports on the lock for the incident agent and anyone else. It asks the kernel (a non-blocking `flock` on a fresh descriptor, released at once) and prints the holder record only as a description, so a holder without a record still shows as held:

```sh
bun packages/infra/release-lock.ts status                  # FREE (exit 0), or HELD {"pid":...,"started":...,"command":[...],"sha":...,"stage":...} (exit 6)
bun packages/infra/release-lock.ts wait --timeout 1800     # FREE (exit 0) once it is free, or HELD (exit 6) at the timeout
bun packages/infra/release-lock.ts path                    # the lock file and its holder record
```

Free when it answers is not a reservation: run `deploy.ts` or `rollback.ts ... --yes` next, which take it themselves and exit 6 if someone got there first.

### What each deploy uploads and records

- **Uploads:** every run of `deploy.ts deploy` uploads the registry and the website, changed or not. Each carries plain-text variables saying what built it:
  - `APM_REVISION`: the git commit, with `-dirty` when the tree had uncommitted changes;
  - `APM_BUILD`: a new random id every run, which is why both change every run;
  - the migration manifest, every migration id in that commit, in parts of at most 4,000 characters (`APM_MIGRATIONS_0`, ..., counted by `APM_MIGRATIONS_PARTS`), sealed by `APM_MIGRATIONS_SHA256`.

  The docs Worker is assets-only: Alchemy uploads it only when its pages change, and Cloudflare keeps no variables on its versions.
- **Smoke check:** after Alchemy, a deploy runs `smoke.ts` for its stage once, with the run's build and the account's workers.dev subdomain. Before its behavioural checks the registry (`GET /-/ping`) and the website (`GET /api/build`) must each answer three times in a row, uncached, with that build in `x-apm-build`; it waits up to 2 minutes for Cloudflare to move the traffic. After them they must answer with it again, with no waiting. An old version that still gives the right answers fails the check. The docs run no code, so which docs version answers is not checked.
- **The release record** (`releases.ts`, `deploy-record.ts`): when the smoke check passes, still under the lock, the deploy reads each Worker's live deployment and appends one line to `/home/leo/.config/apmjs/releases.jsonl`. The file has mode 0600, and `APM_RELEASES_LEDGER` overrides the path. The line holds the build id, git SHA, stage, migration manifest and the three live version ids.
  - The registry's and the website's live versions must carry this run's `APM_BUILD`, `APM_REVISION` and sealed manifest in their settings. Cloudflare's deployment list can lag an upload and still name the previous version; the deploy reads again for up to 60 seconds, one deadline that cuts short every request and wait and is checked again just before the append, and then leaves the run unrecorded rather than label an old version with this run's manifest. The variables only confirm this run at that moment: no rollback trusts a version's variables, since a dashboard edit could carry the same values.
  - The docs Worker's live version is recorded as it is.
  - A Worker that does not route all its traffic to one version leaves the run unrecorded.
  - A last line that was left unterminated is ended first, so it stays a broken line of its own.
  - A line that does not parse vouches for nothing, and neither does a build id whose lines disagree.
- **When a deploy fails** (Alchemy fails, the smoke check fails, the run could not be recorded, or reading Cloudflare to record it failed), nothing is recorded, nothing is rolled back, and the deploy exits 1 with what to do next, judged by what is live:
  - every live version is in the record: the `rollback.ts to --build <id>` command for the last recorded build, to run after deciding to;
  - the registry or the website runs a version the record does not name (this run uploaded it and then failed, or was stopped, before recording it): fix forward, by deploying a fixed commit. `rollback.ts` never replaces a version it cannot identify, so there is no rollback from that state. This is the cost of failing closed: the record is written only after a passing smoke check, and nothing records an upload on its own;
  - only the docs run an unrecorded version: the rollback command still works for the registry and the website.

### By hand

`packages/infra/rollback.ts` is the only way to roll back, for a person or the incident agent. It runs on evo-1 from `/home/leo/code/apmjs`, because it needs `~/.config/apmjs/cloudflare-token` and the release record, which only that machine's deploys write. It never prints the token, and changes nothing without `--yes`.

```sh
bun packages/infra/rollback.ts list     --stage production              # recent deployments of each Worker, live first, with the recorded build of each
bun packages/infra/rollback.ts to --stage production --build <id>       # what it would do: website and registry (add --worker docs for the docs) back to that build
bun packages/infra/rollback.ts to --stage production --build <id> --yes # do it
bun packages/infra/rollback.ts previous --stage production [--yes]      # each named Worker (default website and registry) to its previous deployment, if that is a recorded pair
bun packages/infra/rollback.ts to --stage production --worker docs --deployment <id> --yes
```

Before it changes anything it refuses (exit 1, and nothing changed) unless all of these hold:

- **Recorded live versions:** every version a Worker being rolled back runs now is named by the release record. One that is not (a deploy that failed or was stopped after its upload, or a change outside `deploy.ts`) is never replaced: fix forward.
- **Recorded targets:** every version a Worker being rolled back would route traffic to, on every share of a split deployment, is named by a canonical line of the release record as that Worker.
- **One-line pair:** afterwards, every registry and website version receiving traffic, rolled back or left as it is, is named by one canonical line: a pair one deploy left live. There is no time-window rule. So the registry and the website go back together (`to --build <id>`); either one alone is refused unless the other already runs that line's version. The docs pair with nothing.
- **Migrations fit:** that line's manifest fits the stage's migration ledger (`apm_migrations`, read only, through `neon-url`, within 15 s): every migration in it is applied, and every applied migration not in it is marked `-- apm:rollback-safe`, wherever its number sorts. `--skip-migration-check` skips only this comparison, for someone who has checked the schema by hand; nothing skips the others.

With `--yes` it takes the release lock first (exit 6 while someone else holds it, nothing changed). Once it has started changing Workers (website, then docs, then registry), it can still stop part-way, also with exit 1:

- **Live re-read:** just before changing each Worker it reads its live deployment again, and stops if that is not the deployment it planned from, or runs a version the record does not name.
- **A refused change:** Cloudflare refuses a deployment, or a read fails.

Workers it already changed stay changed, and it prints which went back and which did not. Read that output before running anything else.

The database itself never rolls back.

## The apm CLI

`curl -fsSL https://apmjs.dev/install | sh` installs the CLI as one standalone binary (`bun build --compile`; no Bun or git needed to run it). The website serves, from the stage's `apmjs-cli-<stage>` bucket (`apps/web/lib/cli-download.ts`, answered in `proxy.ts` so a 100 MB binary streams straight from R2):

| Path | What | Cache |
| --- | --- | --- |
| `/install` | the install script (`packages/infra/cli-install.ts`), with every released binary's SHA-256 written into it | 5 minutes |
| `/cli/releases.txt` | every released binary: version, platform, SHA-256 | 5 minutes |
| `/cli/<version>/apm-<target>` | a binary: `linux-x64`, `linux-arm64`, `linux-x64-musl`, `darwin-x64`, `darwin-arm64`; served only once `<version>/SHA256SUMS` exists, an uncached 404 before | a year, immutable |
| `/cli/<version>/SHA256SUMS` | that version's checksums, as `sha256sum -c` reads them | a year, immutable |

A release uploads files and deploys nothing:

```sh
bun packages/infra/release-cli.ts --stage staging
bun packages/infra/release-cli.ts --stage production
```

It releases the version in `packages/cli/src/version.ts` (keep `packages/cli/package.json` the same; a test checks). It holds the release lock, builds the five binaries, checks this machine's own one runs without Bun on PATH and prints the version, uploads them, then writes `cli/<version>/SHA256SUMS`, which is what makes the version released. Then it rebuilds `cli/releases.txt` and the install script from every released version and publishes both, downloads every binary back through the site and hashes it, compares the script the site serves with the one it wrote, and runs the install command into a fresh HOME. Only then does it append a line to `~/.config/apmjs/cli-releases.jsonl` (`APM_CLI_RELEASES_LEDGER`), a separate file from `releases.jsonl`, which `rollback.ts` trusts. Production also refuses a tree with uncommitted changes.

A released version never changes. A run that finds the version's `SHA256SUMS` builds nothing and uploads no binary; it only republishes the index and the script if they differ, and checks them. A run cut short before `SHA256SUMS` uploads the binaries again. So rerunning is always safe. To ship new CLI code, raise the version first.

The website must be deployed with the bucket before the first release on a stage: `deploy.ts` creates the bucket and the binding, and the release fails its checks (and records nothing) until the site serves `/install` and `/cli/*`. The smoke check runs the install on every deploy; until a stage has a CLI release on record it passes as skipped, and after that `/install` must work.

After a production release passes its checks, it runs `gh workflow run update-apm.yml --repo opencoredev/homebrew-tap -f version=<version>` with this machine's `gh` sign-in, which needs Actions write access to the tap. The workflow runs on GitHub independently of the release: it installs the new formula with `brew install opencoredev/tap/apm`, runs `brew test` on macOS arm64 and Intel and on Linux x64 and arm64, and commits `Formula/apm.rb` only if the formula changed and all four pass. Rerunning an older version changes nothing. If `gh` is missing, fails or takes over 30 seconds, the release still succeeds and prints that command to run by hand. Users install with `brew install opencoredev/tap/apm`.

The darwin binaries are ad-hoc signed by `bun build --compile` (`codesign -dv` shows `Signature=adhoc`), which is enough for macOS to run a binary that curl downloaded. The musl build needs `libstdc++` and `libgcc`; the script says so when it does not run.

To try a release on this machine: `bun packages/infra/release-cli.ts --stage local --serve` keeps the bucket in `~/.cache/apm-cli-local` and serves it on `http://127.0.0.1:8790` with the website's own handler in workerd. `--host <tailscale address>` serves it to other machines.

## Health checks

`GET https://registry.apmjs.dev/-/apm/v1/health` is for external monitors (Instatus). It is never cached (`Cache-Control: no-store`), sends no secret or address, and an isolate runs its checks at most once every 5 seconds, so a check every 30 seconds from several regions costs a `SELECT 1`, two small R2 reads (the block list, parsed as the install routes parse it, and the queue probe's record) and an npm ping per isolate per check at most. It answers **200 while installs work** and **503 when they do not**:

```json
{
  "status": "ok",
  "installs": "working",
  "checkedAt": "2026-11-16T14:32:52.242Z",
  "checks": {
    "database": { "status": "up", "ms": 4, "detail": "answers" },
    "r2": { "status": "up", "ms": 1, "detail": "answers" },
    "blocklist": { "status": "up", "ms": null, "detail": "synced from the database", "syncedAt": "2026-11-16T14:30:00.000Z" },
    "queue": { "status": "up", "ms": 2, "detail": "the cron's probe was consumed 2 min ago", "lastConsumedAt": "2026-11-16T14:30:04.000Z" },
    "upstream": { "status": "up", "ms": 101, "detail": "answers" }
  }
}
```

| `status` | `installs` | HTTP | Meaning |
| --- | --- | --- | --- |
| `ok` | `working` | 200 | Everything answers. |
| `degraded` | `working` | 200 | Installs work; something else does not answer (usually the queue: scores wait). |
| `degraded` | `npm-only` | 200 | Postgres does not answer. npm's packages install without scores; apm's own packages, sign-in, publish and scores answer 503 (docs/ARCHITECTURE.md, "When Postgres is down"). |
| `down` | `down` | 503 | R2 does not answer (tarballs are read through it), npm does not, or Postgres does not and the block list is missing, unreadable or never synced. |

Each check is `up`, `down` or `unknown`. The queue check reads when the consumer last took the probe message the cron sends every 10 minutes, and reports `down` after 25 minutes without one: the consumer is stopped or far behind. Set Instatus to alert on a non-200, and, to hear about a degraded registry too, on the body not containing `"status":"ok"`. For a plain install probe, `GET https://registry.apmjs.dev/ms` must answer 200 with a packument; during a database outage that answer carries `x-apm-degraded: database-unavailable`.

## Local development

`bun run registry` runs the registry Worker bundle in Miniflare on `http://127.0.0.1:4873/` against a throwaway Postgres (from `initdb`, or `APM_TEST_DATABASE_URL`). Point the website at it with `APM_REGISTRY=http://127.0.0.1:4873/ bun run dev` in `apps/web`. Nothing persists between runs.

## Worker variables

The registry Worker reads these (`packages/registry/src/worker.ts` parses them):

| Variable | Meaning |
| --- | --- |
| `HYPERDRIVE`, `BLOBS`, `ANALYSIS_QUEUE` | The Hyperdrive, R2 and queue bindings. |
| `RESOLVE_RATE_LIMIT` | Rate limiting binding: at most 60 `GET /-/apm/v1/resolve` a minute per `CF-Connecting-IP` in each Cloudflare location, then a 429 with `Retry-After: 60` (`packages/registry/src/resolve-limit.ts`, `packages/infra/registry-env.ts`). Requests without that header (the website's service binding) are not counted, and neither are callers apm verified (a live token, or a website session naming an apm account), so CI behind one NAT signs in; forged credentials count. The CLI asks again after a 429 as `Retry-After` says, at most 3 times and 60 s in all. Without the binding nothing is limited. |
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
| `APM_INSTALL_CHECKS` | `database` (default) or `edge`: what install reads of npm's packages check. Set by `deploy.ts --install-checks`; see "Install checks". |

The website Worker gets `REGISTRY` (a service binding to the registry Worker) and `APM_REGISTRY`.
