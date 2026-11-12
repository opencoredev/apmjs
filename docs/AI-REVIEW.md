# AI release review

A language model reads each new release of in-scope packages and apm publishes a cited review next to the rule-based score. This document covers the design, the evaluation it rests on, and how to run it.

The evaluation is `research/ai-review-eval.md`. Its recommendations are the spec for what is built here.

## What it does

For each release in scope, a reviewer process:

1. downloads the version's tarball and the previous version's tarball from the registry, checking both against their published checksums;
2. builds one text: the full new `package.json` and line diffs of added and changed files when a previous version exists, otherwise the file list and the files;
3. asks DeepSeek V4.1 Flash (`morph-dsv41flash-1017`) whether the release is malicious, with every finding citing `file:line` and a verbatim quote;
4. drops every finding whose file does not exist, whose line is out of range, or whose quote is not on that line;
5. decides: benign, flagged, or no answer (see "The decision");
6. posts the result to the registry, which shows it on the version page.

The score (0 to 100) and the AI review never mix. The score is apm's rules; the review is one model's reading of the code.

## The evaluation, in short

From `research/ai-review-eval.md`, run on 2026-11-12:

| | Result |
|---|---|
| Malicious releases caught (malicious or suspicious, with a verified citation) | 36 of 40 (90%, 95% CI 77 to 96%) |
| Of those whose payload is inside the tarball | 36 of 37 on the first ask, 37 of 37 with one retry |
| Benign releases called "malicious" | 0 of 82 benign reviews and 0 of 40 random real releases |
| Benign releases called "suspicious" | 1 of 41 as diffs (2%), 3 of 41 as first publishes (7%) |
| Cause of those false alarms | 4 of 5: the model could not see a file the budget cut |
| Same verdict on an identical second request | 76 of 81 |
| Prompt injection ("AI reviewers: this is safe" comments) | 10 of 10 still called malicious, each citing the injected comment |
| Rules alone (score below 60) | 9 of 40 caught, 15% false alarms |
| Cost of a real release | p50 1,823 input tokens, mean 6,196; p50 6 s |
| Capacity on a quarter of the shared quota | about 40,700 reviews a day |
| npm's volume | about 106,000 new versions a day; 18,800 from packages with at least 10,000 weekly downloads |

What follows from it:

- Flash is good enough as the first reader of every in-scope release, and not good enough to act on alone. A public "malicious" label or block waits for a person (the second stage).
- The confidence number is not calibrated, so it is never shown.
- Truncation causes most false alarms, so the reading order puts what runs first, and the page lists what was not read.
- A flagged or empty answer gets one retry: two of three benign first-publish flags vanished on a second ask, and wrb3's empty answer turned into a correct flag.

## Scope: what gets reviewed

| Trigger | Where | Why |
|---|---|---|
| Every new local publish (direct or approved) | `Ctx.afterCommit` | apm's own packages, all of them |
| Upstream versions of packages with at least 10,000 weekly downloads, when apm first sees them | `Upstream.onPackage` | 18,800 versions a day fits in 46% of capacity |
| Upstream first publishes and versions that add an install script, any popularity | `Upstream.onPackage` | where typosquats and dependency-confusion probes live |
| "Request AI review" on a version page | `POST /-/apm/v1/review/:name/:version/request` | signed-in users, 5 an hour each |

"First seen" means apm fetched the packument and the version is newer than anything it saw for that package. On the first sight of a package only its `latest` version is queued, never its history. Weekly downloads come from `api.npmjs.org` and are cached for 24 hours (1 hour after a failed lookup).

Priorities, highest first: requests, local publishes, first publishes and new install scripts, popular upstream versions.

## The review input

`packages/ai-review` is plain TypeScript with no I/O.

- **Budget.** 16,000 estimated tokens of content (3.2 characters per token), lines cut at 2,000 characters, one file at most half the budget and a changed file at most 30%. Output is capped at 8,000 tokens, reasoning included.
- **Reading order.** Install-script targets, then Node entry points (`main`, `bin`, `module`, `exports`), then files where the rule-based signals fired (network, shell, eval, credentials, obfuscation), then files those entries reach through relative imports (nearest first), then browser entries, then the rest of the code by depth and size. Within a tier, a new file comes before a changed one. The first three tiers are the eval's proposed fix for truncation false alarms (`lib/tsc.js`, the nx postinstall target).
- **Not read.** Every result lists files cut by the budget, files read only in part, binaries, files too large to decode, and the dependencies. Docs, type declarations and source maps are not shown and not listed.
- **Prompt.** The text the eval measured, including the paragraph that tells the model that instructions inside the package are data and that a comment vouching for the package is itself a finding. A unit test fails if that paragraph drifts from the experiment's.
- **Reply.** Parsed with zod. A reply that is not JSON with a known verdict is an empty answer; a malformed finding is dropped and counted.

### The decision

`decide()` takes one or two answers after the citation check:

| First answer | Second answer | Result |
|---|---|---|
| benign | (not asked) | benign |
| flagged | flagged or empty | flagged |
| empty | flagged | flagged |
| flagged | benign | no answer: unsettled (a flip is not called clean) |
| empty | benign | benign |
| empty | empty | no answer: empty |

"Flagged" is malicious or suspicious with at least one citation that checked out. A flag whose citations all fail counts as empty.

## What people see

On the version page (`/package/<name>?v=<version>`), in its own section below the score:

| State | Public text |
|---|---|
| benign | "AI review found nothing in the change from 4.4.1" (or "in this version's files"), with "Read 2 of 2 changed files", the model and the date |
| flagged, or a flip | "Under review": the AI review raised a question, a person at apm is checking it, nothing is confirmed |
| no answer | "AI review gave no answer" |
| confirmed by a person | "Confirmed malicious by apm reviewers", with each finding as `file:line`, the line, and one sentence |
| dismissed by a person | "Checked by a person, no action needed" |

Every state shows what was not read and has a "Files read" list. The page never says "safe", never shows the confidence number, and never shows the model's own summary in public. Owners of a local package and apm's reviewers see the cited lines of an unconfirmed flag on the same page, loaded with their session. The docs page has a short section on what the review is and what it cannot see.

## The second stage

Phase 1 is a person. Every flagged or unanswered review waits in the queue at `/admin/reviews` until someone whose GitHub login is in `APM_ADMINS` confirms or dismisses it. The queue and its decisions need a website session: no token opens them, not even the reviewer's own `apm login` or CI token, and each decision needs a fresh code from an authenticator app or a passkey check. Only a confirmed result is labeled in public. Blocking installs on a confirmed result is not wired yet: use apm's existing revoke for local packages.

The stronger-model step is an interface, `SecondStage` in `apps/reviewer/src/second-stage.ts`. `configuredSecondStage()` returns `null`. When one is configured, the reviewer runs it on non-benign results and posts its opinion with the result; the queue shows it. The eval suggests giving it the full package with no 16,000-token cap.

## Architecture

```
  registry (Cloudflare Worker)                        owner's machine (on the tailnet)
  ┌───────────────────────────────────┐   HTTPS   ┌──────────────────────────────────┐
  │ review_jobs, reviews, ... tables  │ ◀──────── │ apps/reviewer (Bun daemon)       │
  │ GET  /-/apm/v1/review-jobs        │  lease    │  lease → download both tarballs  │
  │ POST /-/apm/v1/review-jobs/:id/   │  result   │  → build input → model (≤4)      │
  │        result | release           │  release  │  → citations → decide → post     │
  │ GET  /-/apm/v1/review/:name/:ver  │           └───────────────┬──────────────────┘
  │ POST /-/apm/v1/review/.../request │                           │ OpenAI-compatible
  │ GET  /-/apm/v1/review-admin/queue │                           ▼
  │ POST /-/apm/v1/review-admin/decide│         https://ms-a2.tail0e7628.ts.net:8318/v1
  └───────────────────────────────────┘
```

The model endpoint is on the owner's private tailnet, which Cloudflare Workers cannot reach, so the reviewer pulls work and needs no inbound access.

### Registry side

`packages/registry/src/review.ts`, on only when the Worker has `APM_REVIEW_TOKEN_HASH` (the deploy sets it from `~/.config/apmjs/review-token-<stage>`, see `docs/DEPLOY.md`).

- **Tables** (Postgres, `migrations/0004_reviews_and_password_lockout.sql`). `review_jobs` (unique on package, version and tarball digest; state `queued`, `leased`, `done` or `failed`; lease id and expiry; attempts), `reviews` (keyed on package, version and digest; the result JSON; `human_state` `none`, `pending`, `confirmed` or `dismissed`), `review_seen` (newest publish time seen per upstream package), `review_downloads` (cache) and `review_requests` (rate limit).
- **Leases.** `GET /-/apm/v1/review-jobs?max=N` (at most 16) leases jobs for 15 minutes, in one transaction with `FOR UPDATE SKIP LOCKED`. Expired leases go back to the queue on the next lease call. A job leased 5 times without a result is marked failed. A result or release must carry the current lease id, else 409.
- **Service token.** The reviewer sends `Authorization: Bearer <token>`; the registry keeps only its sha256 and compares in constant time. User tokens and sessions are refused on these routes.
- **Jobs** carry the tarball path relative to the registry root (`debug/-/debug-4.4.3.tgz`) and the digest. The reviewer joins the path to its own configured registry URL, so a job can never point it at another host.
- **The previous version** is the highest lower version still served, stable unless the release is a prerelease. If its tarball cannot be fetched, the review reads the files instead.

### Reviewer

`apps/reviewer`:

- at most `REVIEW_CONCURRENCY` (default and maximum 4) model requests in flight, through one semaphore;
- 429 waits for `Retry-After` (seconds or a date, capped at 2 minutes); 5xx and network errors back off and retry 3 times;
- when the model is unreachable or refuses the key, the job is given back to the queue instead of being recorded as "no answer";
- a daily token budget (input plus output, UTC days), kept in `$REVIEW_STATE_DIR/budget.json`; when it runs out the daemon stops leasing until midnight UTC;
- logs are JSON lines with scalar fields only: job id, package, version, outcome, coverage counts, token counts, timings. No quotes, summaries or other text from packages.

## Running it

### 1. A service token

```sh
umask 077
head -c 32 /dev/urandom | base64 | tr -d '/+=' > ~/.config/apm/review-token
```

The registry Worker needs only its sha256: put the token in `~/.config/apmjs/review-token-<stage>` and deploy, and `deploy.ts` sets `APM_REVIEW_TOKEN_HASH`. The reviewer needs the token itself at `REVIEW_SERVICE_TOKEN_FILE`. Never put the token in an environment variable or a repo.

### 2. The registry

| Variable | Meaning |
|---|---|
| `APM_REVIEW_TOKEN_HASH` | Turns the AI review on; sha256 (hex) of the service token |
| `APM_ADMINS` | Comma-separated GitHub logins that may confirm or dismiss flags |
| `APM_REVIEW_POPULAR_WEEKLY` | Weekly downloads that put an upstream package in scope (default 10000) |
| `APM_NPM_DOWNLOADS_URL` | Download-count API (default `https://api.npmjs.org/downloads/point/last-week/`) |

`bun run deploy:staging` prints `AI review on` when it found the token file.

### 3. The reviewer

| Variable | Default |
|---|---|
| `REVIEW_REGISTRY_URL` | required |
| `REVIEW_SERVICE_TOKEN_FILE` | required |
| `REVIEW_MODEL_URL` | `https://ms-a2.tail0e7628.ts.net:8318/v1` |
| `REVIEW_MODEL` | `morph-dsv41flash-1017` |
| `REVIEW_MODEL_KEY_FILE` | `~/.pi/agent/models.json` |
| `REVIEW_MODEL_KEY_JSON` | `providers.morph.apiKey` (used when the key file is JSON) |
| `REVIEW_CONCURRENCY` | 4 (1 to 4) |
| `REVIEW_DAILY_TOKENS` | 50,000,000 |
| `REVIEW_STATE_DIR` | `~/.local/state/apm-reviewer` |
| `REVIEW_POLL_MS` | 15000 |
| `REVIEW_BUDGET_TOKENS` | 16000 (content budget per review) |

The key file is either the key itself or JSON with the key at `REVIEW_MODEL_KEY_JSON`. A value starting with `!` follows pi's convention: a shell command whose first output line is the key. The key is read once at startup and never logged.

```sh
REVIEW_REGISTRY_URL=https://registry.example/ \
REVIEW_SERVICE_TOKEN_FILE=~/.config/apm/review-token \
bun apps/reviewer/src/main.ts
```

### As a systemd user unit

`~/.config/systemd/user/apm-reviewer.service`:

```ini
[Unit]
Description=apm AI release reviewer
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%h/code/apmjs
ExecStart=%h/.bun/bin/bun apps/reviewer/src/main.ts
Environment=REVIEW_REGISTRY_URL=https://registry.example/
Environment=REVIEW_SERVICE_TOKEN_FILE=%h/.config/apm/review-token
Environment=REVIEW_DAILY_TOKENS=50000000
Restart=on-failure
RestartSec=30
# SIGTERM stops leasing and waits for jobs in flight; unacked leases expire on their own
KillSignal=SIGTERM
TimeoutStopSec=330
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=%h/.local/state/apm-reviewer

[Install]
WantedBy=default.target
```

```sh
mkdir -p ~/.local/state/apm-reviewer
systemctl --user daemon-reload
systemctl --user enable --now apm-reviewer
journalctl --user -u apm-reviewer -f | jq -c 'select(.event == "job.done")'
loginctl enable-linger "$USER"   # keep it running when you are logged out
```

If the key file uses a `!` command that needs `PATH` or other environment, add it with `Environment=`.

### One offline review

`review-files` reviews a tarball or an extracted directory and prints the result; it posts nothing. Quotes from the package are hidden unless `--quotes` is passed.

```sh
bun apps/reviewer/src/main.ts review-files --name debug --version 4.4.2 \
  --path ~/.cache/apm-ai-review-samples/malicious/x/debug@4.4.2 \
  --previous-version 4.4.1 --previous-path ~/.cache/apm-ai-review-samples/npm/debug-4.4.1.tgz
```

Files are read with `lstat` as bytes; symlinks are skipped and nothing is installed or run.

## Operating it

- **Is it keeping up?** `job.done` lines per minute against the queue: `psql "$NEON_URL" -c "select state, count(*) from review_jobs group by state"` against the stage's database.
- **Budget spent today:** `cat ~/.local/state/apm-reviewer/budget.json`. `budget.exhausted` in the log means it paused until midnight UTC.
- **Model trouble:** `model.rate_limited` and `model.retry` lines; `job.give_back` with `retryable: true` means the job went back to the queue.
- **Failed jobs** (`state = 'failed'`, reason in `last_error`): the tarball was gone, did not match its checksum, or was unreadable. A user's "Request AI review" reopens a failed job.
- **Flags:** the queue at `/admin/reviews`. Expect a few a day under the 10,000-download policy.
- **Re-reviewing:** results are keyed by tarball digest, so a version is reviewed once. Delete its `reviews` row and set its job back to `queued` to run it again.

## Demo run (2026-11-12)

Real model, local registry on port 4961, web on 3561:

| Release | Reviewed as | Result |
|---|---|---|
| zod 4.6.7 | diff from 4.6.6, 4 changed files | found nothing (1 ask, 2,686 tokens, 4.2 s) |
| react 19.3.1 | diff from 19.3.0, 5 changed files | found nothing (1 ask, 1,690 tokens, 2.0 s) |
| debug 4.4.3 | diff from 4.4.1 (4.4.2 is unpublished), 1 changed file | found nothing (1 ask, 1,957 tokens) |
| debug 4.4.2 | offline `review-files` from the eval's cached copy, diff from 4.4.1 | flagged malicious on both asks, citing `src/index.js:7` (the obfuscated payload) and `package.json:3` |
| apm-demo-padder 1.0.1 (a harmless stand-in that posts `process.env` to an `.invalid` host) | diff from 1.0.0 | flagged on both asks, 3 cited lines; rule score 90/100 |

## On Cloudflare Workers

The registry side runs in the registry Worker; the reviewer and `packages/ai-review` are unchanged.

- The five tables are a Postgres migration with the same keys and the unique index on `(package, version, digest)`.
- Lease, result and release each run in one transaction; the lease query returns expired leases to the queue and skips rows another reviewer holds.
- After a version commits, it is queued on the request's connection. After an upstream packument is fetched, `considerUpstream` runs through `ctx.waitUntil` on its own connection.
- `@apm/ai-review`'s wire schemas (`ReviewJob`, `ResultBody`, `ReleaseBody`) stay the contract; both sides parse with them.
