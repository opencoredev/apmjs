# apm

> Early and moving fast. The registry, CLI and score engine work and are tested. The registry and website run on Cloudflare; see [docs/DEPLOY.md](docs/DEPLOY.md).

A package registry that stock `bun`, `npm` and `pnpm` talk to unmodified, plus `apm`, a thin CLI that checks before your package manager installs, runs or publishes. apm never manages the runtime.

## What it fixes

| npm pain | apm |
| --- | --- |
| A hacked version can't be pulled (72h unpublish, dependents rule) | `yank` (hidden from new installs, lockfiles keep working) and `revoke` (410 + critical advisory in `bun audit` / `npm audit`), any time, with a fresh 2FA or passkey check. A version under 72 hours old is revoked at once, even when other packages depend on it (they are what it would attack); an older one is yanked now and fully revoked after 24h, or sooner if a second owner confirms |
| Account compromised: rotate tokens, hunt versions by hand | `apm incident --since <time>` revokes every token and every version published since then (preview with `--dry-run`, 30-day cap) |
| No trustworthy safety signal | Per-version score: install scripts, shell, network, credential access, eval, obfuscation, new publisher, risky new dependencies, typosquat names. Every point has file:line evidence. Popularity is not an input. What it reads and cannot catch: [docs/SCORE.md](docs/SCORE.md) |
| Publishing is a chore and leaks secrets | `apm publish` packs with your PM, lists files, blocks secrets and missing `main`/`types`/`bin`, previews the score, `--bump patch`. The registry repeats the checks server-side |
| Manifest confusion | Metadata is served from the tarball's package.json; a publish whose request hides install scripts is refused |
| Typosquats, no name check | Domain-search-style name check; new names one edit from popular packages are refused |
| No cooldown by default | `apm add` skips versions under 24h; `https://<registry>/~safe/` gives any client the same filter |
| Coverage | Proxies the public registry: every npm package gets scored on demand; names that exist upstream can't be published here |

## Layout

- `packages/registry`: the registry, a Cloudflare Worker (npm wire protocol, apm API, upstream proxy) written as Effect services over Postgres (Neon via Hyperdrive), R2 and a queue
- `packages/infra`: the Alchemy stack that deploys the registry and the website, plus the deploy and smoke scripts
- `packages/core`: score engine, secret scanner, typo distance, tarball reader
- `packages/cli`: `apm`
- `packages/bun-scanner`: `[install.security] scanner = "@apm/bun-scanner"` makes stock `bun install` refuse revoked and low-scoring versions
- `apps/web`: Next.js + shadcn UI (search with name check, package pages), deployed as a Worker through OpenNext
- `apps/docs`: the documentation site at https://docs.apmjs.dev, built with [Blume](https://useblume.dev) and served as static assets (`cd apps/docs && bun run dev`)
- `tests/acceptance`: over 180 tests that drive real bun, npm and pnpm against the registry's Worker build in Miniflare, on Postgres 18

How it fits together: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## For agents

apm runs a read-only remote MCP server at `https://apmjs.dev/mcp` (tools: `search_packages`, `check_package`, `check_name`, `explain_install`, `get_file_excerpt`). Claude Code: `claude mcp add --transport http apm https://apmjs.dev/mcp`. Without MCP: `GET /api/explain?package=<name>`, `/package/<name>.md`, `/openapi.json`, `/llms.txt`, and `apm explain <pkg> --json`. Setup for Codex and Cursor and the details: [docs/AGENTS.md](docs/AGENTS.md).

## Run it

The registry needs Postgres installed locally (`initdb` on PATH or under `/usr/lib/postgresql`), or a server in `APM_TEST_DATABASE_URL`.

```sh
bun install
bun run registry                                                         # the Worker in Miniflare on :4873; APM_UPSTREAM=off disables the npm proxy
APM_LEGACY_AUTH=1 APM_NAME_POLICY=open bun run registry                  # what tools/seed-demo.ts needs
APM_REGISTRY=http://127.0.0.1:4873/ bun tools/seed-demo.ts               # optional demo data
cd apps/web && APM_REGISTRY=http://127.0.0.1:4873/ bun run dev
bun packages/cli/src/main.ts help
bun scripts/score.ts                                                     # acceptance suite; prints failing count
bun run typecheck && bun run lint
```

Research, plan and council reviews: `research/`.

## Reporting

- A malicious or unsafe package: [open a package report](../../issues/new?template=report-package.yml).
- A vulnerability in apm itself: report it privately, as described in [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE). Contributions: [CONTRIBUTING.md](CONTRIBUTING.md).
