# apm

> Early and moving fast. The registry, CLI and score engine work and are tested; sign-in, GitHub-scoped names and hosting at apmjs.dev are in progress.

A package registry that stock `bun`, `npm` and `pnpm` talk to unmodified, plus `apm`, a thin CLI that checks before your package manager installs, runs or publishes. apm never manages the runtime.

## What it fixes

| npm pain | apm |
| --- | --- |
| A hacked version can't be pulled (72h unpublish, dependents rule) | `yank` (hidden from new installs, lockfiles keep working) and `revoke` (410 + critical advisory in `bun audit` / `npm audit`), any time, with a fresh 2FA or passkey check and a 24h pending window for old or depended-on versions |
| Account compromised: rotate tokens, hunt versions by hand | `apm incident --since <time>` revokes every token and every version published since then (preview with `--dry-run`, 30-day cap) |
| No trustworthy safety signal | Per-version score: install scripts, shell, network, credential access, eval, obfuscation, new publisher, risky new dependencies, typosquat names. Every point has file:line evidence. Popularity is not an input. What it reads and cannot catch: [docs/SCORE.md](docs/SCORE.md) |
| Publishing is a chore and leaks secrets | `apm publish` packs with your PM, lists files, blocks secrets and missing `main`/`types`/`bin`, previews the score, `--bump patch`. The registry repeats the checks server-side |
| Manifest confusion | Metadata is served from the tarball's package.json; a publish whose request hides install scripts is refused |
| Typosquats, no name check | Domain-search-style name check; new names one edit from popular packages are refused |
| No cooldown by default | `apm add` skips versions under 24h; `https://<registry>/~safe/` gives any client the same filter |
| Coverage | Proxies the public registry: every npm package gets scored on demand; names that exist upstream can't be published here |

## Layout

- `packages/registry`: Bun + SQLite registry (npm wire protocol, apm API, upstream proxy)
- `packages/core`: score engine, secret scanner, typo distance, tarball reader
- `packages/cli`: `apm`
- `packages/bun-scanner`: `[install.security] scanner = "@apm/bun-scanner"` makes stock `bun install` refuse revoked and low-scoring versions
- `apps/web`: Next.js + shadcn UI (search with name check, package pages)
- `tests/acceptance`: over 100 tests that drive real bun, npm and pnpm against an in-process registry

## Run it

```sh
bun install
APM_PORT=4873 APM_DATA_DIR=.data/dev bun packages/registry/src/main.ts   # APM_UPSTREAM=off to disable the npm proxy
APM_REGISTRY=http://127.0.0.1:4873/ bun tools/seed-demo.ts               # optional demo data
cd apps/web && bun run build && APM_REGISTRY=http://127.0.0.1:4873/ bun run start -p 3410
bun packages/cli/src/main.ts help
bun scripts/score.ts                                                     # acceptance suite; prints failing count
```

Research, plan and council reviews: `research/`.

## Reporting

- A malicious or unsafe package: [open a package report](../../issues/new?template=report-package.yml).
- A vulnerability in apm itself: report it privately, as described in [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE). Contributions: [CONTRIBUTING.md](CONTRIBUTING.md).
