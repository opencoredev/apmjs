# apm (apmjs.dev): plan v1

A package registry that stock `bun` and `npm` talk to unmodified, plus a thin CLI (`apm`) that wraps whichever package manager the project already uses. We do not manage the runtime. Bun gets the most (security scanner hook, release-age), npm gets the registry features through standard endpoints.

## Problems we target (from the research swarm, research/01..07)

1. Publishing is a chore: double 2FA, expiring tokens, per-package trusted publishing, opaque 404/ENEEDAUTH errors, `.npmignore` leaking secrets, no preview of what ships, prerelease accidentally becoming `latest`, `main`/`types` pointing at files that do not ship.
2. You cannot pull a bad version: 72-hour unpublish, dependents rule, deprecate is advisory only, takedown is a support ticket. Malicious versions live 2-4 hours and that is enough.
3. Hacked account response is manual: rotate every token, find every version the attacker pushed, beg for removal.
4. No trustworthy safety signal: `npm audit` is noise, scores mix popularity with safety, scores are per package not per version, nothing explains itself.
5. Install-time scripts are the attack vector in every 2025-26 worm.
6. No cooldown by default.
7. Typosquatting and no name-availability check.
8. Search ranks badly; package pages lack decision facts (ESM/CJS, types, install scripts, maintainers).

## What we build

### Registry (Bun + SQLite, npm wire protocol)
- Full npm protocol: packuments (full and abbreviated), tarballs, publish (PUT), dist-tags, deprecate, whoami, adduser/login, search, bulk advisories. Proven by acceptance tests that drive real `bun` and `npm`.
- Version states: `deprecated` (advisory), `yanked` (hidden from new resolution, tarball still served for lockfiles, reversible), `revoked` (malicious: hidden, tarball returns 410 with the reason, a critical advisory is served to `bun audit` / `npm audit`, the version number can never be reused). Owner can yank or revoke any time, no 72h window, no dependents test.
- Incident button: one call revokes every token of the account and revokes every version that account published since a timestamp.
- Public per-package event log (publish, yank, revoke, owner change, dist-tag) with actor and reason.
- Security score per version, computed at publish from tarball + manifest + publish history: 0-100, grade A-F, every signal listed with points and file evidence, diff against the previous version. Signals: install scripts, shell exec, network calls, credential/env access, eval/obfuscation, binaries, new publisher, no license, typosquat distance, recent publish (time-based). Popularity is not an input.
- Publish guards: refuse tarballs containing secrets (.env, private keys, cloud/npm/GitHub/Stripe tokens) and name the file; refuse new names one edit away from popular packages; refuse when `main`/`types`/`bin` point at files missing from the tarball; a prerelease never takes `latest` (it goes to `next`).
- Name availability API (domain-search style): exact name, your scope, typo-close popular names, suggestions.
- `~safe` registry view: `https://apmjs.dev/~safe/` serves the same packages minus versions younger than 24h and versions scoring under 40. Works for any client with zero tooling (set the registry URL).
- Server-side resolve API applying the same policy, used by the CLI.
- Bun security scanner package (`@apm/bun-scanner`): `[install.security] scanner = "@apm/bun-scanner"` in bunfig makes stock `bun install` fail on revoked versions and low scores, warn on yanked ones.

### CLI `apm`
- Detects the project's package manager (lockfile, then `packageManager`, then bun if installed, else npm); `--pm` overrides. Unknown commands pass through (`apm run dev` = `bun run dev`).
- `apm add <pkg>`: resolves through the registry policy (cooldown 24h, score floor 40, never revoked), prints the score card, refuses with reasons unless `--force`, then runs `bun add pkg@x.y.z` / `npm install pkg@x.y.z`.
- `apm publish`: packs with the project's PM, prints file list + sizes + score preview, refuses locally on secrets or missing entry files, `--bump patch|minor|major`, `--dry-run`, then publishes through the PM.
- `apm score`, `apm name`, `apm audit` (installed versions vs advisories and revocations), `apm yank`, `apm revoke`, `apm incident`, `apm login`, `apm whoami`.

### Web (Next.js + default shadcn, low UI effort)
- Vercel-Domains-style search: one input, `?q=` in the URL, instant results, a fixed "top results" block answering "is this name free, is it in my scope, is it typo-close to something popular", then all results with score chips.
- Package page: decision panel (score, grade, ESM/CJS, types, install scripts, maintainers, last publish), signals with evidence, versions table with yanked/revoked badges, install command tabs (apm, bun, npm), event log.

## Out of scope for v1 (named, not built)
OIDC trusted publishing (needs real GitHub OIDC), provenance/Sigstore, server-side TS-to-JS builds, org/team management, upstream proxy of npmjs.org, payments.

## How we prove it
Acceptance tests (tests/acceptance) drive real `bun`, `npm` and the `apm` CLI against an in-process registry. A hill climb counts failing tests to zero. The web UI is checked with screenshots and the council.
