# anti-slop provenance

- Source: https://github.com/dmmulroy/anti-slop
- Commit: `13909c9e07590f5a85d93c62712259fe14a883f7` (2026-10-13), the upstream `main` on 2026-11-12.
- Copied: the whole of upstream `src/` into this directory, byte for byte, including the RuleTester suites (`*.test.ts`) and `vendor/eslint-stylistic/` with its own `LICENSE` and `UPSTREAM.md`. Upstream's root `LICENSE` (MIT) is copied as `LICENSE`.
- Entry points: `index.ts` (generic rules, plugin name `anti-slop`) and `effect/index.ts` (Effect rules, plugin name `anti-slop-effect`), registered in the repo's `oxlint.config.ts`.
- Dependencies: `oxlint` and `@oxlint/plugins`, both pinned at exactly `1.93.0`. Upstream pins `1.78.0`; this repo needs 1.80 or later for `@shadcn/lint`. All 24 upstream rule suites pass on 1.93.0.
- Local deviations: none. Rule options and scoping live in `oxlint.config.ts`, not here.

Because the copy is unmodified, this commit is also the base for a three-way merge when updating. Follow upstream's `skills/install-anti-slop/references/update.md`, then run the rule suites:

```sh
for f in tools/oxlint/anti-slop/rules/*.test.ts tools/oxlint/anti-slop/effect/rules/*.test.ts; do node "$f" || break; done
```
