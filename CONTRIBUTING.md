# Contributing

## Setup

You need Bun 1.4 or newer, plus Node with npm for the acceptance tests. pnpm is pinned as a dev dependency.

```sh
bun install
bun scripts/score.ts           # acceptance suite; the last line is the number of failing tests
bunx tsc --noEmit -p .         # typecheck the packages
bun run lint                   # Oxlint, anti-slop and @shadcn/lint; see docs/LINT.md
cd apps/web && bunx tsc --noEmit
```

The acceptance tests in `tests/acceptance` drive the real `bun`, `npm` and `pnpm` clients against an in-process registry. A change to registry or CLI behavior needs a test there first.

## Pull requests

- Keep each pull request to one change, with a test.
- Say what you ran to check it.
- Score rule changes: show the scores of a few real packages before and after the change.
