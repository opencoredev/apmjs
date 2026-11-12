# apm-score-v3, kept as a reference

These files are `packages/core/src/` as of commit `5437674` (apm-score-v3), copied byte for byte. v3 read every
file as raw text, so it is the floor the current scorer must never score above. `test/floor-fuzz.test.ts` scores
the same generated packages with both and asserts the current score is at or below this one.

Do not edit them. They are left out of the lint run for that reason (`oxlint.config.ts`, `docs/LINT.md`).
