-- apm:rollback-safe: one nullable column with no default, which a Worker before this one never reads
--
-- When the cron last queued a kept package's dist-tagged and recent versions for analysis (kept-package.ts,
-- seedKeptPackages): it picks the packages seeded longest ago (or never) first, so every package someone looked at in
-- the last day is reached, a few a sweep. A package page queues the same versions after its answer, under a global
-- bound (analysis.ts, SEED_INTAKE_MAX); this is the path that does not depend on that bound.
--
-- Additive: a nullable column with no default (no rewrite), which a Worker before this one never reads.
SET LOCAL lock_timeout = '2s';

ALTER TABLE kept_packages ADD COLUMN seeded_at bigint;
