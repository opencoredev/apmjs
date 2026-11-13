-- A run that fails with an error it reports keeps its start counted (analysis.ts): `failures` counts those runs and
-- `last_error` names the last one's error class, so after the retries it is allowed the version is stored as
-- incomplete instead of looking queued forever. `swept_at` is when the cron sweep last picked the row up, and the sweep
-- takes the rows it picked longest ago first, so rows it cannot settle never hold back the ones behind them; its index
-- is built concurrently by 0014.
--
-- Adding a column with a constant default changes only the catalog, but it takes an ACCESS EXCLUSIVE lock, which waits
-- for open transactions on the table and holds every later query behind it while it waits. lock_timeout bounds that:
-- the deploy fails and can be run again instead of stalling writes.
SET LOCAL lock_timeout = '2s';
ALTER TABLE analysis_outcomes ADD COLUMN failures integer NOT NULL DEFAULT 0;
ALTER TABLE analysis_outcomes ADD COLUMN last_error text;
ALTER TABLE analysis_outcomes ADD COLUMN swept_at bigint;
