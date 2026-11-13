-- A run that fails with an error it reports keeps its start counted (analysis.ts): `failures` counts those runs and
-- `last_error` names the last one's error class, so after the retries it is allowed the version is stored as
-- incomplete instead of looking queued forever. `swept_at` is when the cron sweep last picked the row up, and the sweep
-- takes the rows it picked longest ago first, so rows it cannot settle never hold back the ones behind them.
ALTER TABLE analysis_outcomes ADD COLUMN failures integer NOT NULL DEFAULT 0;
ALTER TABLE analysis_outcomes ADD COLUMN last_error text;
ALTER TABLE analysis_outcomes ADD COLUMN swept_at bigint;
DROP INDEX analysis_outcomes_unfinished;
CREATE INDEX analysis_outcomes_unfinished ON analysis_outcomes (swept_at NULLS FIRST, started_at) WHERE outcome IS NULL AND started_at IS NOT NULL;
