-- apm:no-transaction
-- The runs the cron sweep looks for (Store.unfinishedAnalyses): begun, never ended. A run counts itself begun in
-- analysis_outcomes before it analyses anything, so a run the platform stops always leaves one of these rows behind.
--
-- Built CONCURRENTLY, outside a transaction, as 0009 is: a plain CREATE INDEX takes a SHARE lock, so a write in flight
-- would hold the build and every later write would queue behind it. 0014 replaces this index with the sweep's order.

SET lock_timeout = '5s';

DROP INDEX CONCURRENTLY IF EXISTS analysis_outcomes_unfinished;

CREATE INDEX CONCURRENTLY IF NOT EXISTS analysis_outcomes_unfinished ON analysis_outcomes (started_at) WHERE outcome IS NULL AND started_at IS NOT NULL;
