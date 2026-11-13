-- apm:no-transaction
-- The sweep's two indexes, built CONCURRENTLY outside a transaction (see 0009 and scripts/migrate.ts), so writes to
-- analysis_jobs and analysis_outcomes go on while they build. A plain CREATE INDEX takes a SHARE lock: behind one open
-- write the build waits, and every later write, such as the queue's next job, waits behind the build.
-- - analysis_jobs_queued: jobs the queue accepted that never started, oldest first (Store.acceptedAnalyses).
-- - analysis_outcomes_unswept: begun, never ended runs in the order the sweep takes them (rows it picked longest ago
--   first, Store.unfinishedAnalyses). It replaces analysis_outcomes_unfinished (0011), which is dropped once this one is built.
-- The build still waits for transactions already open on the table; lock_timeout bounds that wait, and the deploy
-- fails and can be run again. A build that failed leaves an invalid index behind, which IF NOT EXISTS would keep, so
-- each is dropped first; a database that has the old 0013's plain analysis_jobs_queued gets it rebuilt the same way.

SET lock_timeout = '5s';

DROP INDEX CONCURRENTLY IF EXISTS analysis_jobs_queued;

CREATE INDEX CONCURRENTLY IF NOT EXISTS analysis_jobs_queued ON analysis_jobs (queued_at);

DROP INDEX CONCURRENTLY IF EXISTS analysis_outcomes_unswept;

CREATE INDEX CONCURRENTLY IF NOT EXISTS analysis_outcomes_unswept ON analysis_outcomes (swept_at NULLS FIRST, started_at) WHERE outcome IS NULL AND started_at IS NOT NULL;

DROP INDEX CONCURRENTLY IF EXISTS analysis_outcomes_unfinished;
