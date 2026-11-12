-- apm:no-transaction
-- GET /-/apm/v1/recent-packages lists the npm packages scored most recently (the website's sitemap reads it).
-- It walks this index from the newest analysis instead of scanning every stored analysis.
--
-- Built CONCURRENTLY, outside a transaction (see scripts/migrate.ts), so writes to upstream_analysis go on while it
-- builds. The build still waits for transactions already open on the table; lock_timeout bounds that wait, and the
-- deploy fails and can be run again rather than holding the deploy for as long as some transaction stays open.
-- A build that failed leaves an invalid index behind, which IF NOT EXISTS would keep, so it is dropped first.

SET lock_timeout = '5s';

DROP INDEX CONCURRENTLY IF EXISTS upstream_analysis_analyzed_at;

CREATE INDEX CONCURRENTLY IF NOT EXISTS upstream_analysis_analyzed_at ON upstream_analysis (analyzed_at DESC);
