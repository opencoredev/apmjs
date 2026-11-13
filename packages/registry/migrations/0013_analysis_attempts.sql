-- A queued run now counts itself begun before it asks the upstream anything (analysis.ts, runJob), so a run that cannot
-- fetch its tarball leaves a record the sweep finds instead of nothing. `fetch_failures` counts the runs that ended
-- because the upstream could not be asked or would not serve the tarball yet, and `fetch_failed_since` is when the
-- first of them ended; they are starts too, but not analyses, so the analysis limit counts `starts - fetch_failures`,
-- and after enough of them over long enough the version is settled as unavailable instead of being tried for ever.
-- The index that lets the sweep find jobs the queue accepted that never started is built concurrently by 0014.
-- lock_timeout bounds the column changes' lock wait, as in 0012.
SET LOCAL lock_timeout = '2s';
ALTER TABLE analysis_outcomes ADD COLUMN fetch_failures integer NOT NULL DEFAULT 0;
ALTER TABLE analysis_outcomes ADD COLUMN fetch_failed_since bigint;
