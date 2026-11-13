-- Outcomes the Worker's runtime caused rather than the packages, dropped so the queue scores those versions again:
--
-- - unreadable, because workerd's node:zlib refused an inflate held to the exact size the gzip trailer gives
--   (core/src/tarball.ts, GUNZIP_SLACK_BYTES): react 19.3.1, picomatch 4.0.7 and tinyglobby 0.2.17 among them,
--   though Bun inflates each one. A tarball that really inflates past its trailer gets the same outcome again.
-- - the smaller re-run's incomplete analysis, and analysis-limit, stored after runs the default 30 s CPU limit stopped
--   (three 0.187.0, every time) or a store error left looking stopped (vite 8.3.8). The Worker now has 300 s
--   (registry/scripts/compat.ts, WORKER_CPU_MS), and a store error hands the run back instead.
-- - the attempts of runs that began and stored nothing under that limit: counted, the next run would be the smaller
--   re-run again. Runs that failed with an error they reported (failures > 0) keep their count.
--
-- The next request queues each version again, and the sweep requeues the jobs the queue already accepted.
DELETE FROM analysis_outcomes o USING upstream_analysis a
WHERE a.package = o.package AND a.version = o.version AND a.scorer = o.scorer
  AND a.analysis::text LIKE '%an earlier analysis of this version was stopped by the platform''s CPU limit or failed before it stored anything%';

DELETE FROM upstream_analysis
WHERE analysis::text LIKE '%an earlier analysis of this version was stopped by the platform''s CPU limit or failed before it stored anything%';

DELETE FROM analysis_outcomes o
WHERE (o.outcome = 'unreadable' AND o.detail LIKE '%bytes its trailer says%')
   OR o.outcome = 'analysis-limit'
   OR (o.outcome IS NULL AND o.failures = 0
       AND NOT EXISTS (SELECT 1 FROM upstream_analysis a WHERE a.package = o.package AND a.version = o.version AND a.scorer = o.scorer));
