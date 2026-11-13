-- 0015 dropped the outcomes the runtime caused, but each of those versions kept its analysis_jobs reservation, so a
-- request in the next ten minutes found it "already queued" and queued nothing: on staging three 0.187.0 stayed
-- pending until the sweep's requeue. A reservation for a version with no stored analysis and no outcome row is
-- dropped, so the next request queues it at once. A job still on the queue then runs once and the second delivery
-- finds it stored or begun.
DELETE FROM analysis_jobs j
WHERE NOT EXISTS (SELECT 1 FROM upstream_analysis a WHERE a.package = j.package AND a.version = j.version)
  AND NOT EXISTS (SELECT 1 FROM analysis_outcomes o WHERE o.package = j.package AND o.version = j.version);
