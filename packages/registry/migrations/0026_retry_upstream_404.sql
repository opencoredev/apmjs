-- Outcomes that recorded npm's 404 for the tarball of a version its packument listed as unavailable for good. npm's
-- CDN answers 404 for a while right after a publish: @firebase/analytics 0.10.26 was stored "the upstream answered
-- 404" on its first day, held firebase, and npm served it later. Such a 404 is now a fetch failure the queue tries
-- again (upstream.ts isRetryableTarballStatus), and a tarball that keeps failing is still settled unavailable after
-- MAX_FETCH_FAILURES runs over FETCH_GIVE_UP_MS (analysis.ts). Dropping the rows lets the next request queue each
-- version again, and the sweep requeues the jobs the queue already accepted (as 0015 did). Numbered 0026, not 0024:
-- another branch adds 0024 and 0025, and migrations apply by id wherever they sort. It deletes outcome rows
-- only, so code from before it would run on the schema; it is left unmarked like every migration so far.
DELETE FROM analysis_outcomes
WHERE outcome = 'unavailable' AND detail = 'the upstream answered 404';
