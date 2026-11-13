-- Review of 89441a9, finding 5: the next run's plan (analysis.ts, planFor) counted the runs that began and stored
-- nothing as `starts - 1 - failures - fetch_failures`, with no idea which run came last. After two stops and then a run
-- that failed with an error it reported, the next run was the smaller re-run, though the run just before it had ended
-- and was not stopped. `reported_start` is the start number (`starts` when it was written) of the latest run that
-- ended with a reported error or a fetch failure (Store.failAnalysis, Store.failFetch): when it is the run just before,
-- the next one runs in full. NULL until a run reports, which reads as before.
-- lock_timeout bounds the column change's lock wait, as in 0012 and 0013.
SET LOCAL lock_timeout = '2s';
ALTER TABLE analysis_outcomes ADD COLUMN reported_start integer;
