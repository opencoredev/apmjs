-- Production, 13 Nov: seven queue runs shared one isolate and its memory limit ended them all. Recovery read each stop
-- as the CPU limit's, so the next delivery was the smaller re-run, and five versions stored its incomplete 39:
-- express 5.3.0, axios 1.21.1, eslint 10.14.0, prettier 3.10.1 and tailwindcss 4.3.5. The queue now runs one
-- invocation at a time (maxConcurrency 1) and a single stop is run again in full (analysis.ts, planFor), so those
-- results are dropped to be scored again in full.
--
-- Only those five versions' apm-score-v10 analyses are matched, and only when, read as an analysis, their `incomplete`
-- signal carries the line the old re-run wrote, from its first character (in `evidence`, or in `more` past the five
-- shown: on 3549541 the reason was added after the skipped-file lines). Review of 2326d2c, finding 9: matching the
-- message anywhere in the analysis's text also matched it inside an ordinary source evidence line, a correct analysis
-- that quotes it, and deleted that.
--
-- What goes, for each match:
-- - the analysis itself;
-- - the version's analysis_outcomes row while it has no outcome: it still counts the stopped run, so the next run
--   would read less again;
-- - the version's analysis_jobs reservation, so the next request queues it at once (as 0016 did for 0015's).
CREATE TEMP TABLE memory_stop_reruns ON COMMIT DROP AS
SELECT a.package, a.version, a.digest, a.scorer
FROM upstream_analysis a
JOIN (VALUES ('express', '5.3.0'), ('axios', '1.21.1'), ('eslint', '10.14.0'), ('prettier', '3.10.1'), ('tailwindcss', '4.3.5')) AS incident(package, version)
  ON incident.package = a.package AND incident.version = a.version
WHERE a.scorer = 'apm-score-v10'
  AND jsonb_typeof(a.analysis -> 'signals') = 'array'
  AND EXISTS (
    SELECT 1
    FROM jsonb_array_elements(a.analysis -> 'signals') AS s(signal)
    CROSS JOIN LATERAL jsonb_array_elements(
      (CASE WHEN jsonb_typeof(s.signal -> 'evidence') = 'array' THEN s.signal -> 'evidence' ELSE '[]'::jsonb END)
      || (CASE WHEN jsonb_typeof(s.signal -> 'more') = 'array' THEN s.signal -> 'more' ELSE '[]'::jsonb END)
    ) AS e(line)
    WHERE s.signal ->> 'id' = 'incomplete'
      AND jsonb_typeof(e.line) = 'string'
      AND starts_with(e.line #>> '{}', 'an earlier analysis of this version was stopped by the platform''s CPU limit or failed before it stored anything, so this one read at most 4 MB')
  );

DELETE FROM analysis_outcomes o USING memory_stop_reruns m
WHERE o.package = m.package AND o.version = m.version AND o.scorer = m.scorer AND o.outcome IS NULL;

DELETE FROM analysis_jobs j USING memory_stop_reruns m
WHERE j.package = m.package AND j.version = m.version;

DELETE FROM upstream_analysis a USING memory_stop_reruns m
WHERE a.package = m.package AND a.version = m.version AND a.digest = m.digest AND a.scorer = m.scorer;
