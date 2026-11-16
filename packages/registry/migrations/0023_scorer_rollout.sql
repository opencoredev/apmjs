-- apm-score-v11 reads what apm-score-v10 stored where v11 would store the same, so a scorer change does not make every
-- version wait for the queue again (review of e8616ca, finding 2: on production 3,342 of 3,410 v10 analyses qualify).
--
-- apm_v10_reusable(analysis): an apm-score-v10 analysis that left no file unread for its size or the byte budget and
-- stopped nowhere, which is what v11 would store for the same bytes: no skipped file, no `unanalyzed-files` or
-- `incomplete` signal, no partial coverage. @apm/core's reusableAnalysis is the same test in TypeScript;
-- packages/registry/test/scorer-rollout.test.ts holds the two to each other.
--
-- apm_v10_outcome_reusable(outcome): a v10 decision v11 keeps. A version v10 could not fetch, could not read, or whose
-- runs the platform kept stopping is the same for v11. One v10 refused as too large is not: v11 reads it as a stream.
--
-- analysis_jobs.scorer: the scorer a reservation was made for. NULL for reservations made before this (and by the old
-- Worker while a deploy replaces it); the sweep requeues those only when the version never got a result or a run.
--
-- Additive and in one transaction: the functions are new, the column is nullable with no default (no rewrite), and
-- the old Worker reads none of them. lock_timeout bounds the column change's lock wait, as in 0012 and 0013.
SET LOCAL lock_timeout = '2s';

CREATE OR REPLACE FUNCTION apm_v10_reusable(analysis jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT jsonb_typeof(analysis) = 'object'
    AND analysis ->> 'scorer' = 'apm-score-v10'
    AND (analysis -> 'skipped' IS NULL OR analysis -> 'skipped' = '[]'::jsonb)
    AND jsonb_typeof(analysis -> 'signals') = 'array'
    AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(analysis -> 'signals') AS s(signal) WHERE s.signal ->> 'id' IN ('incomplete', 'unanalyzed-files'))
    AND (analysis -> 'coverage' IS NULL OR analysis -> 'coverage' ->> 'kind' = 'complete')
$$;

CREATE OR REPLACE FUNCTION apm_v10_outcome_reusable(outcome text) RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT outcome IN ('unavailable', 'unreadable', 'analysis-limit')
$$;

ALTER TABLE analysis_jobs ADD COLUMN scorer text;
