-- What became of an upstream version's analysis, kept apart from the queue's reservations (analysis_jobs). A version
-- this scorer can never score says why (outcome, detail) instead of reading as queued forever: its tarball is over the
-- download or unpack cap, the upstream serves it in no form apm can check, it is not a package apm can read, or its
-- analysis kept running past the platform's CPU limit. `starts` and `started_at` count the analysis runs begun, so a run
-- the platform stopped before it could store anything is known to the next run (analysis.ts). Rows are per scorer: a
-- new scorer tries again. 0010, not 0009: another branch adds a 0009.
CREATE TABLE analysis_outcomes (
  package text NOT NULL,
  version text NOT NULL,
  scorer text NOT NULL,
  starts integer NOT NULL DEFAULT 0,
  started_at bigint,
  outcome text CHECK (outcome IN ('too-large', 'unavailable', 'unreadable', 'analysis-limit')),
  detail text,
  decided_at bigint,
  PRIMARY KEY (package, version, scorer)
);
