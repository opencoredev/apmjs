-- popular-scores read every named package's whole npm metadata on each request: 7 s for the home page's twelve, past
-- the website's 4 s budget, so the home page waited 4 s and showed no scores. The answer for each upstream package it
-- was asked about is kept here (apm.ts, popularScoresResponse); the cron's sweep works the ones asked about in the
-- last day out again every 10 minutes and drops the ones nobody asked about for a week (apm.ts, refreshLatestScores).
-- A package published on apm is never kept, so a revoke shows at once. version, score and grade are all set or all
-- null (no stored analysis of the latest version yet).
CREATE TABLE latest_scores (
  package text PRIMARY KEY,
  version text,
  score integer,
  grade text,
  computed_at bigint NOT NULL,
  asked_at bigint NOT NULL,
  CHECK ((version IS NULL) = (score IS NULL) AND (score IS NULL) = (grade IS NULL))
);

CREATE INDEX latest_scores_asked_at ON latest_scores (asked_at);
