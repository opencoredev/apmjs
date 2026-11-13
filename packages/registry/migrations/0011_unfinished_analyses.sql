-- The runs the cron sweep looks for (Store.unfinishedAnalyses): begun, never ended. A run counts itself begun in
-- analysis_outcomes before it analyses anything, so a run the platform stops always leaves one of these rows behind.
CREATE INDEX analysis_outcomes_unfinished ON analysis_outcomes (started_at) WHERE outcome IS NULL AND started_at IS NOT NULL;
