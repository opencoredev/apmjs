-- A resolve of next read npm's whole packument of every package in its tree on every request: 118 MB for its 53
-- packages, 17 to 22 s on production. What each read chose of an upstream document is kept here (upstream.ts, chosen):
-- npm's ETag for the packument it was chosen from, the dist-tags, the versions each choice took (a dependency's range
-- or tag, a resolve root's page), keyed by the choice, each with when it was made (it answers for an hour from
-- then, whatever later reads under the same ETag did), and those versions' records with their manifests summarized
-- (walk-catalog.ts). The next read asks npm with If-None-Match: a 304 means the packument is the same, so the same
-- choices hold and are answered from here; anything else is read as before and replaces the row. Scores are never
-- kept here: they are read from upstream_analysis on every read. Rows are bounded in stored bytes
-- (KEPT_CHOICES_MAX_TEXT), in choices (KEPT_CHOICES_MAX_CHOICES) and in number (KEPT_CHOICES_CAPACITY), and the
-- cron drops the ones nobody asked about for a week.
CREATE TABLE upstream_choices (
  -- the URL the packument was asked for at: the upstream and the package, so a 304 from another upstream never
  -- answers from a row kept for this one
  document text PRIMARY KEY,
  etag text NOT NULL,
  kept jsonb NOT NULL,
  fetched_at bigint NOT NULL,
  asked_at bigint NOT NULL
);
