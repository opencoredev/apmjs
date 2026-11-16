-- A package page read npm's whole packument on every view whose isolate had not read it in the last minute: seconds
-- for next (26 MiB parsed) or react, and the website's proxy waited on it before it streamed the page. What a page
-- needs of an upstream package (its dist-tags, text, latest's links, the newest versions with their checksums and
-- npm's ETag) is kept here (kept-package.ts); scores, dismissals and reviews are still read live on every view, and a
-- read that shows a version's source first confirms npm still lists that version. A summary older than five minutes
-- is checked against npm's ETag before it is used. A view of one older than three minutes refreshes it after the
-- response, and the cron's sweep refreshes the ones asked about in the last day; claimed_at keeps two refreshes of one
-- package from running at once, and failures with next_attempt_at back off one npm keeps failing for. A package
-- published on apm is never kept, so a revoke shows at once. Only a package apm stored an analysis of gets a row, each
-- row is at most KEPT_PACKAGE_MAX_BYTES of JSON as UTF-8, and the table is capped (KEPT_PACKAGE_CAPACITY), so it
-- stays small enough to need no index.
CREATE TABLE kept_packages (
  package text PRIMARY KEY,
  summary jsonb NOT NULL,
  computed_at bigint NOT NULL,
  asked_at bigint NOT NULL,
  claimed_at bigint,
  -- refreshes in a row that npm did not answer, and when the sweep may try again: it backs off, so a few packages npm
  -- keeps failing for cannot hold the sweep's place every run
  failures integer NOT NULL DEFAULT 0,
  next_attempt_at bigint
);
