-- Wrong passwords per legacy account in the current window, so the lockout holds across Worker isolates.
CREATE TABLE password_failures (
  "user" text PRIMARY KEY,
  count integer NOT NULL,
  since bigint NOT NULL
);

-- AI release review (docs/AI-REVIEW.md): jobs the reviewer process leases, their results, the newest upstream
-- version apm has considered per package, cached weekly download counts, and "Request AI review" presses.
CREATE TABLE review_jobs (
  id text PRIMARY KEY,
  package text NOT NULL,
  version text NOT NULL,
  digest text NOT NULL,
  source text NOT NULL CHECK (source IN ('local', 'upstream')),
  reasons jsonb NOT NULL,
  priority integer NOT NULL,
  state text NOT NULL CHECK (state IN ('queued', 'leased', 'done', 'failed')),
  lease_id text,
  lease_expires_at bigint,
  attempts integer NOT NULL DEFAULT 0,
  last_error text,
  enqueued_at bigint NOT NULL,
  updated_at bigint NOT NULL
);
CREATE UNIQUE INDEX review_jobs_key ON review_jobs (package, version, digest);
CREATE INDEX review_jobs_ready ON review_jobs (state, priority, enqueued_at);

CREATE TABLE reviews (
  package text NOT NULL,
  version text NOT NULL,
  digest text NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('benign', 'flagged', 'no-answer')),
  result jsonb NOT NULL,
  reviewed_at bigint NOT NULL,
  human_state text NOT NULL CHECK (human_state IN ('none', 'pending', 'confirmed', 'dismissed')),
  human_by text,
  human_at bigint,
  human_note text,
  PRIMARY KEY (package, version, digest)
);
CREATE INDEX reviews_human ON reviews (human_state, reviewed_at);

CREATE TABLE review_seen (
  package text PRIMARY KEY,
  newest_at bigint NOT NULL
);

CREATE TABLE review_downloads (
  package text PRIMARY KEY,
  weekly bigint,
  fetched_at bigint NOT NULL
);

CREATE TABLE review_requests (
  actor text NOT NULL,
  package text NOT NULL,
  version text NOT NULL,
  at bigint NOT NULL
);
CREATE INDEX review_requests_actor ON review_requests (actor, at);
