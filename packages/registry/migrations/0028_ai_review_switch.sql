-- apm:rollback-safe: adds three tables nothing older reads
--
-- The AI review's off switch and the review queue's step-up window (docs/AI-REVIEW.md).
--
-- review_switch: one row per setting apm's reviewers change at request time. 'flags-hold' says whether an AI review
-- flag a person has not decided holds installs (review-first). No row means the deploy's default (APM_AI_FLAGS_HOLD,
-- on unless set), so a fresh database behaves as before.
--
-- review_switch_log: every change of a switch, who and when, next to the decisions the reviews table records.
--
-- step_up_windows: a second factor that unlocks one kind of change for a short time, bound to the session that made
-- it (its token's sha256, as factor_confirmations stores it), the account and the scope it was made for.
--
-- Additive: three new tables, nothing the running Worker reads changes. No index beyond the primary keys: each table
-- holds a handful of rows, and an index in a transactional migration is refused (test/migrate.test.ts).
SET LOCAL lock_timeout = '2s';

CREATE TABLE review_switch (
  name text PRIMARY KEY CHECK (name IN ('flags-hold')),
  value boolean NOT NULL,
  changed_by text NOT NULL,
  changed_at bigint NOT NULL
);

CREATE TABLE review_switch_log (
  id bigserial PRIMARY KEY,
  name text NOT NULL,
  value boolean NOT NULL,
  changed_by text NOT NULL,
  changed_at bigint NOT NULL
);

CREATE TABLE step_up_windows (
  session_hash text NOT NULL,
  auth_user_id text NOT NULL,
  scope text NOT NULL,
  opened_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  PRIMARY KEY (session_hash, scope)
);
