-- Score evidence an apm reviewer dismissed (docs/SCORE.md, "Dismissed evidence"). A dismissal names the exact
-- tarball digest, the scorer that cited the item, the signal, and the file and line, so it never carries over to
-- other bytes, another version or another scorer. An undo keeps the row and records who undid it and when.
CREATE TABLE evidence_dismissals (
  id bigserial PRIMARY KEY,
  scorer text NOT NULL,
  package text NOT NULL,
  version text NOT NULL,
  digest text NOT NULL,
  signal text NOT NULL,
  file text NOT NULL,
  line integer NOT NULL,
  reason text NOT NULL,
  dismissed_by text NOT NULL,
  dismissed_at bigint NOT NULL,
  restored_by text,
  restored_at bigint
);
CREATE UNIQUE INDEX evidence_dismissals_live ON evidence_dismissals (package, version, digest, scorer, signal, file, line) WHERE restored_at IS NULL;
CREATE INDEX evidence_dismissals_package ON evidence_dismissals (package) WHERE restored_at IS NULL;
