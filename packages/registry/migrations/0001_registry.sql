-- apm's own tables. Times are milliseconds since the epoch (bigint), JSON documents are jsonb.

CREATE TABLE users (
  name text PRIMARY KEY,
  password_hash text NOT NULL,
  email text NOT NULL,
  created_at bigint NOT NULL,
  auth_user_id text,
  github_id text,
  github_login text
);
CREATE UNIQUE INDEX users_auth_user ON users (auth_user_id) WHERE auth_user_id IS NOT NULL;

CREATE TABLE tokens (
  token_hash text PRIMARY KEY,
  "user" text NOT NULL REFERENCES users (name),
  label text NOT NULL,
  scope text NOT NULL DEFAULT 'publish' CHECK (scope IN ('publish', 'stage', 'legacy')),
  created_at bigint NOT NULL,
  expires_at bigint,
  revoked_at bigint
);
CREATE INDEX tokens_user ON tokens ("user");

CREATE TABLE packages (
  name text PRIMARY KEY,
  created_at bigint NOT NULL,
  modified_at bigint NOT NULL,
  dist_tags jsonb NOT NULL DEFAULT '{}'::jsonb,
  description text NOT NULL DEFAULT '',
  keywords jsonb NOT NULL DEFAULT '[]'::jsonb,
  readme text NOT NULL DEFAULT ''
);

CREATE TABLE owners (
  package text NOT NULL REFERENCES packages (name),
  "user" text NOT NULL REFERENCES users (name),
  PRIMARY KEY (package, "user")
);
CREATE INDEX owners_user ON owners ("user");

-- tarball_key names the tarball in the blob store: sha512/<hex digest>, so equal bytes share one object.
CREATE TABLE versions (
  package text NOT NULL REFERENCES packages (name),
  version text NOT NULL,
  seq bigserial NOT NULL,
  manifest jsonb NOT NULL,
  shasum text NOT NULL,
  integrity text NOT NULL,
  size bigint NOT NULL,
  tarball_key text NOT NULL,
  published_at bigint NOT NULL,
  published_by text NOT NULL,
  deprecated text,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'yanked', 'revoke-pending', 'revoked')),
  status_reason text,
  status_at bigint,
  status_by text,
  score jsonb,
  PRIMARY KEY (package, version)
);
CREATE INDEX versions_shasum ON versions (shasum);
CREATE INDEX versions_tarball ON versions (tarball_key);
CREATE INDEX versions_publisher ON versions (published_by, published_at);
CREATE INDEX versions_revoke_pending ON versions (status_at) WHERE status = 'revoke-pending';

CREATE TABLE advisories (
  id bigserial PRIMARY KEY,
  package text NOT NULL,
  versions jsonb NOT NULL,
  severity text NOT NULL,
  title text NOT NULL,
  detail text NOT NULL,
  created_at bigint NOT NULL,
  created_by text NOT NULL
);
CREATE INDEX advisories_package ON advisories (package);

CREATE TABLE events (
  id bigserial PRIMARY KEY,
  package text NOT NULL,
  kind text NOT NULL,
  actor text NOT NULL,
  at bigint NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX events_pkg ON events (package, at);
CREATE INDEX events_kind ON events (kind, at);

CREATE TABLE staged (
  id text PRIMARY KEY,
  package text NOT NULL,
  version text NOT NULL,
  manifest jsonb NOT NULL,
  shasum text NOT NULL,
  integrity text NOT NULL,
  size bigint NOT NULL,
  tarball_key text NOT NULL,
  tag text NOT NULL,
  readme text,
  score jsonb,
  staged_by text NOT NULL,
  staged_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
  decided_at bigint,
  decided_by text
);
CREATE INDEX staged_pkg ON staged (package, version);
CREATE INDEX staged_pending ON staged (expires_at) WHERE status = 'pending';
CREATE INDEX staged_by ON staged (staged_by);

CREATE TABLE stepups (
  auth_user_id text PRIMARY KEY,
  at bigint NOT NULL,
  method text NOT NULL
);

CREATE TABLE github_profiles (
  github_id text PRIMARY KEY,
  login text NOT NULL,
  updated_at bigint NOT NULL
);

-- An analysis counts only for the exact bytes it read (digest: "sha512-<hex>" or "sha1-<hex>") and the scorer that made it.
CREATE TABLE upstream_analysis (
  package text NOT NULL,
  version text NOT NULL,
  digest text NOT NULL,
  scorer text NOT NULL,
  analysis jsonb NOT NULL,
  analyzed_at bigint NOT NULL,
  PRIMARY KEY (package, version, digest, scorer)
);

-- Wrong TOTP codes per account, so the lockout holds across Worker isolates.
CREATE TABLE totp_failures (
  auth_user_id text PRIMARY KEY,
  count integer NOT NULL,
  since bigint NOT NULL
);

-- Upstream versions sent to the analysis queue, so one version is queued once at a time.
CREATE TABLE analysis_jobs (
  package text NOT NULL,
  version text NOT NULL,
  queued_at bigint NOT NULL,
  PRIMARY KEY (package, version)
);
