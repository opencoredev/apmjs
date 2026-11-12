-- The second-factor ledger: one attempt budget per account across TOTP and recovery-code checks, each TOTP time
-- step accepted once, passkey checks bound to the session they made and spent on one action, and website
-- confirmations of one named CLI command, used once. It replaces the 10-minute step-up and the failure counter.

DROP TABLE stepups;
DROP TABLE totp_failures;

CREATE TABLE factor_attempts (
  id bigserial PRIMARY KEY,
  auth_user_id text NOT NULL,
  at bigint NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('pending', 'ok', 'bad'))
);
CREATE INDEX factor_attempts_user ON factor_attempts (auth_user_id, at);

CREATE TABLE totp_steps (
  auth_user_id text PRIMARY KEY,
  step bigint NOT NULL
);

CREATE TABLE passkey_proofs (
  session_hash text PRIMARY KEY,
  auth_user_id text NOT NULL,
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  used_at bigint,
  used_for text
);

CREATE TABLE cli_grants (
  id text PRIMARY KEY,
  auth_user_id text NOT NULL,
  action text NOT NULL,
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  used_at bigint
);
CREATE INDEX cli_grants_user ON cli_grants (auth_user_id, action);
