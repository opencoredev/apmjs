-- Second factors bound to the action they confirm. A passkey check used to leave a proof on the session that the
-- first action to arrive could spend, and a passkey sign-in made one too. Now every website factor check issues a
-- confirmation bound to the session, the action and its exact parameters (one canonical key, actions.ts), and the
-- change it confirms spends exactly that confirmation, once. A passkey check answers a challenge the registry made
-- for one named action, so a sign-in never confirms anything.

DROP TABLE passkey_proofs;

CREATE TABLE passkey_challenges (
  id_hash text PRIMARY KEY,
  session_hash text NOT NULL,
  auth_user_id text NOT NULL,
  action text NOT NULL,
  challenge text NOT NULL,
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  used_at bigint
);
CREATE INDEX passkey_challenges_expiry ON passkey_challenges (expires_at);

CREATE TABLE factor_confirmations (
  id_hash text PRIMARY KEY,
  session_hash text NOT NULL,
  auth_user_id text NOT NULL,
  action text NOT NULL,
  factor text NOT NULL CHECK (factor IN ('totp', 'recovery', 'passkey')),
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  used_at bigint
);
CREATE INDEX factor_confirmations_expiry ON factor_confirmations (expires_at);
