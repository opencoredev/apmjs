-- apm:rollback-safe: adds one table nothing older reads
--
-- passkey_uses: when each passkey last answered (a sign-in, or a check that confirmed one action), for the list of
-- passkeys on the account page. Better Auth's passkey table has no such column, and apm leaves Better Auth's tables as
-- its own migrations made them. A passkey gets its row the first time it answers after this deploy, so one last used
-- before it shows no date. Removing a passkey removes its row.
--
-- Additive: one new table, nothing the running Worker reads changes. No index beyond the primary key: an index in a
-- transactional migration is refused (test/migrate.test.ts), and the account page reads it by passkey id.
SET LOCAL lock_timeout = '2s';

CREATE TABLE passkey_uses (
  passkey_id text PRIMARY KEY REFERENCES passkey (id) ON DELETE CASCADE,
  last_used_at bigint NOT NULL
);
