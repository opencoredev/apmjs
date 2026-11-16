-- Review of e4f97b2 (P2): an outcome recorded "apm can never score this version" is keyed by version, not by the
-- bytes it was decided for, so after npm moved a version to another tarball the website still skipped the readme of
-- a tarball it can now open. `digest` is the tarball's checksum label (digestLabel: "sha512-<hex>", or "sha1-<hex>")
-- the outcome was decided for (analysis.ts, markUnscorable); NULL when it was decided for no tarball (npm no longer
-- lists the version) and for every row recorded before this migration, which read as not bound to any tarball.
-- A nullable column with no default changes only the catalog; lock_timeout bounds its lock wait, as in 0012 and 0013.
SET LOCAL lock_timeout = '2s';
ALTER TABLE analysis_outcomes ADD COLUMN digest text;
