-- Which version's publish wrote the package's readme. A publish without a readme keeps the text an earlier one wrote,
-- so the newest version is not always the readme's owner, and revoking the owner must hide the readme (withheld.ts).
-- Rows written before this migration leave it NULL: nobody knows their owner, so their readme is hidden while any
-- version of the package is revoked or revoke-pending.
ALTER TABLE packages ADD COLUMN readme_version text;
