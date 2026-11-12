-- Rejected and expired uploads keep only their audit fields: drop the manifest, readme and score of rows decided
-- before the registry purged them on decision.
UPDATE staged SET manifest = '{}'::jsonb, readme = NULL, score = NULL
WHERE status IN ('rejected', 'expired') AND (manifest <> '{}'::jsonb OR readme IS NOT NULL OR score IS NOT NULL);
