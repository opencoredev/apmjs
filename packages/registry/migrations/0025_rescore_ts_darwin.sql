-- apm:rollback-safe: deletes four stored results and their bookkeeping; older code finds the versions unscored and queues them as it would any other
--
-- Production, 16 to 18 Nov: four macOS builds of typescript's native compiler stored apm-score-v11's smaller re-run,
-- 29/100 (F) and partial, because two runs before it were stopped by the platform. The production Worker (274d284)
-- read their 24 to 27 MB Mach-O lib/tsc as text, a string twice its size in a 128 MB isolate. The deploy before this
-- one (9cb34ca) knows the Mach-O and reads its text in pieces, and reads these tarballs in full (100/100 locally, 90
-- with new-publisher), but it serves a stored v11 result as its own, so these four would stay F until apm-score-v12.
-- typescript@7.0.2 (90/100 on its own) and the packages that bring it in (ts-api-utils, @trpc/server, ts-node) are
-- review-first while they do.
--
-- Only these four versions, each at the tarball digest its F was stored for, and only an apm-score-v11 analysis whose
-- `incomplete` signal carries the re-run's own line from its first character (in `evidence`, or in `more`):
--   @typescript/typescript-darwin-arm64 7.0.2, 7.1.0-dev.20261118.1
--   @typescript/typescript-darwin-x64   7.0.2, 7.1.0-dev.20261118.1
-- darwin-arm64 7.0.1-rc (an analysis-limit outcome too) and the large-JavaScript re-runs (@prisma/studio-core,
-- hyperframes, posthog-js, three) are left: this deploy reads them no more cheaply.
--
-- What goes, for each match (as 0018 did for 13 Nov's):
-- - the apm-score-v11 analysis itself;
-- - the version's apm-score-v11 analysis_outcomes row while it has no outcome: it still counts three starts, so the
--   next run would read less again;
-- - the version's apm-score-v11 analysis_jobs reservation, so the next ask queues it at once.
-- Nothing else: the apm-score-v10 rows, the AI reviews and typescript's own rows stay. A second run finds no match.
--
-- One statement (round 5 review of f328874, P2): the analysis is deleted under the whole guard, and the outcome row and
-- reservation are deleted only for the analyses that statement deleted. A row another connection replaces while the
-- statement waits on its lock is read again as it now stands (READ COMMITTED re-checks the WHERE clause on the newest
-- version of a row it waited for), so a complete analysis written there is not deleted, and nor is its bookkeeping.
SET LOCAL lock_timeout = '2s';

WITH gone AS (
  DELETE FROM upstream_analysis a
  USING (VALUES
    ('@typescript/typescript-darwin-arm64', '7.0.2', 'sha512-828c336abf4cc12fda456a7a7f76b8294ab34630198ceb2618d08ce8b713817ba6f9d05f82c05530df8082f38209b82e5f289c93a2c986906ccf131e6c9f2cc8'),
    ('@typescript/typescript-darwin-arm64', '7.1.0-dev.20261118.1', 'sha512-193fee4506d937c47b581f2bcd06f2715d080b20f5bf90be32fafcdcc0c95fd28904378b157affa5ce14760c2e1fa7eb1a8918fec52b00eb64b79ae431206498'),
    ('@typescript/typescript-darwin-x64', '7.0.2', 'sha512-499f716489ea02936534673db345b5552b24b5848e7bd705a8d388aa63751acf129a48ca65816dd35ec6e15c0fc404889ce0ee01d6d35bbb1788551ff3ddd180'),
    ('@typescript/typescript-darwin-x64', '7.1.0-dev.20261118.1', 'sha512-4c2658941144e5feccb14c92dda360f33c3fbd39b3413eee70a6f55758076446f3a372f29b45667faa5f440912801e2b50a6f2c0c9b752329e4e55596ba8a610')
  ) AS target(package, version, digest)
  WHERE target.package = a.package AND target.version = a.version AND target.digest = a.digest
    AND a.scorer = 'apm-score-v11'
    AND jsonb_typeof(a.analysis -> 'signals') = 'array'
    AND EXISTS (
      SELECT 1
      FROM jsonb_array_elements(a.analysis -> 'signals') AS s(signal)
      CROSS JOIN LATERAL jsonb_array_elements(
        (CASE WHEN jsonb_typeof(s.signal -> 'evidence') = 'array' THEN s.signal -> 'evidence' ELSE '[]'::jsonb END)
        || (CASE WHEN jsonb_typeof(s.signal -> 'more') = 'array' THEN s.signal -> 'more' ELSE '[]'::jsonb END)
      ) AS e(line)
      WHERE s.signal ->> 'id' = 'incomplete'
        AND jsonb_typeof(e.line) = 'string'
        AND starts_with(e.line #>> '{}', '2 earlier analyses of this version were stopped by the platform')
    )
  RETURNING a.package, a.version, a.scorer
),
outcomes AS (
  DELETE FROM analysis_outcomes o USING gone g
  WHERE o.package = g.package AND o.version = g.version AND o.scorer = g.scorer AND o.outcome IS NULL
  RETURNING o.package
)
DELETE FROM analysis_jobs j USING gone g
WHERE j.package = g.package AND j.version = g.version AND j.scorer = g.scorer;
