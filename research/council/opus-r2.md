# Opus 5.5, round 2: score the built product

Evidence I gathered: `bun scripts/score.ts` printed `declared=92 pass=92`, failing 0. I read server.ts, apm.ts, upstream.ts, db.ts, score.ts, names.ts and the bun scanner, looked at the screenshots, and ran three probes against the real registry via the test harness (scripts in /tmp/opus-r2, nothing in the repo touched).

## Scores

| Criterion | Score |
| --- | --- |
| Problem fit | 8 |
| Bun-first design | 8 |
| Security soundness | 4 |
| Correctness and evidence | 7 |
| Usability | 8 |
| Overall | 6.5 |

Problem fit: publishing is better than npm in the ways that matter (secrets refused with the file named, missing `main`/`types` caught, prerelease kept off `latest`, one token, `apm publish` preview). Yank, revoke with a 410, restore, incident with dry run and a public log all exist and are tested with real clients. The score explains itself per version with file:line evidence and a notChecked list.

Bun-first: the security scanner hook makes stock `bun install` refuse revoked and low-scoring versions, and `bun publish` is the default path. npm gets the same registry, `~safe`, and audit advisories. Good split.

Usability: the CLI says why it refused and what to type next. The search page answers "is it free, is it mine, is it a look-alike" in one block, close to Vercel's domain search, and holds up at 390px. Small issues: on desktop the taken `tiny` row shows a "-" chip where mobile shows "A 90"; the tiny-slug log lists "yanked 1.2.0" twice (may predate the idempotent-yank commit); alternatives are not marked free or taken.

Security is where it falls down. The guards work against the attacks the tests model, but three of them fail open, and I could trigger two from outside with stock tools.

## Gaps

1. Anyone can take a public package name during an upstream outage (confirmed). `Upstream.fetchPackage` returns null on any non-200 or network error, `get` caches that null for 60s, and the publish guard treats null as "not on npm". `typoConflicts` returns nothing for a name that is itself popular, so nothing else stops it. Probe: upstream answering 503, user `mallory` runs `bun publish` for `react@99.0.0`, exit 0, and `/-/apm/v1/packages/react` returns `source: local, maintainers: [mallory]`. `lookup` checks local first, so that name now serves mallory's code to every apm user even after npm comes back. That is the dependency-confusion attack the round 1 spec said this guard prevents. Fix: have `fetchPackage` return a tri-state (`found` / `absent on 404` / `unknown`), refuse a first publish on `unknown` with a 503 "cannot verify the name, try again", never cache `unknown`, and also reserve every name in `POPULAR_NAMES` outright. Add an acceptance test with a 503 upstream.

2. The score gate passes anything it has not scored, and the scanner skips files without a code extension (both confirmed). `policyBlock` says "Unanalyzed versions pass the score check", and `upstreamPackument` applies `~safe` without analyzing first. Probe: an upstream package scoring 35 (F), three days old, never requested before. `GET ~safe/up-evil` lists 1.0.0 and `npm install` through `~safe` exits 0. Only after that tarball fetch does `~safe` hide it. Without `--ignore-scripts` its postinstall would already have run. `resolve` has the same hole past the first 5 candidates. Separately, `analyze` only reads files matching `CODE_EXT`, but `node setup` runs an extensionless file as CommonJS. The same exfiltration payload scores 35 F as `setup.js` and 85 B as `setup`. Fix: in `~safe` and `resolve`, treat "not analyzed" as a block, or analyze before deciding (bounded, with a 503 or a hold when the budget runs out). In `analyze`, also scan every file named in an install script, `main`, `bin` or `exports`, and any extensionless or non-JS file that a scanned file `require`s, whatever its extension. Add both probes as tests.

3. Revoking a hacked version waits 24 hours in exactly the hacked-account case (code read, not run). `revokeVersion` makes a revoke final at once only when the version is under 72h old and `dependentsOf(package)` is empty. A compromised package that other packages depend on (the worm scenario) therefore lands in `revoke-pending`, so the tarball keeps being served to lockfile installs (`npm ci`, `bun install --frozen-lockfile`) for 24h. `handleIncident` calls the same function without `forceFinal`, so the incident button also just yanks a hacked popular package for a day unless a second owner exists. The bun scanner and audit do flag it, but stock `npm ci` runs the postinstall before anyone audits. The 72h and dependents rule protects old versions that builds rely on. A version under 72h old, revoked with the owner's password, is the malware case, and dependents pinned to it are the victims. Fix: make fresh versions (under 72h) final at once whatever their dependents, keep the pending path for older ones, and pass `forceFinal` for fresh targets in incident. Add a test: a depended-on package's fresh version is revoked and its tarball returns 410 immediately, both via `revoke` and via `incident`.

Smaller notes, not counted as gaps: `unyank` and dist-tag moves need only a token, so a stolen token can unyank a version the owner pulled or point `latest` at an old vulnerable release. The scanner does not emit the `warn` for yanked versions that the plan promises.
