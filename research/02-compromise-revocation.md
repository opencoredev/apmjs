# Compromised packages and revocation

**Status: PASS**

## Pain points

1. **You cannot pull a bad version once anything depends on it.** npm's policy allows unpublish only within 72h *and* zero dependents; after that, only if <300 weekly downloads, one maintainer, no dependents. A compromised or accidentally-leaked version of a popular package is therefore permanent by policy, and removal becomes a discretionary support action. Who it hurts: every maintainer and every consumer. Severity: **high**.
   > "Regardless of how long ago a package was published, you can unpublish a package that meets all of the following conditions: no other packages … depend on it; it had less than 300 downloads over the last week; it has a single owner/maintainer" — https://docs.npmjs.com/policies/unpublish/ (accessed 2026-11-11)

2. **Deprecate is not revocation, and it is the only self-serve option.** Deprecated versions stay downloadable and installable; the warning is advisory. So the "fix" for a bad release leaves the bad bytes in the dependency graph. Severity: **high**.
   > "This allows the package to be downloaded but publishes a clear warning message … if they are depending on it their builds will not break." — https://docs.npmjs.com/policies/unpublish/

3. **Removal is two-tier: support-mediated, and faster for the well-connected.** Anthropic's Claude Code shipped a source map in `2.1.88` (2026-03-31); the publisher could only *deprecate* it, and it disappeared only after escalation. Severity: **high**.
   > "Amusingly, they deprecated it with a message of 'Unpublished' instead of actually unpublishing it … Looks like Anthropic called in a favor and it's removed now." — https://news.ycombinator.com/item?id=47589150 (2026-03-31); leak context: https://www.infoq.com/news/2026/04/claude-code-source-leak/

4. **The exposure window that matters is hours, and hours is enough.** Malicious versions are typically live 2–4 hours, and that is sufficient to reach production bundles. Severity: **high**.
   > "during the short 2-hour timeframe … the malicious code successfully reached 1 in 10 cloud environments" — https://www.wiz.io/blog/widespread-npm-supply-chain-attack-breaking-down-impact-scope-across-debug-chalk (2025-09-08)
   - chalk/debug/strip-ansi et al., 18–25 packages, first flagged 13:16 UTC 2025-09-08, removed "a few hours later" (same source).
   - nx "s1ngularity": 8 malicious releases, "live for ~4 hours", 2025-08-26/27 — https://nx.dev/blog/s1ngularity-postmortem (2025-09-05).
   - axios `1.14.1` / `0.30.4`: published 2026-03-31 00:21 and 01:00 UTC, removed ~03:00 UTC (~3h30m / ~2h51m) — https://www.endorlabs.com/learn/npm-axios-compromise (2026-03-31).

5. **Historically the window was months, not hours.** `flatmap-stream@0.1.1` shipped inside `event-stream@3.3.6` on 2018-09-09 and was removed 2018-11-26 — roughly 11 weeks of a backdoored, 2M-downloads/week package. Severity: **high**.
   > "npm Security responded by removing flatmap-stream and event-stream@3.3.6 from the Registry and taking ownership of the event-stream package" — https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident (2018-11-27)

6. **postinstall is the delivery mechanism, and npm ran it by default until mid-2026.** Every major incident used install-time script execution: nx, chalk/debug, Shai-Hulud 1.0/2.0, axios (via a typosquatted dependency's postinstall). Severity: **high**.
   > "The malicious packages ran a post-install script that scanned user systems for sensitive data" — https://nx.dev/blog/s1ngularity-postmortem
   > "requiring explicit opt-in for dependency lifecycle scripts, Git dependencies, and remote-URL dependencies" (shipped July 2026, npm v12) — https://github.com/orgs/community/discussions/208130 (2026-09-17)

7. **CI tokens are the real blast radius, and provenance did not stop the install.** nx was detected *because* the malicious packages lacked provenance — and npm installed them anyway. Severity: **high**.
   > "We detected this because the malicious packages lacked NPM provenance signing. Unfortunately, provenance doesn't block unsigned packages from being installed" — https://nx.dev/blog/s1ngularity-postmortem

8. **Worms turn one stolen token into hundreds of packages, repeatedly.** Scale by wave: 500+ packages removed (Sept 2025); 796 packages / 20M weekly downloads (Nov 2025); 42 TanStack packages (May 2026); 400+/444 packages via `keyv` (Aug 2026). Severity: **high**.
   > "Immediate removal of 500+ compromised packages from the npm registry" — https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/ (2025-09-22)
   > "Shai-Hulud 2.0 has successfully taken over and backdoored 796 unique npm packages … over 20 million weekly downloads" — https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/ (2025-11-25)
   > "ChainDrop … affecting more than 400 packages across multiple unrelated publishers" — https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm (2026-08-04)

9. **The security fix itself became a maintainer tax.** Classic tokens were revoked 2025-12-09 with no bulk path: trusted publishing is per-package, web-UI only, and cannot create new packages. Severity: **med**.
   > "OIDC trusted publishing … still cannot be used to publish new packages, requires manual configuration through the npm website on a per-package basis, and lacks an API for bulk setup" — https://socket.dev/blog/npm-to-implement-staged-publishing (2026-01-07)

10. **Consumers had no cooldown for a decade.** A "don't install anything published in the last N hours" switch is the single cheapest defense, and npm only shipped it in Feb 2026. Severity: **med**.
    > "npm took longer but shipped min-release-age in version 11.10.0 in February 2026" — https://nesbitt.io/2026/03/04/package-managers-need-to-cool-down.html (2026-03-04)
    > pnpm `minimumReleaseAge` "defaults to 1440 (1 day)" — https://pnpm.io/supply-chain-security

11. **Maintainer self-sabotage has no revocation story at all.** colors/faker (2022-01-08/09) shipped an infinite loop and `fff`-printing builds; the only remedy was pinning, because the versions were not malicious by npm's definition. Severity: **med**.
    > "Snyk issued a Denial of Service security vulnerability for colors@1.4.1 … We highly recommend you revert" — https://snyk.io/blog/open-source-npm-packages-colors-faker/ (2022-01-09)

12. **The registry can restore what it wants, but you cannot remove what you want.** left-pad was unpublished 2016-03-22 and restored by npm within hours; the asymmetry is the point. Severity: **med**.
    > "Shortly after 2:30 PM (Pacific Time) on Tuesday, March 22, we began observing hundreds of failures per minute" — https://blog.npmjs.org/post/141577284765/kik-left-pad-and-npm (2016-03-23)

13. **Reporting malware is a web form with no status, no SLA, and no appeal.** Severity: **med**.
    > "Confirm validity of the report. Remove the package from the registry. Publish a security placeholder … Publish a security advisory" — https://docs.npmjs.org/reporting-malware-in-an-npm-package (edited 2025-06-09)

## What a better registry/CLI should do

- **Yank, Cargo-style, as a first-class verb**: `bun yank pkg@1.2.3` removes the version from resolution immediately, keeps the tarball for existing lockfiles, and is reversible. No 72h window, no dependents test.
- **Three distinct states, not two**: `deprecated` (advisory), `yanked` (unresolvable for new installs), `revoked` (malicious — install must fail even from a lockfile). Today npm conflates all three into "unpublish or nothing".
- **Signed revocation list** published as a static, cacheable feed (`/security/revocations.json`, signed) that every client checks at install time, so a revoked version cannot be installed offline-first or from a stale lockfile.
- **Self-serve takedown with a public state machine**: report → triage → removed, each with timestamps visible to the reporter; publish median time-to-removal as a public metric.
- **Cooldown on by default** (`minimumReleaseAge`, 24h) in the CLI, not opt-in, with a per-package escape hatch and a clear error message naming the age of the blocked version.
- **Lifecycle scripts denied by default**, allowlist keyed on `name@version+integrity hash`, not just name — so a trusted package that gets a new postinstall is re-prompted.
- **Publish identity binding**: tokens scoped to one package, ≤24h TTL, bound to a device/OIDC subject; any new publisher identity on an existing package triggers a hold.
- **Staged/2-person publish for high-reach packages** (e.g. >1M weekly downloads or >100 dependents), with the approval recorded in a public transparency log.
- **Enforce provenance at install** when a package has a provenance history: refuse the version if the signature is missing or the trust level dropped (`trustPolicy: no-downgrade`).
- **Bulk maintainer operations**: one OIDC config across N packages, one token rotation across N repos, one yank across N versions.
- **Immutable, queryable publish audit log** per package (who, from where, which CI run, which token), exposed via API so incident responders can answer "was I exposed?" in one call.

## Gaps

- No published npm SLA or median time-to-removal; per-incident windows above are vendor-reported, not registry-reported.
- Could not verify how many takedown/unpublish requests npm denies, or the criteria for the discretionary manual removals (Claude Code, left-pad, event-stream ownership transfer).
- Shai-Hulud 1.0 per-package removal times not verified; only the aggregate "500+ removed" and the 2025-09-14 notification date.
- ChainDrop (Aug 2026), Mini Shai-Hulud/TanStack (May 2026) and Red Hat (Jun 2026) are covered from vendor summaries; exact publish-to-removal windows for those waves are unconfirmed.
- Whether npm's new publish-time malware scanning (2026) has a measured false-negative rate is not public.
