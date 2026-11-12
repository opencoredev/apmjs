# Publishing pain — npm registry/CLI evidence

**Status: PASS**

Scope: why publishing to npm is annoying, as of 2026-11-11.

## Pain points

1. **Publishing needs 2FA twice — once to log in, again to publish.** Hurts every interactive publisher. Severity: high.
   > "When you publish a package from the CLI, you always need to log in first, which requires 2FA, and then when you want to publish, you need to authenticate again." — jcubic, https://github.com/orgs/community/discussions/209482 (Oct 4, 2026)
   The suggested fix in that thread ("change your setting to Authorization Only") was answered "There are no such settings".

2. **Classic tokens were revoked on a hard date and broke working release pipelines.** Hurts maintainers with hand-rolled CI. Severity: high.
   > "Any release pipeline that still relies on a classic token will start failing until it migrates to a supported alternative." — Sarah Gooding, https://socket.dev/blog/npm-revokes-classic-tokens (Dec 10, 2025)
   Primary: https://github.blog/changelog/2025-11-05-npm-security-update-classic-token-creation-disabled-and-granular-token-changes/ (Nov 5, 2025).

3. **Granular tokens expire in 7 days (max 90), turning auth into recurring maintenance.** Hurts everyone publishing from CI without OIDC. Severity: high.
   > "New tokens expire after 7 days (max 90)." — u/hichemtab, https://www.reddit.com/r/javascript/comments/1o5rgl6/if_you_have_an_npm_package_read_this_before/ (Oct 2025)
   > "no one likes having to regenerate tokens every 90 days or less and then go through the reconfiguration process." — https://www.theregister.com/ai-ml/2026/05/21/npm-registry-sets-stage-for-more-secure-package-publishing/5244527 (May 21, 2026)

4. **Trusted publishing must be configured per package, on the website, in a settings page nobody finds.** Hurts orgs with many packages. Severity: high.
   > "You need to set up trusted publishing for each of your packages individually. That might be fine if you only maintain a few, it's going to be a huge hassle if you have a lot." — Phil Nash, https://philna.sh/blog/2026/01/28/trusted-publishing-npm/ (Jan 31, 2026). He reports spending "far too long" looking for the settings page.

5. **Trusted publishing fails with errors that point at the wrong subsystem.** Hurts anyone debugging CI. Severity: high.
   > "Both diagnoses were wrong enough to waste hours." — alexeyv, https://github.com/npm/cli/issues/9088 (Mar 10, 2026). npm returned `E404 'pkg@ver' is not in this registry` and `ENEEDAUTH` for a package that existed and a correctly configured OIDC flow; the real cause was an old npm in CI. Also https://dev.to/sirinivask/npm-trusted-publishing-fails-with-a-404-and-the-404-is-lying-to-you-3b7i (Sep 6, 2026).

6. **OIDC cannot publish a package for the first time.** Hurts new packages and renames. Severity: high.
   > "The OIDC mechanism still doesn't work when trying to publish a package for the first time" — https://www.theregister.com/ai-ml/2026/05/21/npm-registry-sets-stage-for-more-secure-package-publishing/5244527 (May 21, 2026)

7. **Provenance is documented as automatic but often isn't.** Needs npm ≥11.5.1, `--provenance`, and a correct `repository` field. Hurts first-time OIDC migrators. Severity: med.
   > "I did not find this to be the case. I needed to add the `--provenance` flag so that my package would publish successfully." — https://philna.sh/blog/2026/01/28/trusted-publishing-npm/ (Jan 31, 2026)

8. **The security story is contradictory: OpenJS tells critical projects *not* to move to OIDC yet.** Hurts maintainers deciding what to do. Severity: med.
   > "We do not recommend critical projects move to this new workflow, but instead focus on hardening their existing workflows." — Wes Todd, OpenJS, via https://socket.dev/blog/npm-revokes-classic-tokens (Dec 10, 2025)
   > "2FA is just right there, it stops this in it's tracks, and GitHub refusing to enforce it is a massive problem" — same source.

9. **`.npmignore` silently replaces `.gitignore`, so adding it can publish your secrets — and you can't see what shipped.** Hurts anyone who adds an ignore file to trim the tarball. Severity: high.
   > "I've now leaked all my AWS credentials out to the public just by adding this `.npmignore` to hide my test directory." — Jeff D., https://jdxcode.medium.com/for-the-love-of-god-dont-use-npmignore-f93c08909d8d (May 26, 2018; behavior unchanged)
   > "`npm publish` doesn't show the files that were packed." — same source. npm 6+ prints a file list, but there is no pre-publish diff or secret check.

10. **Dual ESM/CJS + `exports` + `types` is still unsolved in 2025/2026.** Hurts library authors. Severity: high.
    > "TypeScript in 2025 with ESM and CJS npm publishing is still a mess" — https://lirantal.com/blog/typescript-in-2025-with-esm-and-cjs-npm-publishing (Jan 14, 2025). The author still hand-maintains `exports`, `type`, `types`, and a `tsup.config.ts` for a "zero-config" bundler.

11. **`latest` is mutable, so a prerelease can silently become what everyone installs.** Hurts publishers and all consumers. Severity: med.
    > "The `latest` tag can currently point to non-latest releases, making it a semantical non-sense causing problems with tools attempting to give it one." — arcanis (Yarn), https://github.com/npm/feedback/discussions/109 (Dec 4, 2020; closed, behavior unchanged)
    `bun publish` documents the same hazard: "A prerelease version such as `2.0.0-beta.1` needs a tag: without one it would become `latest`" — https://bun.com/docs/pm/cli/publish

12. **Versioning, changelog, and tagging are entirely DIY.** Hurts monorepos most. Severity: med. The ecosystem answer is a third-party tool — "Changesets has a focus on solving these problems for monorepos" — https://github.com/changesets/changesets. The registry has no version-bump, changelog, or release-notes primitive.

13. **Scoped packages and org setup fail with opaque 404s.** Hurts first-time scoped publishers. Severity: med.
    > "404 '@<scope>/<package>@1.2.1' is not in the npm registry." — https://github.com/orgs/community/discussions/174044 (Sep 19, 2026). Cause is usually a missing org, wrong `--access`, or a token without scope permission.

14. **Name squatting has no remedy unless you own a trademark.** Hurts anyone naming a product. Severity: med.
    > "If there isn't a registered trademark involved, unfortunately there isn't a process available to claim an unused organization name." — GitHub staff, https://github.com/orgs/community/discussions/187762 (Feb 23, 2026). The reporter had waited a week on the support form and a week on email, with no response.

15. **`bun publish` is a drop-in except where it matters: no provenance.** Hurts Bun users who need attestations. Severity: med.
    > "`bun publish` cannot generate provenance statements yet. `--provenance`, `"provenance": true` in `publishConfig` and `NPM_CONFIG_PROVENANCE=true` are errors." — https://bun.com/docs/pm/cli/publish (2026)
    Also: lifecycle scripts are skipped when you pass a tarball path, and `--recursive` aborts the whole run on first failure.

16. **`pnpm publish` adds git-state gates and can half-publish a monorepo.** Hurts monorepo maintainers. Severity: low-med.
    > "By default, pnpm checks that the working tree is clean, that the current branch is the publish branch, and that the branch is up to date with the remote." — https://pnpm.io/cli/publish. Same page: "When a recursive publish fails after the registry accepted some of the uploads".

17. **Unpublish is a 72-hour window, so a bad publish is permanent.** Hurts anyone who ships a broken or leaky tarball. Severity: med.
    > "The current policy allows unpublishing only within 72 hours of publishing" — https://github.com/orgs/community/discussions/150887 (Feb 1, 2026); policy: https://docs.npmjs.com/policies/unpublish/

**Contrast — what JSR already does better (the bar to beat):** publishes TypeScript source with no build step, so it can auto-generate docs ("JSR supports and encourages publishing TypeScript source code rather than pairs of `.js` + `.d.ts` files" — https://jsr.io/docs/publishing-packages); creates provenance automatically from GitHub Actions with no flag (https://jsr.io/docs/trust); and is ESM-only by rule, which deletes the dual-publish problem.

## What a better registry/CLI should do

1. One auth event per session: log in once, publish N times, no second OTP.
2. OIDC as the default CI path, zero stored secrets, configured at org/repo level and inherited by all packages.
3. Allow OIDC first publish (bootstrap a new name from CI).
4. Errors that name the cause: "your npm CLI is 11.4.0, trusted publishing needs ≥11.5.1" — never a fake 404/ENEEDAUTH.
5. Provenance on by default, no flag, no `repository` requirement, plus a "provenance missing because X" line.
6. Whitelist-only packing: `files` is authoritative, `.npmignore` unsupported, `.gitignore` never consulted.
7. Print the exact file list and sizes before upload; block on secret-shaped content with an explicit override.
8. Publish TypeScript source; generate `.d.ts`, ESM and CJS wrappers server-side. No `exports` map to hand-write.
9. Immutable `latest` = highest stable. Prereleases require an explicit tag and are rejected without one.
10. First-class release objects: version bump, changelog entry and git tag as one atomic, reviewable step.
11. Scoped names that work without an org (`@user/pkg` on first push), and name availability as a real API (`GET /-/name/:name`) with a reclaim path for unused names, no trademark needed.
12. Immutable versions with a "yank" (hidden from resolution, kept for lockfiles) instead of a 72-hour cliff.
13. Staged publish as an option, not a mandatory hop; approval via the same session token.
14. Monorepo publish that is all-or-nothing per batch, with a resumable plan printed up front.
15. `bun`/`pnpm`/`npm` publish parity: provenance, lifecycle scripts, identical tag and access semantics.

## Gaps

- No quantitative data on how many publishers the Dec 9, 2025 revocation broke; only anecdote and vendor commentary.
- Could not verify npm's enforcement date for mandatory 2FA on *all* maintainers; the Nov 2025 changelog covers tokens, not account-level enforcement.
- Name-availability complaints: no strong 2024-2026 thread found. "Checking a name means trial-publishing" is **inference** from the absence of a documented availability API.
- JSR's own friction (slow types, ESM-only excluding CJS consumers, scope requirement) is lightly covered — one docs page, no complaint threads read.
- Reddit comment quality is mixed; the r/javascript thread's top replies are about `minimumReleaseAge` and passkeys, not publishing. Did not read the npm staged-publishing docs directly, only The Register's summary.