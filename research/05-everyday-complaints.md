# Everyday complaints: npm registry, website and CLI

**Status: PASS**

Scope: everyday developer pain, excluding publishing and security incidents. Ranked by recurrence across HN, Reddit, GitHub discussions and blogs, 2024–2026 unless noted.

---

## Pain points

### 1. `node_modules` bloat and micro-dependency culture — HIGH, very frequent
Hurts: everyone; worst for CI, Docker and laptops.

> "I've just Next.js + shadcn application and I check size of node_modules, AND IT'S 800mb. What is the code in there... it's look like thousand dependencies." — r/node, 2025, https://www.reddit.com/r/node/comments/1oln4cf/wtf_with_node_modules/

> "you're never quite sure why there are 37 copies of lodash in various states of existence." — GitHub discussion #181598, Dec 10 2025, https://github.com/orgs/community/discussions/181598


### 2. Peer dependency errors (`ERESOLVE`) — HIGH, very frequent
Hurts: app developers on React/Angular upgrades. The standard fix, `--force`, silently breaks the tree.

> "ERESOLVE unable to resolve dependency tree. I was able to circumvent the issue in NPM by using Yarn instead." — r/reactjs, https://www.reddit.com/r/reactjs/comments/mryis8/how_to_solve_peer_dependencies_error_after/

> "npm install --force is a trap, and AI tools just guess versions." — r/SideProject, late 2025, https://www.reddit.com/r/SideProject/comments/1pmj71d/i_built_a_tool_to_fix_peer_dependency_hell_it/

### 3. Slow installs — HIGH, very frequent
Hurts: CI and cold caches.

> "NPM installation alone took more than 3 mins... Tried pnpm and yarn, both are failing to build few artifacts." — r/node, 2024, https://www.reddit.com/r/node/comments/1hgek14/any_way_to_improve_npm_install_time/


### 4. Lockfile churn and merge conflicts — HIGH, very frequent
Hurts: any team with more than one committer. The accepted workaround is deleting the lockfile.

> "by far the highest source of merge conflicts is the package-lock.json file" — Atlassian community, Mar 14 2024, https://community.atlassian.com/forums/discussion/2640023/automatically-resolve-merge-conflicts-in-package-lock

> "My PR has 8,000 line changes because Susan ran npm update on her Windows machine..." — GitHub discussion #181598, Dec 10 2025

### 5. npmjs.com search quality and ranking — HIGH, frequent
Hurts: anyone discovering a package rather than already knowing its name.

> "Searching for 'RabbitMQ' now returns results like vasync and slugid, which are unrelated... Established and actively maintained libraries have been pushed far down the rankings." — stephen-cresswell.com, Dec 23 2024, http://www.stephen-cresswell.com/2024/12/23/npm-search-is-broken.html

> "npm search sorted by downloads this week is giving me irrelevant packages" / "you type in the exact package name, that package is not reliably the first result. Minor edge case, but infuriating" — HN `65`, `nickradford`, Feb 2026, https://news.ycombinator.com/item?id=47010823

Context: npm's search is not npm's — it is the Algolia `npm-search` project, co-maintained by jsDelivr: https://www.jsdelivr.com/blog/joining-forces-with-algolia-for-an-even-better-npm-search/

### 6. ESM vs CJS confusion — HIGH, frequent
Hurts: library consumers and authors; fails at runtime, after install.

> "If ESM is the standard now, why do I have to configure my node file with special information to use it?... it seems absent-minded that I should have to configure my node setup with special flags to utilize the default flavor of a programming language." — r/learnjavascript, 2025, https://www.reddit.com/r/learnjavascript/comments/1nzovp2/if_esm_is_the_standard_now_why_do_i_have_to/

> "I have yet to see a frontend-project that was bigger than some three-person-garage-hobby that didn't occasionally run into CJS versus ESM issues." — HN `Shacklz`, Jun 2024, https://news.ycombinator.com/item?id=40737508


### 7. Abandoned packages: no maintenance signal, no takeover path — HIGH, frequent
Hurts: consumers choosing a dependency; maintainers wanting to hand one over.

> "Our current stance is that unmaintained packages will remain unmaintained. As stewards of the registry it is not in our purview to maintain..." — npm staff, npm/feedback #82, Nov 3 2020, https://github.com/npm/feedback/discussions/82

> "npm does not resolve squatting claims on demand. We do not transfer package, organization, or username ownership simply because another user wants the name." — npm disputes policy, https://docs.npmjs.com/policies/disputes/

> "The 'Is This Package Maintained?' Investigation: Last publish: 3 years ago / Has 47 open issues / Downloads: 4,578,921 weekly / 'Seems fine!'" — GitHub discussion #181598, Dec 10 2025


### 8. Download counts are misleading and gameable — MEDIUM, frequent
Hurts: anyone using downloads as a trust proxy — as the registry's own ranking does.

> "most npm downloads are from CI builds. Every deploy preview, every commit, it's all adding downloads." — r/node, https://www.reddit.com/r/node/comments/1i5jinh/is_npm_downloads_count_fake/


### 9. npm CLI UX and error messages — MEDIUM, frequent
Hurts: beginners most. `ELIFECYCLE`, `ELSPROBLEMS`, `npm ls` trees and `npm audit` walls.

> "npm ERR! code ELIFECYCLE ... This is most likely a problem with the n-app package, npm ERR! not with npm itself." — the canonical confusing output, still the top answer: https://stackoverflow.com/questions/30744964/what-does-the-elifecycle-node-js-error-mean

> "npm audit has a signal-to-noise problem that makes it actively harmful. The typical npm project shows 10-30 'vulnerabilities' from transitive [deps]." — pkgpulse.com, Mar 8 2026, https://www.pkgpulse.com/guides/why-npm-audit-is-broken


### 10. Duplicate / phantom dependency versions — MEDIUM, frequent
Hurts: bundle size, singleton breakage (React hooks, tokens).

> "`npm dedupe` fails to dedupe newer version of dependency when older version of dependency is at root level in package-lock.json" — npm/cli #5307, Aug 16 2022, https://github.com/npm/cli/issues/5307

Rush treats duplicate instances as a first-class hazard: https://rushjs.io/pages/advanced/npm_doppelgangers

### 11. Name squatting and namespace scarcity — MEDIUM, occasional
Hurts: new maintainers who cannot get a good name; users landing on an empty placeholder.

> "It is against npm's Terms of Use to publish a package... simply for the purposes of reserving it for future use. Accounts violating the name squatting policy may be removed or renamed without notice." — npm disputes policy, https://docs.npmjs.com/policies/disputes/


### 12. Package pages lack decision-grade metadata — MEDIUM, occasional
Hurts: anyone evaluating a dependency. A TypeScript icon *does* exist today ("TypeScript icon, indicating that this package has built-in type declarations" — https://www.npmjs.com/package/is-badge). ESM/CJS and maintenance status do not.

> "Currently we have to go into the package repository and check the `type` field in the package.json. It would be nice if npm added a badge there." — r/node, 2021, https://www.reddit.com/r/node/comments/u8gcij/i_feel_like_there_need_to_be_a_way_in_the/

> "Add TypeScript type information to an npm package's page, and ideally in the search index" — asked Oct 22 2020, answered "We have a work item for this on our roadmap now." Repo archived May 1 2024. https://github.com/npm/feedback/discussions/64


### 13. Ownership by GitHub/Microsoft and perceived stagnation — MEDIUM, sentiment
Hurts: trust and morale more than code.

> "didn't know npm was owned by github.. well, that explains things..." — HN `aniceperson`, Jun 2026, https://news.ycombinator.com/item?id=48467705


Counter-evidence: npm shipped staged publishing, v12 install defaults and malware scanning in 2026 (https://github.com/orgs/community/discussions/208130). The complaint is about *consumer-facing* DX, which has moved far less than the security surface.

---

## What a better registry/CLI should do

1. **Search that ranks by intent, not README text.** Weight keywords + exports + types + recency; never let a "Migration" section rank a package for "database migration". Show why each result ranked.
2. **Exact-name match is always result #1**, with "did you mean" for typos and a Levenshtein warning on near-miss names. Debounced, cancellable, sub-100ms.
3. **Package page decision panel**: ESM/CJS/dual, ships-types vs `@types` vs untyped, last publish, release cadence, open-issue ratio, maintainer count, deprecation, install size, transitive deps, licence. One glance, no scrolling.
4. **Maintenance score with a published formula**, plus "this package is unmaintained, here are 3 maintained alternatives".
5. **Adoption/takeover flow**: maintainer marks a package "seeking maintainer"; registry can transfer after N months of inactivity with a public notice period.
6. **Name policy that is enforced, not just written**: reject empty/placeholder packages at publish, expire them after 90 days, publish a public squatting report.
7. **Real usage stats, not tarball 200s**: separate human installs, CI installs, and mirror/bot traffic; label them on the page.
8. **Lockfile designed for merges**: line-oriented, sorted, one entry per package, semantic merge driver shipped by default. `bun.lock`-style text beats nested JSON.
9. **Content-addressed global store + hardlinks by default** (Bun/pnpm model) so 20 projects share one copy; report per-project disk cost.
10. **Peer deps resolved, not refused**: auto-pick the highest satisfying version, show the conflict graph, and make `--force` print exactly what it broke.
11. **Fast by default**: parallel tarball fetch, no tree walk when the lockfile is complete, and `--explain-slow` naming the slow package.
12. **CLI errors that name the fix**: one-line cause, offending package@version, copy-pasteable command. No `ELIFECYCLE` without the underlying exit code and stderr.
13. **`audit` that is actionable**: group by reachable-in-production, allow per-advisory acknowledgement in a committed file, never print 1,200 findings on install.
14. **Duplicate detection built in**: `bun why <pkg>` showing every version and who pulled it, plus a dedupe that works.
15. **ESM-first with CJS interop that just works** — no `type` field archaeology, no `.mjs`/`.cjs` matrix, no dual-package hazard.
16. **Own the whole surface**: registry, site and CLI from one team, so ranking, page metadata and CLI resolution cannot drift apart.

---

## Gaps

- **npmjs.com could not be loaded directly** (bot challenge on curl), so the package-page layout is unverified first-hand. The TS-icon claim comes from npm's rendered page text via search snippets; the ESM-badge absence is inferred from the 2021 request plus no contradicting evidence.
- **No hard numbers on frequency.** Ranking is judgement from recurrence, not a counted corpus.
- **X/Twitter largely inaccessible** without auth; only indirect quotes via HN and blogs.
- **npm v12 breaking changes** (HN 48467705) were read for ownership sentiment only, not verified against npm docs.
- **Bun-specific pain** was out of scope.
