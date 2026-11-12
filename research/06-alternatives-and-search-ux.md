# 06 — Prior art (JSR, vlt/vsr, Bun, pnpm, npm frontends) + Vercel Domains search UX

**Status: PASS**

All pages fetched 2026-11-11 unless dated otherwise.

---

## Pain points

Each item is a problem the prior art targets, plus what it still gets wrong.

1. **Published versions are mutable, so a lockfile is not a proof.** Severity: high. JSR: "JSR is immutable. This means that once you publish a package version, you can't change it." — https://jsr.io/docs/immutability. npm's 72-hour unpublish window is the counter-example (secondary: https://www.pkgpulse.com/guides/jsr-vs-npm-javascript-package-registries-2026, 2026-03-09).

2. **Search ranks by downloads, so quality is invisible until you read the README.** Severity: high. JSR: "The score is used to rank packages in search results, and to help users get a sense of package quality at a glance." — https://jsr.io/docs/scoring. Gap: it is a docs/typing rubric, not a safety signal, and is gameable with a README.

3. **Provenance is all-or-nothing and tied to one CI vendor.** Hurts maintainers on GitLab or a laptop. Severity: med. "To publish provenance for a package, you must publish the package from a GitHub Actions workflow." — https://jsr.io/docs/trust. Bun has no answer: "`bun publish` cannot generate provenance statements yet." — https://bun.com/docs/pm/cli/publish.

4. **Publishing to a "better" registry costs a rewrite.** Hurts the long tail of small packages. Severity: high. "JSR.io checks your code and complains about just about everything… It's too much work with too little gains." — https://www.reddit.com/r/javascript/comments/1fznmzo/why_jsrio_is_bad/ (2024-10-09). JSR enforces ESM-only, no slow types, Windows-safe filenames (https://jsr.io/docs/publishing-packages).

5. **Cross-registry install is a second-class path.** Hurts Bun users. Severity: med. JSR maps everything into one fake scope — "all JSR packages available under the special `@jsr` npm scope" — and Bun is not zero-config: "If you are using npm, an older version of pnpm or Yarn, or Bun, you can use the JSR CLI" (`npx jsr add`). — https://jsr.io/docs/npm-compatibility.

6. **Yank semantics are folklore in most ecosystems.** Severity: med. JSR: yanking means "Semver resolution ignores the version… does not prevent users from downloading that version explicitly… if a user has already downloaded the version, have it in their lock file… they can still use it." — https://jsr.io/docs/packages. Cargo matches: the resolver "will ignore all yanked releases unless they are already in the lockfile" — https://doc.rust-lang.org/cargo/reference/resolver.html. npm has no yank, only deprecate/unpublish.

8. **Malicious versions are found after install, not before.** Severity: high. vlt advertises "163,801 Malicious versions quarantined" — https://vlt.sh/. pnpm's answer is time-based: `minimumReleaseAge` "defaults to `1440` (1 day), meaning newly published packages will not be resolved until they are at least 1 day old" — https://pnpm.io/supply-chain-security.

9. **Trust can silently decrease between releases.** Severity: med. pnpm `trustPolicy: no-downgrade` "will prevent installation of a package if its trust level has decreased compared to previous releases (for example, if it was previously published by a trusted publisher but now only has provenance or no trust evidence)" — https://pnpm.io/supply-chain-security.

10. **Lifecycle scripts run by default.** Severity: high. Bun: "To tell Bun to allow lifecycle scripts for a particular package, add the package to `trustedDependencies`" — https://bun.com/docs/pm/cli/install. pnpm blocks build scripts unless in `allowBuilds`, and `strictDepBuilds` (on by default) fails the install on an unlisted one — https://pnpm.io/supply-chain-security.

11. **The registry website is slow and unshareable.** Hurts discovery and support. Severity: med. npmx: "URL Compatibility – Replace `npmjs.com` with `npmx.dev` in any URL and it just works" — https://github.com/npmx-dev/npmx.dev. Browser only: "Not a registry. We don't host packages." — https://npmx.dev/about.

12. **No way to ask "is this name free, and is it too close to something popular?"** Hurts new publishers and invites typosquatting. Severity: high. Nothing in npm, JSR, or vlt exposes name availability plus typo distance; Socket only catches typosquats at install time ("detect malware, typosquatting, and other suspicious behavior before dependencies are written to disk" — https://socket.dev/blog/socket-integrates-with-bun-1-3-security-scanner-api, 2025-10-10).

---

## What a better registry/CLI should do

**Registry**
- Immutable versions; deletion only in a short window for zero-download, zero-dependent versions (JSR: <24h, <10 downloads, no dependents — https://jsr.io/docs/packages).
- First-class `yank`/`unyank` with JSR/Cargo semantics: out of new resolution, still installable from an existing lockfile, banner on the version page.
- A public score with weights shown on the package page (JSR's "Score" tab), plus a separate, non-gameable safety signal.
- Provenance from any OIDC issuer, not just GitHub Actions; attest the tarball, not only the build.
- Abbreviated packuments by default; quarantine list as a public feed (vlt claims "76% Smaller packuments delivered" — https://vlt.sh/).
- Name-availability API: exact name, per-scope, plus typo distance to the top N packages.

**CLI**
- `install` blocks lifecycle scripts unless allowlisted (`trustedDependencies` / `allowBuilds`), fails closed in CI.
- `minimumReleaseAge` with a per-package exclude list, 24h default for transitive deps; `trustPolicy: no-downgrade` on by default.
- Scanner hook in Bun's shape: `scan({packages})` → advisories with `fatal`/`warn`, fatal cancels the install — https://bun.com/docs/pm/security-scanner-api.
- `audit` reads the lockfile only, never `node_modules`, with `--audit-level`, `--omit`, `--ignore`, `--json` (Bun already does this — https://bun.com/docs/pm/cli/audit).
- Registry + per-scope config in one file (`[install.registry]`, `[install.scopes]` in bunfig — https://bun.com/docs/runtime/bunfig), with env-var interpolation for tokens.
- `publish` refuses an existing version, prints the file list and shasum, supports `--recursive`/`--filter` (https://bun.com/docs/pm/cli/publish).
- `search` answers "is this name free" in one call, with `--json`.

---

## Part B — Vercel Domains search UX (reproducible spec)

Sources: https://vercel.com/changelog/vercel-domains-at-cost-pricing-and-the-fastest-on-the-web (2025-09-25), https://vercel.com/changelog/search-domains-without-authentication (2026-09-28), https://vercel.com/changelog/new-domains-registrar-api-for-domain-search-pricing-purchase-and-management (2025-10-08), plus direct observation of https://vercel.com/domains on 2026-11-11.

**Route and state.** Empty state is `/domains`. Typing moves you to `/domains/search?q=<query>` — the query is in the URL, so every search is shareable and back/forward works. The input is `id="domains-search-input"`, `type="search"`, `autocomplete="off"`, `spellcheck="false"`, placeholder **"Search a domain or describe your idea"**. It lives in the header, so results stream under a stationary input. An `Esc` hint appears beside it while focused.

**Empty state.** Centered `h2` "Begin your search" plus one line: "Enter a domain name, keyword, or prompt to find available domains for your next project."

**Two result sections.**
1. **Top Results** — exactly four rows, always the same TLDs: `.com`, `.dev`, `.app`, `.io`. The "is the obvious thing free" answer, above the fold, no scrolling, no filtering.
2. **All Results** — hundreds of TLDs, preceded by three menu buttons with explicit aria-labels: `TLD filter (not available during AI search)` → "All TLDs"; `Filter` → "Show All" / "Available"; `Sort by` → "Relevance". On narrow viewports these collapse into one `Filters and sort` button.

**Row anatomy.** Each row is a `<button>` (whole row clickable, `aria-label="Domain options"`, `aria-haspopup="menu"`). Left: the name in three spans — matched prefix, remainder, and the TLD in **semibold** with `lang="zxx"` and `translate="no"` so it is never translated or hyphenated. Right: the price, then a 32×32 icon button opening a menu (add to cart / options). Price and status render as fixed-size skeletons (`width: 60px; min-height: 20px`) while loading, so rows never reflow.

**Streaming, not spinners.** Rows appear immediately with skeletons and fill in per row as availability and price arrive. The changelog: "Real-time, streaming results show availability and premium status instantly", built with "structured concurrency, layered caching, Bloom filters, and partitioned batching". No login to search.

**Prompt mode.** The same input takes natural language. `q=fast coffee delivery` returned `fast.coffee`, `quick.cafe`, `express.coffee`, `coffee.delivery`, `get.coffee`, `speedy.coffee`, `caffeine.run`… — brandable candidates across TLDs. The TLD filter is disabled in this mode (per its aria-label), because the model picks the TLD.

**Data contract.** `POST https://api.vercel.com/v1/registrar/domains/search` with `{"domains":["a.com","a.dev"]}`, up to 200 exact names per request, no auth. Per name: `{domain, available, years, price, renewalPrice, premium}`. Observed: `{"domain":"zzq7x4kw9.xyz","available":true,"years":1,"price":1.99,"renewalPrice":13,"premium":false}`. CLI: `vercel domains search acme --limit 5`.

**Mapping to package-name search.** Keep the shape, swap the nouns:
- **Top Results = 4 fixed slots**: exact name unscoped on npm, exact name on JSR, exact name under the user's own scope, and the nearest taken typo-variant. Answers "is it free, and am I about to typosquat" without a second query.
- **All Results** = every scope/registry combination, same three filters: registry (`npm` / `jsr` / `bun` / private), availability (`All` / `Free` / `Taken` / `Deprecated`), sort (`Relevance` / `Downloads` / `Score` / `Typo distance`).
- **Row** = name with the match highlighted and the scope in semibold, a status chip, the price-analog (downloads, bundle size, JSR score), then a 32×32 action button.
- **Prompt mode** = "a fast date library" → candidate names, registry filter disabled for the same reason Vercel disables the TLD filter.

---

## Gaps

- **Vercel's "how we built it" blog post** (promised in the 2025-09-25 changelog) was not found; the concurrency/caching/Bloom-filter detail is only the changelog summary.
- **Keyboard navigation** on vercel.com/domains could not be fully verified: after two searches the page served "Unusual Traffic Detected". `Esc` is confirmed; arrow-key row traversal is **inference** from the row-as-button markup.
- **JSR adoption** (40k+ packages by early 2026) is from a secondary blog, not JSR — approximate.
- **vlt/vsr pricing and provenance support** unverified; vlt.sh is marketing and vsr's README covers deployment, not trust. vsr is FSL-1.1-MIT, not open source.
- **Bun has no `minimumReleaseAge` equivalent** — absent from the bunfig reference as fetched; a missing doc section is not proof the feature is absent.
