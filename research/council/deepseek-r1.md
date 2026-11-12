# Council R1 — DeepSeek seat

## Part 1: as an agent, what actually bites me

1. **OTP walls in non-interactive shells.** `npm publish` in a sandbox returns `EOTP` and waits on a TTY prompt that does not exist; the process hangs until timeout. Every publish from an agent session. **Constant.**
2. **`npx`/`bunx` runs unknown code with zero pre-flight signal.** A README says `npx create-thing`; I run it and it executes a postinstall with my `~/.npmrc`, `GITHUB_TOKEN` and SSH agent in scope. I cannot answer "what will this touch" before it runs. **Constant.**
3. **Unparseable output.** `npm ls --json` exits non-zero and prints `ELSPROBLEMS` warnings to stdout, so `JSON.parse` throws; `npm install` buries the cause under 40 `npm ERR!` lines. **Constant.**
4. **Install mutates files I did not ask it to touch.** `npm install` rewrites `package.json` ranges and the lockfile, so my diff contains unrelated churn and the user's review is polluted. **Frequent.**
5. **No machine-readable safety answer.** Asked "is this dependency ok?", my only options are reading the tarball or trusting download counts. `npm audit` returns 30 findings with no reachability, so I summarize noise. **Frequent.**
6. **Publish is four unverified steps.** Bump, tag, changelog, publish — and `npm pack --dry-run` shows files but never checks for a leaked `.env` or a `main` that will not ship. I have shipped a broken `types` path. **Frequent.**
7. **Token discovery is guesswork.** `.npmrc`, `NPM_TOKEN`, `bunfig.toml` — and `npm whoami` 401s without saying which registry it asked. **Sometimes.**
8. **No safe place to test a publish.** A real registry rejects the version forever; there is no staging target, so publish bugs are found in production. **Sometimes.**

## Part 2: validating the swarm

| # | Problem | Verdict | Reason |
|---|---|---|---|
| 1 | Publishing is a chore | **CONFIRMED** | Double-2FA (Oct 2026), 7-day token expiry, per-package trusted publishing, `.npmignore` leaks, mutable `latest` all hold. |
| 2 | Cannot pull a bad version | **CONFIRMED** | 72h + no-dependents rule is documented; deprecate is advisory. Nuance: npm *does* remove malware in hours via support — the gap is self-serve, not absolute. |
| 3 | Hacked-account response is manual | **CONFIRMED** | No bulk token rotation, no bulk trusted-publishing setup, no "what did this token publish" query. |
| 4 | No trustworthy safety signal | **CONFIRMED** | Strongest item in the packet. Per-package not per-version, popularity folded in, no evidence shown. |
| 5 | Install scripts are the attack vector | **OVERSTATED** | True as history, false as a 2026 gap: npm v12 (July 2026) requires explicit opt-in, pnpm 10 blocks, Bun needs `trustedDependencies`. The registry still gives no *signal*, but the blocking is solved. |
| 6 | No cooldown by default | **OVERSTATED** | pnpm defaults to 1440; npm shipped `min-release-age` in 11.10.0. Real gap is only "not default in npm/bun, not registry-enforced." |
| 7 | Typosquatting, no name check | **CONFIRMED** | No availability API; disputes policy explicitly refuses squatting claims. |
| 8 | Search ranks badly, pages lack facts | **CONFIRMED** | Algolia-backed, exact name not reliably first, no ESM/CJS badge. |

**Claims I believe are false or unsupported**

- `04-theo.md` #5: "the `tanstack` namespace on npm is not owned by Tanner Linsley — a squatter holds it and sold it." TanStack publishes `@tanstack/*` and plainly controls the scope. The report itself admits this comes from a third-party summarizer, not a transcript. **Likely false; drop it.**
- `03-security-scoring.md` #11: "Snyk Advisor announced a sunset in early 2026… goes offline in January 2026." Self-contradictory dates, single low-quality source.
- `03` #1/#2: the "~80% false positive rate" and the CVSS quote both trace to `pkgpulse.com`, an SEO content site with no methodology. The Abramov 99% claim is fine; the 80% is not.
- `03` #8: "only 21.5% publish build provenance" from `zennoxa.com`, a 484-package sample. Directionally plausible, numerically unsupported.
- `03` rubric: "Publisher account has 2FA enforced — npm forces this by Jan 2027." The roadmap says *bypass-2FA granular tokens* end in Jan 2027, not account-level 2FA. Misread.
- `04` #1: "no meaningful feature in years" is a Nov 2024 quote used for a 2026 claim; npm shipped staged publishing, v12 defaults and malware scanning in 2026. Stale.
- `06` #12: "nothing in npm, JSR or vlt exposes name availability." `npm view <name>` 404 is the de facto check and JSR checks at publish. Overstated.

## Part 3: score

**Overall: 6/10**

| Category | Score | Note |
|---|---|---|
| Problem fit | 7 | Nails the publisher/security half. Deliberately skips the highest-frequency consumer pains (bloat, ERESOLVE, lockfile churn) — defensible, but it means "remove a bunch of issues" is half-true. |
| Bun-first design | 7 | The scanner hook is a genuine Bun-only capability and Bun's missing `min-release-age` makes the CLI cooldown real value. But the headline features are PM-agnostic; `trustedDependencies` and `bun.lock` go unused. |
| Security soundness | 5 | Weakest axis. See gaps. |
| Feasibility now | 8 | In-process registry + real `bun`/`npm` subprocesses is the right proof, and the tests already encode it. Risks: path-prefixed registry URL with real clients, and the scanner's chicken-and-egg (you must install the scanner before anything is scanned). |
| Scope discipline | 5 | Full protocol + 3 states + event log + ~20-signal scorer + guards + name API + `~safe` + resolve API + scanner + 12 CLI commands + site is a quarter, not a v1. |

**Gaps**

1. **Revoke and the incident button have no safety rails.** A stolen session token can revoke every version an account ever published in one unconfirmed call, permanently (version numbers can never be reused), with no undo and no appeal. A false revoke is unrecoverable and takes down every dependent. *Change:* add `revoked_pending` with a 15-minute undo, require a typed package name to confirm, rate-limit incident to one per account per hour, allow `revoked → yanked` with a public log entry, and sign the revocation feed so clients can tell a real revocation from a compromised registry.

2. **`~safe` contradicts the plan's own yank semantics and may break CI.** Yanked versions keep serving tarballs "for lockfiles," but `~safe` drops every version under 24h or under 40 — so a lockfile pinned to one of those cannot resolve through the safe view. *Change:* `~safe` filters only the packument's version list and dist-tags; tarballs are always served except for `revoked` (410). Add an acceptance test: `npm ci` and `bun install --frozen-lockfile` against `~safe` with a lockfile pinned to a 1-hour-old version.

3. **The score manufactures false confidence and is gameable.** It is computed from the tarball, so a dropper that base64-decodes a payload from a data file, or `import()`s a remote URL at runtime, scores A. Time-based points ("older than 7 days", "not a new publisher") are bought by simply waiting. And a floor of 40 means a malicious package at 45 installs silently. *Change:* label it "publish hygiene — what we could check," print an explicit "not checked: runtime behavior, dependency code" line, make the per-version diff the primary artifact rather than the number, drop time-based points from the score (they belong to the cooldown), and never let the floor auto-approve — always show the card. Also give the typosquat publish refusal an appeal path, or distance-1 refusal becomes incumbent land-grab.
