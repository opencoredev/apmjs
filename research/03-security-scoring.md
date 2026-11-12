# 03 — Security scoring and audit noise

**Status: PASS**

## Pain points

1. **`npm audit` reports every advisory in the tree, with no reachability or context filter.** Root cause of the rest. **High.** "npm added a default behavior that, in many situations, leads to a 99%+ false positive rate" — https://overreacted.io/npm-audit-broken-by-design/ (2021-07-07). Still true: "npm audit false positive rate: ~80% for a typical project" — https://www.pkgpulse.com/guides/why-npm-audit-is-broken (2026-03-08).

2. **Severity labels are CVSS worst-case, not your deployment.** A build-time ReDoS prints in red as "High". **High.** "CVSS was designed to rate vulnerabilities in the abstract… not… your specific deployment context." — https://www.pkgpulse.com/guides/why-npm-audit-is-broken (2026-03-08).

3. **The noise trains people to ignore the tool, so the one real finding is missed.** **High.** "we have trained an entire generation of developers to either not understand the warnings… or to simply ignore them" — https://overreacted.io/npm-audit-broken-by-design/ (2021-07-07). Dependabot is the same failure: a "noise machine" that "reduce[s] security by causing alert fatigue" — https://devclass.com/security/2026/02/26/github-dependabot-is-a-noise-machine-and-should-be-turned-off-says-go-library-maintainer/4091858 (2026-02-26).

4. **`npm audit fix` is itself unsafe.** **High.** "I ran `npm audit fix --force` today and it **downgraded** the main dependency to a three-year-old version with actual *real* vulnerabilities." — https://overreacted.io/npm-audit-broken-by-design/ (2021-07-07).

5. **Unfixable transitive findings block CI, with no first-class way to accept a risk with a reason.** **High.** "Two advisories… make every SDK 58 project report findings in `npm audit --omit=dev`, and `^13.0.0` cannot reach the fixed release." — https://github.com/expo/expo/issues/52735 (2026-11-01).

6. **CVE scanning is blind to the attack that actually happens: malicious code in a trusted package.** **High.** "The majority of malware in npm is hidden in install scripts." — https://docs.socket.dev/docs/supply-chain-risk (updated ~2026-06).

7. **Provenance is necessary but not sufficient; treating it as a safety signal is dangerous.** **High.** Mini Shai-Hulud compromised 170+ packages with "valid SLSA Build Level 3 provenance attestations… [which] verified where the packages were built, but could not verify that the build environment had been compromised." — https://labs.cloudsecurityalliance.org/research/csa-research-note-mini-shai-hulud-supply-chain-sigstore-2026/ (2026-05-15).

8. **Provenance coverage is too low to be a gate.** **Med.** Of a 484-package real-world tree, "only 21.5% publish build provenance — 78.5% ship with no verifiable link" — https://zennoxa.com/research/npm-provenance-census-2026 (2026-08-25). Hard-failing on it fails 4 in 5 packages.

9. **Download counts are trivially gamed and count CI, not humans.** **High** (as a scoring input). A package with "little to no users" reached "over one million downloads" via a Lambda cron job; npm counts "any successful download of a package (tarball)", with no IP or user-agent weighting — https://dev.to/andyrichardsonn/how-i-exploited-npm-downloads-and-why-you-shouldn-t-trust-them-4bme (2021-03-09).

10. **Health scores are gameable by the maintainer being scored.** **Med.** "As a package maintainer, you can easily increase the quality score and achieve better visibility" — https://itnext.io/increasing-an-npm-packages-search-score-fb557f859300 (2018-07-23). npms.io weights: quality 1.95, popularity 3.3, maintenance 2.05 — https://api-docs.npms.io/.

11. **Scores rot, die, and don't follow ownership changes.** **Med.** Snyk Advisor (popularity/maintenance/community/security, 0–100) "announced a sunset in early 2026… goes offline in January 2026". "The Polyfill.io incident in 2024 affected packages that had good Advisor scores — the score reflected the original maintainer's reputation, not the new owner's behavior." Socket "does not produce a single score the way Advisor did"; Scorecard "requires you to point it at a GitHub repository, not a package name." — https://scanner.blacksight.io/blog/snyk-advisor-alternatives (2026-04-02).

12. **Typosquat detection is historically too false-positive-heavy to ship as a warning.** **Med.** Prior work "trigger[ed] alarms approximately every 200 to 1,000 package installations"; TypoSmart cut false positives 70.4% and removed 3,658 typosquats in a month — https://arxiv.org/html/2502.20528v1 (2025-03).

13. **Developers want abandonment and bus-factor signals, not more CVEs.** **Med.** "something that flags when a dependency is basically abandoned"; "last commit date and bus factor matter more than stars" — https://www.reddit.com/r/webdev/comments/1ruslk4/do_you_actually_evaluate_dependencies_before/ (2026-03).

---

## What a better registry/CLI should do

- **Two numbers, never one.** `Risk` (0–100, higher = safer) and `Maturity` (0–100, adoption/upkeep). Mixing popularity into a security score is the npms/Snyk mistake: gameable, and orthogonal to compromise risk.
- **Score the version, not the package.** A package badge hides the malicious release.
- **Explain every point.** Each signal prints its contribution and evidence (file path, line, attestation subject).
- **Diff the score between versions.** "Risk 92 → 41 because 1.4.2 added a `postinstall` that calls `curl`."
- **Reachability-aware advisories.** Tag findings `runtime-reachable` / `build-time-only` / `dev-only` / `unreachable`; default to runtime-reachable only.
- **First-class risk acceptance.** `bun audit accept GHSA-xxxx --reason "..." --expires 90d`, stored in the repo, shown in score history.
- **Cooldown by default.** Refuse versions published < 24–72h ago unless `--no-cooldown`; defeats worm windows.
- **Never auto-fix.** Suggest, never silently rewrite the lockfile.
- **Maintainer appeal channel.** Counter-claims are shown, not hidden.
- **Publish the rubric and weights** in a versioned doc; version the score (`score-v1`).

---

## Proposed scoring rubric

Design rule: weight what an attacker must *do* and cannot cheaply fake. Everything below is computable from tarball + registry metadata + publish history. Weights sum to 100 for `Risk`.

**Prior art, compactly:** OpenSSF Scorecard scores 20 repo checks 0–10 (Binary-Artifacts, Branch-Protection, CI-Tests, CII-Best-Practices, Code-Review, Contributors, Dangerous-Workflow, Dependency-Update-Tool, Fuzzing, License, Maintained, Packaging, Pinned-Dependencies, SAST, SBOM, Security-Policy, Signed-Releases, Token-Permissions, Vulnerabilities, Webhooks) — https://github.com/ossf/scorecard/blob/main/docs/checks.md. deps.dev adds advisories and attestations per version — https://docs.deps.dev/api/v3/.

**A. Publish identity & integrity — 35**
| Signal | Wt | Why |
|---|---|---|
| Provenance attestation present and verifies against the claimed repo/commit | 12 | Defense against a hijacked pipeline; see pain #7 — a bonus, not a gate |
| Published via trusted publishing / OIDC, not a long-lived token | 8 | Token theft is the documented path in Shai-Hulud and chalk/debug |
| Registry signature present | 4 | Cheap; catches tarball tampering |
| Publisher account has 2FA enforced | 6 | npm forces this by Jan 2027; absence today is a signal |
| ≥2 maintainers, no single-owner bus factor of 1 | 5 | Ownership-transfer attacks (Polyfill.io) start here |

**B. Install-time behavior — 25** (static analysis of the tarball)
| Signal | Wt | Why |
|---|---|---|
| No `preinstall`/`install`/`postinstall` scripts | 10 | "The majority of malware in npm is hidden in install scripts" |
| If scripts exist: no network calls, no shell exec, no `eval`/base64 decode | 8 | Separates `esbuild` (legit native build) from a dropper |
| No prebuilt binaries that don't correspond to source | 4 | Non-reviewable code (Scorecard `Binary-Artifacts`) |
| No obfuscated/minified code without source maps | 3 | Socket: `Obfuscated code` = High |

**C. Runtime behavior surface — 15**
| Signal | Wt | Why |
|---|---|---|
| No network access in non-network packages | 5 | Socket `Network access` = Medium |
| No `child_process`/shell, `eval`, dynamic `require` | 5 | Socket `Shell access`/`Uses eval` |
| No credential-path or env harvesting (`~/.npmrc`, `~/.ssh`, `AWS_*`, `GITHUB_TOKEN`) | 5 | The exfil payload in every 2025–26 npm worm |

**D. Change risk — 15**
| Signal | Wt | Why |
|---|---|---|
| Version older than a 7-day cooldown | 5 | "New releases concentrate the highest supply chain risk" (Socket) |
| Publisher of this version is new to the package | 5 | Socket `Unstable ownership` = High |
| Diff vs previous version not anomalously large | 5 | Catches a rewrite smuggled into a patch bump |

**E. Naming & metadata hygiene — 10**
| Signal | Wt | Why |
|---|---|---|
| Name not within edit distance 1 (incl. transposition/keyboard-adjacent) of a top-10k name | 5 | Median typosquat distance is 1 (arXiv 2502.20528); gate on metadata too, to keep FPs down |
| License present and OSI-approved | 2 | Scorecard `License` |
| `repository` resolves and matches tarball | 2 | Catches manifest confusion |
| Not deprecated | 1 | |

**Hard overrides:** known malware → 0. Runtime-reachable advisory in this version → cap at 40. Missing provenance → no penalty (78.5% of the ecosystem), no bonus.

**`Maturity` (separate, 0–100, never folded into Risk):** log-scaled downloads with CI/bot de-weighting, dependent-package count, package age, release count, TypeScript types shipped, CI/test presence, OpenSSF Scorecard (0–10, ×10). These are the signals developers ask for (pain #13) and the gameable ones (pains #9, #10) — so they belong in a labelled "is this maintained" number, not in "is this safe".

**Why these weights:** 60 of 100 sits on install-time behavior and publish identity, because that is where every documented 2025–26 npm compromise landed. Popularity contributes zero to Risk. Provenance is capped at 12 because it was present on attested malware.

---

## Gaps

- Could not verify whether npm still runs `audit` on `install` in npm 11/12; docs describe flags, not the install hook. (Inference: it does, per Abramov: `npm install` "still uses information from plain `npm audit`".)
- No current false-positive rate for Socket.dev or OpenSSF Scorecard; only vendor claims and one third-party review (safeguard.sh, 2026-02-02).
- No data on how many npm packages enforce 2FA or use trusted publishing — only the Jan 2027 deadline.
- The 21.5% provenance figure is a 484-package sample of popular packages, not the registry; registry-wide coverage is likely far lower (inference).
- No study on whether developers change install decisions when shown a score; the "what they want" evidence is anecdotal (Reddit/HN).
