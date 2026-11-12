# Part 1: problems I hit as an agent

1. **Auth failures hide the actual fix.** `npm publish` in a clean CI job can return `ENEEDAUTH`, `EOTP`, or a misleading 404 when the real issue is token scope or an old npm. This bites on release setup and token rotation.
2. **`npx` is blind code execution.** A skill saying `npx some-tool@latest` asks me to fetch and run mutable code without an integrity pin, permission summary, or useful trust signal. This bites whenever I try an unfamiliar tool.
3. **Peer dependency resolution ends in unsafe guesses.** `npm install` on a React upgrade hits `ERESOLVE`; `--force` or `--legacy-peer-deps` proceeds with a tree that may fail at runtime. This bites weekly during dependency upgrades.
4. **Lockfiles churn across machines.** A routine `npm install` can rewrite thousands of lines after another OS or npm version touches the project, obscuring the intended dependency change. This bites in shared repos and cross-platform CI.
5. **CLI output is poor for automation.** JSON modes still encounter warnings on stderr, nested error text, and different exit behavior across commands. I often have to scrape human output or inspect state after `npm install` or `npm view` fails.
6. **Audit noise hides actionable findings.** A small app reports a wall of dev-only transitive advisories; `npm audit fix --force` can make breaking or regressive changes. This bites often on older repositories.
7. **Publishing has too many independent correctness checks.** `exports`, `types`, `main`, `files`, ESM/CJS output, and prerelease tags can each be locally valid but wrong in the uploaded tarball. This bites nearly every library release.
8. **Install scripts make installs nondeterministic and risky.** `npm ci` can execute package code, download native binaries, and fail behind a proxy before the project itself runs. This bites on native dependencies and unfamiliar repositories.

# Part 2: swarm validation

1. **CONFIRMED.** npm docs and maintainer reports support the token, trusted-publishing, packing, tagging, and entry-file failures.
2. **CONFIRMED.** npm's own unpublish policy documents the 72-hour and dependents restrictions, and deprecation leaves bytes installable.
3. **CONFIRMED.** Token revocation and finding attacker-published versions lack a first-class bulk incident workflow, though the report relies partly on inference.
4. **OVERSTATED.** Audit noise and weak scoring are real, but "no trustworthy signal" dismisses useful Socket, deps.dev, and OpenSSF evidence; this plan's heuristic score is not inherently more trustworthy.
5. **OVERSTATED.** Lifecycle scripts are a major, repeated payload path, but "every 2025-26 worm" is broader than the evidence and Bun/pnpm already provide meaningful controls.
6. **CONFIRMED.** npm's cooldown is opt-in and recent, while pnpm shows why a default release-age policy is useful.
7. **CONFIRMED.** Typosquatting and poor name discovery are real, although a one-edit-distance publishing ban needs an appeal path.
8. **CONFIRMED.** Exact-match failures, weak ranking, and missing decision metadata are supported by multiple independent accounts.

## False or unsupported claims

- `06-alternatives-and-search-ux.md`, "published versions are mutable, so a lockfile is not a proof": false. npm documents registry data as immutable. Unpublish removes availability; it does not mutate bytes, and lockfile integrity still verifies downloaded content.
- `01-publishing.md`, "unpublish is a 72-hour window, so a bad publish is permanent": false as written. I checked npm's policy: versions older than 72 hours can still be unpublished with no dependents, under 300 weekly downloads, and one maintainer. `02-compromise-revocation.md` states this correctly.
- `01-publishing.md`, "you can't see what shipped": overstated. `npm pack --dry-run` and `npm publish --dry-run` expose the file list. The defensible complaint is that a checked preview diff and secret gate are not enforced.
- `03-security-scoring.md`: the rubric awards 12 points for provenance, then its hard overrides say missing provenance earns "no bonus." Those rules cannot both determine the same score.
- `03-security-scoring.md`, "~80% for a typical project": unsupported by the cited article's visible methodology. It should not be presented as a measured current rate.
- `04-theo.md`, "no meaningful feature in years": a quoted opinion, not a validated fact. `05-everyday-complaints.md` itself lists staged publishing, malware scanning, and v12 install defaults as counter-evidence.

# Part 3: plan score

| Category | Score |
| --- | ---: |
| Overall | **6.5/10** |
| Problem fit | **9/10** |
| Bun-first design | **8/10** |
| Security soundness | **4/10** |
| Feasibility now | **6/10** |
| Scope discipline | **6/10** |

The plan attacks the right publishing and incident-response problems, and the Bun scanner is a genuine advantage over a wrapper-only product. The safe registry view also works with stock npm. But the plan calls heuristic filtering "safe" without establishing detection quality, and its incident controls create an availability attack of their own. "Full npm protocol" is much broader than the acceptance specs.

## Three gaps to close

1. **A stolen owner token can mass-revoke every release.** Separate reversible owner yanks from destructive security revocation. Require fresh web reauthentication and out-of-band confirmation for bulk revocation, show the exact affected versions before execution, and provide an audited recovery state. Revoke tokens immediately during incident response, but do not let that same compromised credential irreversibly 410 months of releases.
2. **The score can be bypassed and its policy has unsafe gaps.** Label it a heuristic risk signal with an `unknown` state, not proof of safety. Add adversarial fixtures for encoded payloads, indirect module loading, native binaries, transitive scripts, non-registry dependencies, cached installs, scanner network failure, and revoked direct tarball URLs. Add scoped, audited policy overrides for legitimate scripts, secret false positives, and valid near-names.
3. **The tests do not prove several stated contracts.** Replace the yank tarball-only assertion with a real cold-cache reinstall from an existing lockfile; test revoked installs for both stock clients, npm's 409 retry, both login flows, cache validators, and metadata-only PUTs. Drop "full protocol" or finish those cases. Also reject an explicit prerelease `--tag latest` rather than silently changing it to `next`.