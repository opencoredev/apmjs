Part 1: agent experience

These are representative agent workflows. Frequencies are qualitative estimates, not measured telemetry or commands executed during this review.

1. Authentication interrupts automation. I run `npm publish` in a noninteractive shell; expired credentials or an OTP challenge stop the release. Frequent in publishing workflows.
2. Peer conflicts invite unsafe shortcuts. I run `npm install` after upgrading React; `ERESOLVE` blocks installation, while `--force` can leave incompatible peers. Frequent during framework upgrades.
3. Package execution hides its consequences. I encounter `npx tool@latest` in a skill; approving installation also permits arbitrary executable code with my environment and filesystem access. Recurring whenever unfamiliar tools enter a workflow.
4. Audit output lacks application context. I run `npm audit`; transitive build-tool findings compete with exploitable runtime vulnerabilities. Frequent in established projects.
5. Package-manager detection is ambiguous. I run an install where `packageManager` specifies pnpm but stale npm/Bun lockfiles remain; the wrong manager rewrites dependency state. Occasional, expensive when missed.
6. Packing differs from the working tree. I run `npm publish` after a local build; ignored output or broken `exports` makes the installed package fail despite local tests passing. Occasional per release.
7. Module compatibility fails after installation. I install an ESM-only dependency into a CommonJS tool; execution fails with an import/require compatibility error. Recurring in mixed-generation projects.
8. Revocation cannot recall cached code. I rerun an install with an existing lockfile/cache after a compromise; previously downloaded bytes can survive registry removal. Incident-specific, with high consequences.

Part 2: swarm validation

| Plan problem | Verdict | Reason |
| --- | --- | --- |
| 1. Publishing is a chore | OVERSTATED | Auth and packaging friction are real; npm already has file previews and dry runs, and repeated login is not universal. |
| 2. Cannot pull a bad version | OVERSTATED | Popular-package self-service removal is constrained, but unpublish exists, including exceptions after 72 hours. |
| 3. Account response is manual | CONFIRMED | Correlating malicious releases, invalidating credentials and coordinating removal remains substantial incident work. |
| 4. No trustworthy safety signal | OVERSTATED | Advisories, provenance and existing scanners offer useful evidence; none establishes package safety. |
| 5. Scripts cause every worm | OVERSTATED | No comprehensive evidence supports “every”; runtime injection also matters, and denying install scripts does not stop it. |
| 6. No cooldown by default | CONFIRMED | A default waiting period is useful, but configurable cooldown already exists in Bun/npm, and the reports describe pnpm enabling it by default. |
| 7. Typosquatting/no availability check | OVERSTATED | Typosquatting is real; lacking a dedicated combined API does not mean developers cannot check existing names. |
| 8. Search/pages lack decision facts | OVERSTATED | Search complaints are credible, but maintainers and TypeScript indicators already exist; better consolidation is the opportunity. |

Specific corrections and unsupported claims:

- `01-publishing.md`, #9 and #17: “can't see what shipped” and permanent publication after 72 hours are too broad. I opened npm's [publish documentation](https://docs.npmjs.com/cli/v11/commands/npm-publish/), which documents `npm pack --dry-run`, and its [unpublish policy](https://docs.npmjs.com/policies/unpublish/), which lists later-removal exceptions.
- `02-compromise-revocation.md`, #6: including chalk/debug among incidents requiring postinstall is false. The cited [Wiz report](https://www.wiz.io/blog/widespread-npm-supply-chain-attack-breaking-down-impact-scope-across-debug-chalk), opened here, describes injected code executing in frontend bundles. Selected incident windows also do not establish that malicious releases are “typically” live 2–4 hours. The “well-connected” explanation for faster removal is speculation.
- `03-security-scoring.md`, #1: 80% or 99% false-positive figures do not establish a general rate. Deployment-inapplicable advisories are not necessarily false vulnerability reports.
- `04-theo.md`, #7: “npm still runs them by default” is outdated without a version qualifier. The cited [npm update](https://github.com/orgs/community/discussions/208130), opened here, says v12 requires explicit opt-in. Third-party summaries in this report should remain attributed to those summaries rather than treated as verified verbatim Theo quotations.
- `06-alternatives-and-search-ux.md`, #1: unpublish does not imply mutable version contents. npm explicitly forbids reusing a name/version after deletion. Its Bun cooldown gap is also outdated: [Bun install docs](https://bun.com/docs/pm/cli/install), opened here, document `minimumReleaseAge`.
- `07-registry-protocol.md`, §2.3: scoped packages defaulting to restricted access conflicts with the opened npm v11 publish documentation, which states public for new packages. Pin client versions rather than assuming one historical default.

Part 3: plan score

The registry/scanner split is sensible. The weakest assumptions are ecosystem adoption and treating a static score as an enforceable safety guarantee.

| Category | Score /10 | Assessment |
| --- | --- | --- |
| Overall | 6.5 | Worth prototyping after tightening the guarantees. |
| Problem fit | 7 | Publishing preflight and incident tools help; original CI-auth pain largely remains out of scope. |
| Bun-first design | 8 | Native scanner integration is a real advantage; cooldown alone is already available. |
| Security soundness | 4 | Owner abuse, recovery authority, score evasion and enforcement bypasses remain unspecified. |
| Feasibility now | 7 | A local registry demo is feasible; tests cannot establish full protocol or malware-detection coverage. |
| Scope discipline | 6 | Broad implementation scope, with no convincing path for existing npm dependency graphs. |

Three gaps to close:

1. Define adoption and compatibility. With upstream proxying excluded, replacing the default registry breaks ordinary npm dependency graphs. Start with an apm-owned scope alongside npm, document which dependencies receive protection, and prove a mixed-registry application. Describe the supported protocol subset instead of “full npm protocol.” Add `apm x` to PLAN.md or remove its acceptance requirement. Define pnpm support consistently.
2. Specify enforcement before grading safety. Check complete resolved graphs before execution, including transitives, aliases, direct URLs, cached lockfiles and scanner outages. Separate “unknown” from “safe”; version the rubric and calibrate against benign networking/native packages and evasive malware. Publish the exact tarball scanned locally. Current tests omit these cases; the revocation scanner test uses `--force`, and the yank test never reinstalls its existing lockfile. State npm cache limitations explicitly.
3. Separate publishing authority from destructive recovery. A stolen publish token must not authorize account-wide revocation or irreversible historical takedowns. Require independently authenticated recovery, scoped credentials, an incident preview and an atomic freeze/revoke transaction. Preserve evidence and define recovery/appeal for mistaken or malicious owner actions. Otherwise the incident button becomes an attacker-controlled denial-of-service tool.

PASS: Read the packet, all seven reports, PLAN.md and every acceptance test.

PASS: Checked the linked primary documentation and incident report cited above.

NOT CHECKED: Acceptance tests and runtime behavior, as instructed.
