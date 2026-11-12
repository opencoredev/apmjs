# Council seat: Opus 5.5, round 1

## Part 1: problems I hit as an agent

1. **`npx`/`bunx` runs unpinned code from a skill file.** `npx -y some-mcp-server` resolves `latest` right then, and all I see is a version string: no score, no publisher, no age. Daily.
2. **Interactive prompts hang me.** `npx create-*` asks questions, `npm login` opens a browser, `npm publish` waits for an OTP. I hit the timeout, then guess at `--yes` or `CI=1`. Weekly.
3. **Names I guess can be squatted.** `bun add react-markdown-parser` from memory sometimes installs a stranger's package (slopsquatting). Nothing warns me. Weekly.
4. **Blocked install scripts fail later.** Bun skips `postinstall` outside `trustedDependencies`, so `sharp`, `esbuild` or `prisma` binaries are missing and the error appears at runtime. Weekly.
5. **`ERESOLVE` pushes me to `--legacy-peer-deps`/`--force`.** The error doesn't say which upgrade fixes it. Weekly in React and Angular repos.
6. **Output I can't parse.** Warnings in stdout, spinner escape codes, `npm audit` exiting non-zero on moderate findings, `--json` shapes that change between versions. Daily.
7. **Wrong package manager.** I run `npm install` in a Bun repo and leave `package-lock.json` next to `bun.lock`. Weekly.
8. **Publishing is a wall.** Expiring tokens, OTP, misleading `E404`/`ENEEDAUTH`, and no preview of what ships unless I remember `npm pack --dry-run`. Monthly, but I fail every time.

## Part 2: validating the swarm

| # | Verdict | Reason |
|---|---|---|
| 1 Publishing chore | CONFIRMED | Well sourced (01). The worst parts (2FA twice, token expiry, OIDC per package) are outside v1, though. The plan fixes the lower-frequency pains: secret leaks, prerelease taking `latest`, missing entry files. |
| 2 Can't pull a bad version | CONFIRMED | The npm unpublish policy text checks out (I fetched it: 72h, under 300 downloads, single owner, no dependents). The 2-4h windows are vendor-sourced. |
| 3 Hacked-account response is manual | CONFIRMED | The pain is real, but the evidence is mostly inference from policy docs. No maintainer quote describes the response steps. |
| 4 No trustworthy safety signal | CONFIRMED | Strong sourcing in 03. |
| 5 Install scripts in "every" worm | OVERSTATED | chalk/debug (Sept 2025) injected a crypto-clipper into runtime code, not an install script. npm v12, pnpm and Bun now block dependency scripts by default. The open gaps are runtime payloads and `npx` bins. |
| 6 No cooldown by default | OVERSTATED | pnpm defaults to 1 day, and npm has had `min-release-age` since 11.10. Bun has `install.minimumReleaseAge` (default off; verified in the bunfig docs). The real gap is "off by default" in npm and Bun. |
| 7 Typosquatting / no name check | CONFIRMED (typosquat), OVERSTATED (name check) | Report 01 admits the name-availability pain is inference. |
| 8 Bad search, thin package pages | CONFIRMED | npm does show a TS icon. ESM/CJS and install-script facts are missing. |

**False or unsupported claims**

- **02 #6:** "Every major incident used install-time script execution: nx, chalk/debug…" is false for chalk/debug. That payload was browser-side wallet hijacking inside the shipped code. The claim also feeds PLAN problem 5.
- **06 Gaps:** "Bun has no `minimumReleaseAge` equivalent" is false. The bunfig reference documents `install.minimumReleaseAge` and `minimumReleaseAgeExcludes`; I fetched it today. This also weakens PLAN's "Bun gets the most (… release-age)": Bun already has release-age natively.
- **03 rubric:** "npm forces [2FA] by Jan 2027" is unsupported. Report 01's gaps say that enforcement date could not be verified.
- **04 #8 vs 02 #8:** the Shai-Hulud 2.0 counts disagree (834 vs 796 packages).
- **04:** Theo's revocation-threshold and `npx` risk-card quotes come from third-party summaries, not transcripts. Treat them as paraphrase.

## Part 3: scoring the plan

| Category | Score | Why |
|---|---|---|
| Problem fit | 6 | It fixes publisher-side pains well. But the score, cooldown, `~safe` and scanner only cover packages published to apm, and on day one that is none of what anyone installs. Leo asked for the same commands plus a security score, which implies scoring npm packages. The `npx`/agent risk card (Theo's #6, my #1) is missing, and `apm x` would just pass through to `bunx` unscored. |
| Bun-first design | 7 | The scanner hook is a real Bun-only advantage, and npm still works through `~safe` and audit. Release-age is not an apm advantage, since Bun already has it. Untested: whether Bun's scanner re-scans lockfile packages on `bun install`, which the revoke-from-lockfile test depends on. |
| Security soundness | 4 | Detailed in the three items below this table. |
| Feasibility now | 8 | Everything runs in-process. The tests drive real `bun` and `npm` and are concrete. Risks: web-login polling, Bun scanner semantics, `npm audit` against a custom bulk endpoint. |
| Scope discipline | 6 | Web UI and name API are cheap. Missing: upstream coverage, `apm x`, revoke safeguards, `--json` everywhere. Hard-refusing names one edit from a popular name should be a warning: `preact` is one insertion from `react`. |
| **Overall** | **6** | A good registry skeleton. As written, revoke is a weapon and the score covers an empty registry. |

The three security problems:

1. **Revoke and incident can be abused.** A stolen token can revoke every version of a popular package, and each 410 breaks every downstream lockfile install: left-pad as an API call. `incident` with `since=1970` wipes an account's history.
2. **The score is easy to evade.** Static patterns lose to `globalThis['ev'+'al']` or a runtime second-stage fetch. A clean package adding a malicious dependency scores high (the axios pattern). The public score API lets attackers test evasions.
3. **A floor of 40 may drop native packages.** If `esbuild` or `sharp` (scripts, binaries, network) fall under it, users abandon `~safe`.

## Top three gaps and the change that closes each

1. **Revoke abuse.** Split token scopes: a publish token cannot yank, revoke or run incident. Revoke and incident require password + 2FA re-auth, not a bearer token. Revoking a version older than 72h or with dependents takes effect as a yank immediately and becomes a 410 only after a second owner confirms or a 24h public pending period passes. Cap incident `since` at 30 days. Add acceptance tests: a publish-scoped token gets 403 on revoke, and a 120-day-old version goes to pending.
2. **No upstream, so no coverage.** Move a read-only proxy of registry.npmjs.org into v1: fetch on demand, score on first fetch, cache, and apply `~safe`, scanner, cooldown and audit. Local names shadow upstream only in apm-owned scopes, to avoid dependency confusion. Provable on one machine with a second in-process registry as the fake upstream.
3. **Score robustness and an agent-facing surface.** Add a `new-dependency` signal, where a dependency added in this version passes its own lowest score up. Add a `bin` entry exec signal and a transitive minimum score, and seed the typosquat list from npm's top-N names. Add a known-native-build allowance so `esbuild` and `sharp` clear the floor with an explained signal. Ship `apm x <pkg>` (the npx/bunx replacement) with the score card. Give every command `--json`, and make non-TTY runs never prompt: they fail with a reason. Add a test where a clean package adds a dropper dependency and gets flagged.
