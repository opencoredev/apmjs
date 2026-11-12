# 04 — Theo Browne (t3.gg / @t3dotgg): npm, registries, supply chain

**Status: PASS**

Scope: Theo's YouTube videos and X posts on npm, package registries, supply-chain attacks, JSR, vlt, Bun, pnpm, node_modules, and publishing. Transcripts via `anyapi.youtube.video_transcript` ($0.002/success, 3 paid calls) plus free `treg.web.extract` on rosetta.to, moderncreator.app, finance.biggo.com and x.com. YouTube page extraction alone returns no transcript.

## Videos / posts found

| Date | Title | URL |
|---|---|---|
| ~Nov 2024 | The creator of npm is making something new 👀 (JSR + vlt) | https://www.youtube.com/watch?v=O-wtwVHtUJ8 |
| 2025-12-03 | React got hacked. It's really, really bad. (React2Shell) | https://www.youtube.com/watch?v=UiCEejcV5N4 |
| ~2025-12 | You have no idea how bad this really is. (Shai-Hulud 2.0) | https://www.youtube.com/watch?v=weLhik7ArCY |
| 2026-06-22 | I don't have time to build these things, will you? (Idea 1: better npm) | https://www.youtube.com/watch?v=wEAb0x3wTRc |
| 2026-08-20 | MacOS Is Making Your Mac Slow (pnpm install / node_modules on APFS) | https://www.youtube.com/watch?v=4wVNFaFDIn8 |
| 2026-10-16 | X thread: "npm fucked up our release… Time to fuck up npm 😈" | https://x.com/theo/status/2110937542141059454 |
| 2026-10-16 | X: "Actual garbage package registry holy shit" | https://x.com/theo/status/2110969594416615575 |
| 2026-10-16 | X: "None of those are package registries" (registry ≠ package manager) | https://x.com/theo/status/2110970338511405078 |

## Pain points

1. **The npm registry has shipped no meaningful feature in years, and there is no competitive pressure.** Hurts everyone. Severity: high.
   "I can't honestly remember the last time the npm registry shipped a meaningful new feature and I keep it close eye on that stuff." — https://rosetta.to/u/t3dotgg/the-creator-of-npm-is-making-something-new (~Nov 2024). He adds that competing is "a bit of a suicide run" because npm is bundled into Node and "not many people are paying anything to npm ever."

2. **Publishing a package with correct types/ESM is genuinely hard — hard enough to need a specialist.** Hurts library authors. Severity: high.
   "publishing on npm sucks"; "it is surprisingly difficult… I had to bring on another engineer to make sure we were doing it all right for uploadthing" — same source, ~Nov 2024.

3. **Manifest confusion: the manifest is published separately from the tarball and never validated against it.** Hurts every consumer, and every security tool built on registry metadata. Severity: high.
   "An npm's package manifest is published independently from the tarball manifests are never fully validated against the tarball's contents… any tools or insights using the public registry are susceptible to exploitation" — https://rosetta.to/u/t3dotgg/the-creator-of-npm-is-making-something-new (~Nov 2024). He calls it "a real risk here in terms of novel supply chain attacks."

4. **No revocation. A typo is permanent, and a malicious version cannot be pulled.** Hurts maintainers and incident responders. Severity: high.
   "how bad NPM is about letting you unpublish a version of a package" — https://www.youtube.com/watch?v=weLhik7ArCY (~Dec 2025). Elaborated: a wrong version number on TanStack Query "is now permanent" — https://moderncreator.app/2026-06-22-theo-t3-gg-i-don-t-have-time-to-build-these-things-will-you (2026-06-22).

5. **Name squatting on the canonical namespace.** Hurts OSS projects and their users. Severity: high.
   "The `tanstack` namespace on npm is not owned by Tanner Linsley — a squatter holds it and sold it to a third-party company after Tanner refused to pay." — https://moderncreator.app/2026-06-22-theo-t3-gg-i-don-t-have-time-to-build-these-things-will-you (2026-06-22).

6. **`npx` executes unknown code with zero risk signal — only a version number.** Hurts humans and, newly, agents. Severity: high.
   "Imagine it gave how big this app is. Imagine it gave the author… a score for how likely it thinks it's safe… the permissions that it has when it runs. All I get is this random fucking version number. That's insane." — https://finance.biggo.com/podcast/b111d442a8c473d5 (2026-06-22). Same page: "Agents executing NPX commands from skill files are a new attack surface."

7. **`preinstall`/`postinstall` scripts are the primary worm vector, and npm still runs them by default.** Hurts everyone installing anything. Severity: high.
   "Preinstall scripts are super sketchy, and thankfully more and more package managers are just refusing to run them without authorization." — https://www.youtube.com/watch?v=weLhik7ArCY (~Dec 2025). On PostHog's fix: "moving to PNPM 10, which disables pre-install and post-install scripts. Very good. Once again, use a good package manager, helps a lot of these things."

8. **Shai-Hulud 2.0: 500+ packages / 700+ versions, 834 known infected; npm token → CI takeover → auto-republish.** Hurts maintainers, CI, and downstream users. Severity: high.
   "It would look for NPM tokens… fetch all the packages by that maintainer, and then call update package on each… bump the patch version… and then publish the malicious version." — https://www.youtube.com/watch?v=weLhik7ArCY (~Dec 2025). Payload disguised as `setup_bun.js` to "sneak in this new thing people are excited about."

9. **npm's own auth model was the hole; classic tokens were only killed in Dec 2025.** Hurts publishers. Severity: med.
   "NPM classic token creation is now disabled. Existing classic tokens will be revoked on December 9th, 2025. Migrate to trusted publishing or granular access tokens." — quoted from npmjs.com in https://www.youtube.com/watch?v=weLhik7ArCY (~Dec 2025).

10. **`npm install` and `node_modules` deletion are pathologically slow on macOS/APFS — 5–10x slower than a mid-range Linux box.** Hurts every Mac-based dev and every agent worktree. Severity: high.
    "It took over 35 seconds on my Mac. That same run took under 7 and 12 seconds on my Linux machine." M1 Max: 31s clean / 44s install vs ext4 6s / 4.5s — https://www.youtube.com/watch?v=4wVNFaFDIn8 (2026-08-20). "APFS is garbage to the point where I barely run code agents on my Mac anymore."

11. **npm broke his own release, and he concluded the registry is unfixable from the outside.** Hurts anyone shipping. Severity: high (also a competitive signal).
    "npm fucked up our release. Normally I'd be mad, but honestly I'm kind of excited. I needed a new project. Time to fuck up npm 😈" — https://x.com/theo/status/2110937542141059454 (2026-10-16). Follow-up: "I've tried for almost a decade. The world is moving faster, and they're moving slower. It's one of the biggest bottlenecks in my life. I legitimately think I can build something 10x better in a few weeks." — https://x.com/theo/status/2110937874384511156. And "Actual garbage package registry holy shit" — https://x.com/theo/status/2110969594416615575.

12. **People conflate "registry" with "package manager", which blocks new registries from being evaluated.** Hurts new entrants. Severity: med.
    Asked "Do we really need another alternative to npm, yarn, pnpm, and bun?", he replies: "None of those are package registries" — https://x.com/theo/status/2110970338511405078 (2026-10-16).

13. **Nuance: he does not think npm itself was the weak link in the 2025 hacks.** Severity: med (design guidance).
    "it's actually interesting here that NPM doesn't seem to be the fragile piece. I just assumed it would be. It's GitHub. It's CI." — https://www.youtube.com/watch?v=weLhik7ArCY (~Dec 2025).

14. **JSR's model is what he wants from a registry: publish TS source, registry does docs/dts/transpile, ESM-only, npm-superset.** Severity: opportunity.
    "you just hand them typescript and they figure out the rest which as a dumb typescript dev sounds like a gift" — https://rosetta.to/u/t3dotgg/the-creator-of-npm-is-making-something-new (~Nov 2024). Caveat: JSR's "slow types" rule forces explicit return types, which he dislikes.

15. **vlt launched with a team page and no product; he read that as a bad sign.** Severity: low/med.
    "they're not even talking about things they want to ship… there's no why or what or anything here just the who" — same source (~Nov 2024).

16. **Ecosystem trust erosion: React2Shell (CVSS 10) RSC RCE, Dec 3 2025.** Severity: high but adjacent.
    "It got a 10 for the severity score… one of the worst exploits that we've ever seen in the modern web." — https://www.youtube.com/watch?v=UiCEejcV5N4 (2025-12-03).

## What a better registry/CLI should do

- **Revocable releases with thresholds**: allow retraction for packages under ~100 downloads or under ~5 hours old; keep immutable history beyond that. (His explicit proposal — https://finance.biggo.com/podcast/b111d442a8c473d5)
- **Install-time risk card before execution**: size, last publisher, diff freshness, permission scope (network / fs / obfuscated), and a safety score — for `npx`/`bunx` and for `add`.
- **Paid audit-as-a-service**: ~$0.50/scan, an agent reads every release diff and emits a score, run by a verifiable third party so the result can't be forged.
- **Never run lifecycle scripts by default**; require explicit allowlist per package, and show the script body at prompt time.
- **Manifest and tarball cryptographically bound** — one signed artifact, so manifest confusion is structurally impossible.
- **Namespace protection**: verified org scopes, squatting arbitration, and transfer of canonical names to the real project.
- **Publish from TS source**: registry generates d.ts, API docs, and ESM output; zero-config publish from CI with OIDC/trusted publishing and no long-lived tokens.
- **Private registry overrides public by default**, so internal packages need no ceremony.
- **Filesystem-aware install**: hardlink/copy-on-write store, no per-project `node_modules` duplication, and a `clean` that is fast on APFS.
- **Registry ≠ package manager**: a thin CLI wrapper that works with npm/pnpm/bun lockfiles, so switching registries doesn't require switching package managers.
- **Agent-first surface**: machine-readable risk metadata and a non-interactive `--explain` so an agent can decide before running code.

## Gaps

- No transcript for the Bun-acquisition video (2025-12-03, https://x.com/theo/status/1996096291521396965); his claims about Bun-as-package-manager post-acquisition are unverified.
- "I Finally Changed Package Managers" (pnpm, 2023, https://www.youtube.com/watch?v=ZIKDJBrk56k) and "The Future of Bun" (https://www.youtube.com/watch?v=dSIgEJSi0rY) not transcribed — pre-2024, lower value.
- The 2026-06-22 video's npm section comes from two third-party summaries (moderncreator.app, finance.biggo.com), not the raw transcript; those quotes are the summarizers' transcription.
- No evidence of Theo commenting on JSR's or vlt's status in 2026 — whether either still operates is unverified.
- His own registry project (announced 2026-10-16) has no public name, repo, or spec as of 2026-11-11; "10x better in a few weeks" is a claim, not a shipped artifact.
