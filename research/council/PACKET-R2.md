# Council packet, round 2: score the built product

## The request, in the user's words (lightly cleaned from speech-to-text)
"I have this thing called apmjs and this domain. Find all the problems that humans have with npm. One of my big ones is that it's really annoying to publish something. It's really annoying to revoke a package if it's hacked. It would be cool to have a security score. Build this entire thing from scratch. Don't focus on the UI that much: default shadcn, good layout; I like Vercel domains search. I want it to feel modern and remove a bunch of issues. Preferably Bun compatible; npm compatible too but you won't get all the best parts. Maybe a CLI on top that wraps Bun or npm; we don't manage the runtime; it does the same commands but adds the security score and everything."

## Candidate (paths relative to the repo root)
- Repository: this repo (branch climb/apm)
  - packages/registry/src (server.ts protocol, apm.ts extensions, upstream.ts proxy, db.ts)
  - packages/core/src (score.ts, secrets.ts, names.ts, tarball.ts, entries.ts)
  - packages/cli/src (main.ts, pm.ts, config.ts, api.ts)
  - packages/bun-scanner/src/index.ts
  - apps/web/app, apps/web/components, apps/web/lib
  - tests/acceptance/*.test.ts (92 tests driving real bun, npm and pnpm)
  - research/PLAN.md and research/council/ROUND1.md (what an earlier review asked for and what was accepted or rejected)
- Screenshots of the web UI (desktop 1440px and mobile 390px): shots/*.png
- Live web UI: a private demo deployment

You may run read-only commands. You may run the test suite: `cd <repo> && bun scripts/score.ts` (prints failing count last; takes about 2 minutes). Do not edit files.

## Rubric (score each out of 10, and overall)
- Problem fit: does it fix the npm problems that matter most (publishing friction, pulling a hacked version, a trustworthy safety signal)?
- Bun-first design: real Bun advantages, npm still works.
- Security soundness: can the features be abused or bypassed?
- Correctness and evidence: do the tests prove the claims?
- Usability: CLI output and web UI (the user said UI effort should be low; judge layout and clarity, not polish).

## Output
Scores, then up to three concrete gaps, each with the change that would close it. Zero gaps is valid. Under 800 words. Write it to the output path in your brief and end with the same content as your final message.
