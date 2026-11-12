# Council packet, round 1: the npm hearing

## The request, in the user's words (lightly cleaned from speech-to-text)
"I have this thing called apmjs and this domain. I want you to talk to agents and find all the problems that humans have with npm. One of my big ones is that it's really really annoying to publish something. It's really annoying to revoke a package if it's hacked or something. It would be cool to have a security score and everything. Check Theo's YouTube channel (T3 Chat / T3 Code). In the council have the swarm find them. The council will go ahead and validate. Just talk. It'd be cool if you had the council just as agents. What issues do they have with npm? I want to see what the issues are. Build this entire thing from scratch. Don't focus on the UI that much. Default shadcn, good layout. I like Vercel domains search. I want it to feel modern and remove a bunch of issues. Preferably make it Bun compatible. We can also make it npm compatible but you won't get all the best parts. Maybe have some CLI on top that wraps around Bun or npm, and you just use that. We don't manage the runtime; it does the same commands but adds the security score and everything. I could be 100% wrong."

## Artifacts (paths relative to the repo root)
Research swarm reports (each fact has a source URL):
- research/01-publishing.md
- research/02-compromise-revocation.md
- research/03-security-scoring.md
- research/04-theo.md
- research/05-everyday-complaints.md
- research/06-alternatives-and-search-ux.md
- research/07-registry-protocol.md
Candidate plan:
- research/PLAN.md
Acceptance tests that encode the plan (read for detail; do not run them):
- tests/acceptance/*.test.ts

## Your job (three parts)

### Part 1: speak as an agent
You are an AI coding agent that installs, runs and publishes JavaScript packages every day for users (bun, npm, pnpm, npx/bunx). From your own working experience, list up to 8 problems YOU hit with npm and its ecosystem. For each: one line naming the problem, a concrete failure scenario (what you ran, what went wrong), and how often it bites. Agent-specific problems count (non-interactive prompts, OTP walls, unparseable output, running unknown code via npx from a skill file, etc.).

### Part 2: validate the swarm
For each of the 8 numbered problems under "Problems we target" in PLAN.md, give a verdict: CONFIRMED, OVERSTATED or WRONG, with a one-line reason. Then list any specific claim in the research reports you believe is false or unsupported (name the file and the claim; open the URL if you can). Zero is a valid answer.

### Part 3: score the plan
Score the plan out of 10 overall and for each category:
- Problem fit (does it fix the problems that matter most?)
- Bun-first design (does Bun get real advantages while npm still works?)
- Security soundness (could the features be abused or bypassed? e.g. a malicious owner using revoke, gaming the score)
- Feasibility now (can this be built and proven today on one machine?)
- Scope discipline (is anything here not worth building in v1, or missing that must be?)
Give up to three concrete gaps, each with the change that would close it.

## Output
Write your full answer as Markdown to the output path in your brief, then end with the same content as your final message. Keep it under 1200 words. Do not edit any other file.
