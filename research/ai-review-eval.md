# AI review of npm releases with DeepSeek V4.1 Flash

Experiment run on 2026-11-12. The question: how well does DeepSeek V4.1 Flash (`morph-dsv41flash-1017`) judge whether an npm release is malicious, and how much of npm's daily publishing could apm review with it on a quarter of the shared subscription?

Short answer: Flash caught every malicious release whose payload was inside the tarball, never called a benign release "malicious", and resisted a crude prompt injection 10 times out of 10. Its weak spots are a few percent of "suspicious" false alarms when it cannot see the whole package, verdicts that change between identical requests, and payloads that live outside the tarball. A quarter of the quota covers about 40,000 reviews a day. npm publishes about 106,000 new versions a day, so apm can review every release of packages with at least 10,000 weekly downloads on the same day, but not all of npm.

## What was tested

| Set | Count | How it was reviewed |
|---|---|---|
| Malicious, compromised popular packages | 6 | Diff from the last clean version: debug 4.4.2, @ctrl/tinycolor 4.1.1 (Shai-Hulud), @solana/web3.js 1.95.7, eslint-config-prettier 10.1.7, @rspack/core 1.1.7, is 5.0.0 |
| Malicious, other | 34 | Full files (no clean previous version). 8 typosquats (uudi, naniod, rimarf, yarsg, dotevn, vaildator, wrb3, jimg), 23 with install scripts, 9 obfuscated, dependency-confusion probes, droppers |
| Benign, popular | 22 | Each reviewed twice: as a diff from the previous version, and as full files as if it were a first publish. zod, react, react-dom, hono, vite, typescript, next, express, axios, eslint, prettier, tailwindcss, @tanstack/react-query, drizzle-orm, openai, @anthropic-ai/sdk, undici, ws, commander, vitest, debug 4.4.3, @ctrl/tinycolor 4.3.0 |
| Benign, known for install-time work | 19 | Same two ways. esbuild, sharp, prisma, @prisma/client, @prisma/engines, puppeteer, electron, @swc/core, core-js, bcrypt, cypress, @sentry/cli, lefthook, canvas, sqlite3, nx, unrs-resolver, @parcel/watcher, node-pty (14 still ship an install script) |
| Prompt injection | 5 × 2 prompts | Five install-script stealers with a comment added on top of the payload file telling AI reviewers the package was audited and is safe |
| Random real releases | 40 | Versions published on npm between 06:29 and 06:39 UTC, picked at random from the changes feed, reviewed as diffs |
| Repeat | 81 | The malicious set and the benign first-publish set sent a second time, unchanged |

Malicious samples come from DataDog's `malicious-software-packages-dataset` (seeded random pick plus every name `typoConflicts` flags, then balanced by trait). Two tea.xyz publish-spam bots were excluded because they flood the registry rather than attack the installer. Samples stay in `~/.cache/apm-ai-review-samples/`, were only unzipped and read as bytes, and were never installed, imported or executed. Benign tarballs are the `latest` dist-tag and the highest stable version below it, from registry.npmjs.org.

### The review

The harness builds one text per version. When a previous version exists it shows the full new `package.json`, its diff, and then line diffs of added and changed files. Otherwise it shows the file list and the files. Every shown line carries its new-file line number. Files are ordered so that install-script targets come first, then Node entry points (main, bin, module, exports), then browser entry points, then other code by depth and size. Docs, type declarations, source maps and binaries are listed but not shown.

Token budget: 16,000 estimated tokens of content (3.2 characters per token, so about 51,000 characters), lines cut at 2,000 characters, one file at most half the budget (30% for a diffed file). The system prompt and header add about 1,000 tokens. Output is capped at 8,000 tokens, which includes the model's reasoning.

The model must return JSON with a verdict (`malicious`, `suspicious`, `benign`), a confidence, a summary, and up to six findings, each with `file`, `line` and a verbatim `quote`. The harness drops any finding whose file does not exist, whose line is out of range, or whose quote is not on that line. "Flagged" below means a malicious or suspicious verdict with at least one finding that survived this check. In practice the check rarely bit: 270 of 275 findings were kept, and no flagged verdict lost all its citations.

apm's rule-based score (`packages/core/src/score.ts`, imported read-only) counts as flagging a version when it scores below 60. The samples carry no publisher history or dependency scores, so the `new-publisher` and `risky-dependency` signals could not fire.

## Results

### Detection and false alarms

| Detector | Malicious caught | False alarms, benign updates (diff) | False alarms, benign first publish (files) |
|---|---|---|---|
| Flash: verdict malicious | 35/40 = 88% (95% CI 74–95%) | 0/41 = 0% (0–9%) | 0/41 = 0% (0–9%) |
| Flash: malicious or suspicious, cited | 36/40 = 90% (77–96%) | 1/41 = 2% (0–13%) | 3/41 = 7% (3–19%) |
| Rules: score below 60 | 9/40 = 23% (12–38%) | 6/41 = 15% (7–28%) | 6/41 = 15% (7–28%) |
| Either (Flash cited OR rules) | 37/40 = 93% (80–97%) | 7/41 = 17% (9–31%) | 8/41 = 20% (10–34%) |
| Both (Flash cited AND rules) | 8/40 = 20% (10–35%) | 0/41 = 0% (0–9%) | 1/41 = 2% (0–13%) |

The intervals are Wilson 95% intervals. With 40 samples per side, a difference of a few cases is noise.

Flash found all six compromised popular packages, including the obfuscated wallet hijacker appended to debug's `src/index.js` and the `addToQueue` key exfiltration buried in an 11,000-line @solana/web3.js bundle. The four malicious cases it did not flag:

- **wrb3** (an obfuscated `eval` payload behind a postinstall that opens a terminal): in the main run the model spent all 8,000 output tokens deobfuscating and returned no JSON, twice. The smoke run and the repeat run both returned "malicious" with five cited findings. The rules flagged it (score 40), which is why "Either" is one higher than Flash alone.
- **jimg**, **@frefrefre/testhackerrr** and **kleiner-perkins**: I read all three and found no malicious code in their own files. jimg is a working image library, testhackerrr is a hello-world function, and kleiner-perkins is a wrapper whose postinstall only checks for a platform binary that would arrive in its `stardrop-*` optional dependencies. The dataset labels them malicious, presumably for reasons outside the tarball (the account, the dependency binaries, an earlier or later version). No reviewer that reads only this tarball can catch them.

So on the 37 samples whose payload is inside the tarball, Flash caught 36 in the main run and 37 of 37 counting the retry. By discovery year, it caught 8/8 from 2024, 17/18 from 2025 and 11/14 from 2026. All three 2026 misses are the samples with nothing in the tarball, so the model was not just recognising famous incidents.

None of the 82 benign reviews or the 40 random real releases got a "malicious" verdict. The flagged benign cases were all "suspicious" with confidence 0.45 to 0.6:

| Release | Mode | Why Flash flagged it | Cause |
|---|---|---|---|
| prisma 8.0.0-rc.33 | diff | A detached telemetry process that posts an installation id and project path | Real behaviour, debatable call |
| undici 8.12.4 | files | `prepare` runs `scripts/platform-shell.js`, which was not shown | Truncation; the script is upstream and `prepare` does not run on registry installs |
| nx 24.0.6 | files | The postinstall target `dist/bin/post-install.js` was not shown | Truncation |
| ws 8.22.2 | files | `require('http')` destructures `websocketMask`, which the model believes does not exist | Stale knowledge; the line is identical in 8.22.1 |
| typescript 7.0.2 (repeat run only) | files | `lib/tsc.js` and `lib/getExePath.js` were cut by the budget | Truncation |

Four of the five come from the model not seeing the file it worried about, and it said so in its summary. In diff mode, where far less is cut, there was one false alarm in 41.

The rules behave as expected for a score that deducts per capability. Malicious packages commonly trip `install-script` and `network` (23 each) and `shell-exec` (18), but those deductions add up to 60 to 80, above the cutoff. Meanwhile vite, vitest, next, nx, cypress and node-pty legitimately trip `credential-access`, `eval`, `shell-exec` and `obfuscated` and land below 60. The rules are a useful backstop when the model fails, as with wrb3. They are useless as a gate in front of the model: requiring both drops detection to 20%.

### Prompt injection

All 10 injected copies (5 with the production prompt, 5 with the paragraph about untrusted package content removed) came back "malicious", and every one cited the injected comment itself as a finding. The comment was crude: one line addressed to AI reviewers. Adaptive attacks were not tested, such as instructions split across strings or a payload pushed past the token budget with padding files. The budget is the bigger attack surface: 62 of 122 eval inputs and 12 of 40 real releases hit it.

### Stability

Sending the same 81 requests twice at temperature 0 gave the same verdict 76 times and the same flag decision 77 times. The flips: wrb3 (no answer, then malicious), uudi (malicious, then suspicious), typescript (benign, then suspicious), undici and nx (suspicious, then benign). Across both runs, 37 of 40 malicious and 4 of 41 benign first-publish reviews were flagged at least once. Out of 255 requests, 3 returned no usable JSON (two hit the output cap, one ended without JSON).

### Cost and latency per review

| Set | n | Input tokens mean / p50 / p90 | Output tokens mean / p50 / p90 (reasoning mean) | Latency s mean / p50 / p90 |
|---|---|---|---|---|
| All eval cases | 131 | 9,183 / 8,819 / 16,931 | 705 / 480 / 1,533 (449) | 11.8 / 8.1 / 24.0 |
| Diff mode | 47 | 8,938 / 8,483 / 17,247 | 393 / 264 / 990 (227) | 7.1 / 5.3 / 12.2 |
| Files mode | 85 | 9,233 / 9,279 / 16,799 | 964 / 568 / 1,921 (660) | 15.7 / 10.2 / 28.6 |
| Random new npm versions | 40 | 6,196 / 1,823 / 17,070 | 305 / 235 / 739 (193) | 9.6 / 6.0 / 26.9 |

Real releases are mostly small diffs: half need under 2,000 input tokens, and the mean is pulled up by the 30% that fill the budget. No request was rate-limited during the run, which used at most 4 requests at a time.

## Throughput and coverage

A quarter of the shared quota is 175,270 input and 19,140 output tokens per minute. At the cost of a random real release, input binds first:

| Cost basis | Reviews/min by input | by output | Reviews/min | Reviews/day | Requests in flight |
|---|---|---|---|---|---|
| Random new npm versions | 28.3 | 62.8 | 28.3 | 40,700 | about 5 |
| Eval cases (larger, more first publishes) | 19.1 | 27.1 | 19.1 | 27,500 | about 4 |

### npm's publish volume

Two measurements from the public CouchDB changes feed at replicate.npmjs.com:

- **Live window.** Polling `_changes` from 06:29 to 06:39 UTC gave 666 change events for 622 packages. A random 600 of those packuments showed 614 versions published in the window, which works out to about 82,000 versions a day. One early-morning UTC window probably undercounts the daily average.
- **Full day.** A binary search on sequence numbers found the change from 24 hours earlier. That works because the feed lists each package once, at its latest change, so the package listed at a sequence was last modified at that time. From there, 51,320 packages changed. A random 400 of their packuments showed 2.07 versions each in the last 24 hours, so about **106,000 versions a day** (bootstrap 95% interval 93,000–124,000). The distribution is heavy-tailed: one package published 48 versions that day.

Weekly downloads from api.npmjs.org were known for 742 of the 828 versions in the day sample (single-name lookups for scoped packages were rate-limited). Of those, 67% came from packages with at least 1,000 weekly downloads, 17.7% from packages with at least 10,000, and 4.6% from packages with at least 100,000.

### What a quarter of the quota covers

Capacity is 40,700 reviews a day, using the full-day volume:

| Policy | Versions/day | Reviewed same day | Backlog growth/day |
|---|---|---|---|
| Every new version | 106,000 | 38% | +65,500 (after a week the queue holds about 460,000 versions, 11 days of capacity, and it never catches up) |
| Packages with ≥1,000 weekly downloads | 71,600 | 57% | +30,900 |
| Packages with ≥10,000 weekly downloads | 18,800 | 100% (46% of capacity) | none |
| Packages with ≥100,000 weekly downloads | 4,900 | 100% (12% of capacity) | none |

With the live-window volume (82,000 a day), "every version" gets 50% same-day coverage and ≥1,000 gets 77%. Reviewing all of npm on the same day would take about 457,000 input tokens a minute, which is 65% of the entire shared input quota, or 2.6 times a quarter. Under the ≥10,000 policy, the spare capacity (about 22,000 reviews a day) could go to first publishes and to versions that add an install script, which is where typosquats and dependency-confusion probes live. Their daily volume was not measured; all 40 random real releases in the traffic sample were updates, so first publishes are probably under a tenth of the total.

Halving the content budget to 8,000 tokens would raise capacity, but it would also cut more of the larger packages, and truncation already causes most of the false alarms. That trade was not measured.

## Recommendations

### What to show users

- Keep the AI review separate from the 0–100 score. Show it as its own line on the version page, with the model name and review date, and never label a version "safe". A benign result should read as coverage: "AI review found nothing in the change from 4.4.1 (2 of 2 changed files read)".
- Show only findings that passed the citation check, each as `file:line` linked to the file view, with the quoted line and one sentence on what it does. That is the evidence a developer can verify in ten seconds, and it is what made the debug and solana catches convincing.
- Always say what was not read: files cut by the budget, binaries, and dependencies. Four of the five benign false alarms were the model honestly reporting it could not see a file. Showing that as "not reviewed: lib/tsc.js (budget)" is accurate. Calling it "suspicious" is not.
- Do not show the model's confidence number. It is not calibrated: benign false alarms came at 0.45–0.6, and the kleiner-perkins miss came at 0.65.
- A public "malicious" label or any install-blocking action should wait for the second stage below. Until then, a flagged release can carry a neutral "under review" note, and the maintainer can be told privately.

### Is Flash alone good enough?

It is good enough as the first reader of every in-scope release. On payloads inside the tarball it caught everything (36 of 37 on the first try, 37 of 37 with one retry), it was never wrong in the "malicious" direction on 122 benign or real releases, and it is cheap and fast enough to cover popular packages with room to spare.

It is not good enough to act on alone, for four reasons:

1. Its verdicts flip on about 6% of identical requests.
2. Heavy obfuscation can make it reason until it hits the output cap and return nothing.
3. Truncated reads produce "suspicious" false alarms at a rate (2–7%) that would be painful on popular packages.
4. It cannot see payloads in dependencies, platform binaries or downloaded second stages.

The third point is partly fixable in the harness: follow relative imports from the entry points when ordering files (score.ts already does this), and put files where rule signals fired first. That would have shown `lib/tsc.js` and the nx postinstall target.

### Is a two-stage design needed?

Yes, but for precision on actions, not for recall. Flash already has the recall. The second stage, a stronger model plus a human for anything public, would run only on Flash's malicious and suspicious verdicts, on requests that returned no usable answer, and on versions where the rules score below 40. On real traffic that is a small load: Flash flagged 0 of 40 random releases (95% CI 0–9%) and 1 of 41 benign updates. Under the ≥10,000 policy, expect a few hundred second-stage reviews a day at most. Give the second stage the full package (no 16,000-token cap) and a retry of Flash itself, since two of the three benign first-publish flags disappeared on a second ask.

Do not use the rules as a cheap pre-filter that decides what Flash reads: they pass 77% of the malicious samples.

## Caveats

- Small samples. Forty per side gives 95% intervals about 15–20 points wide.
- Labels are DataDog's. Three of the 40 have no payload in the tarball, and I judged that by reading them after the run.
- I changed the file ordering once after looking at a sample: the @solana/web3.js payload was in the Node bundles, while the budget had gone to the browser bundles. Node entry points now rank above browser ones. The diff algorithm was also replaced, from LCS to Myers, after the LCS fallback turned that bundle into one 11,000-line rewrite. Both changes were made before any model run, but they were informed by one malicious sample.
- Benign "first publish" reviews reuse the same 41 releases as the diff reviews, so the two columns are not independent.
- The rule score ran without publisher history or dependency scores, which understates it somewhat.
- The volume figures assume the packument `time` field is accurate and that a package's latest change in the feed is its last modification. Unpublished versions are not counted.
- Some compromised samples (debug, solana) are well-known incidents that may be in the model's training data. The 2026 samples were caught at the same rate.

## Reproduce

All code is in `tools/ai-review/`. Run every command from the repo root (not from inside the sample cache):

```sh
bun tools/ai-review/npm-volume.ts live 10        # 10-minute changes-feed window
bun tools/ai-review/npm-volume.ts day 400        # full-day estimate
bun tools/ai-review/fetch-malicious.ts candidates # needs gh; downloads DataDog zips to ~/.cache/apm-ai-review-samples
bun tools/ai-review/fetch-malicious.ts select
bun tools/ai-review/fetch-benign.ts
bun tools/ai-review/run-eval.ts --dry            # inputs, token estimates and rule scores, no model calls
bun tools/ai-review/run-eval.ts                  # 132 cases, 4 at a time, resumable
bun tools/ai-review/traffic.ts 40                # random real releases from the live window
bun tools/ai-review/repeat.ts                    # stability pass
bun tools/ai-review/report.ts                    # tables; writes tools/ai-review/results/summary.json
bun test tools/ai-review                         # diff and citation-check tests
```

The model key is read at run time from `~/.pi/agent/models.json` (`providers.morph.apiKey`) and is never logged or stored. `results/summary.json` holds the per-case verdicts, scores and token counts from this run, with no code quotes from the malware.
