# Council round 1 (the npm hearing + plan score)

| Seat | Overall | Problem fit | Bun-first | Security | Feasibility | Scope |
| --- | --- | --- | --- | --- | --- | --- |
| Claude Opus 5.5 | 6 | 6 | 7 | 4 | 8 | 6 |
| GPT-6.1 Sol | 6.5 | 7 | 8 | 4 | 7 | 6 |
| Grok 4.7 | empty seat (provider unavailable) | | | | | |
| Kimi K3.1 | 6.5 | 9 | 8 | 4 | 6 | 6 |
| DeepSeek V4.1 Flash | 6 | 7 | 7 | 5 | 8 | 5 |

Accepted (spec changed, relocked):
- Revoke/incident/restore/owner changes need the account password; a bearer token is not enough.
- Revoking a version older than 72h or with dependents: yank now, 410 after 24h or a second owner's confirmation. Restore (revoked -> yanked) with a public log entry.
- Incident: preview (dryRun), 30-day window cap.
- Upstream proxy in v1: on-demand scoring of public packages, cooldown in ~safe, install gate, merged advisories; names that exist upstream cannot be published (dependency confusion).
- Score: risky-dependency + new-dependency signals, evasion patterns (computed eval, remote import, computed require), notChecked list, `recent` is informational (0 points).
- Tests: cold-cache lockfile reinstall after yank; scanner test without --force; pnpm; --json; apm x stays (it is in the plan now).

Rejected, with reason:
- Reject prerelease publishes tagged latest (Kimi): bun publish tags prereleases latest by default, so rejecting breaks the default Bun flow; we move them to `next` and log it.
- Known-native-build allowance (Opus): string-matching "node-gyp rebuild" is trivially gameable; native packages show the install-script signal and still pass the floor of 40 unless they also exfiltrate.
- Signed revocation feed (DeepSeek): needs key management; out of scope for v1, noted for later.
- Typosquat appeal path: kept as a scoped-name suggestion in the error; a formal appeal flow is v2.
