Shared rules for every research worker:
- Today is 2026-11-11. Prefer sources from 2024-2026; note dates.
- Web: use the shell. Search: treg call treg.web.search --data '{"q":"..."}' --header 'X-Treg-Route-Prefer: tinyfish'
  Read a page: treg call treg.web.extract --data '{"url":"..."}' --header 'X-Treg-Route-Prefer: tinyfish'
  Pipe large outputs through head -c or jq to keep context small. These calls are free. Do not use paid treg endpoints.
- Every fact needs a source URL. No URL, leave it out. Mark anything you inferred as "inference".
- Write your report as Markdown to the exact output path you are given. Structure:
  1. Status line: PASS, ISSUES, or BLOCKED.
  2. "Pain points": numbered list. Each item: one-line problem, who it hurts, severity (high/med/low), evidence (quote under 30 words + URL + date).
  3. "What a better registry/CLI should do": concrete, buildable features that fix those pains, one line each.
  4. "Gaps": what you could not verify.
  Keep it under 1500 words.
- Do not write anything outside your output path. Do not post, sign up, or send anything anywhere.
