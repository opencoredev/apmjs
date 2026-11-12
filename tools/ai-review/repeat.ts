// Second pass over the malicious set and the benign first-publish set, to measure how often Flash's
// verdict changes between identical requests (temperature 0 is not deterministic on this endpoint).
// Usage: bun tools/ai-review/repeat.ts
import { loadCases, runCases } from "./run-eval.ts";

await runCases(
  loadCases().filter((c) => c.group.startsWith("malicious") || (c.group.startsWith("benign") && c.mode === "files")),
  "repeat",
);
