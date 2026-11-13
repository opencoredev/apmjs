// The Workers runtime contract the registry is built and tested against. One place, so the bundle, the
// Miniflare harness and the deployed Worker can never disagree.
export const COMPATIBILITY_DATE = "2026-07-30";
export const COMPATIBILITY_FLAGS: readonly string[] = ["nodejs_compat"];

/**
 * The registry Worker's CPU limit per invocation, set in packages/infra/alchemy.run.ts (`limits.cpuMs`). The queue
 * consumer runs one analysis per invocation under the whole meter (@apm/core, MAX_ANALYSIS_WORK). Measured on staging,
 * a Worker spends about 4.7 times the CPU this repository's benchmark machine does per unit (vite 8.3.8: 5.2 s against
 * 1.1 s), so a full meter is about 70 s there, and three 0.187.0 (168 million units) was stopped at the default 30 s
 * every time and only ever stored the smaller re-run's incomplete score. Five minutes, the most Cloudflare allows,
 * leaves the full meter four times that. Requests are bounded by their own work and never analyse anything.
 */
export const WORKER_CPU_MS = 300_000;
