// The Workers runtime contract the registry is built and tested against. One place, so the bundle, the
// Miniflare harness and the deployed Worker can never disagree.
export const COMPATIBILITY_DATE = "2026-07-30";
export const COMPATIBILITY_FLAGS: readonly string[] = ["nodejs_compat"];
