// How long the website gives one GET /-/apm/v1/resolve, and how long it asks the registry to wait for queued analyses
// inside that. On staging, explain for vite asked with no wait of its own: the registry walked the tree, waited its
// 20 s for the queue, walked again, and the website's 25 s timeout fired first, so explain said "the registry did not
// answer" after 24 s. resolve-budget.test.ts fails if these drift apart from the registry's own wait.

/** The website's deadline for one resolve. */
export const RESOLVE_TIMEOUT_MS = 25_000;

/**
 * What explain asks the registry to wait for analyses still queued (the `wait` parameter). Short, so an agent hears
 * back in seconds; what is still queued then comes back as pending, which explain reports as "still being analysed".
 */
export const EXPLAIN_RESOLVE_WAIT_MS = 3_000;

/**
 * What the registry's two walks of a large tree may take besides the wait: vite's took about 3 s each on staging, and
 * the allowance keeps several times that.
 */
export const RESOLVE_WALK_ALLOWANCE_MS = 12_000;
