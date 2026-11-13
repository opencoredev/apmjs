// PENDING REMOVAL, once the owner approves deleting the staging resource (packages/infra/alchemy.run.ts, AnalysisTail).
// An earlier version of this branch attached a tail Worker to the registry to record why the platform ended a queue
// run. The queue consumer now runs one analysis at a time (maxConcurrency 1), and recovery needs no stop reason, so
// nothing reads what it recorded. It stays deployed, unattached and without bindings, and does nothing.
export default {
  tail: (): void => undefined,
};
