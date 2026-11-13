// Loaded before every test file of a scored run (scripts/score.ts): bun:test's `.only` on test, it and describe, by
// whatever name a file reaches them, throws instead of focusing the run, so the file errors and the score is at least
// 1 (review of efef668, finding 4). The gate's inventory refuses `.only` from the source as well.
import * as bun from "bun:test";

const refuse = (): never => {
  throw new Error("apm score: .only runs part of the suite, which the score refuses");
};

for (const fn of [bun.test, bun.it, bun.describe]) Object.defineProperty(fn, "only", { get: refuse, configurable: true });
