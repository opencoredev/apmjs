// The daily token budget as the worker uses it: a lease never takes more reviews than the budget has room for, and
// tokens a model already used count against the budget even when the review then fails.
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ModelAnswer, ReviewJob } from "@apm/ai-review";
import { DailyBudget, RESERVE_PER_REVIEW } from "../src/budget.ts";
import { silentLogger } from "../src/log.ts";
import { ModelUnavailable } from "../src/model.ts";
import { processJob, runDaemon, runOnce, type WorkerDeps } from "../src/worker.ts";

let stateDir: string;

beforeEach(() => {
  stateDir = mkdtempSync(join(tmpdir(), "apm-reviewer-budget-"));
});

afterEach(() => {
  rmSync(stateDir, { recursive: true, force: true });
});

function job(n: number): ReviewJob {
  return {
    id: `job-${n}`,
    leaseId: `lease-${n}`,
    leaseExpiresAt: new Date(0).toISOString(),
    name: "pkg",
    version: `1.0.${n}`,
    digest: `sha1-${"0".repeat(40)}`,
    tarballPath: `pkg/-/pkg-1.0.${n}.tgz`,
    previous: null,
    reasons: ["publish"],
  };
}

const usage = (tokens: number) => ({ promptTokens: tokens, completionTokens: 0, reasoningTokens: 0, latencyMs: 1 });
const benign: ModelAnswer = { kind: "ok", content: JSON.stringify({ verdict: "benign", summary: "ok", findings: [] }), finishReason: "stop", usage: usage(1000) };

function deps(budget: DailyBudget, over: Partial<WorkerDeps> = {}): WorkerDeps & { leased: number[]; released: string[] } {
  const leased: number[] = [];
  const released: string[] = [];
  let next = 0;

  return {
    leased,
    released,
    registry: {
      lease: async (max) => {
        leased.push(max);

        return Array.from({ length: max }, () => job(next++));
      },
      tarball: async () => [],
      result: async () => {},
      release: async (id) => {
        released.push(id);
      },
    },
    model: { model: "test", ask: async () => benign },
    budget,
    log: silentLogger,
    secondStage: null,
    budgetTokens: 4000,
    ...over,
  };
}

describe("leasing within the daily budget", () => {
  test("runOnce leases only as many jobs as the budget has room for", async () => {
    const d = deps(new DailyBudget(stateDir, 2 * RESERVE_PER_REVIEW));

    expect(await runOnce(d, 4)).toBe(2);
    expect(d.leased).toEqual([2]);
  });

  test("the daemon counts jobs in flight against the budget before leasing more", async () => {
    const controller = new AbortController();
    const gate = Promise.withResolvers<void>();

    const d = deps(new DailyBudget(stateDir, RESERVE_PER_REVIEW), {
      model: {
        model: "test",
        ask: async () => {
          await gate.promise;

          return benign;
        },
      },
    });

    const done = runDaemon({ ...d, concurrency: 4, pollMs: 5, signal: controller.signal });

    await Bun.sleep(50);
    controller.abort();
    gate.resolve();
    await done;
    expect(d.leased).toEqual([1]);
  });
});

describe("spending", () => {
  test("tokens of a first attempt count even when the retry finds the model unavailable", async () => {
    const budget = new DailyBudget(stateDir, 10 * RESERVE_PER_REVIEW);
    let asks = 0;

    const d = deps(budget, {
      model: {
        model: "test",
        ask: async () => {
          asks++;

          // an unreadable first answer earns a retry
          if (asks === 1) return { kind: "ok", content: "not json", finishReason: "stop", usage: usage(12_345) };
          throw new ModelUnavailable("the model could not be reached");
        },
      },
    });

    expect(await processJob(d, job(0))).toBe("released");
    expect(asks).toBe(2);
    expect(budget.usedToday()).toBe(12_345);
  });

  test("a budget that cannot be written still gives the job back", async () => {
    const budget = new DailyBudget(stateDir, 10 * RESERVE_PER_REVIEW);

    budget.spend = () => {
      throw new Error("ENOSPC: no space left on device");
    };

    let asks = 0;

    const d = deps(budget, {
      model: {
        model: "test",
        ask: async () => {
          asks++;

          if (asks === 1) return { kind: "ok", content: "not json", finishReason: "stop", usage: usage(100) };
          throw new ModelUnavailable("the model could not be reached");
        },
      },
    });

    expect(await processJob(d, job(0))).toBe("released");
    expect(d.released).toEqual(["job-0"]);
  });

  test("a job already charged and only posting its result holds no reserve", async () => {
    const controller = new AbortController();
    const posting = Promise.withResolvers<void>();
    let next = 0;
    let charged = false;

    const d = deps(new DailyBudget(stateDir, 2 * RESERVE_PER_REVIEW), {
      registry: {
        lease: async (max) => {
          d.leased.push(max);

          // the second job only appears once the first has been charged and is posting
          return next === 0 || (next === 1 && charged) ? [job(next++)] : [];
        },
        tarball: async () => [],
        result: () => {
          charged = true;

          return posting.promise;
        },
        release: async () => {},
      },
    });

    const done = runDaemon({ ...d, concurrency: 2, pollMs: 5, signal: controller.signal });

    await Bun.sleep(50);
    controller.abort();
    posting.resolve();
    await done;
    // the first job spent 1000 tokens and is waiting on the registry: one full reserve is still free
    expect(next).toBe(2);
  });
});
