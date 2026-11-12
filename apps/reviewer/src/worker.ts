// Reviews leased jobs: download the version and its previous one, build the input, ask the model
// (once or twice), check citations, decide, and post the result. Infrastructure failures give the job
// back to the queue; only the model's own answers become results.
import {
  buildReviewInput,
  packageFilesOf,
  runReview,
  type Decision,
  type PackageFiles,
  type ReviewInput,
  type ReviewJob,
  type ReviewResult,
  type ReviewRun,
} from "@apm/ai-review";
import type { DailyBudget } from "./budget.ts";
import type { Logger } from "./log.ts";
import { ModelUnavailable, type ModelClient } from "./model.ts";
import { RegistryError, type RegistryClient } from "./registry.ts";
import type { SecondStage } from "./second-stage.ts";

export type WorkerDeps = {
  registry: RegistryClient;
  model: ModelClient;
  budget: DailyBudget;
  log: Logger;
  secondStage: SecondStage | null;
  budgetTokens: number;
  now?: () => number;
};

/** The registry's result body for one finished run. */
export function resultOf(input: { decision: Decision; run: ReviewRun; review: ReviewInput; model: string; at: number; secondOpinion: ReviewResult["secondOpinion"] }): ReviewResult {
  const base = {
    model: input.model,
    reviewedAt: new Date(input.at).toISOString(),
    summary: input.decision.summary.slice(0, 2000),
    coverage: input.review.coverage,
    read: input.review.read.slice(0, 5000),
    notRead: input.review.notRead.slice(0, 2000),
    attempts: input.run.attempts.map((a) => ({
      result: a.result,
      kept: a.kept,
      dropped: a.dropped,
      promptTokens: a.usage.promptTokens,
      completionTokens: a.usage.completionTokens,
      latencyMs: Math.round(a.usage.latencyMs),
    })),
    secondOpinion: input.secondOpinion,
  };

  const d = input.decision;

  switch (d.outcome) {
    case "benign":
      return { ...base, outcome: "benign" };
    case "flagged":
      return { ...base, outcome: "flagged", verdict: d.verdict, findings: d.findings };
    case "no-answer":
      return { ...base, outcome: "no-answer", reason: d.reason, findings: d.findings };
    default: {
      const _exhaustive: never = d;

      return _exhaustive;
    }
  }
}

async function loadPrevious(deps: WorkerDeps, job: ReviewJob): Promise<{ version: string; pkg: PackageFiles } | null> {
  if (!job.previous) return null;

  try {
    return { version: job.previous.version, pkg: packageFilesOf(await deps.registry.tarball(job.previous)) };
  } catch (cause) {
    // without the previous version the review reads the files instead of the diff
    deps.log("warn", "job.previous_unavailable", { job: job.id, name: job.name, version: job.version, previous: job.previous.version, why: cause instanceof Error ? cause.message : String(cause) });

    return null;
  }
}

export type JobOutcome = "posted" | "released" | "failed";

export async function processJob(deps: WorkerDeps, job: ReviewJob): Promise<JobOutcome> {
  const started = performance.now();
  const ids = { job: job.id, name: job.name, version: job.version };

  deps.log("info", "job.start", { ...ids, reasons: job.reasons.join(","), previous: job.previous?.version ?? null });

  try {
    const pkg = packageFilesOf(await deps.registry.tarball(job));
    const previous = await loadPrevious(deps, job);
    const review = buildReviewInput({ name: job.name, version: job.version, pkg, previous, budgetTokens: deps.budgetTokens });
    const run = await runReview({ review, pkg, ask: deps.model.ask });
    const tokens = run.attempts.reduce((n, a) => n + a.usage.promptTokens + a.usage.completionTokens, 0);

    deps.budget.spend(tokens);
    let secondOpinion: ReviewResult["secondOpinion"] = null;

    if (deps.secondStage && run.decision.outcome !== "benign") {
      const verdict = run.decision.outcome === "flagged" ? run.decision.verdict : null;

      secondOpinion = await deps.secondStage.review({ job, pkg, previous: previous?.pkg ?? null, firstStage: { verdict, findings: run.decision.findings } });
    }

    const result = resultOf({ decision: run.decision, run, review, model: deps.model.model, at: (deps.now ?? Date.now)(), secondOpinion });

    await deps.registry.result(job.id, { leaseId: job.leaseId, result });
    deps.log("info", "job.done", {
      ...ids,
      outcome: run.decision.outcome,
      mode: review.coverage.mode,
      filesInScope: review.coverage.filesInScope,
      filesRead: review.coverage.filesRead,
      notRead: review.notRead.filter((n) => n.kind === "file").length,
      attempts: run.attempts.length,
      findings: run.decision.outcome === "benign" ? 0 : run.decision.findings.length,
      tokens,
      ms: Math.round(performance.now() - started),
    });

    return "posted";
  } catch (cause) {
    const retryable = cause instanceof ModelUnavailable || (cause instanceof RegistryError && cause.retryable);
    const why = cause instanceof Error ? cause.message : String(cause);

    deps.log(retryable ? "warn" : "error", "job.give_back", { ...ids, retryable, why: why.slice(0, 300) });

    try {
      await deps.registry.release(job.id, { leaseId: job.leaseId, error: why.slice(0, 500), retryable });

      return "released";
    } catch (releaseCause) {
      // the lease expires on its own and the job returns to the queue
      deps.log("error", "job.release_failed", { ...ids, why: releaseCause instanceof Error ? releaseCause.message.slice(0, 300) : "unknown" });

      return "failed";
    }
  }
}

/** Leases as many jobs as there are free slots and reviews them. Returns how many jobs it took. */
export async function runOnce(deps: WorkerDeps, slots: number): Promise<number> {
  if (!deps.budget.canStart()) return 0;
  const jobs = await deps.registry.lease(slots);

  await Promise.all(jobs.map((j) => processJob(deps, j)));

  return jobs.length;
}

/** The daemon loop: keeps up to `concurrency` jobs in flight until `signal` aborts, then drains. */
export async function runDaemon(deps: WorkerDeps & { concurrency: number; pollMs: number; signal: AbortSignal }): Promise<void> {
  const inflight = new Set<Promise<JobOutcome>>();
  let backoff = 0;
  let budgetNoted = false;

  const pause = (ms: number): Promise<void> =>
    new Promise((resolve) => {
      const t = setTimeout(resolve, ms);

      deps.signal.addEventListener("abort", () => {
        clearTimeout(t);
        resolve();
      });
    });

  while (!deps.signal.aborted) {
    if (!deps.budget.canStart()) {
      if (!budgetNoted) deps.log("warn", "budget.exhausted", { usedToday: deps.budget.usedToday(), limit: deps.budget.limit, resumesInMs: deps.budget.msUntilReset() });
      budgetNoted = true;
      await pause(Math.min(deps.budget.msUntilReset() + 1000, 10 * 60_000));
      continue;
    }

    budgetNoted = false;
    const free = deps.concurrency - inflight.size;

    if (free <= 0) {
      await Promise.race(inflight);
      continue;
    }

    let jobs: ReviewJob[] = [];

    try {
      jobs = await deps.registry.lease(free);
      backoff = 0;
    } catch (cause) {
      backoff = Math.min(backoff === 0 ? 2000 : backoff * 2, 5 * 60_000);
      deps.log("warn", "lease.failed", { why: cause instanceof Error ? cause.message.slice(0, 200) : "unknown", retryInMs: backoff });
      await pause(backoff);
      continue;
    }

    for (const job of jobs) {
      const p = processJob(deps, job).finally(() => inflight.delete(p));

      inflight.add(p);
    }

    if (jobs.length === 0) {
      if (inflight.size === 0) await pause(deps.pollMs);
      else await Promise.race([...inflight, pause(deps.pollMs)]);
    }
  }

  deps.log("info", "daemon.draining", { inflight: inflight.size });
  await Promise.all(inflight);
}
