// apm's AI reviewer. Runs on a machine that can reach the model; pulls jobs from the registry over HTTP
// and needs no inbound access. See docs/AI-REVIEW.md.
//
//   bun apps/reviewer/src/main.ts                 the daemon (config from env)
//   bun apps/reviewer/src/main.ts review-files --name debug --version 4.4.2 --path <tgz|dir> \
//       [--previous-version 4.4.1 --previous-path <tgz|dir>] [--quotes]
//                                                 one offline review, printed as JSON; posts nothing
import { parseArgs } from "node:util";
import { z } from "zod";
import { buildReviewInput, runReview } from "@apm/ai-review";
import { DailyBudget } from "./budget.ts";
import { configFrom, readModelKey, readSecretFile } from "./config.ts";
import { loadPackage } from "./local-files.ts";
import { jsonLogger } from "./log.ts";
import { modelClient } from "./model.ts";
import { registryClient } from "./registry.ts";
import { configuredSecondStage } from "./second-stage.ts";
import { resultOf, runDaemon } from "./worker.ts";

const OfflineConfig = z.object({
  REVIEW_MODEL_URL: z.url().default("https://ms-a2.tail0e7628.ts.net:8318/v1"),
  REVIEW_MODEL: z.string().min(1).default("morph-dsv41flash-1017"),
  REVIEW_MODEL_KEY_FILE: z.string().min(1).default(`${process.env.HOME ?? ""}/.pi/agent/models.json`),
  REVIEW_MODEL_KEY_JSON: z.string().min(1).default("providers.morph.apiKey"),
});

function keyLoader(file: string, jsonPath: string): () => string {
  let key: string | null = null;

  return () => (key ??= readModelKey(file, jsonPath));
}

async function reviewFiles(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      name: { type: "string" },
      version: { type: "string" },
      path: { type: "string" },
      "previous-version": { type: "string" },
      "previous-path": { type: "string" },
      quotes: { type: "boolean", default: false },
    },
  });

  const args = z
    .object({ name: z.string().min(1), version: z.string().min(1), path: z.string().min(1), "previous-version": z.string().optional(), "previous-path": z.string().optional(), quotes: z.boolean() })
    .parse(values);

  const env = OfflineConfig.parse(process.env);
  const model = modelClient({ url: env.REVIEW_MODEL_URL.replace(/\/+$/, ""), model: env.REVIEW_MODEL, key: keyLoader(env.REVIEW_MODEL_KEY_FILE, env.REVIEW_MODEL_KEY_JSON), concurrency: 1, log: jsonLogger });
  const pkg = loadPackage(args.path);
  const prevPath = args["previous-path"];
  const prevVersion = args["previous-version"];
  const previous = prevPath && prevVersion ? { version: prevVersion, pkg: loadPackage(prevPath) } : null;
  const review = buildReviewInput({ name: args.name, version: args.version, pkg, previous });
  const run = await runReview({ review, pkg, ask: model.ask });
  const result = resultOf({ decision: run.decision, run, review, model: model.model, at: Date.now(), secondOpinion: null });

  // quotes and excerpts are package code; print them only when asked
  const shown = args.quotes || result.outcome === "benign" ? result : { ...result, findings: result.findings.map((f) => ({ ...f, quote: "(hidden; pass --quotes)", excerpt: "(hidden; pass --quotes)" })) };

  process.stdout.write(`${JSON.stringify({ name: args.name, version: args.version, ...shown }, null, 2)}\n`);
}

async function daemon(): Promise<void> {
  const config = configFrom(process.env);
  const log = jsonLogger;
  const controller = new AbortController();

  for (const sig of ["SIGTERM", "SIGINT"] as const) {
    process.on(sig, () => {
      log("info", "daemon.signal", { signal: sig });
      controller.abort();
    });
  }

  // fail at start, not on the first job, when the key or token cannot be read
  const key = readModelKey(config.modelKeyFile, config.modelKeyJson);

  log("info", "daemon.start", { registry: config.registryUrl, model: config.model, modelUrl: config.modelUrl, concurrency: config.concurrency, dailyTokens: config.dailyTokens });
  await runDaemon({
    registry: registryClient({ url: config.registryUrl, token: readSecretFile(config.serviceTokenFile) }),
    model: modelClient({ url: config.modelUrl, model: config.model, key: () => key, concurrency: config.concurrency, log }),
    budget: new DailyBudget(config.stateDir, config.dailyTokens),
    log,
    secondStage: configuredSecondStage(),
    budgetTokens: config.budgetTokens,
    concurrency: config.concurrency,
    pollMs: config.pollMs,
    signal: controller.signal,
  });
  log("info", "daemon.stopped");
}

const [command, ...rest] = process.argv.slice(2);

if (command === "review-files") await reviewFiles(rest);
else if (command === undefined) await daemon();
else {
  process.stderr.write(`unknown command ${command}; run with no arguments for the daemon, or review-files\n`);
  process.exit(2);
}
