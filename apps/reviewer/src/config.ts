// Reviewer configuration, from the environment. Secrets are read from files, never from env values.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { z } from "zod";

const Env = z.object({
  REVIEW_MODEL_URL: z.url().default("https://ms-a2.tail0e7628.ts.net:8318/v1"),
  REVIEW_MODEL: z.string().min(1).default("morph-dsv41flash-1017"),
  REVIEW_MODEL_KEY_FILE: z.string().min(1).default(join(homedir(), ".pi", "agent", "models.json")),
  /** Dotted path to the key inside the key file when it is JSON; ignored for a plain-text key file. */
  REVIEW_MODEL_KEY_JSON: z.string().min(1).default("providers.morph.apiKey"),
  REVIEW_REGISTRY_URL: z.url(),
  REVIEW_SERVICE_TOKEN_FILE: z.string().min(1),
  /** Model requests in flight at once. The eval ran at 4 and was never rate-limited; more is refused. */
  REVIEW_CONCURRENCY: z.coerce.number().int().min(1).max(4).default(4),
  /** Input plus output tokens per UTC day. A quarter of the shared quota is about 250M input a day. */
  REVIEW_DAILY_TOKENS: z.coerce.number().int().min(1).default(50_000_000),
  REVIEW_STATE_DIR: z.string().min(1).default(join(homedir(), ".local", "state", "apm-reviewer")),
  REVIEW_POLL_MS: z.coerce.number().int().min(100).default(15_000),
  REVIEW_BUDGET_TOKENS: z.coerce.number().int().min(1000).max(64_000).default(16_000),
});

export type Config = {
  modelUrl: string;
  model: string;
  modelKeyFile: string;
  modelKeyJson: string;
  registryUrl: string;
  serviceTokenFile: string;
  concurrency: number;
  dailyTokens: number;
  stateDir: string;
  pollMs: number;
  budgetTokens: number;
};

export function configFrom(env: { readonly [key: string]: string | undefined }): Config {
  const e = Env.parse(env);

  return {
    modelUrl: e.REVIEW_MODEL_URL.replace(/\/+$/, ""),
    model: e.REVIEW_MODEL,
    modelKeyFile: e.REVIEW_MODEL_KEY_FILE,
    modelKeyJson: e.REVIEW_MODEL_KEY_JSON,
    registryUrl: e.REVIEW_REGISTRY_URL.replace(/\/?$/, "/"),
    serviceTokenFile: e.REVIEW_SERVICE_TOKEN_FILE,
    concurrency: e.REVIEW_CONCURRENCY,
    dailyTokens: e.REVIEW_DAILY_TOKENS,
    stateDir: e.REVIEW_STATE_DIR,
    pollMs: e.REVIEW_POLL_MS,
    budgetTokens: e.REVIEW_BUDGET_TOKENS,
  };
}

const JsonTree: z.ZodType<JsonTree> = z.lazy(() => z.union([z.string(), z.number(), z.boolean(), z.null(), z.array(JsonTree), z.record(z.string(), JsonTree)]));

type JsonTree = string | number | boolean | null | JsonTree[] | { [key: string]: JsonTree };

function at(tree: JsonTree, path: readonly string[]): string | null {
  let cur: JsonTree = tree;

  for (const key of path) {
    const obj = z.record(z.string(), JsonTree).safeParse(cur);

    if (!obj.success) return null;
    const next = obj.data[key];

    if (next === undefined) return null;
    cur = next;
  }

  const s = z.string().safeParse(cur);

  return s.success ? s.data : null;
}

/**
 * The model key from its file: the file's text, or for a JSON file the string at `jsonPath`. A value
 * starting with "!" is pi's convention for a command whose first output line is the key. The key is
 * returned to the caller only; nothing here logs or stores it.
 */
export function readModelKey(file: string, jsonPath: string): string {
  const text = readFileSync(file, "utf8");
  let raw = text.trim();

  if (raw.startsWith("{")) {
    const tree = JsonTree.safeParse(JSON.parse(raw));
    const found = tree.success ? at(tree.data, jsonPath.split(".")) : null;

    if (found === null) throw new Error(`the key file has no string at ${jsonPath}`);
    raw = found.trim();
  }

  if (raw.startsWith("!")) {
    const out = execFileSync("/bin/sh", ["-c", raw.slice(1)], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 30_000 });

    raw = (out.split("\n")[0] ?? "").trim();
  }

  if (raw === "") throw new Error("the model key resolved to an empty value");

  return raw;
}

export function readSecretFile(file: string): string {
  const s = readFileSync(file, "utf8").trim();

  if (s === "") throw new Error(`${file} is empty`);

  return s;
}
