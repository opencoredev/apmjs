// OpenAI-compatible chat client for the review model. The key is read from ~/.pi/agent/models.json at
// runtime and never logged or written anywhere.
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const BASE_URL = "https://ms-a2.tail0e7628.ts.net:8318/v1";
export const MODEL = "morph-dsv41flash-1017";

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

let cachedKey: string | null = null;
function apiKey(): string {
  if (cachedKey) return cachedKey;
  const raw: unknown = JSON.parse(readFileSync(join(homedir(), ".pi", "agent", "models.json"), "utf8"));
  const providers = isRecord(raw) ? raw.providers : undefined;
  const morph = isRecord(providers) ? providers.morph : undefined;
  const key = isRecord(morph) ? morph.apiKey : undefined;
  if (typeof key !== "string" || !key) throw new Error("providers.morph.apiKey missing in ~/.pi/agent/models.json");
  // pi convention: a value starting with "!" is a shell command whose first output line is the key.
  const resolved = key.startsWith("!") ? execSync(key.slice(1), { shell: "/bin/sh", encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).split("\n")[0]?.trim() : key;
  if (!resolved) throw new Error("providers.morph.apiKey resolved to an empty value");
  cachedKey = resolved;
  return resolved;
}

export type ChatMessage = { role: "system" | "user"; content: string };

export type ChatResult = {
  content: string;
  promptTokens: number;
  completionTokens: number;
  reasoningTokens: number;
  cachedTokens: number;
  latencyMs: number;
  attempts: number;
  rateLimited: number;
};

function num(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) ? v : 0;
}

/** One chat completion with retries: honors Retry-After on 429, backs off on 5xx and network errors. */
export async function chat(messages: readonly ChatMessage[], opts: { maxTokens: number; temperature?: number }): Promise<ChatResult> {
  let rateLimited = 0;
  for (let attempt = 1; ; attempt++) {
    const started = performance.now();
    let res: Response;
    try {
      res = await fetch(`${BASE_URL}/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${apiKey()}` },
        body: JSON.stringify({
          model: MODEL,
          messages,
          max_tokens: opts.maxTokens,
          temperature: opts.temperature ?? 0,
          response_format: { type: "json_object" },
        }),
        signal: AbortSignal.timeout(300_000),
      });
    } catch (e) {
      if (attempt >= 5) throw e;
      await Bun.sleep(2000 * attempt);
      continue;
    }
    if (res.status === 429) {
      rateLimited++;
      const after = Number(res.headers.get("retry-after") ?? "");
      await res.body?.cancel();
      if (attempt >= 12) throw new Error("rate limited 12 times");
      await Bun.sleep(Number.isFinite(after) && after > 0 ? after * 1000 : 5000 * attempt);
      continue;
    }
    if (res.status >= 500) {
      const text = (await res.text()).slice(0, 200);
      if (attempt >= 5) throw new Error(`HTTP ${res.status}: ${text}`);
      await Bun.sleep(3000 * attempt);
      continue;
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
    const body: unknown = await res.json();
    const latencyMs = performance.now() - started;
    const choices = isRecord(body) && Array.isArray(body.choices) ? body.choices : [];
    const first: unknown = choices[0];
    const message = isRecord(first) ? first.message : undefined;
    const content = isRecord(message) && typeof message.content === "string" ? message.content : "";
    const usage = isRecord(body) && isRecord(body.usage) ? body.usage : {};
    const ctd = isRecord(usage.completion_tokens_details) ? usage.completion_tokens_details : {};
    const ptd = isRecord(usage.prompt_tokens_details) ? usage.prompt_tokens_details : {};
    return {
      content,
      promptTokens: num(usage.prompt_tokens),
      completionTokens: num(usage.completion_tokens),
      reasoningTokens: num(ctd.reasoning_tokens),
      cachedTokens: num(ptd.cached_tokens),
      latencyMs,
      attempts: attempt,
      rateLimited,
    };
  }
}
