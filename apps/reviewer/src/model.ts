// OpenAI-compatible chat client for the review model. At most `concurrency` requests are in flight;
// 429 answers wait for Retry-After. When the model cannot be reached at all the call throws
// ModelUnavailable, so the job goes back to the queue instead of being recorded as "no answer".
import { z } from "zod";
import { MAX_OUTPUT_TOKENS, type Ask, type ChatMessage, type ModelAnswer, type Usage } from "@apm/ai-review";
import type { Logger } from "./log.ts";

export class ModelUnavailable extends Error {}

const Completion = z.object({
  choices: z
    .array(
      z.object({
        message: z.object({ content: z.string().nullish() }).nullish(),
        finish_reason: z.string().nullish(),
      }),
    )
    .default([]),
  usage: z
    .object({
      prompt_tokens: z.number().catch(0).default(0),
      completion_tokens: z.number().catch(0).default(0),
      completion_tokens_details: z.object({ reasoning_tokens: z.number().catch(0).default(0) }).nullish(),
    })
    .nullish(),
});

/** Counts permits; waiters run in arrival order. */
export class Semaphore {
  private active = 0;
  private readonly waiting: (() => void)[] = [];

  constructor(private readonly limit: number) {}

  async run<T>(fn: () => Promise<T>): Promise<T> {
    // a released permit passes straight to the next waiter, so a newcomer cannot slip in between
    if (this.active < this.limit) this.active++;
    else await new Promise<void>((resolve) => this.waiting.push(resolve));

    try {
      return await fn();
    } finally {
      const next = this.waiting.shift();

      if (next) next();
      else this.active--;
    }
  }
}

/** Seconds or an HTTP date; capped at two minutes. Null when absent or unreadable. */
export function retryAfterMs(header: string | null, now: number = Date.now()): number | null {
  if (header === null || header.trim() === "") return null;
  const secs = Number(header);
  const ms = Number.isFinite(secs) ? secs * 1000 : Date.parse(header) - now;

  if (!Number.isFinite(ms) || ms < 0) return null;

  return Math.min(ms, 120_000);
}

export type ModelClient = { ask: Ask; model: string };

const NO_USAGE: Usage = { promptTokens: 0, completionTokens: 0, reasoningTokens: 0, latencyMs: 0 };

export function modelClient(input: {
  url: string;
  model: string;
  key: () => string;
  concurrency: number;
  log: Logger;
  sleep?: (ms: number) => Promise<void>;
  timeoutMs?: number;
}): ModelClient {
  const gate = new Semaphore(input.concurrency);
  const sleep = input.sleep ?? ((ms: number) => Bun.sleep(ms));

  async function once(messages: readonly ChatMessage[]): Promise<ModelAnswer> {
    let rateLimited = 0;

    for (let attempt = 1; ; attempt++) {
      const started = performance.now();
      let res: Response;

      try {
        res = await fetch(`${input.url}/chat/completions`, {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${input.key()}` },
          body: JSON.stringify({ model: input.model, messages, max_tokens: MAX_OUTPUT_TOKENS, temperature: 0, response_format: { type: "json_object" } }),
          signal: AbortSignal.timeout(input.timeoutMs ?? 300_000),
        });
      } catch (cause) {
        if (attempt >= 4) throw new ModelUnavailable("the model could not be reached", { cause });
        input.log("warn", "model.retry", { attempt, why: "network" });
        await sleep(2000 * attempt);
        continue;
      }

      if (res.status === 429) {
        rateLimited++;
        const wait = retryAfterMs(res.headers.get("retry-after")) ?? 5000 * rateLimited;

        await res.body?.cancel();

        if (rateLimited > 12) throw new ModelUnavailable("rate limited 12 times in a row");
        input.log("warn", "model.rate_limited", { waitMs: wait, times: rateLimited });
        await sleep(wait);
        attempt--;
        continue;
      }

      if (res.status >= 500 || res.status === 408) {
        await res.body?.cancel();

        if (attempt >= 4) throw new ModelUnavailable(`the model answered HTTP ${res.status}`);
        input.log("warn", "model.retry", { attempt, status: res.status });
        await sleep(3000 * attempt);
        continue;
      }

      if (res.status === 401 || res.status === 403) {
        await res.body?.cancel();

        throw new ModelUnavailable(`the model refused the key (HTTP ${res.status})`);
      }

      if (!res.ok) {
        // a request the model will never accept (too long, malformed): an empty answer, not an outage
        await res.body?.cancel();

        return { kind: "failed", error: `HTTP ${res.status}`, usage: { ...NO_USAGE, latencyMs: performance.now() - started } };
      }

      const body = Completion.safeParse(await res.json().catch(() => null));
      const latencyMs = performance.now() - started;

      if (!body.success) return { kind: "failed", error: "unreadable completion", usage: { ...NO_USAGE, latencyMs } };
      const choice = body.data.choices[0];
      const u = body.data.usage;

      return {
        kind: "ok",
        content: choice?.message?.content ?? "",
        finishReason: choice?.finish_reason ?? null,
        usage: { promptTokens: u?.prompt_tokens ?? 0, completionTokens: u?.completion_tokens ?? 0, reasoningTokens: u?.completion_tokens_details?.reasoning_tokens ?? 0, latencyMs },
      };
    }
  }

  return { model: input.model, ask: (messages) => gate.run(() => once(messages)) };
}
