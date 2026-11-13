// The registry Worker's CPU limit is what bounds a queued analysis on Cloudflare. At the default 30 s, three 0.187.0
// (168 million meter units, about 4.7 times as slow per unit on a Worker as here) was stopped every time and stored
// only the re-run's incomplete score. The stack sets the limit from the one constant the registry reasons with
// (the registry's own tests check that a started run's window covers it: analysis-recovery.test.ts).
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { WORKER_CPU_MS } from "../../registry/scripts/compat.ts";

const stack = readFileSync(join(import.meta.dir, "..", "alchemy.run.ts"), "utf8");

/** The source of the resource declared as `yield* Cloudflare.<kind>("<id>", { ... })`, up to the next resource. */
function resource(id: string): string {
  const start = stack.indexOf(`("${id}", {`);

  if (start < 0) throw new Error(`alchemy.run.ts declares no resource "${id}"`);
  const next = stack.indexOf("yield* Cloudflare.", start);

  return stack.slice(start, next < 0 ? undefined : next);
}

describe("the registry Worker's CPU limit", () => {
  test("the stack sets it from WORKER_CPU_MS", () => {
    expect(resource("Registry")).toMatch(/limits: \{ cpuMs: WORKER_CPU_MS \}/);
  });

  test("it is at least Cloudflare's default and within its maximum", () => {
    expect(WORKER_CPU_MS).toBeGreaterThanOrEqual(30_000);
    expect(WORKER_CPU_MS).toBeLessThanOrEqual(300_000);
  });
});
