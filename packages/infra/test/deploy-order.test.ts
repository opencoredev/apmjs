// The registry deploys before the website: the website's REGISTRY service binding makes it depend on the registry, and
// Alchemy starts a resource only after the resources it depends on have finished (deploy.ts, "Order"). The registry
// must not depend on the website, or the two would form a cycle that Alchemy precreates together.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const stack = readFileSync(join(import.meta.dir, "..", "alchemy.run.ts"), "utf8");

/** The source of the resource declared as `yield* Cloudflare.<kind>("<id>", { ... })`, up to the next resource. */
function resource(id: string): string {
  const start = stack.indexOf(`("${id}", {`);

  if (start < 0) throw new Error(`alchemy.run.ts declares no resource "${id}"`);
  const next = stack.indexOf("yield* Cloudflare.", start);

  return stack.slice(start, next < 0 ? undefined : next);
}

describe("deploy order", () => {
  test("the website binds the registry Worker, so Alchemy deploys the registry first", () => {
    expect(stack).toMatch(/const registry = yield\* Cloudflare\.Worker\("Registry"/);
    expect(resource("Web")).toMatch(/env: \{ REGISTRY: registry\b/);
  });

  test("the registry does not depend on the website", () => {
    expect(resource("Registry")).not.toMatch(/\bwebsite\b/);
  });
});
