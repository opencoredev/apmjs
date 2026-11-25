// Greptile security finding on 48e0915: every reload of a risky package's page made the registry walk its tree again
import { describe, expect, test } from "bun:test";
import { cachedResolve, POLICY_TTL_MS, type PolicyStore } from "./policy-cache";
import { resolvedTo } from "./testing";
import type { ResolveOutcome } from "./source";

describe("the package views' resolve, kept a minute", () => {
  const setup = (answer: ResolveOutcome) => {
    let clock = 0;
    const asked: string[] = [];
    const store: PolicyStore = new Map();

    const resolve = cachedResolve({
      resolve: async ({ name, range }) => (asked.push(`${name}@${range}`), answer),
      store,
      now: () => clock,
    });

    return { resolve, asked, tick: (ms: number) => (clock += ms) };
  };

  test("views together share one read, and a view inside the minute reuses it", async () => {
    const { resolve, asked, tick } = setup(resolvedTo("1.0.0"));

    await Promise.all([resolve({ name: "x", range: "1.0.0" }), resolve({ name: "x", range: "1.0.0" })]);
    tick(POLICY_TTL_MS - 1);
    await resolve({ name: "x", range: "1.0.0" });
    expect(asked).toEqual(["x@1.0.0"]);

    tick(1);
    await resolve({ name: "x", range: "1.0.0" });
    await resolve({ name: "x", range: "2.0.0" });
    expect(asked).toEqual(["x@1.0.0", "x@1.0.0", "x@2.0.0"]);
  });

  test("an answer the registry did not give is not kept", async () => {
    const { resolve, asked } = setup({ kind: "unavailable" });

    await resolve({ name: "x", range: "1.0.0" });
    await resolve({ name: "x", range: "1.0.0" });
    expect(asked).toEqual(["x@1.0.0", "x@1.0.0"]);
  });
});
