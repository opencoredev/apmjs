// Search ranks every term against every package published here, and a term is compared with each name by edit
// distance, which costs the product of their lengths. An unbounded search text was then CPU without bound: against 100
// packages, a 12 000-character term took 2 s and 500 name-length words took 1.8 s, and both grow with the registry.
import { afterAll, beforeAll, expect, test } from "bun:test";
import { z } from "zod";
import { addUser, putPublish, startRegistry, type Registry } from "../../../tests/acceptance/harness";

const SearchAnswer = z.object({ objects: z.array(z.object({ package: z.object({ name: z.string() }) })) });
const PACKAGES = 100;

// far above what a search of these packages takes once bounded (tens of ms), far below what it took (about 2 s)
const BOUND_MS = 600;

let reg: Registry;

beforeAll(async () => {
  reg = await startRegistry({ namePolicy: "open" });
  const token = await addUser(reg, "alice");

  for (let i = 0; i < PACKAGES; i++) expect((await putPublish(reg, token, { name: `search-cost-package-${i}`, version: "1.0.0" })).status).toBe(201);
}, 120_000);

afterAll(async () => {
  await reg.stop();
});

async function search(text: string): Promise<{ ms: number; names: string[] }> {
  const t0 = performance.now();
  const res = await fetch(`${reg.url}-/v1/search?size=250&text=${encodeURIComponent(text)}`);
  const body = SearchAnswer.parse(await res.json());

  expect(res.status).toBe(200);

  return { ms: performance.now() - t0, names: body.objects.map((o) => o.package.name) };
}

test("a very long term is answered within the bound", async () => {
  const { ms } = await search("x".repeat(12_000));

  expect(ms).toBeLessThan(BOUND_MS);
});

test("hundreds of name-length words are answered within the bound", async () => {
  const words = Array.from({ length: 500 }, (_, i) => `search-cost-packagf-${i}`).join(" ");
  const { ms } = await search(words);

  expect(ms).toBeLessThan(BOUND_MS);
});

test("a misspelled name still finds its package", async () => {
  expect((await search("search-cost-packagf-7")).names).toContain("search-cost-package-7");
});
