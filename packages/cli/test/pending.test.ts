// Review of d49bf6e, finding 4, the CLI's half: a cold top-level `apm add` was refused at once, and a version the
// registry had queued read as unchecked. Now /resolve answers 202 while anything in the tree has no score yet, and
// `apm add` and `apm x` ask again with progress for a bounded time, then refuse with "still being analysed, try again in
// a minute". The registry is a local recording stub that never stops answering 202, and the token is fake.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CLI = join(import.meta.dir, "..", "src", "main.ts");
let asked = 0;
let server: ReturnType<typeof Bun.serve> | null = null;

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req): Response {
      const u = new URL(req.url);

      if (u.pathname === "/-/apm/v1/resolve") {
        asked++;

        return Response.json(
          { error: "cold@1.0.0 is still being analysed", name: "cold", range: "latest", version: "1.0.0", pending: [{ name: "cold", version: "1.0.0" }], pendingCount: 1, retryAfter: 0, skipped: [] },
          { status: 202, headers: { "retry-after": "0" } },
        );
      }

      return Response.json({ error: "not here" }, { status: 404 });
    },
  });
});

afterAll(() => {
  server?.stop(true);
});

async function apm(args: string[]): Promise<{ code: number; out: string; ms: number }> {
  const home = mkdtempSync(join(tmpdir(), "apm-pending-"));
  const cwd = mkdtempSync(join(tmpdir(), "apm-pending-app-"));

  writeFileSync(join(cwd, "package.json"), JSON.stringify({ name: "app", version: "1.0.0" }));

  const t0 = performance.now();

  const p = Bun.spawn(["bun", CLI, ...args], {
    cwd,
    env: { PATH: process.env.PATH ?? "", HOME: home, NO_COLOR: "1", APM_REGISTRY: server?.url.href ?? "", APM_PENDING_WAIT_MS: "1500" },
    stdout: "pipe",
    stderr: "pipe",
  });

  const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);

  return { code, out: out + err, ms: performance.now() - t0 };
}

describe("a version still being analysed", () => {
  for (const cmd of ["add", "x"]) {
    test(`apm ${cmd}: asks again with progress, then refuses with when to try again`, async () => {
      asked = 0;
      const r = await apm([cmd, "cold"]);

      expect(r.code).toBe(1);
      expect(r.out).toContain("still being analysed, try again in a minute");
      expect(r.out).toContain("waiting,");
      // asked more than once, inside the bound
      expect(asked).toBeGreaterThan(1);
      expect(r.ms).toBeGreaterThanOrEqual(1400);
      expect(r.ms).toBeLessThan(20_000);
    }, 30_000);
  }
});
