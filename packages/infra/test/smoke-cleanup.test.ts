// smoke.ts's workspace holds the check identity's login token (publish/.npmrc), so it must not outlive the run however
// the run ends: a check that throws, or a signal from whoever started it.
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SMOKE = join(import.meta.dir, "..", "smoke.ts");
let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "apm-smoke-cleanup-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function start(subdomain: string) {
  // a subdomain with a space makes every stage URL invalid: the first fetch throws without touching the network
  return Bun.spawn(["bun", SMOKE, "--stage", "staging", "--subdomain", subdomain], { env: { PATH: process.env.PATH ?? "", TMPDIR: dir, APM_SECRETS_DIR: join(dir, "secrets") }, stdout: "pipe", stderr: "pipe" });
}

describe("smoke.ts's workspace", () => {
  test("is removed when a check throws and the run crashes", async () => {
    const proc = start("bad host");
    const [code, err] = await Promise.all([proc.exited, new Response(proc.stderr).text()]);

    expect(code).not.toBe(0);
    expect(err).toContain("docsSite");
    expect(readdirSync(dir).filter((f) => f.startsWith("apm-smoke-"))).toEqual([]);
  });

  test("is removed when the run is stopped with SIGTERM", async () => {
    const proc = start("bad host");

    // stopped as soon as the workspace exists, before the crashing check gets to run
    for (let i = 0; i < 200 && !readdirSync(dir).some((f) => f.startsWith("apm-smoke-")); i++) await Bun.sleep(5);
    proc.kill("SIGTERM");
    await proc.exited;
    expect(readdirSync(dir).filter((f) => f.startsWith("apm-smoke-"))).toEqual([]);
  });
});
