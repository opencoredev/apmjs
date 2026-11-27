// smoke.ts's workspace holds the check identity's login token (publish/.npmrc), so it must not outlive the run however
// the run ends: a check that throws, or a catchable signal (a dropped SSH session sends SIGHUP).
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
  const env = { PATH: process.env.PATH ?? "", TMPDIR: dir, APM_SECRETS_DIR: join(dir, "secrets"), APM_SMOKE_HTTP_TIMEOUT_MS: "2000", APM_SMOKE_COMMAND_TIMEOUT_MS: "5000" };

  return Bun.spawn(["bun", SMOKE, "--stage", "staging", "--subdomain", subdomain], { env, stdout: "pipe", stderr: "pipe" });
}

describe("smoke.ts's workspace", () => {
  test("is removed when every check throws", async () => {
    // a subdomain with a space makes every stage URL invalid: each check throws without touching the network
    const proc = start("bad host");
    const [code, out] = await Promise.all([proc.exited, new Response(proc.stdout).text()]);

    expect(code).toBe(1);
    expect(out).toContain("FAIL: the docs site (stopped: ");
    expect(out).toMatch(/^0\/\d+ passed$/m);
    expect(readdirSync(dir).filter((f) => f.startsWith("apm-smoke-"))).toEqual([]);
  }, 60_000);

  test.each([
    ["SIGHUP", 129],
    ["SIGINT", 130],
    ["SIGQUIT", 131],
    ["SIGABRT", 134],
    ["SIGTERM", 143],
  ] as const)("is removed when the run is stopped with %s while a check waits", async (signal, code) => {
    // a local socket that accepts and never answers: the docs check's first fetch (userinfo@127.0.0.1) hangs on it
    const connected = Promise.withResolvers<void>();

    const silent = Bun.listen({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        open() {
          connected.resolve();
        },
        data() {},
      },
    });

    try {
      const proc = start(`x@127.0.0.1:${silent.port}/#`);

      await connected.promise;
      expect(readdirSync(dir).filter((f) => f.startsWith("apm-smoke-"))).toHaveLength(1);
      proc.kill(signal);
      expect(await proc.exited).toBe(code);
      expect(readdirSync(dir).filter((f) => f.startsWith("apm-smoke-"))).toEqual([]);
    } finally {
      silent.stop(true);
    }
  });
});
