// smoke.ts against what can go wrong with a stage: an endpoint that accepts and never answers must fail its check within
// the timeout, not hold the deploy waiting on smoke; a 404 from /install passes only where the CLI release record is;
// and the package check must give a very large package a real verdict (issue #1).
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readCliReleases, type CliRelease } from "../cli-ledger.ts";
import { installStep, largePackageAnswer, smokeTimeouts } from "../smoke-checks.ts";

const SMOKE = join(import.meta.dir, "..", "smoke.ts");

describe("smokeTimeouts", () => {
  test("bounds every request and command by default, and takes overrides in whole milliseconds", () => {
    expect(smokeTimeouts({})).toEqual({ httpMs: 30_000, commandMs: 600_000 });
    expect(smokeTimeouts({ APM_SMOKE_HTTP_TIMEOUT_MS: "250", APM_SMOKE_COMMAND_TIMEOUT_MS: "1000" })).toEqual({ httpMs: 250, commandMs: 1000 });

    for (const bad of ["0", "-5", "1.5", "soon"]) expect(() => smokeTimeouts({ APM_SMOKE_HTTP_TIMEOUT_MS: bad })).toThrow("APM_SMOKE_HTTP_TIMEOUT_MS");
  });
});

describe("a 404 from /install", () => {
  const release: CliRelease = { version: "0.1.2", stage: "staging", at: "2026-11-20T00:00:00Z", sha: "a".repeat(40), site: "https://apmjs.dev", binaries: "built", sums: [], script: "b".repeat(64) };

  test("a machine without the CLI release record reads it as no release at all: what let a broken /install pass", () => {
    const dir = mkdtempSync(join(tmpdir(), "apm-no-ledger-"));

    try {
      expect(readCliReleases("production", join(dir, "cli-releases.jsonl"))).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("fails without a record, instead of passing as a stage with no CLI release", () => {
    const step = installStep({ status: 404, stage: "production", record: { kind: "absent", path: "/home/ci/.config/apmjs/cli-releases.jsonl" } });

    expect(step.kind).toBe("fail");
    expect(step.kind === "fail" && step.detail).toContain("no CLI release record (/home/ci/.config/apmjs/cli-releases.jsonl)");
  });

  test("is skipped only when the record exists and names no release for the stage", () => {
    expect(installStep({ status: 404, stage: "staging", record: { kind: "read", releases: [] } })).toEqual({ kind: "skip", detail: "skipped: no CLI release on staging yet (bun packages/infra/release-cli.ts --stage staging)" });
    expect(installStep({ status: 404, stage: "staging", record: { kind: "read", releases: [release] } })).toEqual({ kind: "install" });
  });

  test("any other answer runs the install, record or not", () => {
    for (const record of [{ kind: "absent", path: "x" } as const, { kind: "read", releases: [] } as const]) expect(installStep({ status: 200, stage: "production", record })).toEqual({ kind: "install" });
  });
});

describe("the package check for a very large package", () => {
  test("a real verdict with a version passes", () => {
    for (const verdict of ["install", "review-first", "do-not-install"]) expect(largePackageAnswer({ name: "next", status: 200, body: { verdict, version: "16.4.6" } })).toEqual({ ok: true, detail: `${verdict} 16.4.6` });
  });

  test("issue #1's answer, unknown because the registry did not answer, fails and says so", () => {
    const body = { verdict: "unknown", version: null, summary: "apm could not check next: the registry did not answer. Nothing was checked; try again." };

    expect(largePackageAnswer({ name: "next", status: 200, body })).toEqual({ ok: false, detail: `next: verdict unknown (${body.summary})` });
  });

  test("not found, no version, an error status or an unreadable body fail", () => {
    expect(largePackageAnswer({ name: "next", status: 200, body: { verdict: "not-found", version: null } }).ok).toBe(false);
    expect(largePackageAnswer({ name: "next", status: 200, body: { verdict: "install", version: null } })).toEqual({ ok: false, detail: "next: verdict install with no version" });
    expect(largePackageAnswer({ name: "firebase", status: 429, body: { error: "Too many requests." } })).toEqual({ ok: false, detail: "firebase: HTTP 429" });
    expect(largePackageAnswer({ name: "firebase", status: 200, body: null })).toEqual({ ok: false, detail: "firebase: verdict missing" });
  });
});

describe("smoke.ts against a stage that accepts connections and never answers", () => {
  let silent: Bun.TCPSocketListener;
  let dir: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "apm-smoke-hang-"));
    silent = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {} } });
  });

  afterAll(() => {
    silent.stop(true);
    rmSync(dir, { recursive: true, force: true });
  });

  test("every check fails within its timeout, the run finishes and reports, and it exits 1", async () => {
    const started = Date.now();

    // every stage URL resolves to the silent socket: the subdomain's userinfo@ names the host, and # ends the path
    const proc = Bun.spawn(["bun", SMOKE, "--stage", "staging", "--subdomain", `x@127.0.0.1:${silent.port}/#`], {
      env: { PATH: process.env.PATH ?? "", TMPDIR: dir, APM_SECRETS_DIR: join(dir, "secrets"), APM_CLI_RELEASES_LEDGER: join(dir, "cli-releases.jsonl"), APM_SMOKE_HTTP_TIMEOUT_MS: "300", APM_SMOKE_COMMAND_TIMEOUT_MS: "2000" },
      stdout: "pipe",
      stderr: "pipe",
    });

    const [out, code] = await Promise.all([new Response(proc.stdout).text(), proc.exited]);
    const lines = out.split("\n");

    expect(code).toBe(1);
    expect(lines).toContain("FAIL: the docs site (no answer within 300 ms)");
    expect(lines).toContain("FAIL: the CLI install script (no answer within 300 ms)");
    expect(lines).toContain("FAIL: the package check gives a very large package (next) a real verdict, not unknown (next: no answer within 300 ms)");
    expect(lines).toContain("FAIL: the package check gives a very large package (firebase) a real verdict, not unknown (firebase: no answer within 300 ms)");
    expect(out).toMatch(/^0\/\d+ passed$/m);
    expect(Date.now() - started).toBeLessThan(60_000);
  }, 90_000);
});

test("smoke.ts sends every request through its bounded fetch", () => {
  const source = readFileSync(SMOKE, "utf8");

  expect(source.match(/\bfetch\(/g)?.length).toBe(1);
  expect(source).toContain("signal: AbortSignal.timeout(TIMEOUTS.httpMs)");
});
