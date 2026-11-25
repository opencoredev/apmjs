// smoke.ts against what can go wrong with a stage: an endpoint that accepts and never answers must fail its check within
// the timeout, not hold the deploy waiting on smoke; a 404 from /install passes only where the CLI release record is;
// and the package check must give a very large package a real verdict (issue #1).
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readdirSync, readFileSync, readlinkSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readCliReleases, type CliRelease } from "../cli-ledger.ts";
import { installCheck } from "../cli-check.ts";
import { cliRecordOf, installStep, largePackageAnswer, resultLine, smokeTimeouts } from "../smoke-checks.ts";

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
    const step = installStep({ status: 404, stage: "production", readRecord: () => ({ kind: "absent", path: "/home/ci/.config/apmjs/cli-releases.jsonl" }) });

    expect(step.kind).toBe("fail");
    expect(step.kind === "fail" && step.detail).toContain("no CLI release record (/home/ci/.config/apmjs/cli-releases.jsonl)");
  });

  test("is skipped only when the record exists and names no release for the stage", () => {
    expect(installStep({ status: 404, stage: "staging", readRecord: () => ({ kind: "read", releases: [] }) })).toEqual({ kind: "skip", detail: "skipped: no CLI release on staging yet (bun packages/infra/release-cli.ts --stage staging)" });
    expect(installStep({ status: 404, stage: "staging", readRecord: () => ({ kind: "read", releases: [release] }) })).toEqual({ kind: "install" });
  });

  test("any other answer runs the install without reading the record, so an unreadable one cannot fail a working installer", () => {
    for (const status of [200, 500]) {
      const step = installStep({
        status,
        stage: "production",
        readRecord: () => {
          throw new Error("EACCES: permission denied, open 'cli-releases.jsonl'");
        },
      });

      expect(step).toEqual({ kind: "install" });
    }
  });

  test("a record with a line that does not parse (a write torn by a crash) cannot vouch for no release, so a 404 fails", () => {
    const dir = mkdtempSync(join(tmpdir(), "apm-torn-ledger-"));
    const path = join(dir, "cli-releases.jsonl");

    try {
      writeFileSync(path, `${JSON.stringify(release)}\n{"version":"0.1.3","stage":"produc`);
      // what smoke read before: the torn production line is dropped, and production looks like it never had a release
      expect(readCliReleases("production", path)).toEqual([]);
      const record = cliRecordOf("production", path);

      expect(record).toEqual({ kind: "unreadable", path, broken: 1 });
      expect(installStep({ status: 404, stage: "production", readRecord: () => record }).kind).toBe("fail");
      writeFileSync(path, `${JSON.stringify(release)}\n`);
      expect(cliRecordOf("staging", path)).toEqual({ kind: "read", releases: [release] });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("the CLI install check", () => {
  test("an installed apm that hangs on --version fails the check within the command timeout", async () => {
    // an install script that installs an apm which never answers, and says what the real script says
    const script = ['mkdir -p "$HOME/.apm/bin"', `printf '#!/bin/sh\\nsleep 30\\n' > "$HOME/.apm/bin/apm"`, 'chmod +x "$HOME/.apm/bin/apm"', 'echo "apm 0.1.2 (linux-x64) installed to $HOME/.apm/bin/apm"', `echo "SHA-256 ${"0".repeat(64)}, checked against this script"`].join("\n");
    const site = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: (req) => (new URL(req.url).pathname === "/install" ? new Response(script) : new Response("not found", { status: 404 })) });
    const started = Date.now();

    try {
      const r = await installCheck(`http://127.0.0.1:${site.port}`, { httpMs: 1000, commandMs: 500 });

      expect(r.ok).toBe(false);
      expect(r.detail).toContain("apm --version gave no result within 500 ms");
      expect(Date.now() - started).toBeLessThan(5_000);
    } finally {
      site.stop(true);
    }
  }, 40_000);
});

describe("a result line", () => {
  test("text the stage wrote cannot print a line of its own, such as a forged PASS", () => {
    const summary = "apm could not check next.\nPASS: the registry resolves every locked version (forged)\r\u2028\u001b[2K";
    const { detail } = largePackageAnswer({ name: "next", status: 200, body: { verdict: "unknown", version: null, summary } });
    const line = resultLine(false, "the package check gives a very large package (next) a real verdict, not unknown", detail);

    expect(line.split("\n")).toEqual([expect.stringMatching(/^FAIL: .*PASS: the registry resolves every locked version \(forged\)/), ""]);

    for (const c of ["\r", "\u2028", "\u001b"]) expect(line).not.toContain(c);
  });

  test("smoke.ts prints every result through it", () => {
    const source = readFileSync(SMOKE, "utf8");

    expect(source).toContain("process.stdout.write(resultLine(ok, name, detail));");
    expect(source).not.toMatch(/`\$\{ok \? "PASS" : "FAIL"\}/);
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
    expect(lines.some((l) => l.startsWith("FAIL: explain answers install for a large package (next@"))).toBe(true);
    expect(lines).toContain("FAIL: the package check gives a very large package (firebase) a real verdict, not unknown (firebase: no answer within 300 ms)");
    expect(out).toMatch(/^0\/\d+ passed$/m);
    expect(Date.now() - started).toBeLessThan(60_000);
  }, 90_000);

  // processes are found by their working directory under /proc, which only Linux has (CI runs on Linux)
  test.skipIf(process.platform !== "linux")("stopping the run kills the command it was waiting on, not only itself", async () => {
    // the commands smoke runs work in its workspace, under TMPDIR: any process whose cwd is there is one of them
    const commands = (): number[] =>
      readdirSync("/proc")
        .filter((p) => /^\d+$/.test(p))
        .filter((p) => {
          try {
            return readlinkSync(`/proc/${p}/cwd`).startsWith(dir);
          } catch {
            return false;
          }
        })
        .map(Number);

    const proc = Bun.spawn(["bun", SMOKE, "--stage", "staging", "--subdomain", `x@127.0.0.1:${silent.port}/#`], {
      env: { PATH: process.env.PATH ?? "", TMPDIR: dir, APM_SECRETS_DIR: join(dir, "secrets"), APM_CLI_RELEASES_LEDGER: join(dir, "cli-releases.jsonl"), APM_SMOKE_HTTP_TIMEOUT_MS: "300", APM_SMOKE_COMMAND_TIMEOUT_MS: "60000" },
      stdout: "pipe",
      stderr: "pipe",
    });

    try {
      // the docs and install checks time out in 600 ms, then bun install of the first locked project waits on the socket
      for (let i = 0; i < 200 && commands().length === 0; i++) await Bun.sleep(25);
      expect(commands().length).toBeGreaterThan(0);
      proc.kill("SIGTERM");
      expect(await proc.exited).toBe(143);

      for (let i = 0; i < 40 && commands().length > 0; i++) await Bun.sleep(25);
      expect(commands()).toEqual([]);
    } finally {
      proc.kill("SIGKILL");

      for (const pid of commands()) process.kill(pid, "SIGKILL");
    }
  }, 30_000);
});

test("every request smoke.ts makes carries a timeout", () => {
  const calls = readFileSync(SMOKE, "utf8")
    .split("\n")
    .filter((l) => /\bfetch\(/.test(l));

  expect(calls.length).toBeGreaterThan(0);

  for (const call of calls) expect(call).toContain("AbortSignal.timeout(");
});
