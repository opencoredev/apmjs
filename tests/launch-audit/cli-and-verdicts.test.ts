// Launch-audit check (CLI config, explain verdicts, cooldown parity, version drift, and CLI polish).
import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { loadConfig } from "../../packages/cli/src/config.ts";
import { explain as cliExplain, resolveForVerdict as cliResolveForVerdict, type ResolvedInput } from "../../packages/cli/src/explain.ts";
import { CLI_VERSION } from "../../packages/cli/src/version.ts";

const ROOT = join(import.meta.dir, "..", "..");
const CLI_MAIN = join(ROOT, "packages", "cli", "src", "main.ts");

function makeTempDir(prefix: string, base: string = tmpdir()): string {
  return mkdtempSync(join(base, prefix));
}

function runCli(args: string[], cwd: string, env: Record<string, string> = {}) {
  const res = Bun.spawnSync([process.execPath, CLI_MAIN, ...args], {
    cwd,
    env: { PATH: process.env.PATH ?? "", HOME: cwd, NO_COLOR: "1", TMPDIR: tmpdir(), ...env },
    stdout: "pipe",
    stderr: "pipe",
  });

  return { code: res.exitCode, stdout: res.stdout.toString(), stderr: res.stderr.toString() };
}

function freshResolved(version: string): ResolvedInput {
  return {
    kind: "ok",
    version,
    report: {
      score: 100,
      grade: "A",
      scorer: "apm-score-v11",
      signals: [],
      capabilities: [],
      notChecked: [],
      coverage: { kind: "complete" },
    },
    skipped: [],
    deps: {
      warnings: [{ kind: "cooldown", name: "fast-pkg", version, via: [], text: "Published under 24 hours ago." }],
      unchecked: 0,
      uncheckedDeps: [],
      risks: [],
      reviews: { kind: "on", underReview: [], flagged: [], confirmed: [], pending: [], noAnswer: [] },
    },
  };
}

function oldResolved(version: string): ResolvedInput {
  return {
    kind: "ok",
    version,
    report: {
      score: 100,
      grade: "A",
      scorer: "apm-score-v11",
      signals: [],
      capabilities: [],
      notChecked: [],
      coverage: { kind: "complete" },
    },
    skipped: [],
    deps: {
      warnings: [],
      unchecked: 0,
      uncheckedDeps: [],
      risks: [],
      reviews: { kind: "on", underReview: [], flagged: [], confirmed: [], pending: [], noAnswer: [] },
    },
  };
}

describe("launch audit: CLI & verdicts", () => {
  test("P0: loadConfig does not treat an ancestor $HOME/.npmrc as a project .npmrc", () => {
    const home = makeTempDir("apm-audit-home-");
    const projectParent = makeTempDir("apm-audit-proj-", homedir());

    try {
      writeFileSync(join(home, ".npmrc"), "registry=https://apm.example.test/\n");

      const cfg = loadConfig(projectParent, { HOME: home, APM_TOKEN: "apm_secretsecretsecret" });

      expect(cfg.registry).toBe("https://apm.example.test/");
      expect(cfg.token).toBe("apm_secretsecretsecret");
    } finally {
      rmSync(home, { recursive: true, force: true });
      rmSync(projectParent, { recursive: true, force: true });
    }
  });

  test("P0: packages/cli/test/sandbox.test.ts does not leak TMPDIR='undefined' when TMPDIR is unset", () => {
    const res = Bun.spawnSync([process.execPath, "test", "packages/cli/test/sandbox.test.ts", "packages/cli/test/rate-limited.test.ts"], {
      cwd: ROOT,
      env: { PATH: process.env.PATH ?? "", HOME: homedir(), NO_COLOR: "1" },
      stdout: "pipe",
      stderr: "pipe",
    });

    expect(res.exitCode).toBe(0);
  });

  test("P1: nonexistent version range returns not-found (not review-first) on CLI explain", () => {
    const refused = {
      kind: "refused" as const,
      reason: "No version of zod matching 99.99.99 passes the policy.",
      skipped: [],
      newest: null,
      confirmed: [],
    };

    const cliVerdict = cliExplain({
      name: "zod",
      range: "99.99.99",
      resolved: refused,
      review: { kind: "not-reviewed" },
      older: { kind: "not-needed" },
    });

    expect(cliVerdict.verdict).toBe("not-found");
  });

  test("P1: CLI resolveForVerdict skips 3+ fresh versions inside the 24h cooldown like web does", async () => {
    const result = await cliResolveForVerdict({
      range: "latest",
      resolve: async (range) => {
        if (range === "latest") return freshResolved("1.0.3");

        if (range === "<1.0.3") return freshResolved("1.0.2");

        if (range === "<1.0.2") return freshResolved("1.0.1");

        if (range === "<1.0.1") return oldResolved("1.0.0");

        return { kind: "missing", reason: "none" };
      },
    });

    expect(result.resolved.kind).toBe("ok");

    if (result.resolved.kind === "ok") expect(result.resolved.version).toBe("1.0.0");
  });

  test("P1: CLI_VERSION is bumped past 0.1.1 for the unreleased CLI/core commits since 8cbbc00", () => {
    const pkg = z.object({ version: z.string() }).parse(JSON.parse(readFileSync(join(ROOT, "packages/cli/package.json"), "utf8")));

    expect(CLI_VERSION).not.toBe("0.1.1");
    expect(pkg.version).toBe(CLI_VERSION);
  });

  test("P2: apm publish --bump does not mutate package.json if secret checks fail", () => {
    const dir = makeTempDir("apm-audit-bump-");

    try {
      const initial = JSON.stringify({ name: "@alice/bump-test", version: "1.0.0", main: "index.js", license: "MIT" }, null, 2);

      writeFileSync(join(dir, "package.json"), `${initial}\n`);
      writeFileSync(join(dir, "index.js"), "module.exports = 1;\n");
      writeFileSync(join(dir, ".env"), "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz\n");

      const out = runCli(["publish", "--bump", "patch"], dir, { APM_REGISTRY: "http://127.0.0.1:1/" });
      const after = z.object({ version: z.string() }).parse(JSON.parse(readFileSync(join(dir, "package.json"), "utf8")));

      expect(out.code).not.toBe(0);
      expect(after.version).toBe("1.0.0");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("P2: CLI --json usage errors emit a non-null error message", () => {
    const dir = makeTempDir("apm-audit-json-");

    try {
      const out = runCli(["explain", "--json"], dir);
      const parsed = z.object({ ok: z.boolean(), error: z.string().nullable() }).parse(JSON.parse(out.stdout));

      expect(out.code).toBe(2);
      expect(parsed.ok).toBe(false);
      expect(parsed.error).not.toBeNull();
      expect((parsed.error ?? "").length).toBeGreaterThan(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
