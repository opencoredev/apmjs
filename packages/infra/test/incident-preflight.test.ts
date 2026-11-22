// The incident preflight (incident-preflight.ts): each rule on its own, then the whole preflight against a real git
// repository, a stand-in for Cloudflare's deployments API, a release record of its own and a migration ledger handed in.
// It passes a clean app-only commit and refuses a dirty tree, a deploy-machinery change, an unrecorded live version and an
// Alchemy lock change; it reports the live release's install-check mode, which an incident deploy inherits.
import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  alchemyLockPins,
  checkoutDrift,
  checkoutSnapshot,
  evaluateMigrations,
  forbiddenInfraChanges,
  INCIDENT_PREFLIGHT_MARKER,
  isIncidentSafe,
  preflightLines,
  resolveIncidentInstallChecks,
  runIncidentPreflight,
  type MigrationSource,
} from "../incident-preflight.ts";
import { recordLiveRelease } from "../deploy-record.ts";
import type { Release } from "../releases.ts";
import { provenanceVars, type Cloudflare, type Deployment } from "../rollback.ts";

const TOKEN = "fake-cloudflare-token-that-must-never-be-printed";
const ACCOUNT = "0123456789abcdef0123456789abcdef";

describe("isIncidentSafe", () => {
  test("the marker alone, with a reason, or after blank and other comment lines", () => {
    expect(isIncidentSafe("-- apm:incident-safe\nALTER TABLE t ADD COLUMN c int;")).toBe(true);
    expect(isIncidentSafe("-- apm:incident-safe: adds a column nothing reads yet\nSELECT 1;")).toBe(true);
    expect(isIncidentSafe("-- apm:incident-safe reviewed by a person\nSELECT 1;")).toBe(true);
    expect(isIncidentSafe("\n\n-- adds the column\n-- apm:incident-safe\nSELECT 1;")).toBe(true);
    expect(isIncidentSafe("   -- apm:incident-safe   \nSELECT 1;")).toBe(true);
  });

  test("not after the first statement, not a lookalike, not the rollback marker", () => {
    expect(isIncidentSafe("SELECT 1;\n-- apm:incident-safe")).toBe(false);
    expect(isIncidentSafe("-- apm:incident-safely\nSELECT 1;")).toBe(false);
    expect(isIncidentSafe("-- apm:rollback-safe\nSELECT 1;")).toBe(false);
    expect(isIncidentSafe("")).toBe(false);
  });
});

describe("forbiddenInfraChanges", () => {
  test("allows app code and the infra tests", () => {
    expect(forbiddenInfraChanges(["packages/infra/test/rollback.test.ts", "packages/infra/test/fixtures/a/b.ts", "packages/registry/src/worker.ts", "apps/web/app/page.tsx", "packages/registry/scripts/dev.ts", "apps/web/package.json", "bun.lock"])).toEqual([]);
  });

  test("refuses the deploy machinery, the registry's build scripts and the root package.json", () => {
    const forbidden = [
      "packages/infra/deploy.ts",
      "packages/infra/alchemy.run.ts",
      "packages/infra/incident-preflight.ts",
      "packages/infra/smoke-fixtures/x/package.json",
      "packages/infra/package.json",
      "packages/registry/scripts/migrate.ts",
      "packages/registry/scripts/compat.ts",
      "packages/registry/scripts/build.ts",
      "packages/registry/scripts/build-test.ts",
      "package.json",
    ];

    expect(forbiddenInfraChanges([...forbidden, "apps/web/x.ts"])).toEqual(forbidden);
  });
});

/** A bun.lock in the form bun writes it (trailing commas), with the Alchemy version and one package's integrity given. */
function lockText(input: { alchemy: string; cloudflare: string; integrity?: string; extra?: string }): string {
  return `{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "root", "devDependencies": { "@alchemy.run/cloudflare-runtime": "${input.cloudflare}", "zod": "4.6.7", }, },
    "packages/infra": { "name": "@apm/infra", "dependencies": { "alchemy": "${input.alchemy}", "@alchemy.run/cloudflare": "${input.cloudflare}", "pg": "8.23.1", }, },
  },
  "packages": {
    "alchemy": ["alchemy@${input.alchemy}", "", {}, "sha512-alchemy"],
    "@alchemy.run/cloudflare": ["@alchemy.run/cloudflare@${input.cloudflare}", "", {}, "${input.integrity ?? "sha512-cloudflare"}"],
    "@alchemy.run/cloudflare-runtime": ["@alchemy.run/cloudflare-runtime@${input.cloudflare}", "", {}, "sha512-runtime"],
    "pg": ["pg@${input.extra ?? "8.23.1"}", "", {}, "sha512-pg"],
  },
}
`;
}

describe("alchemyLockPins", () => {
  const base = alchemyLockPins(lockText({ alchemy: "2.0.0-beta.85", cloudflare: "2.0.0-beta.85" }));

  test("finds every workspace spec and package entry, and a lock that changed elsewhere pins the same", () => {
    expect(base.ok).toBe(true);

    if (!base.ok) return;

    expect(Object.keys(base.pins)).toEqual([
      "package @alchemy.run/cloudflare",
      "package @alchemy.run/cloudflare-runtime",
      "package alchemy",
      "workspace (root) devDependencies @alchemy.run/cloudflare-runtime",
      "workspace packages/infra dependencies @alchemy.run/cloudflare",
      "workspace packages/infra dependencies alchemy",
    ]);
    const otherPg = alchemyLockPins(lockText({ alchemy: "2.0.0-beta.85", cloudflare: "2.0.0-beta.85", extra: "8.24.0" }));

    expect(otherPg).toEqual(base);
  });

  test("a changed alchemy or @alchemy.run/* version or integrity is a different pin", () => {
    expect(alchemyLockPins(lockText({ alchemy: "2.0.0-beta.86", cloudflare: "2.0.0-beta.85" }))).not.toEqual(base);
    expect(alchemyLockPins(lockText({ alchemy: "2.0.0-beta.85", cloudflare: "2.0.0-beta.86" }))).not.toEqual(base);
    expect(alchemyLockPins(lockText({ alchemy: "2.0.0-beta.85", cloudflare: "2.0.0-beta.85", integrity: "sha512-other" }))).not.toEqual(base);
  });

  test("the repository's own bun.lock reads", () => {
    const own = alchemyLockPins(readFileSync(join(import.meta.dir, "..", "..", "..", "bun.lock"), "utf8"));

    expect(own.ok).toBe(true);

    if (own.ok) expect(Object.keys(own.pins)).toContain("package alchemy");
  });

  test("a lock that is not JSONC, or not a bun.lock, is refused", () => {
    expect(alchemyLockPins("{ not json").ok).toBe(false);
    expect(alchemyLockPins('{ "lockfileVersion": 1 }').ok).toBe(false);
    expect(alchemyLockPins("").ok).toBe(false);
  });
});

describe("evaluateMigrations", () => {
  const sql = (text: string): Buffer => Buffer.from(text);
  const SAFE = sql("-- apm:incident-safe: reviewed\nALTER TABLE t ADD COLUMN c int;\n");
  const UNSAFE = sql("ALTER TABLE t DROP COLUMN c;\n");
  const FIRST = sql("CREATE TABLE t (id int);\n");

  function verdict(input: { applied: string[]; head: Record<string, Buffer>; deployed: Record<string, Buffer> }) {
    const candidate: MigrationSource[] = Object.entries(input.head).map(([id, bytes]) => ({ id, bytes }));

    return evaluateMigrations({ applied: input.applied, candidate, atHead: (id) => input.head[id] ?? null, atDeployed: (id) => input.deployed[id] ?? null });
  }

  test("nothing pending passes", () => {
    const v = verdict({ applied: ["0001_a"], head: { "0001_a": FIRST }, deployed: { "0001_a": FIRST } });

    expect(v).toEqual({ pending: [], appliedIssues: [], reasons: [] });
  });

  test("a pending migration marked incident-safe and unchanged since the deployed commit passes", () => {
    const v = verdict({ applied: ["0001_a"], head: { "0001_a": FIRST, "0002_b": SAFE }, deployed: { "0001_a": FIRST, "0002_b": SAFE } });

    expect(v.reasons).toEqual([]);
    expect(v.pending).toEqual([{ id: "0002_b", incidentSafe: true, unchangedSinceDeployed: true }]);
  });

  test("a pending migration not marked refuses, even one the deployed commit had", () => {
    const v = verdict({ applied: ["0001_a"], head: { "0001_a": FIRST, "0002_b": UNSAFE }, deployed: { "0001_a": FIRST, "0002_b": UNSAFE } });

    expect(v.reasons).toEqual(["pending migrations not marked -- apm:incident-safe: 0002_b"]);
  });

  test("a pending migration the candidate added or edited refuses, marked or not", () => {
    const added = verdict({ applied: ["0001_a"], head: { "0001_a": FIRST, "0002_b": SAFE }, deployed: { "0001_a": FIRST } });

    expect(added.reasons).toEqual(["pending migrations added or edited since the deployed commit: 0002_b"]);
    const edited = verdict({ applied: ["0001_a"], head: { "0001_a": FIRST, "0002_b": SAFE }, deployed: { "0001_a": FIRST, "0002_b": sql(`${SAFE.toString()}-- more\n`) } });

    expect(edited.reasons).toEqual(["pending migrations added or edited since the deployed commit: 0002_b"]);
  });

  test("an applied migration edited, removed, or re-added refuses; one already absent on the deployed commit passes", () => {
    const edited = verdict({ applied: ["0001_a"], head: { "0001_a": sql("CREATE TABLE t (id bigint);\n") }, deployed: { "0001_a": FIRST } });

    expect(edited.appliedIssues).toEqual(["0001_a is applied and was edited since the deployed commit"]);
    expect(edited.reasons).toHaveLength(1);
    const removed = verdict({ applied: ["0001_a", "0002_b"], head: { "0001_a": FIRST }, deployed: { "0001_a": FIRST, "0002_b": SAFE } });

    expect(removed.appliedIssues).toEqual(["0002_b is applied and was removed since the deployed commit"]);
    const readded = verdict({ applied: ["0001_a", "0002_old"], head: { "0001_a": FIRST, "0002_old": SAFE }, deployed: { "0001_a": FIRST } });

    expect(readded.appliedIssues).toEqual(["0002_old is applied and was re-added since the deployed commit"]);
    // historical ledger row already absent at deployed.sha (e.g. a renamed staging migration): unchanged
    const historical = verdict({ applied: ["0001_a", "0017_historical"], head: { "0001_a": FIRST }, deployed: { "0001_a": FIRST } });

    expect(historical).toEqual({ pending: [], appliedIssues: [], reasons: [] });
  });
});

describe("resolveIncidentInstallChecks", () => {
  test("inherits the live mode when neither the flag nor the environment asks", () => {
    expect(resolveIncidentInstallChecks({ argv: ["deploy", "--incident"], env: {}, deployed: "edge", requested: "database" })).toEqual({ kind: "ok", installChecks: "edge", inherited: true });
    expect(resolveIncidentInstallChecks({ argv: ["deploy", "--incident"], env: {}, deployed: "database", requested: "database" })).toEqual({ kind: "ok", installChecks: "database", inherited: true });
  });

  test("accepts an explicit mode that matches, refuses one that differs", () => {
    expect(resolveIncidentInstallChecks({ argv: ["--install-checks", "edge"], env: {}, deployed: "edge", requested: "edge" })).toEqual({ kind: "ok", installChecks: "edge", inherited: false });
    expect(resolveIncidentInstallChecks({ argv: [], env: { APM_INSTALL_CHECKS: "database" }, deployed: "edge", requested: "database" }).kind).toBe("refused");
    expect(resolveIncidentInstallChecks({ argv: ["--install-checks", "edge"], env: {}, deployed: "database", requested: "edge" }).kind).toBe("refused");
  });
});

test("deploy.ts carries the markers the incident helper checks for", () => {
  const text = readFileSync(join(import.meta.dir, "..", "deploy.ts"), "utf8");

  expect(INCIDENT_PREFLIGHT_MARKER).toBe("APM_INCIDENT_PREFLIGHT_V1");
  expect(text).toContain("APM_INCIDENT_PREFLIGHT_V1");
  expect(text).toContain("APM_RELEASE_LOCK");
  expect(text).toContain("--incident");
});

// ---------- against a real repository ----------
const dirs: string[] = [];

afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

function sh(cwd: string, args: readonly string[]): string {
  const run = Bun.spawnSync(["git", ...args], { cwd, stdout: "pipe", stderr: "pipe", env: { PATH: process.env.PATH ?? "", HOME: cwd, GIT_CONFIG_NOSYSTEM: "1" } });

  if (run.exitCode !== 0) throw new Error(`git ${args.join(" ")}: ${run.stderr.toString()}`);

  return run.stdout.toString().trim();
}

function put(repo: string, files: Readonly<Record<string, string>>): void {
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(repo, path)), { recursive: true });
    writeFileSync(join(repo, path), text);
  }
}

function commit(repo: string, files: Readonly<Record<string, string>>, message: string): string {
  put(repo, files);
  sh(repo, ["add", "-A"]);
  sh(repo, ["commit", "-q", "-m", message]);

  return sh(repo, ["rev-parse", "HEAD"]);
}

const LOCK = lockText({ alchemy: "2.0.0-beta.85", cloudflare: "2.0.0-beta.85" });
const M1 = "CREATE TABLE t (id int);\n";

/** A repository with one commit: what is deployed. */
function deployedRepo() {
  const repo = mkdtempSync(join(tmpdir(), "apm-incident-preflight-"));

  dirs.push(repo);
  sh(repo, ["init", "-q", "-b", "main"]);
  sh(repo, ["config", "user.email", "test@example.invalid"]);
  sh(repo, ["config", "user.name", "test"]);
  sh(repo, ["config", "commit.gpgsign", "false"]);

  const sha = commit(
    repo,
    {
      "package.json": '{ "name": "root" }\n',
      "bun.lock": LOCK,
      "packages/infra/deploy.ts": "// deploy\n",
      "packages/infra/test/a.test.ts": "// a\n",
      "packages/registry/scripts/migrate.ts": "// migrate\n",
      "packages/registry/migrations/0001_first.sql": M1,
      "apps/web/page.tsx": "export {};\n",
    },
    "deployed",
  );

  return { repo, sha };
}

describe("checkoutSnapshot and checkoutDrift", () => {
  test("unchanged is no drift; a changed tracked file, a new migration file, or a new commit is", () => {
    const { repo, sha } = deployedRepo();
    const before = checkoutSnapshot(repo);

    expect(before.ok).toBe(true);

    if (!before.ok) throw new Error(before.error);
    expect(before.head).toBe(sha);
    expect(before.trackedStatus).toBe("");
    expect(checkoutDrift(repo, before)).toBeNull();

    // an unrelated untracked file is not what a deploy builds or migrates from
    put(repo, { "notes.txt": "x\n" });
    expect(checkoutDrift(repo, before)).toBeNull();

    // an untracked migration file on disk IS drift so it cannot slip past preflight into migrate()
    put(repo, { "packages/registry/migrations/0099_sneaky.sql": "SELECT 1;\n" });
    expect(checkoutDrift(repo, before)).toContain("migration files on disk changed");
    rmSync(join(repo, "packages/registry/migrations/0099_sneaky.sql"));
    expect(checkoutDrift(repo, before)).toBeNull();

    put(repo, { "apps/web/page.tsx": "export const a = 1;\n" });
    const dirty = checkoutSnapshot(repo);

    expect(checkoutDrift(repo, before)).toContain("tracked");
    put(repo, { "apps/web/page.tsx": "export const a = 2;\n" });
    // same status line, other contents: the diff hash still tells
    expect(checkoutDrift(repo, dirty)).toContain("contents changed");

    put(repo, { "apps/web/page.tsx": "export {};\n" });
    expect(checkoutDrift(repo, before)).toBeNull();
    commit(repo, { "apps/web/other.ts": "export {};\n" }, "next");
    expect(checkoutDrift(repo, before)).toContain("HEAD moved");
  });

  test("an unreadable git index fails closed in checkoutSnapshot and checkoutDrift", () => {
    const { repo } = deployedRepo();
    const before = checkoutSnapshot(repo);

    expect(before.ok).toBe(true);
    const prev = process.env.GIT_INDEX_FILE;
    process.env.GIT_INDEX_FILE = "/dev/null";

    try {
      const failed = checkoutSnapshot(repo);

      expect(failed.ok).toBe(false);
      expect(checkoutDrift(repo, before)).toContain("could not be read");
      expect(checkoutDrift(repo, failed)).toContain("initial checkout could not be read");
    } finally {
      if (prev === undefined) delete process.env.GIT_INDEX_FILE;
      else process.env.GIT_INDEX_FILE = prev;
    }
  });
});

describe("runIncidentPreflight", () => {
  let server: ReturnType<typeof Bun.serve>;
  let cf: Cloudflare;
  let live: Map<string, Deployment[]>;

  beforeAll(() => {
    server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        if (req.headers.get("authorization") !== `Bearer ${TOKEN}`) return Response.json({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }, { status: 403 });
        const m = new RegExp(`^/client/v4/accounts/${ACCOUNT}/workers/scripts/([^/]+)/deployments$`).exec(new URL(req.url).pathname);
        const deployments = m === null ? undefined : live.get(decodeURIComponent(m[1] ?? ""));

        if (deployments === undefined) return Response.json({ success: false, errors: [{ code: 10007, message: "not found" }] }, { status: 404 });

        return Response.json({ success: true, errors: [], result: { deployments } });
      },
    });
    cf = { apiBase: `http://127.0.0.1:${server.port}/client/v4`, token: TOKEN, accountId: ACCOUNT };
  });

  afterAll(() => {
    void server.stop(true);
  });

  afterEach(() => {
    live = new Map();
  });

  function liveAt(versions: { registry: string; web: string }): void {
    live = new Map([
      ["apmjs-registry-production", [{ id: "d-reg", created_on: "2026-11-22T00:00:00Z", source: "api", versions: [{ version_id: versions.registry, percentage: 100 }] }]],
      ["apmjs-web-production", [{ id: "d-web", created_on: "2026-11-22T00:00:00Z", source: "api", versions: [{ version_id: versions.web, percentage: 100 }] }]],
    ]);
  }

  function line(sha: string, installChecks?: Release["installChecks"]): Release {
    const release: Release = {
      build: "1dc3b60c-0796-4c01-8518-196335d3e156",
      sha,
      stage: "production",
      at: "2026-11-22T00:00:00Z",
      manifest: ["0001_first"],
      workers: { registry: { script: "apmjs-registry-production", versionId: "reg-v1" }, web: { script: "apmjs-web-production", versionId: "web-v1" } },
    };

    // a line from before the field has none
    if (installChecks !== undefined) release.installChecks = installChecks;

    return release;
  }

  const run = (repo: string, releases: readonly Release[], applied: readonly string[] | null = ["0001_first"]) =>
    runIncidentPreflight({ cf, stage: "production", repo, releases, readAppliedMigrations: async () => applied });

  test("a clean app-only commit passes, with the live release's install-check mode", async () => {
    const { repo, sha } = deployedRepo();
    const head = commit(repo, { "apps/web/page.tsx": "export const fixed = true;\n", "packages/infra/test/b.test.ts": "// b\n" }, "fix");

    liveAt({ registry: "reg-v1", web: "web-v1" });
    const edge = await run(repo, [line(sha, "edge")]);

    expect(edge.evidence.reasons).toEqual([]);
    expect(edge.ok).toBe(true);
    expect(edge.deployed).toEqual({ build: "1dc3b60c-0796-4c01-8518-196335d3e156", sha, installChecks: "edge" });
    expect(edge.evidence).toMatchObject({ stage: "production", ok: true, checkout: { head, clean: true }, changedInfraFiles: [], alchemyLock: { kind: "same" }, pendingMigrations: [], appliedMigrationIssues: [] });

    // a line from before the field: the database mode
    const older = await run(repo, [line(sha)]);

    expect(older.ok).toBe(true);
    expect(older.deployed?.installChecks).toBe("database");

    const [verdict, evidence] = preflightLines(edge);

    expect(verdict).toBe("incident preflight: PASS");
    expect(JSON.parse(evidence)).toMatchObject({ stage: "production", ok: true, deployed: { sha } });
    expect(evidence).not.toContain(TOKEN);
  });

  test("a dirty tree refuses", async () => {
    const { repo, sha } = deployedRepo();

    put(repo, { "apps/web/page.tsx": "export const wip = 1;\n" });
    liveAt({ registry: "reg-v1", web: "web-v1" });
    const r = await run(repo, [line(sha)]);

    expect(r.ok).toBe(false);
    expect(r.evidence.checkout.clean).toBe(false);
    expect(r.evidence.reasons.join("\n")).toContain("tracked changes");
    expect(preflightLines(r)[0]).toStartWith("incident preflight: REFUSED: ");
  });

  test("a change to the deploy machinery or the root package.json refuses", async () => {
    const { repo, sha } = deployedRepo();

    commit(repo, { "packages/infra/deploy.ts": "// deploy, changed\n", "package.json": '{ "name": "root", "x": 1 }\n', "packages/registry/scripts/migrate.ts": "// changed\n" }, "infra");
    liveAt({ registry: "reg-v1", web: "web-v1" });
    const r = await run(repo, [line(sha)]);

    expect(r.ok).toBe(false);
    expect(r.evidence.changedInfraFiles).toEqual(["package.json", "packages/infra/deploy.ts", "packages/registry/scripts/migrate.ts"]);
  });

  test("a live version no release line names, a split, or a missing Worker refuses", async () => {
    const { repo, sha } = deployedRepo();

    liveAt({ registry: "reg-v2", web: "web-v1" });
    const unrecorded = await run(repo, [line(sha)]);

    expect(unrecorded.ok).toBe(false);
    expect(unrecorded.deployed).toBeNull();
    expect(unrecorded.evidence.reasons.join("\n")).toContain("no release-record line names the live pair");

    liveAt({ registry: "reg-v1", web: "web-v1" });
    live.set("apmjs-web-production", [{ id: "d", created_on: "2026-11-22T00:00:00Z", versions: [{ version_id: "web-v1", percentage: 50 }, { version_id: "web-v2", percentage: 50 }] }]);
    expect((await run(repo, [line(sha)])).evidence.reasons.join("\n")).toContain("does not route all its traffic to one version");

    live.delete("apmjs-web-production");
    expect((await run(repo, [line(sha)])).evidence.reasons.join("\n")).toContain("no such Worker");
  });

  test("a release line whose commit is dirty or unknown refuses", async () => {
    const { repo, sha } = deployedRepo();

    liveAt({ registry: "reg-v1", web: "web-v1" });
    expect((await run(repo, [line(`${sha}-dirty`)])).evidence.reasons.join("\n")).toContain("has no clean commit");
    expect((await run(repo, [line("f".repeat(40))])).evidence.reasons.join("\n")).toContain("is not in this repository");
  });

  test("a changed Alchemy pin in bun.lock refuses; another package's does not", async () => {
    const { repo, sha } = deployedRepo();

    commit(repo, { "bun.lock": lockText({ alchemy: "2.0.0-beta.85", cloudflare: "2.0.0-beta.85", extra: "8.24.0" }) }, "pg");
    liveAt({ registry: "reg-v1", web: "web-v1" });
    expect((await run(repo, [line(sha)])).ok).toBe(true);

    commit(repo, { "bun.lock": lockText({ alchemy: "2.0.0-beta.86", cloudflare: "2.0.0-beta.85" }) }, "alchemy");
    const r = await run(repo, [line(sha)]);

    expect(r.ok).toBe(false);
    expect(r.evidence.alchemyLock).toEqual({ kind: "changed", keys: ["package alchemy", "workspace packages/infra dependencies alchemy"] });
  });

  test("migrations: an added one, an unmarked pending one and an unreadable ledger refuse; a reviewed one passes", async () => {
    const { repo } = deployedRepo();
    const reviewed = commit(repo, { "packages/registry/migrations/0002_reviewed.sql": "-- apm:incident-safe: reviewed\nALTER TABLE t ADD COLUMN c int;\n", "packages/registry/migrations/0003_unmarked.sql": "ALTER TABLE t DROP COLUMN c;\n" }, "migrations");

    liveAt({ registry: "reg-v1", web: "web-v1" });
    // deployed already had both, applied only the first: 0003 is pending and unmarked
    const unmarked = await run(repo, [line(reviewed)]);

    expect(unmarked.ok).toBe(false);
    expect(unmarked.evidence.pendingMigrations).toEqual([
      { id: "0002_reviewed", incidentSafe: true, unchangedSinceDeployed: true },
      { id: "0003_unmarked", incidentSafe: false, unchangedSinceDeployed: true },
    ]);
    expect((await run(repo, [line(reviewed)], ["0001_first", "0003_unmarked"])).ok).toBe(true);

    commit(repo, { "packages/registry/migrations/0004_new.sql": "-- apm:incident-safe\nSELECT 1;\n" }, "new");
    const added = await run(repo, [line(reviewed)], ["0001_first", "0003_unmarked"]);

    expect(added.evidence.reasons).toEqual(["pending migrations added or edited since the deployed commit: 0004_new"]);

    const unreadable = await run(repo, [line(reviewed)], null);

    expect(unreadable.evidence.reasons).toEqual(["the stage's migration ledger could not be read (no neon-url, or the database did not answer in time)"]);
  });

  test("an unreadable git index fails closed even on a dirty tree", async () => {
    const { repo, sha } = deployedRepo();

    put(repo, { "apps/web/page.tsx": "export const wip = 1;\n" });
    liveAt({ registry: "reg-v1", web: "web-v1" });
    const prev = process.env.GIT_INDEX_FILE;
    process.env.GIT_INDEX_FILE = "/dev/null";

    try {
      const r = await run(repo, [line(sha)]);

      expect(r.ok).toBe(false);
      expect(r.evidence.checkout.clean).toBe(false);
      expect(r.evidence.reasons.join("\n")).toContain("could not be read");
    } finally {
      if (prev === undefined) delete process.env.GIT_INDEX_FILE;
      else process.env.GIT_INDEX_FILE = prev;
    }
  });
});

describe("recordLiveRelease beforeAppend guard", () => {
  test("refuses to append when beforeAppend detects drift after Cloudflare confirms live versions", async () => {
    const build = "1dc3b60c-0796-4c01-8518-196335d3e156";
    const sha = "a".repeat(40);
    const manifest = ["0001_first"];
    const stamp = provenanceVars(sha, build, manifest);
    const bindings = (extra: Record<string, string> = {}) => Object.entries({ ...stamp, ...extra }).map(([name, text]) => ({ type: "plain_text", name, text }));

    const srv = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        const path = new URL(req.url).pathname;

        if (path.endsWith("/deployments")) {
          const id = path.includes("registry") ? "reg-v1" : path.includes("web") ? "web-v1" : "docs-v1";

          return Response.json({ success: true, errors: [], result: { deployments: [{ id: "d1", created_on: "2026-11-22T00:00:00Z", versions: [{ version_id: id, percentage: 100 }] }] } });
        }

        if (path.includes("/versions/")) {
          const extra: Record<string, string> = path.includes("registry") ? { APM_INSTALL_CHECKS: "edge" } : {};

          return Response.json({ success: true, errors: [], result: { resources: { bindings: bindings(extra) } } });
        }

        return Response.json({ success: false, errors: [] }, { status: 404 });
      },
    });

    try {
      const appended: Release[] = [];
      let checks = 0;

      const recorded = await recordLiveRelease({
        cf: { apiBase: `http://127.0.0.1:${srv.port}/client/v4`, token: TOKEN, accountId: ACCOUNT },
        stage: "production",
        build,
        sha,
        manifest,
        installChecks: "edge",
        beforeAppend: () => {
          checks++;

          return "the checkout changed since this deploy started: HEAD moved";
        },
        append: (r) => appended.push(r),
      });

      expect(checks).toBe(1);
      expect(appended).toEqual([]);
      expect(recorded).toEqual({ kind: "not-recorded", why: "the checkout changed since this deploy started: HEAD moved" });

      // if beforeAppend itself consumes the remaining deadline, do not append after expiry
      const lateAppended: Release[] = [];

      const late = await recordLiveRelease({
        cf: { apiBase: `http://127.0.0.1:${srv.port}/client/v4`, token: TOKEN, accountId: ACCOUNT },
        stage: "production",
        build,
        sha,
        manifest,
        installChecks: "edge",
        deadlineMs: 60,
        beforeAppend: () => {
          Bun.sleepSync(80);

          return null;
        },
        append: (r) => lateAppended.push(r),
      });

      expect(lateAppended).toEqual([]);
      expect(late.kind).toBe("not-recorded");
    } finally {
      void srv.stop(true);
    }
  });
});
