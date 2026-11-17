// The rollback tooling against a stand-in for Cloudflare's Workers deployments API and a release record of its own
// (APM_RELEASES_LEDGER): the manual command (rollback.ts) lists, plans and rolls back without printing the token, takes
// the website back before the registry, refuses while the release lock is held, refuses any target no canonical line of
// the record names, refuses unless that line's migration manifest fits the migration ledger and the registry and website
// left live are named by one line, and refuses to change a Worker that someone changed after it planned. The record
// itself: deploy.ts writes each Worker's live version after its smoke check passed (deploy-record.ts), a torn last line
// never swallows the next record, and a build id whose lines disagree is trusted nowhere.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import type { Release } from "../releases.ts";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "pg";
import { z } from "zod";
import { emptyDatabase } from "../../../tests/acceptance/postgres.ts";
import { migrationFiles } from "../../registry/scripts/migrate.ts";
import { recordLiveRelease, type Recording } from "../deploy-record.ts";
import { finishDeploy, recoveryAdvice, smokeCommand } from "../deploy-finish.ts";
import { appendRelease, readReleases, releaseNamingAll } from "../releases.ts";
import { halfAnswering } from "../../../tests/acceptance/half-answering.ts";
import { CloudflareError, isRollbackSafe, ledgerOf, migrationCheck, previousOf, provenanceVars, unsafeMigrations, type Cloudflare, type Deployment, type WorkerKind } from "../rollback.ts";

const TOKEN = "fake-cloudflare-token-that-must-never-be-printed";
const ACCOUNT = "0123456789abcdef0123456789abcdef";

type Posted = { script: string; force: string | null; versions: unknown; message: unknown };

const Post = z.object({ strategy: z.literal("percentage"), versions: z.array(z.object({ version_id: z.string(), percentage: z.number() })), annotations: z.object({ "workers/message": z.string() }) });

let server: ReturnType<typeof Bun.serve>;
let api: string;
let deployments: Map<string, Deployment[]>;
let posted: Posted[];
let failPosts: boolean;

/** Each version's plain-text variables, as Cloudflare's version settings give them; a version not here answers 404. */
let versionVars: Map<string, Record<string, string>>;

/** When set, every read of a deployment list answers with this status (Cloudflare having a bad minute). */
let failLists: number | null;

/** How long the stand-in takes to answer each request: a slow API. */
let delayMs: number;

/** A change the stand-in makes to a Worker's deployments on the nth list of them: someone deploying mid-rollback. */
let onList: Map<string, { at: number; change: () => void }>;
let lists: Map<string, number>;

/** The release record: what each deploy run left live once its smoke check passed (deploy.ts appends it). */
let releases: Release[];

/** Every migration in the repository: what the live database's ledger holds. */
const ALL = migrationFiles().map((m) => m.id);
const NEWEST = ALL.at(-1) ?? "";
const [B1, B2, B3, B4, B5] = ["aaaa0001", "aaaa0002", "aaaa0003", "aaaa0004", "aaaa0005"] as const;

function dep(id: string, version: string, at: string): Deployment {
  return { id, created_on: at, source: "api", versions: [{ version_id: version, percentage: 100 }] };
}

function release(build: string, manifest: readonly string[], versions: Partial<Record<WorkerKind, string>>): Release {
  const workers = Object.fromEntries(Object.entries(versions).map(([kind, versionId]) => [kind, { script: `apmjs-${kind}-production`, versionId }]));

  return { build, sha: `sha-of-${build}`, stage: "production", at: "2026-11-16T00:00:00Z", manifest: [...manifest], workers };
}

function reset(): void {
  onList = new Map();
  lists = new Map();
  deployments = new Map([
    ["apmjs-registry-production", [dep("r3", "rv3", "2026-11-16T10:00:00Z"), dep("r2", "rv2", "2026-11-15T10:00:00Z"), dep("r1", "rv1", "2026-11-14T10:00:00Z")]],
    ["apmjs-web-production", [dep("w2", "wv2", "2026-11-16T10:01:00Z"), dep("w1", "wv1", "2026-11-15T10:01:00Z")]],
    ["apmjs-docs-production", [dep("d1", "dv1", "2026-11-14T10:02:00Z")]],
  ]);
  posted = [];
  failPosts = false;
  versionVars = new Map();
  failLists = null;
  delayMs = 0;
  // one line per deploy run: rv2 and wv1 went out together, rv3 and wv2, rv4 and wv3; rv1 was built before the newest
  // migration existed
  releases = [
    release(B1, ALL.slice(0, -1), { registry: "rv1", docs: "dv1" }),
    release(B2, ALL, { registry: "rv2", web: "wv1", docs: "dv0" }),
    release(B3, ALL, { registry: "rv3", web: "wv2" }),
    release(B4, ALL, { registry: "rv4", web: "wv3" }),
  ];
}

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      if (delayMs > 0) await Bun.sleep(delayMs);

      if (req.headers.get("authorization") !== `Bearer ${TOKEN}`) return Response.json({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }, { status: 403 });
      const url = new URL(req.url);

      if (url.pathname === "/client/v4/accounts") return Response.json({ success: true, result: [{ id: ACCOUNT }] });
      const v = new RegExp(`^/client/v4/accounts/${ACCOUNT}/workers/scripts/([^/]+)/versions/([^/]+)$`).exec(url.pathname);

      if (v !== null) {
        const vars = versionVars.get(decodeURIComponent(v[2] ?? ""));

        if (vars === undefined) return Response.json({ success: false, errors: [{ code: 10007, message: "version not found" }] }, { status: 404 });
        const bindings = [{ type: "secret_text", name: "APM_AUTH_SECRET" }, { type: "r2_bucket", name: "BLOBS", bucket_name: "b" }, ...Object.entries(vars).map(([name, text]) => ({ type: "plain_text", name, text }))];

        return Response.json({ success: true, result: { id: v[2], number: 1, metadata: {}, resources: { bindings, script: {}, script_runtime: {} } } });
      }

      if (failLists !== null && req.method === "GET") return Response.json({ success: false, errors: [{ code: 10013, message: "service unavailable" }] }, { status: failLists });
      const m = new RegExp(`^/client/v4/accounts/${ACCOUNT}/workers/scripts/([^/]+)/deployments$`).exec(url.pathname);
      const script = decodeURIComponent(m?.[1] ?? "");
      const list = deployments.get(script);

      if (m === null || list === undefined) return Response.json({ success: false, errors: [{ code: 10007, message: "This Worker does not exist on your account." }] }, { status: 404 });

      if (req.method === "GET") {
        const n = (lists.get(script) ?? 0) + 1;

        lists.set(script, n);

        if (onList.get(script)?.at === n) onList.get(script)?.change();

        return Response.json({ success: true, result: { deployments: [...(deployments.get(script) ?? list)].reverse() } });
      }

      if (failPosts) return Response.json({ success: false, errors: [{ code: 10021, message: "deployment refused" }] }, { status: 400 });
      const body = Post.parse(await req.json());
      posted.push({ script, force: url.searchParams.get("force"), versions: body.versions, message: body.annotations["workers/message"] });
      const made: Deployment = { id: `new-${posted.length}`, created_on: new Date(Date.parse("2026-11-16T12:00:00Z") + posted.length * 1000).toISOString(), source: "api", versions: body.versions };
      deployments.set(script, [made, ...list]);

      return Response.json({ success: true, result: made });
    },
  });
  api = `http://127.0.0.1:${server.port}/client/v4`;
});

afterAll(async () => {
  await server.stop(true);
});

beforeEach(reset);

const cf = (): Cloudflare => ({ apiBase: api, token: TOKEN, accountId: ACCOUNT });

describe("migration markers", () => {
  test("a migration is rollback-safe only when its leading comment says so", () => {
    expect(isRollbackSafe("-- adds a table\n-- apm:rollback-safe: additive only\nCREATE TABLE t (id int);\n")).toBe(true);
    expect(isRollbackSafe("-- apm:no-transaction\n-- apm:rollback-safe\nCREATE INDEX CONCURRENTLY i ON t (id);\n")).toBe(true);
    expect(isRollbackSafe("-- drops a column\nALTER TABLE t DROP COLUMN c;\n")).toBe(false);
    // a marker after the first statement is not the file's header
    expect(isRollbackSafe("CREATE TABLE t (id int);\n-- apm:rollback-safe\n")).toBe(false);
    expect(isRollbackSafe("-- apm:rollback-safety reviewed\nSELECT 1;\n")).toBe(false);
  });

  test("an applied migration with no marker, or no file, is not safe", () => {
    const ids = migrationFiles().map((m) => m.id);

    expect(unsafeMigrations(ids)).toEqual(ids);
    expect(unsafeMigrations(["9999_unknown"])).toEqual(["9999_unknown"]);
  });
});

describe("previousOf", () => {
  test("skips deployments that run the live versions", () => {
    const list = [dep("c", "v2", "3"), dep("b", "v2", "2"), dep("a", "v1", "1")];

    expect(previousOf(list)?.id).toBe("a");
    expect(previousOf([dep("only", "v1", "1")])).toBeNull();
  });
});

describe("rollback.ts, the manual command", () => {
  let secrets: string;

  beforeAll(() => {
    secrets = mkdtempSync(join(tmpdir(), "apm-rollback-secrets-"));
    writeFileSync(join(secrets, "cloudflare-token"), `${TOKEN}\n`, { mode: 0o600 });
  });

  afterAll(() => rmSync(secrets, { recursive: true, force: true }));

  async function cli(args: string[]): Promise<{ code: number; out: string }> {
    const record = join(secrets, "releases.jsonl");

    writeFileSync(record, releases.map((r) => `${JSON.stringify(r)}\n`).join(""), { mode: 0o600 });

    const proc = Bun.spawn(["bun", join(import.meta.dir, "..", "rollback.ts"), ...args], {
      env: { PATH: process.env.PATH ?? "", HOME: secrets, APM_SECRETS_DIR: secrets, APM_CLOUDFLARE_API: api, APM_RELEASE_LOCK: join(secrets, "release.lock"), APM_RELEASES_LEDGER: record },
      stdout: "pipe",
      stderr: "pipe",
    });

    const [stdout, stderr, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);

    return { code, out: stdout + stderr };
  }

  test("list shows each Worker's recent deployments, live first, and never the token", async () => {
    const r = await cli(["list", "--stage", "production"]);

    expect(r.code).toBe(0);
    expect(r.out).toContain("apmjs-registry-production:");
    expect(r.out).toMatch(/live {2}r3 {2}2026-11-16T10:00:00Z/);
    expect(r.out).toContain("apmjs-docs-production:");
    expect(r.out).not.toContain(TOKEN);
    expect(posted).toEqual([]);
  });

  test("without --yes it plans and changes nothing", async () => {
    const r = await cli(["previous", "--stage", "production", "--skip-migration-check"]);

    expect(r.code).toBe(0);
    expect(r.out).toContain("would roll back apmjs-web-production: live w2 → deployment w1");
    expect(r.out).toContain("would roll back apmjs-registry-production: live r3 → deployment r2");
    expect(r.out).toContain("Nothing changed");
    expect(posted).toEqual([]);
  });

  test("previous --yes takes the website back, then the registry, each to its deployment before the live one", async () => {
    const r = await cli(["previous", "--stage", "production", "--skip-migration-check", "--yes"]);

    expect(r.code).toBe(0);
    expect(posted.map((p) => [p.script, p.force, p.versions])).toEqual([
      ["apmjs-web-production", "true", [{ version_id: "wv1", percentage: 100 }]],
      ["apmjs-registry-production", "true", [{ version_id: "rv2", percentage: 100 }]],
    ]);
    expect(r.out).not.toContain(TOKEN);
  });

  test("to --build takes the website and the registry back to the pair one deploy made; docs go back on their own", async () => {
    expect((await cli(["to", "--stage", "production", "--build", B2, "--skip-migration-check", "--yes"])).code).toBe(0);
    expect((await cli(["to", "--stage", "production", "--worker", "docs", "--version", "dv0", "--skip-migration-check", "--yes"])).code).toBe(0);
    expect(posted.map((p) => [p.script, p.versions])).toEqual([
      ["apmjs-web-production", [{ version_id: "wv1", percentage: 100 }]],
      ["apmjs-registry-production", [{ version_id: "rv2", percentage: 100 }]],
      ["apmjs-docs-production", [{ version_id: "dv0", percentage: 100 }]],
    ]);
    const missing = await cli(["to", "--stage", "production", "--worker", "registry", "--deployment", "nope", "--skip-migration-check", "--yes"]);

    expect(missing.code).toBe(1);
    expect(missing.out).toContain("no deployment nope");
  });

  test("it refuses when it cannot read the stage's migration ledger", async () => {
    const r = await cli(["previous", "--stage", "production", "--yes"]);

    expect(r.code).toBe(1);
    expect(r.out).toContain("ledger could not be read");
    expect(r.out).toContain("--skip-migration-check");
    expect(posted).toEqual([]);
  });

  test("it refuses a registry version no recorded deploy run left live, whatever its variables say", async () => {
    // a dashboard edit that kept rv2's variables, or a version whose stamps were invented: Cloudflare would answer with
    // the same APM_BUILD and manifest, but the release record never saw an upload of it
    const r = await cli(["to", "--stage", "production", "--worker", "registry", "--version", "rv-copy", "--skip-migration-check", "--yes"]);

    expect(r.code).toBe(1);
    expect(r.out).toContain("apmjs-registry-production rv-copy, apmjs-web-production wv2, which no one line of the release record");
    expect(posted).toEqual([]);
  });

  test("a registry rollback alone is refused when the website live with it is from another deploy; so is the website alone", async () => {
    // rv2 went out with wv1, and the website runs wv2
    const registry = await cli(["to", "--stage", "production", "--worker", "registry", "--deployment", "r2", "--skip-migration-check", "--yes"]);

    expect(registry.code).toBe(1);
    expect(registry.out).toContain("which no one line of the release record");
    expect(registry.out).toContain("--build");
    const web = await cli(["to", "--stage", "production", "--worker", "web", "--deployment", "w1", "--skip-migration-check", "--yes"]);

    expect(web.code).toBe(1);
    expect(web.out).toContain("which no one line of the release record");
    expect(posted).toEqual([]);
  });

  test("every version receiving traffic is checked, not only the first", async () => {
    // a split registry deployment whose second version no recorded run left live
    deployments.set("apmjs-registry-production", [dep("r3", "rv3", "2026-11-16T10:00:00Z"), { id: "r-split", created_on: "2026-11-15T12:00:00Z", source: "api", versions: [{ version_id: "rv2", percentage: 90 }, { version_id: "rv-copy", percentage: 10 }] }, dep("r1", "rv1", "2026-11-14T10:00:00Z")]);
    const split = await cli(["to", "--stage", "production", "--worker", "registry", "--deployment", "r-split", "--skip-migration-check", "--yes"]);

    expect(split.code).toBe(1);
    expect(split.out).toContain("apmjs-registry-production rv-copy");
    expect(split.out).toContain("which no one line of the release record");
    // the website live with a registry rollback is checked whole too: a split across two builds is no pair
    deployments.set("apmjs-web-production", [{ id: "w-split", created_on: "2026-11-16T10:05:00Z", source: "api", versions: [{ version_id: "wv1", percentage: 50 }, { version_id: "wv2", percentage: 50 }] }, dep("w1", "wv1", "2026-11-15T10:01:00Z")]);
    const pair = await cli(["to", "--stage", "production", "--worker", "registry", "--deployment", "r1", "--skip-migration-check", "--yes"]);

    expect(pair.code).toBe(1);
    expect(pair.out).toContain("which no one line of the release record");
    expect(posted).toEqual([]);
  });

  test("a pair is trusted only when one line names both: two lines sharing a build id do not make one", async () => {
    // rv9 and wv9, each recorded on its own line under the same build id: each version maps to build B9, but no line
    // names them together, and the two lines disagree
    releases.push(release("bbbb0009", ALL, { registry: "rv9" }), release("bbbb0009", ALL, { web: "wv9" }));
    deployments.set("apmjs-registry-production", [dep("r9", "rv9", "2026-11-16T09:00:00Z"), ...(deployments.get("apmjs-registry-production") ?? [])]);
    const r = await cli(["to", "--stage", "production", "--worker", "web", "--version", "wv9", "--skip-migration-check", "--yes"]);

    expect(r.code).toBe(1);
    expect(r.out).toContain("build bbbb0009 has lines that disagree");
    expect(r.out).toContain("which no one line of the release record");
    expect(posted).toEqual([]);
  });

  test("just before each change it reads what is live again: a Worker someone changed after the plan is left alone", async () => {
    // the plan lists the registry once; someone deploys before the registry's step, which lists it again
    onList.set("apmjs-registry-production", { at: 2, change: () => deployments.set("apmjs-registry-production", [dep("someone", "rv5", "2026-11-16T12:30:00Z"), ...(deployments.get("apmjs-registry-production") ?? [])]) });
    const r = await cli(["to", "--stage", "production", "--build", B2, "--skip-migration-check", "--yes"]);

    expect(r.code).toBe(1);
    expect(r.out).toContain("NOT rolling back apmjs-registry-production: its live deployment is now someone, not r3 as planned");
    // the website went first, as planned; the registry was not touched
    expect(posted.map((p) => p.script)).toEqual(["apmjs-web-production"]);
  });

  test("a live version the record does not name (a dashboard deploy) stops the rollback before it changes that Worker", async () => {
    deployments.set("apmjs-web-production", [dep("dash", "wv-dashboard", "2026-11-16T12:00:00Z"), ...(deployments.get("apmjs-web-production") ?? [])]);
    const r = await cli(["to", "--stage", "production", "--build", B2, "--skip-migration-check", "--yes"]);

    expect(r.code).toBe(1);
    expect(r.out).toContain("apmjs-web-production runs wv-dashboard, which no line of the release record names");
    expect(r.out).toContain("fix forward");
    expect(r.out).not.toContain("not deployed through deploy.ts");
    expect(posted).toEqual([]);
  });

  test("the plan already refuses to replace a live version the record does not name (a failed deploy's upload), and says to fix forward", async () => {
    deployments.set("apmjs-registry-production", [dep("r9", "rv9", "2026-11-16T12:00:00Z"), ...(deployments.get("apmjs-registry-production") ?? [])]);
    const r = await cli(["to", "--stage", "production", "--build", B2, "--skip-migration-check"]);

    expect(r.code).toBe(1);
    expect(r.out).toContain("Not rolling back: apmjs-registry-production runs rv9, which no line of the release record names");
    expect(r.out).toContain("fix forward: deploy a fixed commit with bun packages/infra/deploy.ts deploy --stage production");
    expect(r.out).not.toContain("Run again with --yes");
    expect(posted).toEqual([]);
  });

  test("a live deployment that routes traffic to no version is never treated as recorded: nothing is replaced", async () => {
    // an empty version list, or one whose only share is 0%: nothing the release record could name runs there
    for (const versions of [[], [{ version_id: "wv2", percentage: 0 }]]) {
      reset();
      deployments.set("apmjs-web-production", [{ id: "w-none", created_on: "2026-11-16T12:00:00Z", source: "api", versions }, ...(deployments.get("apmjs-web-production") ?? [])]);
      const r = await cli(["to", "--stage", "production", "--build", B2, "--skip-migration-check", "--yes"]);

      expect(r.code).toBe(1);
      expect(r.out).toContain("apmjs-web-production's live deployment w-none, which routes traffic to no version");
      expect(r.out).toContain("fix forward");
      expect(posted).toEqual([]);
    }
  });

  test("just before a change, a live deployment that now routes traffic to no version stops that Worker", async () => {
    // the plan saw r3 running rv3; when the registry's step reads it again, the same deployment names no version
    onList.set("apmjs-registry-production", { at: 2, change: () => deployments.set("apmjs-registry-production", [{ id: "r3", created_on: "2026-11-16T10:00:00Z", source: "api", versions: [] }, ...(deployments.get("apmjs-registry-production") ?? []).slice(1)]) });
    const r = await cli(["to", "--stage", "production", "--build", B2, "--skip-migration-check", "--yes"]);

    expect(r.code).toBe(1);
    expect(r.out).toContain("NOT rolling back apmjs-registry-production: apmjs-registry-production's live deployment r3, which routes traffic to no version");
    expect(posted.map((p) => p.script)).toEqual(["apmjs-web-production"]);
  });

  test("while someone else holds the release lock it changes nothing, and says so", async () => {
    // the incident helper's flock on the same file (APM_RELEASE_LOCK)
    const lock = join(secrets, "release.lock");
    const held = Bun.spawn(["python3", "-c", `import fcntl, time\nf = open(${JSON.stringify(lock)}, "a+")\nfcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)\nprint("held", flush=True)\ntime.sleep(20)`], { stdout: "pipe" });

    try {
      await new Response(held.stdout).body?.getReader().read();
      const r = await cli(["previous", "--stage", "production", "--skip-migration-check", "--yes"]);

      expect(r.code).toBe(6);
      expect(r.out).toContain("APM_RELEASE_LOCK");
      expect(r.out).toContain("is held by");
      expect(posted).toEqual([]);
    } finally {
      held.kill();
      await held.exited;
    }
  });

  test("the website and docs are checked against the ledger too: without it nothing goes back", async () => {
    const r = await cli(["to", "--stage", "production", "--worker", "docs", "--version", "dv0", "--yes"]);

    expect(r.code).toBe(1);
    expect(r.out).toContain("ledger could not be read");
    expect(posted).toEqual([]);
  });
});

describe("the schema check", () => {
  let db: { url: string; drop: () => Promise<void> };

  beforeAll(async () => {
    db = await emptyDatabase();
    const c = new Client({ connectionString: db.url });
    await c.connect();
    await c.query("CREATE TABLE apm_migrations (id text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())");
    // when each ran does not matter: what matters is which schema the target version's code was written for
    await c.query("INSERT INTO apm_migrations (id, applied_at) SELECT unnest($1::text[]), '2026-01-01T00:00:00Z'", [ALL]);
    await c.end();
  });

  afterAll(async () => {
    await db?.drop();
  });

  test("the ledger is read whole from the database, and a server that stops answering costs no more than the deadline", async () => {
    expect(await ledgerOf(db.url)).toEqual(ALL);
    expect(await ledgerOf(null)).toBeNull();
    const stalled = await halfAnswering();

    try {
      const t0 = performance.now();

      expect(await ledgerOf(stalled.url, 500)).toBeNull();
      expect(performance.now() - t0).toBeLessThan(900);
      await Bun.sleep(200);
      // its connection was destroyed, not left waiting for the rest of the answer
      expect(stalled.open()).toBe(0);
    } finally {
      await stalled.stop();
    }
  });

  /** The check for a registry version, with the manifest its recorded run wrote down. */
  const check = (version: string, ledger: () => Promise<readonly string[] | null> = () => ledgerOf(db.url)) => {
    const manifest = releases.find((r) => r.workers.registry?.versionId === version)?.manifest ?? [];

    return migrationCheck({ manifests: [{ version, migrations: manifest }], ledger });
  };

  test("a version built before the newest migration is refused, even if it was deployed again after it ran", async () => {
    deployments.set("apmjs-registry-production", [dep("r9", "rv3", "2026-11-17T00:00:00Z"), dep("r8", "rv1", "2026-11-16T23:00:00Z"), ...(deployments.get("apmjs-registry-production") ?? [])]);

    expect(await check("rv1")).toEqual({ kind: "unsafe", ids: [NEWEST] });
  });

  test("an applied migration outside the manifest is checked wherever it sorts: one added later with a lower number is refused", async () => {
    expect(await check("rv3", async () => [...ALL, "0020_late_drop_column"])).toEqual({ kind: "unsafe", ids: ["0020_late_drop_column"] });
  });

  test("a manifest naming a migration the database has not applied is refused, however high its number", async () => {
    releases.push(release(B5, [...ALL, "9999_future"], { registry: "rv-future" }));

    expect(await check("rv-future")).toEqual({ kind: "not-applied", version: "rv-future", ids: ["9999_future"] });
  });

  test("a version built with every applied migration passes; a ledger that cannot be read does not", async () => {
    expect(await check("rv3")).toEqual({ kind: "ok", extra: [] });
    expect(await check("rv3", async () => null)).toEqual({ kind: "unreadable" });
  });

  test("the stamp on each upload splits a long manifest into parts that each fit a Worker variable", () => {
    const many = Array.from({ length: 400 }, (_, i) => `${String(i).padStart(4, "0")}_a_migration_with_a_long_descriptive_name`);
    const vars = provenanceVars("commit-y", B5, many);
    const parts = Number(vars.APM_MIGRATIONS_PARTS);

    expect(parts).toBeGreaterThan(1);
    expect(Object.values(vars).every((v) => v.length <= 4_000)).toBe(true);
    expect(Array.from({ length: parts }, (_, i) => vars[`APM_MIGRATIONS_${i}`]).join("")).toBe(many.join(","));
  });
});

describe("the release record", () => {
  let dir: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "apm-releases-"));
  });

  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  test("a torn last line stays a broken line of its own: the next record is never glued to it", () => {
    const path = join(dir, "torn.jsonl");
    const first = release(B1, ALL, { registry: "rv1", web: "wv0", docs: "dv1" });

    // a write cut short: half a line, no newline
    writeFileSync(path, `${JSON.stringify(first)}\n{"build":"aaaa0002","sha":"cut`, { mode: 0o600 });
    appendRelease(release(B3, ALL, { registry: "rv3", web: "wv2", docs: "dv1" }), path);

    expect(readReleases("production", path).map((r) => r.build)).toEqual([B1, B3]);
    expect(readFileSync(path, "utf8").split("\n")[1]).toBe('{"build":"aaaa0002","sha":"cut');
  });

  test("no live versions at all is named by no line: an empty set never matches vacuously", () => {
    const lines = [release(B2, ALL, { registry: "rv2", web: "wv1" })];

    expect(releaseNamingAll(lines, [])).toBeNull();
    expect(releaseNamingAll(lines, [{ script: "apmjs-registry-production", versionId: "rv2" }])?.build).toBe(B2);
  });

  test("a build id whose lines disagree is trusted nowhere; the same line twice counts once", () => {
    const path = join(dir, "dupes.jsonl");
    const same = release(B2, ALL, { registry: "rv2", web: "wv1", docs: "dv0" });

    for (const r of [same, same, release(B3, ALL, { registry: "rv3", web: "wv2", docs: "dv0" }), release(B3, ALL, { registry: "rv-other", web: "wv2", docs: "dv0" })]) appendRelease(r, path);

    expect(readReleases("production", path).map((r) => r.build)).toEqual([B2]);
  });
});

describe("deploy-record.ts, after a deploy whose smoke check passed", () => {
  const stamp = (build: string, manifest: readonly string[] = ALL, sha = `sha-of-${build}`) => provenanceVars(sha, build, manifest);

  const record = (extra: { deadlineMs?: number } = {}) => {
    const written: Release[] = [];
    const done = recordLiveRelease({ cf: cf(), stage: "production", build: B5, sha: `sha-of-${B5}`, manifest: ALL, append: (r) => void written.push(r), deadlineMs: extra.deadlineMs ?? 400, intervalMs: 20 });

    return { written, done };
  };

  test("it records each Worker's live version once the registry's and the website's variables say this run's build", async () => {
    versionVars.set("rv3", stamp(B5));
    versionVars.set("wv2", stamp(B5));
    const { written, done } = record();

    expect((await done).kind).toBe("recorded");
    expect(written).toEqual([
      {
        build: B5,
        sha: `sha-of-${B5}`,
        stage: "production",
        at: expect.any(String),
        manifest: ALL,
        workers: {
          registry: { script: "apmjs-registry-production", versionId: "rv3" },
          web: { script: "apmjs-web-production", versionId: "wv2" },
          // assets-only: it keeps no variables, so what is live is recorded as it is
          docs: { script: "apmjs-docs-production", versionId: "dv1" },
        },
      },
    ]);
  });

  test("a stale deployment list naming an older version is never labelled with this run: it waits, then records nothing", async () => {
    // the list still names rv3, built by B3, after this run uploaded its own
    versionVars.set("rv3", stamp(B3));
    versionVars.set("wv2", stamp(B5));
    const { written, done } = record();
    const r = await done;

    expect(r.kind).toBe("not-recorded");
    expect(r.kind === "not-recorded" ? r.why : "").toContain(`apmjs-registry-production version rv3 says build ${B3}, not this run's ${B5}`);
    expect(written).toEqual([]);
  });

  test("once the list catches up it records the version this run uploaded", async () => {
    versionVars.set("rv3", stamp(B3));
    versionVars.set("rv5", stamp(B5));
    versionVars.set("wv2", stamp(B5));
    onList.set("apmjs-registry-production", { at: 2, change: () => deployments.set("apmjs-registry-production", [dep("r5", "rv5", "2026-11-16T12:00:00Z"), ...(deployments.get("apmjs-registry-production") ?? [])]) });
    const { written, done } = record({ deadlineMs: 5_000 });

    expect((await done).kind).toBe("recorded");
    expect(written[0]?.workers.registry?.versionId).toBe("rv5");
  });

  test("the same build id with another revision or manifest is not this run", async () => {
    versionVars.set("rv3", stamp(B5, ALL.slice(0, -1)));
    versionVars.set("wv2", stamp(B5, ALL, "sha-of-something-else"));
    const revision = await record().done;

    expect(revision.kind === "not-recorded" ? revision.why : "").toContain("apmjs-web-production version wv2 says build aaaa0005 but differs from this run's stamp in APM_REVISION");
    versionVars.set("wv2", stamp(B5));
    const { written, done } = record();
    const manifest = await done;

    expect(manifest.kind === "not-recorded" ? manifest.why : "").toContain("differs from this run's stamp in APM_MIGRATIONS_SHA256, APM_MIGRATIONS_0");
    expect(written).toEqual([]);
  });

  test("one deadline bounds the whole recording: a slow API that would match after it records nothing", async () => {
    versionVars.set("rv3", stamp(B5));
    versionVars.set("wv2", stamp(B5));
    // five reads of 40 ms each against a 100 ms budget: every answer matches, but only after the deadline
    delayMs = 40;
    const t0 = performance.now();
    const { written, done } = record({ deadlineMs: 100 });
    const r = await done;

    expect(r.kind).toBe("not-recorded");
    expect(r.kind === "not-recorded" ? r.why : "").toContain("100 ms");
    expect(written).toEqual([]);
    // the request in flight at the deadline is cut short, not waited out
    expect(performance.now() - t0).toBeLessThan(180);
  });

  test("stale reads that catch up within the deadline, slowly, still record", async () => {
    versionVars.set("rv3", stamp(B3));
    versionVars.set("rv5", stamp(B5));
    versionVars.set("wv2", stamp(B5));
    delayMs = 25;
    onList.set("apmjs-registry-production", { at: 2, change: () => deployments.set("apmjs-registry-production", [dep("r5", "rv5", "2026-11-16T12:00:00Z"), ...(deployments.get("apmjs-registry-production") ?? [])]) });
    const t0 = performance.now();
    const { written, done } = record({ deadlineMs: 3_000 });

    expect((await done).kind).toBe("recorded");
    expect(written[0]?.workers.registry?.versionId).toBe("rv5");
    expect(performance.now() - t0).toBeLessThan(3_000);
  });

  test("a Worker that splits its traffic is not recorded, and neither is the run", async () => {
    versionVars.set("rv3", stamp(B5));
    versionVars.set("wv2", stamp(B5));
    deployments.set("apmjs-web-production", [{ id: "w-split", created_on: "2026-11-16T12:00:00Z", source: "api", versions: [{ version_id: "wv2", percentage: 90 }, { version_id: "wv1", percentage: 10 }] }]);
    const { written, done } = record();

    expect((await done).kind).toBe("not-recorded");
    expect(written).toEqual([]);
  });
});

describe("deploy.ts after Alchemy (deploy-finish.ts)", () => {
  const steps = (over: Partial<{ alchemyExit: number; smoke: number; record: () => Promise<Recording> }> = {}) => {
    const lines: string[] = [];
    const calls = { smoke: 0, record: 0 };

    const run = finishDeploy({
      alchemyExit: over.alchemyExit ?? 0,
      smoke: async () => {
        calls.smoke += 1;

        return over.smoke ?? 0;
      },
      record: async () => {
        calls.record += 1;

        return (over.record ?? (async () => ({ kind: "recorded", release: release(B5, ALL, { registry: "rv5", web: "wv5", docs: "dv1" }) }) as const))();
      },
      advice: async () => "ADVICE",
      log: (l) => void lines.push(l),
    });

    return { lines, calls, run };
  };

  test("a passing deploy runs the smoke check once and records the release", async () => {
    const s = steps();

    expect(await s.run).toBe(0);
    expect(s.calls).toEqual({ smoke: 1, record: 1 });
    expect(s.lines.join("\n")).toContain(`release record: build ${B5}`);
  });

  test("Alchemy failing: no smoke check, nothing recorded, and the advice", async () => {
    const s = steps({ alchemyExit: 3 });

    expect(await s.run).toBe(1);
    expect(s.calls).toEqual({ smoke: 0, record: 0 });
    expect(s.lines.join("\n")).toContain("Alchemy exited 3; nothing recorded, nothing rolled back. ADVICE");
  });

  test("the smoke check failing: nothing recorded, and the advice", async () => {
    const s = steps({ smoke: 1 });

    expect(await s.run).toBe(1);
    expect(s.calls).toEqual({ smoke: 1, record: 0 });
    expect(s.lines.join("\n")).toContain("the smoke check failed; nothing recorded, nothing rolled back. ADVICE");
  });

  test("recording failing (Cloudflare answering 503) is reported with the advice, not as a stack trace", async () => {
    const s = steps({
      record: async () => {
        throw new CloudflareError(503, "Cloudflare answered 503 for GET /workers/scripts/apmjs-web-production/deployments");
      },
    });

    expect(await s.run).toBe(1);
    expect(s.lines.join("\n")).toContain("deploy FAILED: the smoke check passed, but recording the release failed (Cloudflare answered 503");
    expect(s.lines.join("\n")).toContain("nothing recorded, nothing rolled back. ADVICE");
  });

  test("a live deploy that could not be recorded fails, with the advice", async () => {
    const s = steps({ record: async () => ({ kind: "not-recorded", why: "stale" }) });

    expect(await s.run).toBe(1);
    expect(s.lines.join("\n")).toContain("NOT recorded (stale)");
    expect(s.lines.join("\n")).toContain("ADVICE");
  });

  test("the smoke command carries the run's build and the subdomain deploy.ts resolved", () => {
    expect(smokeCommand("/infra", "staging", B5, "acct")).toEqual(["bun", "/infra/smoke.ts", "--stage", "staging", "--build", B5, "--subdomain", "acct"]);
  });
});

describe("the recovery advice after a failed deploy", () => {
  const advise = () => recoveryAdvice({ cf: cf(), stage: "production", releases: releases });

  test("when every live version is recorded, it is the rollback command to the last recorded build", async () => {
    const a = await advise();

    expect(a).toContain(`bun packages/infra/rollback.ts to --stage production --build ${B4}`);
  });

  test("when this run left an unrecorded registry or website live, rollback cannot replace it: fix forward", async () => {
    deployments.set("apmjs-registry-production", [dep("r9", "rv9", "2026-11-16T12:00:00Z"), ...(deployments.get("apmjs-registry-production") ?? [])]);
    const a = await advise();

    expect(a).toContain("apmjs-registry-production rv9");
    expect(a).toContain("fix forward");
    expect(a).toContain("bun packages/infra/deploy.ts deploy --stage production");
    expect(a).not.toContain("rollback.ts to");
  });

  test("an unrecorded docs version alone does not stop the registry and the website going back", async () => {
    deployments.set("apmjs-docs-production", [dep("d9", "dv9", "2026-11-16T12:00:00Z"), ...(deployments.get("apmjs-docs-production") ?? [])]);
    const a = await advise();

    expect(a).toContain("apmjs-docs-production dv9");
    expect(a).toContain(`bun packages/infra/rollback.ts to --stage production --build ${B4}`);
  });

  test("a live registry deployment that routes traffic to no version cannot be rolled back from: fix forward", async () => {
    deployments.set("apmjs-registry-production", [{ id: "r-none", created_on: "2026-11-16T12:00:00Z", source: "api", versions: [] }, ...(deployments.get("apmjs-registry-production") ?? [])]);
    const a = await advise();

    expect(a).toContain("apmjs-registry-production deployment r-none, which routes traffic to no version");
    expect(a).toContain("fix forward");
    expect(a).not.toContain("rollback.ts to");
  });

  test("when what is live cannot be read, it says so and how to look", async () => {
    failLists = 503;
    const a = await advise();

    expect(a).toContain("could not be read");
    expect(a).toContain("bun packages/infra/rollback.ts list --stage production");
  });
});
