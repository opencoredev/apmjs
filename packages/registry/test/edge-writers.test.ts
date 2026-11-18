// Every write that can make an edge view (edge-checks.ts) wrong, found by reading the shipped code, and what covers it.
// An edge view clears a name for npm's tarball and install document when the block list neither lists it as published
// here nor lists a confirmed version of it. Two facts in Postgres decide that: a `packages` row (a name published
// here) and a review whose human_state is 'confirmed'. So every statement in shipped code (the Workers, the reviewer,
// the CLI, the infra tools, migrations; not benches or tests) that inserts a package or can set a review's human_state
// is listed here with the code that puts its block on the list first, and this test fails on one it does not know.
// Operational scripts (scripts/) count as shipped; the benches under scripts/perf write their own SQL to databases of
// their own and are left out, like tests.
// Revoke, yank, restore, deprecate, dist-tags and owners change `versions`, `packages` and `owners` rows of packages
// published here, which a view never clears, so they need no entry. Unblocks (a dismissal, a review stored again) only
// make the list stricter than the database until the cron's sync, and the edge sends a listed name to the database.
import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const ROOT = join(import.meta.dir, "..", "..", "..");

/** Shipped source: everything under these, except tests, fixtures, benches and dependencies. */
const SHIPPED = ["packages", "apps", "tools", "scripts"];

/** Benches: they run against a database of their own (scripts/perf/*-bench.ts). */
const BENCHES = join(ROOT, "scripts", "perf");

function files(dir: string): string[] {
  const out: string[] = [];

  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === "test" || entry === "tests" || entry === "fixtures" || entry === "dist" || entry === ".next" || entry === ".open-next" || entry.startsWith(".")) continue;
    const path = join(dir, entry);

    if (path === BENCHES) continue;

    if (statSync(path).isDirectory()) out.push(...files(path));
    else if (/\.(ts|tsx|sql|py|sh)$/.test(entry) && !/\.test\.tsx?$/.test(entry)) out.push(path);
  }

  return out;
}

/** A statement that makes a name published here, or can make a review confirmed. */
const WRITES = [/INSERT\s+INTO\s+packages\b/gi, /INSERT\s+INTO\s+reviews\b/gi, /UPDATE\s+reviews\b[^;`]*\bhuman_state\b/gi];

/** One known writer: where it is, and the check that what covers it is still there. */
type Writer = { file: string; statement: RegExp; covered: string; check: () => boolean };

const read = (file: string): string => readFileSync(join(ROOT, file), "utf8");

const WRITERS: Writer[] = [
  {
    file: "packages/registry/src/db.ts",
    statement: /INSERT INTO packages \(name, created_at, modified_at\)/,
    covered:
      "Store.createPackage, called only from commitVersion (publish and staged approval), which creates a package only under the fence fenceNewName took before the transaction: the name on the list, then the publish fence's wait, which every Worker holds",
    check: () => {
      const callers = files(join(ROOT, "packages")).filter((f) => readFileSync(f, "utf8").includes(".createPackage("));
      const server = read("packages/registry/src/server.ts");
      const account = read("packages/registry/src/account.ts");
      const worker = read("packages/registry/src/worker.ts");

      return (
        callers.map((f) => relative(ROOT, f)).join() === "packages/registry/src/server.ts" &&
        // the fence: on the list, then the wait, outside any transaction
        /export const fenceNewName = [\s\S]{0,300}yield\* blockBeforeCommit\(\{ local: \[name\] \}\);\s*yield\* holdForEdges;/.test(server) &&
        // a package is created only under it
        /const created = yield\* store\.createPackage\(v\.name, at, v\.publisher\);[\s\S]{0,600}if \(created && !\(v\.fence\.kind === "fenced" && v\.fence\.name === v\.name\)\) \{\s*return yield\* Effect\.fail/.test(server) &&
        // both callers take it before their transaction
        /const fence = yield\* fenceNewName\(name\);\s*yield\* commitVersion\(\{/.test(server) &&
        /const fence = yield\* fenceNewName\(row\.package\);[\s\S]{0,800}yield\* store\.tx\(/.test(account) &&
        // every Worker holds the fence, whatever its read mode, for FIRST_PUBLISH_HOLD_MS in production
        /PublishFence\.layer\(controls\.publishFenceMs\)/.test(worker) &&
        /const PRODUCTION: TestControls = \{ faults: new Set\(\), publishFenceMs: FIRST_PUBLISH_HOLD_MS \};/.test(worker)
      );
    },
  },
  {
    file: "packages/registry/src/review.ts",
    statement: /UPDATE reviews SET human_state = \$\{d\.decision === "confirm" \? "confirmed" : "dismissed"\}/,
    covered: "decideResponse: a confirmation is put on the list before the UPDATE runs, and nothing is written when that fails",
    check: () =>
      /if \(d\.decision === "confirm"\) \{\s*yield\* blockBeforeCommit\(\{ confirmed: \[\{ name: d\.name, version: d\.version, digest: d\.digest \}\] \}\)[\s\S]{0,400}sql`UPDATE reviews SET human_state/.test(read("packages/registry/src/review.ts")),
  },
  {
    file: "packages/registry/src/review.ts",
    statement: /INSERT INTO reviews \(package, version, digest, outcome, result, reviewed_at, human_state, human_by, human_at, human_note\)/,
    covered: "resultResponse: the AI reviewer's result, stored as 'none' or 'pending', never 'confirmed' (a stored result can only unblock)",
    check: () => read("packages/registry/src/review.ts").includes('const human: HumanState = r.outcome === "benign" ? "none" : "pending";'),
  },
  {
    file: "packages/registry/src/review.ts",
    statement: /UPDATE reviews SET human_state = 'dismissed', human_by = \$\{by\}/,
    covered: "bulkDismissResponse: dismisses only, and only flags still pending, so it can only unblock",
    check: () => /sql`UPDATE reviews SET human_state = 'dismissed'[^`]*AND human_state = 'pending' RETURNING package`/.test(read("packages/registry/src/review.ts")),
  },
];

describe("writes an edge view depends on", () => {
  test("every statement in shipped code that publishes a name here or can confirm a review is a known, covered writer", () => {
    const found: { file: string; text: string }[] = [];

    for (const top of SHIPPED) {
      for (const f of files(join(ROOT, top))) {
        const text = readFileSync(f, "utf8");

        for (const re of WRITES) {
          for (const m of text.matchAll(re)) found.push({ file: relative(ROOT, f), text: text.slice(m.index, m.index + 200) });
        }
      }
    }

    // operational scripts are read too
    expect(files(join(ROOT, "scripts")).map((f) => relative(ROOT, f))).toContain("scripts/dev-registry.ts");
    // the migrations create the tables and backfill nothing into them
    const unknown = found.filter((w) => !WRITERS.some((k) => k.file === w.file && k.statement.test(w.text)));

    expect(unknown).toEqual([]);
    expect(found.length).toBe(WRITERS.length);
  });

  for (const w of WRITERS) {
    test(`${w.file}: ${w.covered}`, () => {
      expect(w.check()).toBe(true);
    });
  }
});
