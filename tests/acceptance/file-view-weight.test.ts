// A file or readme view of a package published here reads that one version from the database, not every version of
// the package with its whole score (review of b91a69c, P2: 15 versions with scores the size of next's made a 115-byte
// file answer pull 5.7 MB). The version's state is still read on every view, so a revoke refuses the next one, even
// once its files are cached. Counted through a database link that measures the bytes Postgres sends.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { z } from "zod";
import { addUser, putPublish, startRegistry, type Registry } from "./harness";

const NAME = "local-weight";
const VERSIONS = 15;
const LATEST = `1.0.${VERSIONS - 1}`;
const PATHS = [`-/apm/v1/file/${NAME}/${LATEST}?path=index.js`, `-/apm/v1/readme/${NAME}/${LATEST}`] as const;

let reg: Registry;

/** The bytes Postgres sent while one request ran, and its answer. */
async function weighed(path: string): Promise<{ status: number; databaseBytes: number }> {
  const link = reg.databaseLink;

  if (link === null) throw new Error("the registry started without its database link");
  const before = link.received();
  const res = await fetch(`${reg.url}${path}`);
  await res.arrayBuffer();

  return { status: res.status, databaseBytes: link.received() - before };
}

beforeAll(async () => {
  reg = await startRegistry({ now: () => Date.parse("2026-11-19T12:00:00Z"), databaseLink: true });
  const token = await addUser(reg, "local-weight-owner");

  for (let i = 0; i < VERSIONS; i++) {
    const r = await putPublish(reg, token, { name: NAME, version: `1.0.${i}`, license: "MIT", main: "index.js" }, { files: { "index.js": "module.exports = 1;\n", "README.md": `# ${NAME}\n` } });

    if (r.status !== 201) throw new Error(`publish 1.0.${i}: ${r.status}`);
  }

  // every version's score as large as next's: 2,656 files apm did not read
  const skipped = Array.from({ length: 2_656 }, (_, i) => ({ path: `dist/compiled/some-vendored-library/build/chunks/module-${String(i).padStart(5, "0")}.production.min.js`, size: 20_000 + i, reason: "over-budget" }));
  await reg.query("UPDATE versions SET score = score || jsonb_build_object('skipped', $1::jsonb) WHERE package = $2", [JSON.stringify(skipped), NAME]);
}, 120_000);

afterAll(async () => {
  await reg.stop();
});

describe("a local package's file and readme views", () => {
  test("read the one version asked for, not every version's score", async () => {
    const [one] = z.array(z.object({ bytes: z.coerce.number() })).parse(await reg.query("SELECT octet_length(score::text) AS bytes FROM versions WHERE package = $1 AND version = $2", [NAME, LATEST]));

    if (one === undefined) throw new Error("no row for the version");
    // the version's own row, whole, and the statements around it; every version's score would be 15 times that
    const allowed = one.bytes + 256 * 1024;

    for (const path of PATHS) {
      // the first view builds and caches the file index; the second reads it from the blob store
      for (let view = 0; view < 2; view++) {
        const got = await weighed(path);

        expect(got.status, path).toBe(200);
        expect(got.databaseBytes, path).toBeLessThan(allowed);
      }
    }

    expect(one.bytes * VERSIONS).toBeGreaterThan(allowed * 4);
  });

  test("still read the version's state on every view: a revoke refuses the next one, with its files cached", async () => {
    await reg.query("UPDATE versions SET status = 'revoked', status_reason = 'a leaked key', status_at = $1 WHERE package = $2 AND version = $3", [Date.parse("2026-11-19T12:00:00Z"), NAME, LATEST]);

    for (const path of PATHS) expect((await weighed(path)).status, path).toBe(410);
  });
});
