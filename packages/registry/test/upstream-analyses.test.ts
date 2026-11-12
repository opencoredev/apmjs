// An upstream package's analyses and its live dismissals come back in one query whose size grows with their sum, not
// their product: every byte of it lands in the Worker's 128 MB. The bytes are counted on the wire, by a proxy between
// the store and a real Postgres.
import { describe, expect, test } from "bun:test";
import { Effect } from "effect";
import { createServer, connect } from "node:net";
import { Client } from "pg";
import { z } from "zod";
import { SCORER } from "@apm/core";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Store } from "../src/db.ts";

const NAME = "many-analyses";
const ANALYSES = 1_000;
const DISMISSALS = 100;

/** A TCP proxy to `target` that counts the bytes the server sends back. */
async function countingProxy(target: URL): Promise<{ url: string; received: () => number; reset: () => void; close: () => void }> {
  let received = 0;

  const server = createServer((client) => {
    const upstream = connect(Number(target.port), target.hostname);
    upstream.on("data", (chunk: Buffer) => {
      received += chunk.length;
      client.write(chunk);
    });
    client.on("data", (chunk: Buffer) => upstream.write(chunk));
    client.on("close", () => upstream.destroy());
    upstream.on("close", () => client.destroy());
    client.on("error", () => upstream.destroy());
    upstream.on("error", () => client.destroy());
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = z.object({ port: z.number() }).parse(server.address());
  const url = new URL(target);
  url.hostname = "127.0.0.1";
  url.port = String(port);

  return { url: url.toString(), received: () => received, reset: () => (received = 0), close: () => server.close() };
}

describe("upstreamAnalyses", () => {
  test(`${ANALYSES} analyses and ${DISMISSALS} dismissals come back once each, in one round trip`, async () => {
    const db = await freshDatabase();
    const proxy = await countingProxy(new URL(db.url));

    try {
      const c = new Client({ connectionString: db.url });
      await c.connect();
      const analysis = { score: 90, grade: "A", signals: [], note: "n".repeat(150) };
      await c.query(
        `INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at)
         SELECT $1, '1.0.' || i, 'sha512-' || i, $2, $3::jsonb, 0 FROM generate_series(1, $4::int) i`,
        [NAME, SCORER, JSON.stringify(analysis), ANALYSES],
      );
      // dismissals of other bytes: they are sent with the analyses but match none, so the scores stay as stored
      await c.query(
        `INSERT INTO evidence_dismissals (scorer, package, version, digest, signal, file, line, reason, dismissed_by, dismissed_at)
         SELECT $2, $1, '1.0.' || i, 'sha512-other', 'eval', 'lib/index.js', i, $3, 'admin', i FROM generate_series(1, $4::int) i`,
        [NAME, SCORER, `A fixture line, not a threat. ${"r".repeat(150)}`, DISMISSALS],
      );

      // each analysis as sent (its jsonb text plus about 40 bytes of version and digest), and each dismissal
      const sizes = await c.query(
        `SELECT (SELECT sum(octet_length(analysis::text) + 40) FROM upstream_analysis WHERE package = $1) AS analyses,
                (SELECT sum(octet_length(to_jsonb(e)::text)) FROM evidence_dismissals e WHERE package = $1) AS dismissals`,
        [NAME],
      );

      await c.end();
      const { analyses, dismissals } = z.object({ analyses: z.coerce.number(), dismissals: z.coerce.number() }).parse(sizes.rows[0]);
      const linear = analyses + dismissals;

      proxy.reset();
      const { scores, unscorable } = await Effect.runPromise(Effect.flatMap(Store, (s) => s.upstreamAnalyses(NAME)).pipe(Effect.provide(Store.postgres(proxy.url)), Effect.scoped));

      expect(scores.size).toBe(ANALYSES);
      // the same round trip carries the versions decided unscorable (migration 0010); this package has none
      expect(unscorable.size).toBe(0);
      expect(scores.get("1.0.1 sha512-1")).toEqual(analysis);
      // what was sent is the analyses and the dismissals once each, plus the connection's own messages; a join that
      // repeated the dismissals on every analysis row would send about ANALYSES times the dismissals' size
      expect(proxy.received()).toBeGreaterThan(linear);
      expect(proxy.received()).toBeLessThan(linear * 1.5 + 16 * 1024);
    } finally {
      proxy.close();
      await db.drop();
    }
  }, 60_000);
});
