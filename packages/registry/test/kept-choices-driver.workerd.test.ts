// What the database driver allocates to write one kept-choices row, measured where it runs: inside workerd, through
// the real Store and a real Postgres (review of acdb8eb, finding 1). The installed @effect/sql-pg encodes a long
// string parameter into a buffer of its own, grown from 8 KiB in doubling steps, then copies the whole frame into
// another buffer for the socket. On acdb8eb keepPlans reserved only the row's UTF-8 bytes for that: a 20,421-byte
// reservation let the driver take a 65,536-byte encoding buffer while the pool was fully charged, and the write went
// through. Here the encoding buffer and the frame are watched while the plan's text is encoded, and what the write
// reserved must cover both; a write whose allowance does not fit is skipped.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { join } from "node:path";
import { Client } from "pg";
import { z } from "zod";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { startWorkerdHeap, type WorkerdHeap } from "./workerd-heap.ts";

const SRC = join(import.meta.dir, "..", "src");
const EFFECT = join(import.meta.dir, "..", "node_modules", "effect", "src", "index.ts");

let db: Awaited<ReturnType<typeof freshDatabase>>;
let heap: WorkerdHeap;

const entry = (url: string) => `
import { Buffer } from "node:buffer";
import { Effect } from ${JSON.stringify(EFFECT)};
import { Store } from ${JSON.stringify(join(SRC, "db.ts"))};
import { MemoryPool } from ${JSON.stringify(join(SRC, "memory.ts"))};
import { KeptSide, keptPlan, keepPlans } from ${JSON.stringify(join(SRC, "kept-choices.ts"))};

export default {
  async fetch(request) {
    const { limit, document, tight } = await request.json();
    const at = Date.now();
    const pool = new MemoryPool(limit);
    const side = KeptSide.open(pool);
    const record = { package: "app", version: "1.0.0", manifest: { scripts: { install: "x".repeat(20000) } }, shasum: "1".repeat(40), integrity: "", size: 0, tarball_key: "", published_at: at, seq: 0, published_by: "u", deprecated: null, status: "active", status_reason: null, status_at: null, status_by: null, score: null };
    const plan = keptPlan({ document, etag: '"same"', distTags: { latest: "1.0.0" }, versions: new Map([["v", [record]]]), reserve: side, at });
    if (!plan) throw new Error("no plan");
    const handle = side.holdPlan(plan);
    const writer = pool.request(limit);
    const other = pool.request(limit);
    // tight: the rest of the pool, but what the row's UTF-8 bytes take (what acdb8eb reserved for the driver)
    if (tight) other.take(pool.limit - plan.weight - plan.bytes);
    const seen = [];
    let frame = 0;
    const encodeInto = TextEncoder.prototype.encodeInto;
    const allocUnsafe = Buffer.allocUnsafe;
    TextEncoder.prototype.encodeInto = function (text, into) {
      if (text === plan.text) seen.push({ backing: into.buffer.byteLength, reserved: writer.taken });
      return encodeInto.call(this, text, into);
    };
    Buffer.allocUnsafe = function (size) {
      if (seen.length > 0 && size > plan.bytes) frame = Math.max(frame, size);
      return allocUnsafe.call(this, size);
    };
    try {
      await Effect.runPromise(Effect.gen(function* () { yield* keepPlans({ store: yield* Store, plans: [handle], at, lease: writer }); }).pipe(Effect.provide(Store.postgres(${JSON.stringify(url)})), Effect.scoped));
    } finally {
      TextEncoder.prototype.encodeInto = encodeInto;
      Buffer.allocUnsafe = allocUnsafe;
    }
    const after = { charged: pool.charged, other: other.taken, released: handle.claim() === null };
    writer.release();
    other.release();
    side.close();
    return Response.json({ seen, frame, after });
  },
};
`;

const Answer = z.object({ seen: z.array(z.object({ backing: z.number(), reserved: z.number() })), frame: z.number(), after: z.object({ charged: z.number(), other: z.number(), released: z.boolean() }) });

beforeAll(async () => {
  db = await freshDatabase();
  heap = await startWorkerdHeap(entry(db.url));
}, 120_000);

afterAll(async () => {
  await heap.dispose();
  await db.drop();
});

const rows = async (document: string): Promise<number> => {
  const c = new Client({ connectionString: db.url });
  await c.connect();

  try {
    return z.array(z.object({ n: z.number() })).parse((await c.query(`SELECT count(*)::int AS n FROM upstream_choices WHERE document = $1`, [document])).rows)[0]?.n ?? 0;
  } finally {
    await c.end();
  }
};

const write = async (limit: number, document: string, tight: boolean) => Answer.parse(await (await heap.dispatch("/", { method: "POST", body: JSON.stringify({ limit, document, tight }) })).json());

describe("a kept-choices write reserves what the driver allocates", () => {
  test("with the pool full but the row's own bytes, the write is skipped: the driver's buffers would not fit", async () => {
    const got = await write(200_000, "tight", true);

    process.stdout.write(`[driver] tight: ${JSON.stringify(got)}\n`);
    // on acdb8eb: encoded into a 65,536-byte buffer under a 20,421-byte reservation, and the row was written

    for (const s of got.seen) expect(s.reserved).toBeGreaterThanOrEqual(s.backing + got.frame);
    expect(got.seen).toEqual([]);
    expect(await rows("tight")).toBe(0);
    expect(got.after.released).toBe(true);
    expect(got.after.charged).toBe(got.after.other);
  }, 60_000);

  test("with room, the write goes through, its reservation covering the encoding buffer and the frame", async () => {
    const got = await write(1_000_000, "roomy", false);

    process.stdout.write(`[driver] roomy: ${JSON.stringify(got)}\n`);
    expect(got.seen.length).toBeGreaterThan(0);

    for (const s of got.seen) expect(s.reserved).toBeGreaterThanOrEqual(s.backing + got.frame);
    expect(await rows("roomy")).toBe(1);
    expect(got.after.released).toBe(true);
    expect(got.after.charged).toBe(got.after.other);
  }, 60_000);
});
