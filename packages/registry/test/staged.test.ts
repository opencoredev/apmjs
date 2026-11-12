// The staged-upload quota counts every byte a waiting upload keeps, not only its tarball, and the insert
// re-checks the quotas and the pending version atomically.
import { describe, expect, test } from "bun:test";
import { Effect } from "effect";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Store, type NewStaged, type StageInsert, type StoreApi } from "../src/db.ts";
import type { StoreError } from "../src/errors.ts";

const now = Date.parse("2026-11-12T00:00:00Z");

function staged(input: { id: string; version: string; readme: string }): NewStaged {
  return {
    id: input.id,
    package: "@u/p",
    version: input.version,
    manifest: { name: "@u/p", version: input.version, description: "d".repeat(500) },
    shasum: "0".repeat(40),
    integrity: "sha512-x",
    size: 10,
    tarball_key: "sha512/x",
    tag: "latest",
    readme: input.readme,
    score: { signals: [] },
    staged_by: "u",
    staged_at: now,
    expires_at: now + 1000,
  };
}

async function withStore(fn: (url: string, run: <A>(f: (s: StoreApi) => Effect.Effect<A, StoreError>) => Promise<A>) => Promise<void>): Promise<void> {
  const db = await freshDatabase();

  try {
    await fn(db.url, (f) => Effect.runPromise(Effect.flatMap(Store, f).pipe(Effect.provide(Store.postgres(db.url)), Effect.scoped)));
  } finally {
    await db.drop();
  }
}

describe("staged uploads", () => {
  test("bytes count the readme, manifest and score as well as the tarball", () =>
    withStore(async (_url, run) => {
      await run((s) => s.insertStaged(staged({ id: "a", version: "1.0.0", readme: "r".repeat(4096) })));
      const load = await run((s) => s.pendingStagedLoad({ user: "u", name: "@u/p", now }));

      expect(load.byUser).toBe(1);
      expect(load.bytesByUser).toBeGreaterThan(10 + 4096 + 500);
    }));

  test("concurrent inserts pass the per-package limit once, and one version waits once", () =>
    withStore(async (_url, run) => {
      const limits = { perUser: 20, perPackage: 2, bytesPerUser: 1024 * 1024 };

      const results = await Promise.all(
        Array.from({ length: 6 }, (_, i) => run((s) => s.insertStagedWithin(staged({ id: `p${i}`, version: `1.0.${i % 3}`, readme: "" }), limits))),
      );

      const kinds = (k: StageInsert["kind"]): number => results.filter((r) => r.kind === k).length;

      expect(kinds("staged")).toBe(2);
      expect(kinds("staged") + kinds("duplicate") + kinds("over")).toBe(6);
      expect((await run((s) => s.pendingStagedLoad({ user: "u", name: "@u/p", now }))).byPackage).toBe(2);
    }));

  test("the byte quota counts metadata", () =>
    withStore(async (_url, run) => {
      const r = await run((s) => s.insertStagedWithin(staged({ id: "big", version: "2.0.0", readme: "r".repeat(2000) }), { perUser: 20, perPackage: 5, bytesPerUser: 1500 }));

      expect(r.kind).toBe("over");
    }));

  test("a rejected or expired upload keeps its audit fields only", () =>
    withStore(async (_url, run) => {
      await run((s) => s.insertStaged(staged({ id: "rej", version: "3.0.0", readme: "secret readme" })));
      await run((s) => s.insertStaged(staged({ id: "exp", version: "3.0.1", readme: "secret readme" })));
      expect(await run((s) => s.decideStaged("rej", { status: "rejected", at: now, by: "u" }))).toBe(true);
      await run((s) => s.expireStaged(now + 5000));

      for (const id of ["rej", "exp"]) {
        const row = await run((s) => s.getStaged(id));

        expect(row?.manifest).toEqual({});
        expect(row?.readme).toBeNull();
        expect(row?.score).toBeNull();
        expect(row?.staged_by).toBe("u");
      }
    }));
});
