// The staged-upload quota counts every byte a waiting upload keeps, not only its tarball.
import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/db.ts";

const dir = mkdtempSync(join(tmpdir(), "apm-staged-unit-"));
const store = new Store(dir);
const now = Date.parse("2026-11-12T00:00:00Z");

afterAll(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

function staged(id: string, readme: string) {
  return {
    id,
    package: "@u/p",
    version: `1.0.${id.length}`,
    manifest: { name: "@u/p", version: "1.0.0", description: "d".repeat(500) },
    shasum: "0".repeat(40),
    integrity: "sha512-x",
    size: 10,
    tag: "latest",
    readme,
    score: { signals: [] },
    staged_by: "u",
    staged_at: now,
    expires_at: now + 1000,
  };
}

describe("pendingStagedLoad", () => {
  test("bytes count the readme, manifest and score as well as the tarball", () => {
    store.insertStaged(staged("a", "r".repeat(4096)));
    const load = store.pendingStagedLoad({ user: "u", name: "@u/p", now });

    expect(load.byUser).toBe(1);
    expect(load.bytesByUser).toBeGreaterThan(10 + 4096 + 500);
  });
});
