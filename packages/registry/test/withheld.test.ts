// What a withheld version leaves in the package's text and not-checked list, and what search pays to work it out.
import { describe, expect, test } from "bun:test";
import { Effect, Layer } from "effect";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Clock } from "../src/clock.ts";
import { Store, type NewVersion, type StoreApi } from "../src/db.ts";
import { searchPackages } from "../src/search.ts";
import { eventDetailShown, fileReferences, packageTextShown, withheldDismissals, withheldLimitations, withheldSkipped } from "../src/withheld.ts";

const now = Date.parse("2026-11-12T00:00:00Z");

describe("packageTextShown", () => {
  test("two shown publishes in the same millisecond: the later insert's text wins, as the database orders them", () => {
    // as the store lists them: published_at, then seq
    const versions = [
      { status: "active", published_at: now, seq: 1, manifest: { description: "older", keywords: ["older"] } },
      { status: "active", published_at: now, seq: 2, manifest: { description: "newer", keywords: ["newer"] } },
      { status: "revoked", published_at: now + 1, seq: 3, manifest: { description: "withheld", keywords: ["withheld"] } },
    ] as const;

    expect(packageTextShown({ description: "withheld", keywords: ["withheld"] }, versions)).toEqual({ description: "newer", keywords: ["newer"] });
  });
});

describe("withheldLimitations", () => {
  test("a dependency whose key is not a valid npm name is not named", () => {
    const manifest = { dependencies: { "Secret Token=abc123": "https://example.invalid/x.tgz", "plain-url": "https://example.invalid/y.tgz" } };
    const stored = ["dependency Secret Token=abc123 (https://example.invalid/x.tgz): tarball URL", "dependency plain-url (https://example.invalid/y.tgz): tarball URL"];
    const out = withheldLimitations(stored, manifest);

    expect(out).toContain("dependency a dependency with an invalid name: tarball URL: installs code from outside any registry");
    expect(out).toContain("dependency plain-url: tarball URL: installs code from outside any registry");
    expect(out.join("\n")).not.toContain("Secret");
  });
});

describe("withheldDismissals", () => {
  test("each dismissed item keeps its signal, line and reason; its path is a numbered reference and its evidence goes", () => {
    const item = (file: string, line: number) => ({ signal: "eval" as const, file, line, reason: "fixture", at: 1, evidence: [`${file}:${line}: eval(x)`] });
    const list = [item("lib/secret-sk_live_x.js", 3), item("index.js", 1), item("lib/secret-sk_live_x.js", 9)];
    const out = withheldDismissals(list, fileReferences(list.map((d) => d.file)));

    expect(out).toEqual([
      { signal: "eval", file: "file 2", line: 3, reason: "fixture", at: 1, evidence: [] },
      { signal: "eval", file: "file 1", line: 1, reason: "fixture", at: 1, evidence: [] },
      { signal: "eval", file: "file 2", line: 9, reason: "fixture", at: 1, evidence: [] },
    ]);
  });
});

describe("withheldSkipped", () => {
  test("each file the score did not read keeps its size and reason; its path is the answer's reference for it", () => {
    const ref = fileReferences(["lib/LEAKMARK-big.txt", "index.js"]);
    const out = withheldSkipped([{ path: "lib/LEAKMARK-big.txt", size: 40_000_000, reason: "too-large" }], ref);

    expect(out).toEqual([{ path: "file 2", size: 40_000_000, reason: "too-large" }]);
  });
});

describe("eventDetailShown", () => {
  const withheld = new Set(["1.1.0"]);

  test("a withheld version's deprecation message and tag go; the version and the revoke's reason stay", () => {
    expect(eventDetailShown({ kind: "deprecate", detail: { version: "1.1.0", message: "use the secret sk_live_x" }, withheld })).toEqual({ version: "1.1.0", withheld: true });
    expect(eventDetailShown({ kind: "publish", detail: { version: "1.1.0", tag: "latest", approvedBy: "u", stagedAt: "2026-11-12T00:00:00.000Z" }, withheld })).toEqual({
      version: "1.1.0",
      approvedBy: "u",
      stagedAt: "2026-11-12T00:00:00.000Z",
      withheld: true,
    });
    expect(eventDetailShown({ kind: "revoke", detail: { version: "1.1.0", reason: "leaked a key", confirms: null }, withheld })).toEqual({ version: "1.1.0", reason: "leaked a key", confirms: null, withheld: true });
    // a kind this list does not know keeps only its version
    expect(eventDetailShown({ kind: "something-new", detail: { version: "1.1.0", note: "publisher text" }, withheld })).toEqual({ version: "1.1.0", withheld: true });
  });

  test("a shown version's event, and one that names no version, are as stored", () => {
    expect(eventDetailShown({ kind: "deprecate", detail: { version: "1.0.0", message: "use 2" }, withheld })).toEqual({ version: "1.0.0", message: "use 2" });
    expect(eventDetailShown({ kind: "owner-add", detail: { user: "v" }, withheld })).toEqual({ user: "v" });
  });
});

// ---------- search's lookup of withheld text ----------
function version(name: string, v: string, description: string): NewVersion {
  return {
    package: name,
    version: v,
    manifest: { name, version: v, description, keywords: [description] },
    shasum: "0".repeat(40),
    integrity: "sha512-x",
    size: 1,
    tarball_key: `sha512/${name}-${v}`,
    published_at: now,
    published_by: "u",
    score: null,
  };
}

/** The store, with every method it is asked for counted by name. */
function counted(api: StoreApi, calls: string[]): StoreApi {
  return new Proxy(api, {
    get(target, key, receiver) {
      // oxlint-disable-next-line anti-slop/no-runtime-typeof -- a Proxy's property key may be a symbol; only the store's named methods are counted
      if (typeof key === "string") calls.push(key);

      // oxlint-disable-next-line anti-slop/no-reflect-get -- the counter hands back every property of the real store unchanged
      return Reflect.get(target, key, receiver);
    },
  });
}

/** Store calls one search makes with `withheld` of the packages having a revoked version, and its hits' descriptions. */
async function searchWith(withheld: number): Promise<{ calls: string[]; descriptions: string[] }> {
  const db = await freshDatabase();
  const base = Store.postgres(db.url);

  try {
    const run = <A, E>(eff: Effect.Effect<A, E, Store>) => Effect.runPromise(eff.pipe(Effect.provide(base), Effect.scoped));

    await run(
      Effect.gen(function* () {
        const s = yield* Store;

        yield* s.createUser({ name: "u", password_hash: "", email: "u@example.invalid", created_at: now });

        for (let i = 0; i < 6; i++) {
          const name = `pkg-${i}`;

          yield* s.createPackage(name, now, "u");
          yield* s.insertVersion(version(name, "1.0.0", `shown ${i}`));
          yield* s.insertVersion(version(name, "1.1.0", i < withheld ? `withheld ${i}` : `shown ${i}`));
          yield* s.updatePackageMeta(name, { modifiedAt: now, description: i < withheld ? `withheld ${i}` : `shown ${i}`, keywords: [] });
          yield* s.setDistTags(name, { latest: "1.0.0" }, now);

          if (i < withheld) yield* s.setStatus(name, "1.1.0", { status: "revoked", reason: "r", at: now, by: "u" });
        }
      }),
    );

    const calls: string[] = [];
    const countedStore = Layer.effect(Store, Effect.map(Store, (api) => counted(api, calls))).pipe(Layer.provide(base));
    const hits = await Effect.runPromise(searchPackages("pkg").pipe(Effect.provide(Layer.mergeAll(countedStore, Clock.fixed({ now, wallNow: now }))), Effect.scoped));

    return { calls, descriptions: hits.map((h) => h.pkg.description) };
  } finally {
    await db.drop();
  }
}

describe("search", () => {
  test("asks the store the same number of times however many packages have a withheld version", async () => {
    const one = await searchWith(1);
    const four = await searchWith(4);

    expect(four.calls).toEqual(one.calls);
    expect(four.calls).not.toContain("listVersions");
    // and each package still shows its shown version's text
    expect(four.descriptions).toEqual(["shown 0", "shown 1", "shown 2", "shown 3", "shown 4", "shown 5"]);
  }, 60_000);
});
