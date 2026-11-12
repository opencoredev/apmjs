// The package page's early review and score reads are used only for the version the page ends up showing.
import { describe, expect, test } from "bun:test";
import { answerFor, askedVersion, shownOf, type Shown } from "./early-answer";
import type { Fetched } from "./registry-fetch";

type Answer = { version: string; status: string; redacted: boolean };

const ok = (version: string): Fetched<Answer> => ({ kind: "ok", value: { version, status: "reviewed", redacted: false } });
const redacted = (version: string): Fetched<Answer> => ({ kind: "ok", value: { version, status: "reviewed", redacted: true } });
const active = (version: string): Shown => ({ version, withheld: false });
const withheld = (version: string): Shown => ({ version, withheld: true });
const missing: Fetched<Answer> = { kind: "missing" };
const down: Fetched<Answer> = { kind: "unavailable", reason: { kind: "timeout" } };

/** A read that records whether the page fell back to it. */
function reader(answer: Fetched<Answer>) {
  const calls: string[] = [];

  return { calls, read: (version: string) => () => (calls.push(version), Promise.resolve(answer)) };
}

describe("answerFor", () => {
  test("an early answer for the shown version is used, with no second read", async () => {
    const r = reader(ok("2.0.0"));

    expect(await answerFor({ early: Promise.resolve(ok("1.0.0")), asked: "latest", shown: active("1.0.0"), read: r.read("1.0.0") })).toEqual(ok("1.0.0"));
    expect(r.calls).toEqual([]);
  });

  test("latest moved between the two reads: the shown version is read", async () => {
    const r = reader(ok("1.0.0"));

    expect(await answerFor({ early: Promise.resolve(ok("1.1.0")), asked: "latest", shown: active("1.0.0"), read: r.read("1.0.0") })).toEqual(ok("1.0.0"));
    expect(r.calls).toEqual(["1.0.0"]);
  });

  test("a ?v= the package does not have: the early answer is for nothing shown, so latest is read", async () => {
    const r = reader(ok("3.0.0"));

    expect(await answerFor({ early: Promise.resolve(missing), asked: "9.9.9", shown: active("3.0.0"), read: r.read("3.0.0") })).toEqual(ok("3.0.0"));
    expect(r.calls).toEqual(["3.0.0"]);
  });

  test("a 404 for exactly the shown version stands", async () => {
    const r = reader(ok("1.0.0"));

    expect(await answerFor({ early: Promise.resolve(missing), asked: "1.0.0", shown: active("1.0.0"), read: r.read("1.0.0") })).toEqual(missing);
    expect(r.calls).toEqual([]);
  });

  test("a 404 for a tag is read again by version (a registry that does not resolve tags)", async () => {
    const r = reader(ok("1.0.0"));

    expect(await answerFor({ early: Promise.resolve(missing), asked: "latest", shown: active("1.0.0"), read: r.read("1.0.0") })).toEqual(ok("1.0.0"));
    expect(r.calls).toEqual(["1.0.0"]);
  });

  test("a revoke the package answer saw after the early read: the unredacted early answer is read again", async () => {
    const r = reader(redacted("1.0.0"));

    expect(await answerFor({ early: Promise.resolve(ok("1.0.0")), asked: "1.0.0", shown: withheld("1.0.0"), read: r.read("1.0.0") })).toEqual(redacted("1.0.0"));
    expect(r.calls).toEqual(["1.0.0"]);
  });

  test("a redacted early answer for a withheld version is used as it is", async () => {
    const r = reader(redacted("1.0.0"));

    expect(await answerFor({ early: Promise.resolve(redacted("1.0.0")), asked: "1.0.0", shown: withheld("1.0.0"), read: r.read("1.0.0") })).toEqual(redacted("1.0.0"));
    expect(r.calls).toEqual([]);
  });

  test("a redacted early answer for a version the package answer calls active is more restrictive, so it stands", async () => {
    const r = reader(ok("1.0.0"));

    expect(await answerFor({ early: Promise.resolve(redacted("1.0.0")), asked: "1.0.0", shown: active("1.0.0"), read: r.read("1.0.0") })).toEqual(redacted("1.0.0"));
    expect(r.calls).toEqual([]);
  });

  test("an outage on the early read stands, so a down registry is waited on once", async () => {
    const r = reader(ok("1.0.0"));

    expect(await answerFor({ early: Promise.resolve(down), asked: "latest", shown: active("1.0.0"), read: r.read("1.0.0") })).toEqual(down);
    expect(r.calls).toEqual([]);
  });
});

describe("shownOf", () => {
  test("revoked and revoke-pending are withheld; active and yanked are not; a version not listed is not", () => {
    const versions = ["active", "yanked", "revoke-pending", "revoked"].map((status, i) => ({ version: `1.0.${i}`, status }));

    expect(["1.0.0", "1.0.1", "1.0.2", "1.0.3", "9.9.9"].map((v) => shownOf(versions, v).withheld)).toEqual([false, false, true, true, false]);
  });
});

describe("askedVersion", () => {
  test("the first ?v=, and none for an empty or absent one", () => {
    expect(askedVersion("1.2.3")).toBe("1.2.3");
    expect(askedVersion(["1.2.3", "2.0.0"])).toBe("1.2.3");
    expect(askedVersion("")).toBeUndefined();
    expect(askedVersion(undefined)).toBeUndefined();
  });
});
