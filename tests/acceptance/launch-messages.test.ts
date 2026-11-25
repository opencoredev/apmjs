// HOME-502 walkthroughs, end to end against the in-process registry and the real bun.
// B3/C3: apm add of a look-alike name (expresss, one edit from express) printed a green check and "apm: no warnings".
// D15: a package whose only version is a prerelease tagged next read as "score unknown (not analyzed)" and "--force
// does not help ... unknown names stay blocked", with no word about the tag.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addUser, apm, installedVersion, makeSandbox, pkgTgz, putPublish, writeConsumer, type Registry, startRegistry } from "./harness";

let upstream: ReturnType<typeof Bun.serve>;
let reg: Registry;
let alice: string;
let work: string;

beforeAll(async () => {
  // npm, as far as this test goes: one look-alike package, first published long ago with a single version
  const tgz = pkgTgz({ name: "expresss", version: "1.0.0", main: "index.js", license: "MIT" });
  const integrity = `sha512-${createHash("sha512").update(tgz).digest("base64")}`;
  const shasum = createHash("sha1").update(tgz).digest("hex");

  upstream = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const url = new URL(req.url);

      if (url.pathname === "/expresss/-/expresss-1.0.0.tgz") return new Response(tgz);

      if (url.pathname !== "/expresss") return Response.json({ error: "Not found" }, { status: 404 });

      return Response.json({
        name: "expresss",
        "dist-tags": { latest: "1.0.0" },
        versions: { "1.0.0": { name: "expresss", version: "1.0.0", main: "index.js", license: "MIT", dist: { tarball: `${url.origin}/expresss/-/expresss-1.0.0.tgz`, shasum, integrity } } },
        time: { created: "2025-01-01T00:00:00Z", "1.0.0": "2025-01-01T00:00:00Z" },
        maintainers: [{ name: "someone" }],
      });
    },
  });
  reg = await startRegistry({ upstream: upstream.url.toString() });
  alice = await addUser(reg, "alice");
  work = mkdtempSync(join(tmpdir(), "apm-launch-"));
});

afterAll(async () => {
  await reg?.stop();
  upstream?.stop(true);
});

describe("apm add, as first-time users met it", () => {
  test("a look-alike name installs with a WARNING that names the popular package, and never with \"no warnings\"", async () => {
    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg, alice);
    const r = await apm(["add", "expresss"], { cwd: app, env: sb.env, timeoutMs: 120_000 });

    expect(r.code, r.out).toBe(0);
    expect(r.out).toContain("! expresss@1.0.0");
    expect(r.out).toContain('WARNING expresss@1.0.0 has a name like a popular package\'s: one edit away from "express"');
    expect(r.out).toContain("did you mean express?");
    expect(r.out).not.toContain("apm: no warnings");
    expect(r.out).toContain("apm: no other warnings; the name expresss looks like a popular package's (above)");
    expect(installedVersion(app, "expresss")).toBe("1.0.0");
  });

  test("a package whose only version is tagged next: apm add says so and gives the command with the tag", async () => {
    const published = await putPublish(reg, alice, { name: "pre-only-pkg", version: "0.0.1-test.1", main: "index.js", license: "MIT" }, { tags: { next: "0.0.1-test.1" } });

    expect([200, 201]).toContain(published.status);
    const sb = makeSandbox(reg, alice);
    const app = writeConsumer(work, reg, alice);
    const r = await apm(["add", "pre-only-pkg"], { cwd: app, env: sb.env, timeoutMs: 120_000 });

    expect(r.code).toBe(1);
    expect(r.out).toContain("pre-only-pkg has no version tagged latest");
    expect(r.out).toContain("Its versions are tagged next (0.0.1-test.1)");
    expect(r.out).toContain("To install the version tagged next, run the same command with pre-only-pkg@next in place of pre-only-pkg");
    expect(r.out).not.toContain("--force does not help");
    expect(r.out).not.toContain("score unknown");

    const tagged = await apm(["add", "pre-only-pkg@next"], { cwd: app, env: sb.env, timeoutMs: 120_000 });

    expect(tagged.code, tagged.out).toBe(0);
    expect(installedVersion(app, "pre-only-pkg")).toBe("0.0.1-test.1");
  });
});
