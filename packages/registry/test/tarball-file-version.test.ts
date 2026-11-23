// A tarball URL names one version: "<name>-<version>.tgz". A prerelease whose identifiers look like a version
// (1.0.0-0.3.7, the semver spec's own example) was read as the version after its last dash, 0.3.7, so the URL served
// another version's bytes and checked that version's status, for apm's own packages and for npm's.
import { afterAll, beforeAll, expect, test } from "bun:test";
import { encodePkg, putPublish, startRegistry, type Registry } from "../../../tests/acceptance/harness";

const VERSIONS = [
  ["0.3.7", "module.exports = 'plain';\n"],
  ["1.0.0-0.3.7", "module.exports = 'prerelease';\n"],
] as const;

let upstream: Registry;
let reg: Registry;

beforeAll(async () => {
  upstream = await startRegistry({ namePolicy: "open" });
  reg = await startRegistry({ namePolicy: "open", upstream: upstream.url });
});

afterAll(async () => {
  await reg.stop();
  await upstream.stop();
});

async function publishBoth(into: Registry, name: string): Promise<void> {
  const token = await into.mintToken({ user: "alice", scope: "publish" });

  for (const [version, body] of VERSIONS) {
    const res = await putPublish(into, token, { name, version, license: "MIT", main: "index.js" }, { files: { "index.js": body }, tags: { [version.includes("-") ? "next" : "latest"]: version } });

    expect(res.status).toBe(201);
  }
}

async function tgz(from: Registry, name: string, version: string): Promise<Buffer> {
  const res = await fetch(`${from.url}${encodePkg(name)}/-/${name}-${version}.tgz`);

  expect(res.status).toBe(200);

  return Buffer.from(await res.arrayBuffer());
}

test("apm's own package: pkg-1.0.0-0.3.7.tgz serves 1.0.0-0.3.7, not 0.3.7", async () => {
  await publishBoth(reg, "tarball-dash");

  const plain = await tgz(reg, "tarball-dash", "0.3.7");
  const pre = await tgz(reg, "tarball-dash", "1.0.0-0.3.7");

  expect(pre.equals(plain)).toBe(false);
});

test("an npm package: pkg-1.0.0-0.3.7.tgz serves 1.0.0-0.3.7, not 0.3.7", async () => {
  await publishBoth(upstream, "upstream-dash");

  const expected = await tgz(upstream, "upstream-dash", "1.0.0-0.3.7");
  const pre = await tgz(reg, "upstream-dash", "1.0.0-0.3.7");

  expect(pre.equals(expected)).toBe(true);
});
