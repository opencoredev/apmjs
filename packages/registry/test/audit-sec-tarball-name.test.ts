// A tarball URL names one version: "<name>-<version>.tgz". A prerelease whose identifiers look like a version
// (1.0.0-0.3.7, the semver spec's own example) must not be read as the version after its last dash.
import { afterAll, beforeAll, expect, test } from "bun:test";
import { encodePkg, putPublish, startRegistry, type Registry } from "../../../tests/acceptance/harness";

let reg: Registry;

beforeAll(async () => {
  reg = await startRegistry({ namePolicy: "open" });
});

afterAll(async () => {
  await reg.stop();
});

test("pkg-1.0.0-0.3.7.tgz serves 1.0.0-0.3.7, not 0.3.7", async () => {
  const token = await reg.mintToken({ user: "alice", scope: "publish" });
  const name = "tarball-dash";

  for (const [version, body] of [
    ["0.3.7", "module.exports = 'plain';\n"],
    ["1.0.0-0.3.7", "module.exports = 'prerelease';\n"],
  ] as const) {
    expect((await putPublish(reg, token, { name, version, license: "MIT", main: "index.js" }, { files: { "index.js": body }, tags: { [version.includes("-") ? "next" : "latest"]: version } })).status).toBe(201);
  }

  const fetchTgz = async (version: string): Promise<Uint8Array> => {
    const res = await fetch(`${reg.url}${encodePkg(name)}/-/${name}-${version}.tgz`);
    expect(res.status).toBe(200);

    return new Uint8Array(await res.arrayBuffer());
  };

  const plain = await fetchTgz("0.3.7");
  const pre = await fetchTgz("1.0.0-0.3.7");

  expect(Buffer.from(pre).equals(Buffer.from(plain))).toBe(false);
});
