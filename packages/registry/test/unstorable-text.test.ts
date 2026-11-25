// Postgres stores neither a NUL nor an unpaired surrogate in jsonb or text, and JSON.parse accepts both. A publish whose
// package.json or readme held one, or an npm deprecate whose message did, failed at the insert and answered 500
// "Internal error" (reported as an infra failure). They are refused, as input apm cannot store.
import { afterAll, beforeAll, expect, test } from "bun:test";
import { encodePkg, putPublish, startRegistry, type Registry } from "../../../tests/acceptance/harness";

let reg: Registry;
let token: string;

beforeAll(async () => {
  reg = await startRegistry({ namePolicy: "open" });
  token = await reg.mintToken({ user: "alice", scope: "publish" });
});

afterAll(async () => {
  await reg.stop();
});

test.each([
  ["nul-description", { description: "a\u0000b" }],
  ["surrogate-description", { description: "a\ud800b" }],
  ["nul-dependency-range", { dependencies: { "left-padz": "1\u0000" } }],
  ["nul-readme", { readme: "hi\u0000there" }],
] as const)("a publish with %s is refused, and nothing is half-published", async (name, extra) => {
  const res = await putPublish(reg, token, { name, version: "1.0.0", main: "index.js", ...extra });

  expect(res.status).toBe(422);
  expect((await fetch(`${reg.url}${encodePkg(name)}`)).status).toBe(404);
});

test("a NUL in a file path inside the tarball still publishes, as before", async () => {
  const res = await putPublish(reg, token, { name: "nul-path", version: "1.0.0", main: "index.js" }, { files: { "a\u0000b.txt": "x", "index.js": "1" } });

  expect(res.status).toBe(201);
});

test.each([
  ["nul-deprecate", "a\u0000b"],
  ["surrogate-deprecate", "a\ud800b"],
] as const)("%s: a deprecation message apm cannot store is refused, and the version is unchanged", async (name, message) => {
  expect((await putPublish(reg, token, { name, version: "1.0.0", main: "index.js" })).status).toBe(201);

  const res = await fetch(`${reg.url}${encodePkg(name)}`, {
    method: "PUT",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify({ name, versions: { "1.0.0": { name, version: "1.0.0", deprecated: message } } }),
  });

  expect(res.status).toBe(422);
  const doc = await fetch(`${reg.url}${encodePkg(name)}/1.0.0`);

  expect(await doc.json()).not.toHaveProperty("deprecated");
});
