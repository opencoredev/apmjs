// A website confirmation approves one exact command ("npm owner add bob pkg"). The npm owner route must not let that
// one confirmation authorise a different or larger change than the one approved.
import { afterAll, beforeAll, expect, test } from "bun:test";
import { deviceLogin, enableTotp, encodePkg, getJson, putPublish, signInWithGitHub, startFakeGitHub, startRegistry, totp, type FakeGitHub, type Registry } from "../../../tests/acceptance/harness";

let reg: Registry;
let gh: FakeGitHub;

beforeAll(async () => {
  gh = startFakeGitHub();
  reg = await startRegistry({ github: gh });
});

afterAll(async () => {
  await reg.stop();
});

test("one confirmation for `owner add bob` cannot also add carol", async () => {
  const owner = await signInWithGitHub(reg, gh, "oscar");
  const secret = await enableTotp(owner);
  await signInWithGitHub(reg, gh, "bob");
  await signInWithGitHub(reg, gh, "carol");
  const token = (await deviceLogin(owner)).token;
  const live = await reg.mintToken({ user: "oscar", scope: "publish" });
  const name = "@oscar/pkg";

  expect((await putPublish(reg, live, { name, version: "1.0.0", license: "MIT", main: "index.js" })).status).toBe(201);
  const command = { kind: "owner-add", name, user: "bob" } as const;
  const conf = await owner.json("-/apm/v1/factor/confirm", { method: "POST", body: { action: { kind: "cli-confirm", command }, code: totp(secret) } });
  const id = (conf.body as { confirmation: string }).confirmation;

  expect((await owner.json("-/apm/v1/verify", { method: "POST", body: { command, confirmation: id } })).status).toBe(200);
  const res = await getJson(`${reg.url}${encodePkg(name)}/-rev/1`, {
    method: "PUT",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify({ maintainers: [{ name: "oscar" }, { name: "bob" }, { name: "carol" }] }),
  });
  const owners = (res.body as { owners?: string[] }).owners ?? [];

  expect(owners).not.toContain("carol");
  expect(res.status).toBeGreaterThanOrEqual(400);
});
