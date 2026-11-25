// Semver ignores build metadata, so 1.0.0+a, 1.0.0+b and 1.0.0 are the same version. The database key compares the
// whole text, so each was stored with its own bytes: one version published several times.
import { afterAll, beforeAll, expect, test } from "bun:test";
import { addUser, putPublish, startRegistry, type Registry } from "../../../tests/acceptance/harness";

let reg: Registry;
let token: string;

beforeAll(async () => {
  reg = await startRegistry();
  token = await addUser(reg, "alice");
});

afterAll(async () => {
  await reg.stop();
});

test("a version equal to a published one but for build metadata is refused", async () => {
  expect((await putPublish(reg, token, { name: "build-meta", version: "1.0.0+a" })).status).toBe(201);
  expect((await putPublish(reg, token, { name: "build-meta", version: "1.0.0+b" })).status).toBe(409);
  expect((await putPublish(reg, token, { name: "build-meta", version: "1.0.0" })).status).toBe(409);
  // a different version still publishes
  expect((await putPublish(reg, token, { name: "build-meta", version: "1.0.1" })).status).toBe(201);
});
