// Semver ignores build metadata, so 1.0.0+a and 1.0.0+b are the same version; both were stored, which is a version
// published twice with different bytes. apm accepts strict semver without build metadata.
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

test("a version with build metadata is refused, so 1.0.0+b cannot follow 1.0.0+a", async () => {
  expect((await putPublish(reg, token, { name: "build-meta", version: "1.0.0+a" })).status).toBe(400);
  expect((await putPublish(reg, token, { name: "build-meta", version: "1.0.0+b" })).status).toBe(400);
  expect((await putPublish(reg, token, { name: "build-meta", version: "1.0.0" })).status).toBe(201);
});
