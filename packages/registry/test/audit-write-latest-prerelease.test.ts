import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { addUser, getJson, putPublish, startRegistry, type Registry } from "../../../tests/acceptance/harness";

let reg: Registry;
let tok: string;

beforeAll(async () => {
  reg = await startRegistry();
  tok = await addUser(reg, "alice");
});
afterAll(async () => {
  await reg?.stop();
});

describe("latest after a prerelease-only first publish", () => {
  test("the first stable release takes latest from a prerelease", async () => {
    await putPublish(reg, tok, { name: "pf", version: "2.0.0-beta.1" });
    await putPublish(reg, tok, { name: "pf", version: "1.0.0" });
    const tags = await getJson(`${reg.url}-/package/pf/dist-tags`);
    console.log("dist-tags:", JSON.stringify(tags.body));
    expect(tags.body).toMatchObject({ latest: "1.0.0" });
  });
});
