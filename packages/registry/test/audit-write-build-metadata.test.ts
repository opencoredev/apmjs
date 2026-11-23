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

describe("a version that differs only in build metadata is the same version", () => {
  test("1.0.0+b cannot be published after 1.0.0+a", async () => {
    const a = await putPublish(reg, tok, { name: "bm", version: "1.0.0+a" });
    const b = await putPublish(reg, tok, { name: "bm", version: "1.0.0+b" });
    console.log("first", a.status, "second", b.status);
    expect(b.status).toBeGreaterThanOrEqual(400);
  });
});
