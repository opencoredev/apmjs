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

const whoami = async (t: string) => (await getJson(`${reg.url}-/whoami`, { headers: { authorization: `Bearer ${t}` } })).status;

describe("DELETE /-/user/token/<token>", () => {
  test("revokes the token named in the path, not the caller's", async () => {
    const leaked = await addUser(reg, "alice");
    expect(await whoami(leaked)).toBe(200);
    await getJson(`${reg.url}-/user/token/${leaked}`, { method: "DELETE", headers: { authorization: `Bearer ${tok}` } });
    console.log("leaked token whoami:", await whoami(leaked), "caller token whoami:", await whoami(tok));
    expect(await whoami(leaked)).toBe(401);
  });
});
