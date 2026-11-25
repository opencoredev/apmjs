// DELETE /-/user/token/<token> (npm logout) revoked the caller's own token whatever the path named: revoking a leaked
// token while signed in with another one signed that one out, left the leaked token live, and answered ok.
import { afterAll, beforeAll, expect, test } from "bun:test";
import { addUser, getJson, startRegistry, type Registry } from "../../../tests/acceptance/harness";

let reg: Registry;

beforeAll(async () => {
  reg = await startRegistry();
});

afterAll(async () => {
  await reg.stop();
});

const whoami = async (token: string): Promise<number> => (await getJson(`${reg.url}-/whoami`, { headers: { authorization: `Bearer ${token}` } })).status;

const revoke = async (named: string, caller: string): Promise<number> => (await getJson(`${reg.url}-/user/token/${encodeURIComponent(named)}`, { method: "DELETE", headers: { authorization: `Bearer ${caller}` } })).status;

test("the token the path names is revoked, not the caller's", async () => {
  const caller = await addUser(reg, "alice");
  const leaked = await addUser(reg, "alice");

  expect(await revoke(leaked, caller)).toBe(200);
  expect(await whoami(leaked)).toBe(401);
  expect(await whoami(caller)).toBe(200);
});

test("npm logout, which names the caller's own token, still revokes it", async () => {
  const token = await addUser(reg, "bob");

  expect(await revoke(token, token)).toBe(200);
  expect(await whoami(token)).toBe(401);
});

test("another account's token is not revoked", async () => {
  const mine = await addUser(reg, "carol");
  const theirs = await addUser(reg, "dave");

  expect(await revoke(theirs, mine)).toBe(404);
  expect(await whoami(theirs)).toBe(200);
  expect(await whoami(mine)).toBe(200);
});
