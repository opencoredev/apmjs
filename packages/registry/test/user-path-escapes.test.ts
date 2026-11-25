// PUT and GET /-/user/org.couchdb.user:<name> decoded the name with a bare decodeURIComponent, so a malformed escape
// threw a URIError: a 500 and a defect report for bad input instead of a 400.
import { afterAll, beforeAll, expect, test } from "bun:test";
import { addUser, getJson, startRegistry, type Registry } from "../../../tests/acceptance/harness";

let reg: Registry;

beforeAll(async () => {
  reg = await startRegistry();
});

afterAll(async () => {
  await reg.stop();
});

test("a user lookup with a malformed escape in the name is a 400", async () => {
  expect((await getJson(`${reg.url}-/user/org.couchdb.user:%FF`)).status).toBe(400);
});

test("an adduser with a malformed escape in the name is a 400", async () => {
  const res = await getJson(`${reg.url}-/user/org.couchdb.user:%FF`, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: "\u00ff", password: "a-long-password" }),
  });

  expect(res.status).toBe(400);
});

test("a user lookup by HEAD with a malformed escape in the name is a 400", async () => {
  expect((await fetch(`${reg.url}-/user/org.couchdb.user:%FF`, { method: "HEAD" })).status).toBe(400);
});

test("a well-formed escape still decodes to the user's name", async () => {
  await addUser(reg, "erin");

  expect(await getJson(`${reg.url}-/user/org.couchdb.user:%65rin`)).toEqual({ status: 200, body: { _id: "org.couchdb.user:erin", name: "erin" } });
});
