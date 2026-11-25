// A NUL (%00) in a name reached Postgres, which refuses it in text: the request ended as a store error, answered 500
// "Internal error" and reported as an infra failure. It is bad input: 400, before any route reads the database.
import { afterAll, beforeAll, expect, test } from "bun:test";
import { startRegistry, type Registry } from "../../../tests/acceptance/harness";

let reg: Registry;

beforeAll(async () => {
  reg = await startRegistry({ namePolicy: "open" });
});

afterAll(async () => {
  await reg.stop();
});

test.each(["-/apm/v1/score/%00", "-/apm/v1/resolve?name=%00", "-/apm/v1/packages/p%00/versions/1.0.0", "p%00", "p%00/1.0.0", "-/package/p%00/dist-tags"])("GET /%s is a 400", async (path) => {
  const res = await fetch(`${reg.url}${path}`);

  expect(res.status).toBe(400);
});

test("a name without a NUL still answers as before", async () => {
  expect((await fetch(`${reg.url}-/apm/v1/score/no-such-package-anywhere`)).status).toBe(404);
});
