// `apm incident` revokes each version "by the same rule as apm revoke" (guides/pull-a-version): at once under 72 hours,
// after 24 hours otherwise. A version already revoke-pending stays pending under apm revoke, but the incident sweep took
// that refusal as a final revoke, so the 24 h window an older version gets ended at once.
import { afterAll, beforeAll, expect, test } from "bun:test";
import { z } from "zod";
import { addUser, dig, getJson, putPublish, startRegistry, type Registry } from "../../../tests/acceptance/harness";

const DAY = 24 * 60 * 60 * 1000;
const PASSWORD = "correct-horse-battery";
const Status = z.array(z.object({ status: z.string() }));

let clock = Date.parse("2026-01-01T00:00:00Z");
let reg: Registry;

beforeAll(async () => {
  reg = await startRegistry({ now: () => clock, namePolicy: "open" });
});

afterAll(async () => {
  await reg.stop();
});

const api = (path: string, token: string, body: Record<string, string>) =>
  getJson(`${reg.url}-/apm/v1/${path}`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify(body) });

test("an incident sweep leaves an older version's pending revoke pending, as apm revoke does", async () => {
  const bob = await addUser(reg, "bob", PASSWORD);
  const since = new Date(clock - DAY).toISOString();

  expect((await putPublish(reg, bob, { name: "pend-lib", version: "1.0.0" })).status).toBe(201);
  // past the 72 hours a fresh version is revoked at once
  clock += 4 * DAY;
  expect(dig((await api("revoke", bob, { name: "pend-lib", version: "1.0.0", reason: "bad", password: PASSWORD })).body, "status")).toBe("revoke-pending");

  clock += 60 * 60 * 1000;
  const incident = await api("incident", bob, { since, reason: "phished", password: PASSWORD });

  expect(incident.status).toBe(200);
  expect(dig(incident.body, "statuses", "pend-lib@1.0.0")).toBe("revoke-pending");
  expect(Status.parse(await reg.query("SELECT status FROM versions WHERE package = 'pend-lib' AND version = '1.0.0'"))[0]?.status).toBe("revoke-pending");
});

test("a pending revoke past its 24 h is revoked to an incident sweep, as to every other read, not reported as pending", async () => {
  const dana = await addUser(reg, "dana", PASSWORD);
  const since = new Date(clock - DAY).toISOString();

  expect((await putPublish(reg, dana, { name: "matured-lib", version: "1.0.0" })).status).toBe(201);
  expect((await putPublish(reg, dana, { name: "matured-lib", version: "1.0.1" })).status).toBe(201);
  clock += 4 * DAY;
  expect(dig((await api("revoke", dana, { name: "matured-lib", version: "1.0.0", reason: "bad", password: PASSWORD })).body, "status")).toBe("revoke-pending");
  // past the window, before the cron writes it
  clock += DAY + 60 * 60 * 1000;

  const incident = await api("incident", dana, { since: new Date(Date.parse(since) - 4 * DAY).toISOString(), reason: "phished", password: PASSWORD });

  expect(incident.status).toBe(200);
  expect(dig(incident.body, "statuses", "matured-lib@1.0.0")).toBeUndefined();
  expect(JSON.stringify(dig(incident.body, "revoked"))).not.toContain("matured-lib@1.0.0");
  expect(dig(incident.body, "statuses", "matured-lib@1.0.1")).toBe("revoke-pending");
});

// the reason goes into the version's status_reason, an advisory and the event log, which refuse a NUL or an unpaired
// surrogate: the write failed inside the transaction and the change answered 500
test.each([
  ["revoke", "a\u0000b"],
  ["revoke", "a\ud800b"],
  ["yank", "a\u0000b"],
  ["incident", "a\u0000b"],
] as const)("apm %s with a reason apm cannot store (%j) is refused, and the version is unchanged", async (action, reason) => {
  const carol = await addUser(reg, `carol-${action}-${reason.charCodeAt(1)}`, PASSWORD);
  const name = `reason-${action}-${reason.charCodeAt(1)}`;

  expect((await putPublish(reg, carol, { name, version: "1.0.0" })).status).toBe(201);
  const body: Record<string, string> = action === "incident" ? { since: new Date(clock - DAY).toISOString(), reason, password: PASSWORD } : { name, version: "1.0.0", reason, password: PASSWORD };

  expect((await api(action, carol, body)).status).toBe(400);
  expect(Status.parse(await reg.query("SELECT status FROM versions WHERE package = $1", [name]))[0]?.status).toBe("active");
});
