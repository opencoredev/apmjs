// The account page lists every passkey its count includes (the same rows, no key material), named by the password
// manager its AAGUID names, with when it was added and last used. Removing one takes a fresh factor made to remove
// exactly that passkey, from the website, removes only the signed-in account's own passkey, and never the account's
// last way in.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { z } from "zod";
import { dig, signInWithGitHub, startFakeGitHub, startRegistry, type Browser, type FakeGitHub, type Registry } from "./harness";
import { addSoftPasskey, type SoftPasskey } from "./passkey";

const ONE_PASSWORD = "bada5566-a7aa-401f-bd96-45619a55120d";

const Listed = z.object({
  security: z.object({ passkeys: z.number() }),
  passkeys: z.array(z.object({ id: z.string(), name: z.string().nullable(), provider: z.string().nullable(), createdAt: z.string().nullable(), lastUsedAt: z.string().nullable() }).strict()),
});

let reg: Registry;
let gh: FakeGitHub;
let owner: Browser;
let other: Browser;
let first: SoftPasskey;
let second: SoftPasskey;
let othersKey: SoftPasskey;

async function listed(b: Browser) {
  const r = await b.json("-/apm/v1/account");

  expect(r.status).toBe(200);

  return Listed.parse(r.body);
}

async function idOf(key: SoftPasskey): Promise<string> {
  const rows = z.array(z.object({ id: z.string() })).length(1).parse(await reg.query(`SELECT id FROM passkey WHERE "credentialID" = $1`, [key.credentialId]));

  return rows[0]?.id ?? "";
}

/** A passkey check made to remove passkey `id`, answered by `key`: the confirmation it issues. */
async function confirmRemoval(b: Browser, id: string, key: SoftPasskey): Promise<string> {
  const action = { kind: "passkey-remove", id };
  const ch = await b.json("-/apm/v1/factor/passkey-challenge", { method: "POST", body: { action } });

  expect(ch.status).toBe(200);
  const response = key.assert({ challenge: String(dig(ch.body, "options", "challenge")), origin: new URL(reg.url).origin });
  const r = await b.json("-/apm/v1/factor/confirm", { method: "POST", body: { action, passkey: { challengeId: dig(ch.body, "challengeId"), response } } });

  expect(r.status, JSON.stringify(r.body)).toBe(200);

  return String(dig(r.body, "confirmation"));
}

const remove = (b: Browser, body: { id: string; confirmation?: string }, headers: Record<string, string> = {}) => b.json("-/apm/v1/account/passkeys/remove", { method: "POST", body, headers });

beforeAll(async () => {
  gh = startFakeGitHub();
  reg = await startRegistry({ github: gh });
  owner = await signInWithGitHub(reg, gh, "octo-owner");
  other = await signInWithGitHub(reg, gh, "octo-other");
  // the first account read binds each apm user, which the software passkey is registered for
  await owner.json("-/apm/v1/account");
  await other.json("-/apm/v1/account");
  first = await addSoftPasskey(reg, "octo-owner");
  second = await addSoftPasskey(reg, "octo-owner");
  othersKey = await addSoftPasskey(reg, "octo-other");
  await reg.query(`UPDATE passkey SET aaguid = $1 WHERE "credentialID" = $2`, [ONE_PASSWORD, first.credentialId]);
}, 60_000);

afterAll(async () => {
  await reg?.stop();
  await gh?.stop();
});

describe("the passkey list", () => {
  test("lists exactly the passkeys the count includes, oldest first, named by AAGUID, with no key material", async () => {
    const a = await listed(owner);

    expect(a.security.passkeys).toBe(2);
    expect(a.passkeys.map((p) => p.id)).toEqual([await idOf(first), await idOf(second)]);
    expect(a.passkeys.map((p) => p.provider)).toEqual(["1Password", null]);
    expect(a.passkeys.every((p) => p.name === "test passkey" && p.createdAt !== null && p.lastUsedAt === null)).toBe(true);
    // .strict() above refuses any other field, such as the credential id or the public key
  });

  test("a passkey sign-in and a passkey check each record when that passkey was last used", async () => {
    const options = await owner.json("api/auth/passkey/generate-authenticate-options");

    const signIn = await owner.json("api/auth/passkey/verify-authentication", {
      method: "POST",
      body: { response: second.assert({ challenge: String(dig(options.body, "challenge")), origin: new URL(reg.url).origin }) },
    });

    expect(signIn.status, JSON.stringify(signIn.body)).toBe(200);
    expect((await listed(owner)).passkeys.map((p) => p.lastUsedAt !== null)).toEqual([false, true]);

    await confirmRemoval(owner, "unused-id", first);
    expect((await listed(owner)).passkeys.map((p) => p.lastUsedAt !== null)).toEqual([true, true]);
  });
});

describe("removing a passkey", () => {
  test("needs a fresh factor made for removing exactly that passkey, and the website's origin", async () => {
    const firstId = await idOf(first);
    const secondId = await idOf(second);

    expect((await remove(owner, { id: firstId })).status).toBe(401);
    // a check made to remove the other passkey does not remove this one
    expect((await remove(owner, { id: firstId, confirmation: await confirmRemoval(owner, secondId, first) })).status).toBe(401);
    expect((await remove(owner, { id: firstId, confirmation: await confirmRemoval(owner, firstId, first) }, { origin: "https://evil.example" })).status).toBe(403);
    expect((await listed(owner)).security.passkeys).toBe(2);
  });

  test("never removes another account's passkey", async () => {
    const theirs = await idOf(othersKey);
    const r = await remove(owner, { id: theirs, confirmation: await confirmRemoval(owner, theirs, first) });

    expect(r.status).toBe(404);
    expect((await listed(other)).security.passkeys).toBe(1);
  });

  test("removes the passkey, and a confirmation works once", async () => {
    const secondId = await idOf(second);
    const confirmation = await confirmRemoval(owner, secondId, second);

    expect((await remove(owner, { id: secondId, confirmation })).status).toBe(200);
    expect((await remove(owner, { id: secondId, confirmation })).status).toBe(401);
    const a = await listed(owner);

    expect(a.security.passkeys).toBe(1);
    expect(a.passkeys.map((p) => p.id)).toEqual([await idOf(first)]);
    expect(await reg.query(`SELECT count(*)::int AS n FROM passkey_uses WHERE passkey_id = $1`, [secondId])).toEqual([{ n: 0 }]);
  });

  test("keeps the last passkey of an account with nothing else to sign in with, and removes it once GitHub is linked", async () => {
    const theirs = await idOf(othersKey);
    const linked = await reg.query(`SELECT a.* FROM account a JOIN users u ON u.auth_user_id = a."userId" WHERE u.name = 'octo-other'`);

    await reg.query(`DELETE FROM account a USING users u WHERE u.auth_user_id = a."userId" AND u.name = 'octo-other'`);
    const refused = await remove(other, { id: theirs, confirmation: await confirmRemoval(other, theirs, othersKey) });

    expect(refused.status).toBe(409);
    expect(JSON.stringify(refused.body)).toContain("only way to sign in");
    expect((await listed(other)).security.passkeys).toBe(1);

    expect(linked.length).toBe(1);
    await reg.query(`INSERT INTO account SELECT * FROM json_populate_record(NULL::account, $1::json)`, [JSON.stringify(linked[0])]);
    expect((await remove(other, { id: theirs, confirmation: await confirmRemoval(other, theirs, othersKey) })).status).toBe(200);
    expect((await listed(other)).security.passkeys).toBe(0);
  });
});
