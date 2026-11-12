// A software passkey for the acceptance suite: a P-256 key registered straight into Better Auth's passkey table for
// one account, and WebAuthn assertions signed with it the way a browser's authenticator answers a challenge.
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import { z } from "zod";
import type { Registry } from "./harness";

const Jwk = z.object({ x: z.string(), y: z.string() });

export type Assertion = {
  id: string;
  rawId: string;
  type: "public-key";
  response: { clientDataJSON: string; authenticatorData: string; signature: string };
  clientExtensionResults: Record<string, never>;
};

export type SoftPasskey = {
  credentialId: string;
  /** Answers `challenge` (base64url, as the options carry it) for the relying party at `origin`. */
  assert: (input: { challenge: string; origin: string }) => Assertion;
};

/** The COSE_Key (RFC 9053) of a P-256 public key: {1: 2, 3: -7, -1: 1, -2: x, -3: y} in CBOR. */
function coseKey(x: Buffer, y: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]), x, Buffer.from([0x22, 0x58, 0x20]), y]);
}

/** Registers a new passkey for the apm user `name` and returns it. */
export async function addSoftPasskey(reg: Registry, name: string): Promise<SoftPasskey> {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = Jwk.parse(publicKey.export({ format: "jwk" }));
  const credentialId = randomBytes(16).toString("base64url");
  const users = await reg.query("SELECT auth_user_id FROM users WHERE name = $1", [name]);
  const authUserId = z.array(z.object({ auth_user_id: z.string() })).length(1).parse(users)[0]?.auth_user_id;

  await reg.query(
    `INSERT INTO passkey (id, name, "publicKey", "userId", "credentialID", counter, "deviceType", "backedUp", transports, "createdAt")
     VALUES ($1, 'test passkey', $2, $3, $4, 0, 'singleDevice', false, NULL, now())`,
    [randomBytes(8).toString("hex"), coseKey(Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")).toString("base64"), authUserId, credentialId],
  );

  return { credentialId, assert: assertWith(privateKey, credentialId) };
}

function assertWith(key: KeyObject, credentialId: string): SoftPasskey["assert"] {
  let counter = 0;

  return ({ challenge, origin }) => {
    counter += 1;
    const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin, crossOrigin: false }));
    const count = Buffer.alloc(4);
    count.writeUInt32BE(counter);
    // rpIdHash, flags (user present and verified), sign count
    const authData = Buffer.concat([createHash("sha256").update(new URL(origin).hostname).digest(), Buffer.from([0x05]), count]);
    const signature = sign("sha256", Buffer.concat([authData, createHash("sha256").update(clientData).digest()]), key);

    return {
      id: credentialId,
      rawId: credentialId,
      type: "public-key",
      response: { clientDataJSON: clientData.toString("base64url"), authenticatorData: authData.toString("base64url"), signature: signature.toString("base64url") },
      clientExtensionResults: {},
    };
  };
}
