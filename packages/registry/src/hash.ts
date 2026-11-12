// Digests and random ids. node:crypto runs on Workers under nodejs_compat and keeps these synchronous.
import { createHash } from "node:crypto";

export function sha1Hex(bytes: Uint8Array): string {
  return createHash("sha1").update(bytes).digest("hex");
}

export function sha256Hex(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

/** npm's integrity string ("sha512-<base64>") and the hex digest the blob store keys tarballs by. */
export type Sha512Digest = { integrity: string; hex: string };

/** Both forms of a tarball's sha512, from one pass over the bytes. */
export function sha512(bytes: Uint8Array): Sha512Digest {
  const digest = createHash("sha512").update(bytes).digest();

  return { integrity: `sha512-${digest.toString("base64")}`, hex: digest.toString("hex") };
}

/** The blob key for a tarball: content-addressed by sha512. */
export function tarballKey(sha512Hex: string): string {
  return `sha512/${sha512Hex}`;
}

export function randomId(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);

  return Buffer.from(buf).toString("base64url");
}
