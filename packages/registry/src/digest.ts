// A tarball's content digest, as the packument names it: what stored analyses, reviews and dismissals are keyed by.

export type Digest = { algo: "sha512" | "sha1"; hex: string };

export function digestOf(v: { integrity: string; shasum: string }): Digest | null {
  if (v.integrity.startsWith("sha512-")) {
    const raw = Buffer.from(v.integrity.slice("sha512-".length), "base64");

    if (raw.length === 64) return { algo: "sha512", hex: raw.toString("hex") };
  }

  if (/^[0-9a-f]{40}$/i.test(v.shasum)) return { algo: "sha1", hex: v.shasum.toLowerCase() };

  return null;
}

/** "sha512-<hex>": names a tarball's bytes; stored analyses are keyed by it. */
export function digestLabel(d: Digest): string {
  return `${d.algo}-${d.hex}`;
}
