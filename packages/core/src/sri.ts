// Subresource integrity (SRI) strings, as lockfiles and packuments carry them: "sha512-<base64> sha1-<base64>". One
// parse and one comparison for the registry's scan and the CLI's lockfile check, so the two never disagree about whether
// two strings name the same bytes (review of 2a098b1, findings 1 and 10).

/**
 * The hash algorithms an installer can check, weakest first: npm's ssri, pnpm and bun verify a tarball with the strongest
 * one an SRI string lists, and ignore algorithms they do not know.
 */
const ALGORITHMS = ["sha1", "sha224", "sha256", "sha384", "sha512"] as const;

export type SriAlgorithm = (typeof ALGORITHMS)[number];

const isAlgorithm = (s: string): s is SriAlgorithm => ALGORITHMS.some((a) => a === s);

/** An SRI string's digests by algorithm: one algorithm may list several. Unknown algorithms and options are dropped. */
export type Sri = ReadonlyMap<SriAlgorithm, ReadonlySet<string>>;

export function parseSri(text: string): Sri {
  const out = new Map<SriAlgorithm, Set<string>>();

  for (const token of text.trim().split(/\s+/)) {
    const dash = token.indexOf("-");

    if (dash <= 0) continue;
    const alg = token.slice(0, dash).toLowerCase();
    // "?opt" after the digest is an SRI option, not part of it
    const digest = token.slice(dash + 1).replace(/\?.*$/, "");

    if (!isAlgorithm(alg) || digest === "") continue;
    const set = out.get(alg) ?? new Set<string>();

    set.add(digest);
    out.set(alg, set);
  }

  return out;
}

/** The strongest algorithm an SRI lists: the one an installer verifies the tarball with. */
export function strongestAlgorithm(sri: Sri): SriAlgorithm | null {
  for (let i = ALGORITHMS.length - 1; i >= 0; i--) {
    const alg = ALGORITHMS[i];

    if (alg !== undefined && sri.has(alg)) return alg;
  }

  return null;
}

/** An SRI string from parsed digests, algorithms strongest first and digests sorted: equal digests give equal strings. */
export function formatSri(sri: Sri): string {
  return [...ALGORITHMS]
    .reverse()
    .flatMap((alg) => [...(sri.get(alg) ?? [])].sort().map((d) => `${alg}-${d}`))
    .join(" ");
}

/** "sha1-<base64>" from a packument's hex shasum, or null when it is not one. */
export function sha1FromShasum(shasum: string): string | null {
  return /^[0-9a-f]{40}$/i.test(shasum) ? `sha1-${Buffer.from(shasum, "hex").toString("base64")}` : null;
}

/**
 * What one integrity says about another's bytes. `matched`: the algorithm the installer checks `sent` with is one both
 * list, and every digest of `sent` in an algorithm both list is one `known` lists too. `mismatched`: some algorithm both
 * list has a digest in `sent` that `known` does not have, so the installer may accept other bytes. `unverified`: the
 * two cannot be compared (no algorithm in common, or the installer checks an algorithm only `sent` lists), which is
 * not the same as matched.
 */
export type IntegrityMatch = { kind: "matched" } | { kind: "mismatched"; algorithm: SriAlgorithm } | { kind: "unverified"; reason: string };

export function compareIntegrity(input: { sent: string; known: string }): IntegrityMatch {
  const sent = parseSri(input.sent);
  const known = parseSri(input.known);
  const shared = [...sent.keys()].filter((alg) => known.has(alg));

  for (const alg of shared) {
    const ours = known.get(alg) ?? new Set<string>();

    if ([...(sent.get(alg) ?? [])].some((d) => !ours.has(d))) return { kind: "mismatched", algorithm: alg };
  }

  const strongest = strongestAlgorithm(sent);

  if (strongest === null) return { kind: "unverified", reason: "it lists no hash algorithm an installer checks" };

  if (shared.length === 0) return { kind: "unverified", reason: `it lists ${[...sent.keys()].join(", ")} and the registry knows ${[...known.keys()].join(", ") || "no hash"}, so the two cannot be compared` };

  if (!shared.includes(strongest)) return { kind: "unverified", reason: `the package manager checks its ${strongest} hash, which the registry does not know` };

  return { kind: "matched" };
}

/**
 * Whether two integrities of one lockfile entry name different bytes: some algorithm both list has different digests.
 * The same digests in another order, or with an extra algorithm, are not different.
 */
export function integritiesConflict(a: string, b: string): boolean {
  const x = parseSri(a);
  const y = parseSri(b);

  return [...x.keys()].some((alg) => {
    const ys = y.get(alg);

    if (ys === undefined) return false;
    const xs = x.get(alg) ?? new Set<string>();

    return xs.size !== ys.size || [...xs].some((d) => !ys.has(d));
  });
}
