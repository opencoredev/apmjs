// The upstream tarball puts this isolate has out to R2 (upstream.ts, keepBlob). A verified tarball is kept in R2 as a
// cache of npm's after its answer, and the put holds the tarball's bytes until R2 settles it. Without a bound, a burst
// of installs (or an R2 that stops answering) leaves one put per tarball out, each holding up to 32 MiB, in an isolate
// that has 128 MB. So, per isolate:
//
// - one put per key: a second request for the same tarball while its put is out does not start another;
// - at most `maxPuts` puts, holding at most `maxBytes` between them: a put that would pass either is skipped (the
//   tarball is not cached, and costs a later download from npm);
// - a put's share is given back when the put itself settles, never when its caller stops waiting for it (R2_PUT_MS):
//   bytes a late put still holds are still counted.

/** What the ledger allows out at once. */
export type PutLimits = { readonly maxPuts: number; readonly maxBytes: number };

/** The isolate's bound: a few puts, and room for one tarball at MAX_UPSTREAM_TARBALL_BYTES with smaller ones beside it. */
export const UPSTREAM_PUT_LIMITS: PutLimits = { maxPuts: 8, maxBytes: 48 * 1024 * 1024 };

/** What `start` did: began the put (`settled` is when the put itself settles; it never rejects), or skipped it. */
export type PutStart = { readonly kind: "started"; readonly settled: Promise<void> } | { readonly kind: "duplicate" } | { readonly kind: "full" };

export class PendingPuts {
  readonly #limits: PutLimits;
  readonly #out = new Map<string, number>();
  #bytes = 0;

  constructor(limits: PutLimits) {
    this.#limits = limits;
  }

  /** Puts out, and the bytes they hold. */
  get load() {
    return { puts: this.#out.size, bytes: this.#bytes };
  }

  /**
   * Runs `put` for `key`, holding `bytes` until it settles, unless a put of `key` is out already or this one would pass
   * the limits. `put` is not called when skipped.
   */
  start(input: { key: string; bytes: number; put: () => Promise<void> }): PutStart {
    if (this.#out.has(input.key)) return { kind: "duplicate" };

    if (this.#out.size + 1 > this.#limits.maxPuts || this.#bytes + input.bytes > this.#limits.maxBytes) return { kind: "full" };
    this.#out.set(input.key, input.bytes);
    this.#bytes += input.bytes;

    const release = (): void => {
      if (this.#out.delete(input.key)) this.#bytes -= input.bytes;
    };

    let running: Promise<void>;

    try {
      running = input.put();
    } catch {
      running = Promise.resolve();
    }

    return { kind: "started", settled: running.then(release, release) };
  }
}

/** This isolate's ledger. */
export const upstreamPuts = new PendingPuts(UPSTREAM_PUT_LIMITS);
