// The memory a Worker isolate holds for npm's package metadata, as one pool of weight (packument-read.ts, WEIGHTS: an
// upper bound on the heap a packument is held in). An isolate has 128 MB for every request it runs at once, so what
// the reader keeps, what converting it builds, what serializing it buffers, the shared-cache writes still running
// after their response, and the isolate cache's entries all come out of one POOL_WEIGHT. Each holder takes a Lease:
// a request (REQUEST_WEIGHT at most), the isolate cache (CACHE_WEIGHT at most), or a piece of background work.
//
// Two kinds of charge:
// - own weight (take/give): memory only this lease's holder refers to, such as a read in progress or a conversion's
//   temporaries;
// - a Block: memory several holders may refer to at once, such as a package a request read, the isolate cache keeps
//   and a background write is still serializing. The pool counts a block once while anyone holds it, and every holder
//   counts it against its own limit; it leaves the pool only when its last holder drops it, so a cache eviction or a
//   request that ends frees only its share of the ownership.
//
// A lease is open until every holder of it lets go (release, and each retain()'s release): a streamed answer keeps its
// request's lease until the last byte is sent. Closing a lease drops every block it holds and gives back its own weight
// and its children's. What does not fit is refused at once, never waited for: the caller reports the package as not
// checked (over-budget), as it does when one request has used its own limit.
//
// The claim: the sum of every open lease's own weight and every held block's weight never passes the pool's limit.
// Charging covers the reads, their parsed values and the cache; the known gaps where memory outlives its charge are
// listed in docs/ARCHITECTURE.md ("Known gaps").
import { Context, Effect, Layer } from "effect";

const MiB = 1024 * 1024;

/** All the package metadata an isolate holds at once, leaving 48 of its 128 MiB to the runtime and other work. */
export const POOL_WEIGHT = 80 * MiB;

/**
 * The most one request holds (a resolve walk, a scan, the packument route). next, react and typescript together hold
 * 60.7 MiB (63.4 at peak); at 64 MiB a root of 1 MiB beside them left next unchecked, so 72 MiB leaves room for a root
 * of up to about 8 MiB (71.4 MiB at peak), inside the 80 MiB pool.
 */
export const REQUEST_WEIGHT = 72 * MiB;

/** The most the isolate cache keeps. Oldest go first, and the pool takes them back when a read needs the room. */
export const CACHE_WEIGHT = 32 * MiB;

/**
 * How long background work may run before it is told to stop: its lease's signal aborts then. The lease is not given
 * back at the deadline: the work lets go once it has stopped (and dropped what it refers to), and work that does not
 * stop keeps its charge, so the pool never counts as free memory something still refers to.
 */
export const BACKGROUND_DEADLINE_MS = 30_000;

/** Memory several holders may refer to at once: counted once in the pool while any of them holds it. */
export class Block {
  readonly weight: number;
  /** @internal the leases that hold it; empty once dropped by the last, and then it is never held again */
  readonly holders = new Set<Lease>();

  constructor(weight: number) {
    this.weight = weight;
  }

  /** Whether some lease still holds it. */
  get live(): boolean {
    return this.holders.size > 0;
  }
}

/** What a lease is for: its limit, and whether the pool may take its blocks back under pressure (the cache's). */
export type LeaseKind = "request" | "cache" | "background" | "child";

export class Lease {
  readonly pool: MemoryPool;
  readonly kind: LeaseKind;
  readonly limit: number;
  private readonly parent: Lease | null;
  /** Weight only this lease holds (take/give), not its blocks or its children's. */
  private own = 0;
  /** Own weight, blocks and children's, against `limit`; and the most it has been. */
  private counted = 0;
  private peak = 0;
  private readonly blocks = new Set<Block>();
  private readonly children = new Set<Lease>();
  /** Holders that have not let go yet: the opener, and each retain(). */
  private holds = 1;
  private openerGone = false;
  private openFlag = true;

  /** @internal made by MemoryPool and Lease.child only */
  constructor(input: { pool: MemoryPool; kind: LeaseKind; limit: number; parent: Lease | null }) {
    this.pool = input.pool;
    this.kind = input.kind;
    this.limit = input.limit;
    this.parent = input.parent;
  }

  get open(): boolean {
    return this.openFlag;
  }

  /** The lease this one is a child of, or itself: the request (or job, or background work) it belongs to. */
  get root(): Lease {
    return this.parent?.root ?? this;
  }

  /** Everything this lease counts against its limit: own weight, the blocks it holds, its children's. */
  get taken(): number {
    return this.counted;
  }

  /** The most `taken` has been. */
  get peakTaken(): number {
    return this.peak;
  }

  /** Nothing more fits: a read would be refused at its first kept byte. */
  get exhausted(): boolean {
    return this.full() || !this.pool.hasRoom();
  }

  /** This lease or a parent is at its limit. */
  private full(): boolean {
    return this.counted >= this.limit || (this.parent?.full() ?? false);
  }

  /** Throws when the lease is closed: a read under a closed lease would hold memory nothing counts. */
  assertOpen(): void {
    if (!this.openFlag) throw new Error(`a ${this.kind} memory lease was used after it was released`);
  }

  /** Whether `n` more fits under this lease's limit and every parent's. */
  private fits(n: number): boolean {
    return this.counted + n <= this.limit && (this.parent?.fits(n) ?? true);
  }

  /** `n` more (or less) counted here and in every parent. */
  private count(n: number): void {
    this.counted += n;

    if (this.counted > this.peak) this.peak = this.counted;
    this.parent?.count(n);
  }

  /** Takes `n` of own weight, or nothing and false when that would pass a limit: this lease's, a parent's, the pool's. */
  take(n: number): boolean {
    this.assertOpen();

    if (n <= 0) return true;

    if (!this.fits(n) || !this.pool.reserve(n)) return false;
    this.own += n;
    this.count(n);

    return true;
  }

  /** Gives back up to `n` of own weight. */
  give(n: number): void {
    const back = Math.min(Math.max(0, n), this.own);

    if (back === 0) return;
    this.own -= back;
    this.count(-back);
    this.pool.free(back);
  }

  /** Turns `n` of own weight into a block this lease holds, which others may hold too (hold). */
  seal(n: number): Block {
    this.assertOpen();
    const weight = Math.min(Math.max(0, n), this.own);
    this.own -= weight;
    const block = new Block(weight);
    block.holders.add(this);
    this.blocks.add(block);

    return block;
  }

  /** Holds `block` too, counted against this lease's limits; true when it is held (already, or now). */
  hold(block: Block): boolean {
    this.assertOpen();

    if (this.blocks.has(block)) return true;

    // a block nobody holds has left the pool, and what it stood for may be gone: it is never brought back
    if (!block.live || !this.fits(block.weight)) return false;
    block.holders.add(this);
    this.blocks.add(block);
    this.count(block.weight);

    return true;
  }

  /** Lets go of `block`: the pool frees it when no other lease holds it. */
  drop(block: Block): void {
    if (!this.blocks.delete(block)) return;
    this.count(-block.weight);
    block.holders.delete(this);

    if (!block.live) this.pool.free(block.weight);
  }

  /** Whether this lease is the only holder of `block`, so dropping it frees memory. */
  soleHolder(block: Block): boolean {
    return block.holders.size === 1 && block.holders.has(this);
  }

  /** A lease that counts against this one (and its parents) with a limit of its own, for part of a request's work. */
  child(limit: number = Number.POSITIVE_INFINITY): Lease {
    this.assertOpen();
    const made = new Lease({ pool: this.pool, kind: "child", limit, parent: this });
    this.children.add(made);

    return made;
  }

  /** One more holder: the lease stays open until it calls the function returned (once; later calls do nothing). */
  retain(): () => void {
    this.assertOpen();
    this.holds++;
    let done = false;

    return () => {
      if (done) return;
      done = true;
      this.letGo();
    };
  }

  /** The opener lets go (once; later calls do nothing). */
  release(): void {
    if (this.openerGone) return;
    this.openerGone = true;
    this.letGo();
  }

  private letGo(): void {
    this.holds--;

    if (this.holds <= 0) this.close();
  }

  /** Gives everything back: its children's, its blocks (freed when no one else holds them), its own weight. */
  protected close(): void {
    if (!this.openFlag) return;

    // deleting the entry being visited is safe while iterating a Set
    for (const c of this.children) c.close();

    for (const b of this.blocks) this.drop(b);
    this.give(this.own);
    this.openFlag = false;
    this.parent?.children.delete(this);
    this.pool.closed(this);
  }
}

/**
 * The lease of work that runs after the response. `signal` aborts at its deadline (BACKGROUND_DEADLINE_MS): the work
 * stops, lets go of what it refers to, and only then releases the lease. Until it does, what it holds stays charged.
 */
export class BackgroundLease extends Lease {
  /** When the work must stop: it aborts at `deadline`, or when the pool finds it past it. */
  readonly signal: AbortSignal;
  /** By the pool's clock. */
  readonly deadline: number;
  private readonly stopper = new AbortController();
  private timer: ReturnType<typeof setTimeout> | null;

  /** @internal made by MemoryPool.backgroundLease only */
  constructor(input: { pool: MemoryPool; deadline: number; ms: number }) {
    super({ pool: input.pool, kind: "background", limit: Number.POSITIVE_INFINITY, parent: null });
    this.deadline = input.deadline;
    this.signal = this.stopper.signal;
    this.timer = setTimeout(() => this.stop(), input.ms);
  }

  /** Tells the work to stop. Nothing is given back here: the work releases the lease once it has stopped. */
  stop(): void {
    this.clearTimer();

    if (!this.stopper.signal.aborted) this.stopper.abort(new Error("the background work passed its deadline"));
  }

  private clearTimer(): void {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
  }

  protected override close(): void {
    this.clearTimer();
    super.close();
  }
}

/** Takes back room from a holder that may give it up (the isolate cache): at least `need`, if it can. */
export type Reclaimer = (need: number) => void;

export class MemoryPool {
  readonly limit: number;
  private used = 0;
  private peak = 0;
  private readonly reclaimers: Reclaimer[] = [];
  private readonly background = new Set<BackgroundLease>();
  private cacheLease: Lease | null = null;
  private readonly clock: () => number;

  constructor(limit: number = POOL_WEIGHT, clock: () => number = Date.now) {
    this.limit = limit;
    this.clock = clock;
  }

  /** What every open lease's own weight and every live block weigh together. */
  get charged(): number {
    return this.used;
  }

  /** The most `charged` has been since the pool was made or resetPeak() was called. */
  get peakCharged(): number {
    return this.peak;
  }

  resetPeak(): void {
    this.peak = this.used;
  }

  /** A request's lease: the route handler opens one and every read the request makes takes from it. */
  request(limit: number = REQUEST_WEIGHT): Lease {
    return new Lease({ pool: this, kind: "request", limit, parent: null });
  }

  /** The isolate cache's lease, one per pool (`limit` counts only when it is first made). */
  cache(limit: number = CACHE_WEIGHT): Lease {
    this.cacheLease ??= new Lease({ pool: this, kind: "cache", limit, parent: null });

    return this.cacheLease;
  }

  /**
   * A lease for work that runs after the response (a shared-cache write, the review's look at a package), with no
   * limit but the pool's. Its signal tells the work to stop at BACKGROUND_DEADLINE_MS; the lease stays open, and
   * charged, until the work has stopped and released it.
   */
  backgroundLease(): BackgroundLease {
    const made = new BackgroundLease({ pool: this, deadline: this.clock() + BACKGROUND_DEADLINE_MS, ms: BACKGROUND_DEADLINE_MS });
    this.background.add(made);

    return made;
  }

  /** `reclaim` is asked for room before a take is refused. */
  onPressure(reclaim: Reclaimer): void {
    this.reclaimers.push(reclaim);
  }

  /** @internal */
  reserve(n: number): boolean {
    if (this.used + n > this.limit) this.makeRoom(this.used + n - this.limit);

    if (this.used + n > this.limit) return false;
    this.used += n;
    this.peak = Math.max(this.peak, this.used);

    return true;
  }

  /** @internal */
  free(n: number): void {
    this.used -= n;
  }

  /** Whether one more byte fits, after asking holders that can give room back. */
  hasRoom(): boolean {
    if (this.used < this.limit) return true;
    this.makeRoom(1);

    return this.used < this.limit;
  }

  /** @internal */
  closed(lease: Lease): void {
    if (lease instanceof BackgroundLease) this.background.delete(lease);
  }

  private makeRoom(need: number): void {
    const now = this.clock();

    // work past its deadline is told to stop (in case its timer has not fired); what it holds stays charged until it
    // has, so this take is not given that room
    for (const l of this.background) if (now >= l.deadline) l.stop();
    const target = this.used - need;

    for (const reclaim of this.reclaimers) {
      if (this.used <= target) return;
      reclaim(this.used - target);
    }
  }
}

/** This isolate's pool: module state, so every request the isolate runs shares it. */
export const ISOLATE_POOL = new MemoryPool();

/**
 * The lease of the request (or queue job, or sweep) being run: its entry point (worker.ts) opens it, and every route
 * reads npm's package metadata under it or under a child of it. The upstream reader takes a lease as an argument, so
 * code that has none cannot read.
 */
export class RequestMemory extends Context.Service<RequestMemory, Lease>()("@apm/registry/RequestMemory") {
  /**
   * A request lease from `pool` for each run this layer is provided to, released when the run ends; a streamed answer
   * that retained it keeps it open until its last byte.
   */
  static layer(pool: MemoryPool = ISOLATE_POOL): Layer.Layer<RequestMemory> {
    return Layer.effect(
      RequestMemory,
      Effect.acquireRelease(
        Effect.sync(() => pool.request()),
        (lease) => Effect.sync(() => lease.release()),
      ),
    );
  }
}
