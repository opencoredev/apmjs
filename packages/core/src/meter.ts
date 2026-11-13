// One work meter for a whole analysis (apm-score-v10): unpack, parse, scope, constant folding, flow, cross-file
// resolution, decoders, code read from text and scoring all charge it before they do work that grows with the input.
//
// A deployed Cloudflare Worker's clock does not move while synchronous code runs, so a time limit bounds nothing
// there. Counted work does: every charged unit is a step of bounded cost (measured, docs/SCORE.md "Bounded, and how"),
// so a meter of MAX_ANALYSIS_WORK units bounds the CPU one analysis can use, whatever the package holds.
//
// When the meter runs out it throws MeterExhausted, which unwinds the whole analysis: no phase can carry on past it.
// It stays exhausted, so a later charge throws again even if some caller swallowed the first throw, and `analyze`
// checks it before it returns. The analysis then reports `incomplete`, naming the phase that ran it out.
//
// The meter is ambient: `withMeter` installs it for the synchronous call it wraps, and `charge` charges the one
// installed. Analysis is synchronous from the tarball's bytes to its report, so nothing else can run in between, and
// a helper deep in the tree (an AST walk, a label set's union) charges without every caller passing the meter down.
// The public entry points (`analyze`, `readTarball`, `readTar`, `gunzipCapped`, `findSecrets`, `scanFile`) install a
// fresh meter when none is installed, so no caller can run them unbounded.

/** The phases an analysis is made of, as an exhausted meter names them. */
export const PHASES = ["gunzip", "tar", "parse", "scope", "read", "fold", "flow", "cross-file", "decode", "held", "text", "score"] as const;

export type Phase = (typeof PHASES)[number];

/** What each phase is called where an `incomplete` reason names it. */
export const PHASE_NAMES: Record<Phase, string> = {
  gunzip: "inflating the tarball",
  tar: "reading the tar archive",
  parse: "parsing",
  scope: "working out scopes",
  read: "reading the program's tree",
  fold: "working out constant strings",
  flow: "following where values go",
  "cross-file": "following values across files",
  decode: "running decoder functions",
  held: "reading code held as text",
  text: "the text rules",
  score: "scoring",
};

/**
 * Units one analysis may spend: 320 million. The slowest package of the 70-package corpus under the registry's caps
 * (three 0.187.0, 20 MB unpacked) spends 168 million (6.3 s of CPU in V8); the most expensive unit measured across the
 * adversarial suite costs 53 ns, so the whole meter is about 17 s of CPU, under the 25 s this must stay within to
 * finish inside a Worker's default 30 s limit (docs/SCORE.md, "Bounded, and how").
 */
export const MAX_ANALYSIS_WORK = 320_000_000;

/** Thrown when an analysis has spent its meter. Unwinds the analysis; `analyze` turns it into `incomplete`. */
export class MeterExhausted extends Error {
  override readonly name = "MeterExhausted";

  constructor(
    readonly phase: Phase,
    readonly limit: number,
  ) {
    super(`analysis work limit (${limit} units) reached while ${PHASE_NAMES[phase]}`);
  }
}

export class Meter {
  private spentUnits = 0;
  private exhaustedIn: Phase | null = null;
  /** Units spent in each phase, for the measurements in docs/SCORE.md. */
  readonly byPhase: Record<Phase, number> = { gunzip: 0, tar: 0, parse: 0, scope: 0, read: 0, fold: 0, flow: 0, "cross-file": 0, decode: 0, held: 0, text: 0, score: 0 };

  constructor(readonly limit: number = MAX_ANALYSIS_WORK) {}

  get used(): number {
    return this.spentUnits;
  }

  /** The phase that ran the meter out, or null while it has units left. */
  get exhausted(): Phase | null {
    return this.exhaustedIn;
  }

  /** Spends `units` in `phase` before the work they pay for; throws MeterExhausted once the meter is spent. */
  charge(phase: Phase, units: number): void {
    if (this.exhaustedIn !== null) throw new MeterExhausted(this.exhaustedIn, this.limit);

    // a charge that does not fit is refused, not spent: the work it would pay for never runs
    if (this.spentUnits + units > this.limit) {
      this.exhaustedIn = phase;

      throw new MeterExhausted(phase, this.limit);
    }

    this.spentUnits += units;
    this.byPhase[phase] += units;
  }
}

let current: Meter | null = null;

/** Runs `fn` with `meter` installed, then puts back what was installed before. */
export function withMeter<T>(meter: Meter, fn: () => T): T {
  const outer = current;
  current = meter;

  try {
    return fn();
  } finally {
    current = outer;
  }
}

/** Runs `fn` under `meter`, else under the installed meter, else under a fresh one: an entry point is never unbounded. */
export function metered<T>(meter: Meter | undefined, fn: () => T): T {
  if (meter) return meter === current ? fn() : withMeter(meter, fn);

  return current ? fn() : withMeter(new Meter(), fn);
}

/** The installed meter, if any. */
export function currentMeter(): Meter | null {
  return current;
}

/** Charges the installed meter. Outside any analysis (a unit test calling a helper) it charges nothing. */
export function charge(phase: Phase, units: number): void {
  if (current) current.charge(phase, units);
}

let phaseNow: Phase = "read";

/** Runs `fn` as `phase`: what helpers shared by several phases charge (an AST walk, a scope lookup) is charged to it. */
export function inPhase<T>(phase: Phase, fn: () => T): T {
  const outer = phaseNow;
  phaseNow = phase;

  try {
    return fn();
  } finally {
    phaseNow = outer;
  }
}

/** Charges the phase running now (see `inPhase`). */
export function chargeNow(units: number): void {
  if (current) current.charge(phaseNow, units);
}

/**
 * Characters a text pass reads per unit. Calibrated (docs/SCORE.md) so a unit of text work costs about what a unit of
 * tree or label work does: one pass of one linear regex over this many characters.
 */
export const CHARS_PER_UNIT = 32;

/** Charges `passes` linear passes over `chars` characters. */
export function chargeText(phase: Phase, chars: number, passes = 1): void {
  if (current) current.charge(phase, Math.ceil((chars * passes) / CHARS_PER_UNIT) + 1);
}

/**
 * A per-phase allowance carved out of the meter: charging it charges the meter too, so the meter stays the one bound,
 * and the allowance only decides when this phase alone stops (a file's flow budget, say) while the analysis goes on.
 */
export class Allowance {
  private spent = 0;

  constructor(
    readonly phase: Phase,
    readonly max: number,
  ) {}

  get used(): number {
    return this.spent;
  }

  get left(): number {
    return Math.max(0, this.max - this.spent);
  }

  /** Whether `units` more fit in this allowance. Charges nothing. */
  fits(units: number): boolean {
    return this.spent + units <= this.max;
  }

  /** Spends `units` here and on the meter; false when this allowance is spent (the meter running out throws instead). */
  take(units: number): boolean {
    charge(this.phase, units);
    this.spent += units;

    return this.spent <= this.max;
  }

  /** Counts `units` against this allowance for work that already charged the meter as it went (a decoder's steps). */
  count(units: number): void {
    this.spent += units;
  }
}
