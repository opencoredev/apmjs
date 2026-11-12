// The daily token budget, kept in a small state file so a restart does not reset it.
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";

const State = z.object({ day: z.string(), tokens: z.number().int().min(0) });

/** Tokens a review is assumed to need before it starts: two attempts near the input cap plus output. */
export const RESERVE_PER_REVIEW = 2 * (17_000 + 8_000);

export class DailyBudget {
  private day: string;
  private used: number;
  private readonly file: string;

  constructor(
    stateDir: string,
    readonly limit: number,
    private readonly now: () => number = Date.now,
  ) {
    mkdirSync(stateDir, { recursive: true });
    this.file = join(stateDir, "budget.json");
    this.day = this.today();
    this.used = 0;

    try {
      const s = State.parse(JSON.parse(readFileSync(this.file, "utf8")));

      if (s.day === this.day) this.used = s.tokens;
    } catch {
      // no state yet
    }
  }

  private today(): string {
    return new Date(this.now()).toISOString().slice(0, 10);
  }

  private roll(): void {
    const d = this.today();

    if (d !== this.day) {
      this.day = d;
      this.used = 0;
    }
  }

  /** Whether another review fits in what is left of today's budget. */
  canStart(): boolean {
    this.roll();

    return this.used + RESERVE_PER_REVIEW <= this.limit;
  }

  spend(tokens: number): void {
    this.roll();
    this.used += tokens;
    const tmp = `${this.file}.tmp`;

    writeFileSync(tmp, JSON.stringify({ day: this.day, tokens: this.used }), { mode: 0o600 });
    renameSync(tmp, this.file);
  }

  usedToday(): number {
    this.roll();

    return this.used;
  }

  /** Milliseconds until the budget resets at 00:00 UTC. */
  msUntilReset(): number {
    const n = this.now();
    const next = Date.UTC(new Date(n).getUTCFullYear(), new Date(n).getUTCMonth(), new Date(n).getUTCDate() + 1);

    return next - n;
  }
}
