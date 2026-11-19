// What a binary's reading is charged as it finds its results (kept.ts), for tests that size a budget by it.
import { scanBinaryText } from "../src/index.ts";

/** The least a binary's reading must be given to keep for it to finish: to keep all it finds. */
export function chargeOf(data: Uint8Array): number {
  let lo = 0;
  let hi = 64 * 1024 * 1024;

  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2);

    const r = scanBinaryText(data, mid);

    if (r.kind === "read" && !r.stopped) hi = mid;
    else lo = mid + 1;
  }

  return lo;
}
