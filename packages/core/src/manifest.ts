// How big and how deep a package.json is, read without recursion, before anything recursive reads it. The entry
// collector (entries.ts, a recursive zod schema), the format check (score.ts) and JSON.stringify all recurse, and a
// manifest nested a few thousand levels deep overflows the stack in any of them: at 3,000 levels zod threw, and at 6,000
// JSON.stringify threw before the meter was charged at all (review of d49bf6e, finding 3). This walk keeps its own
// stack, charges the meter per value it visits, and stops at the first limit, so a manifest past one is reported as
// `incomplete` without being read further.
import { z } from "zod";
import { charge, chargeText } from "./meter.ts";
import type { AnalyzeInput } from "./score.ts";

/** A package.json as the analysis is handed it: a JSON object. */
type Manifest = AnalyzeInput["manifest"];

const Text = z.string();

/**
 * The most apm reads in one package.json. Real manifests sit far inside them: the deepest `exports` in the corpus
 * is 4 levels under "exports", and the largest manifest has a few thousand values.
 */
export const MANIFEST_LIMITS = { depth: 64, values: 100_000, chars: 4 * 1024 * 1024 } as const;

export type ManifestLimit = keyof typeof MANIFEST_LIMITS;

/** Within every limit, or the first limit the walk reached. */
export type ManifestReading = { kind: "ok"; values: number; chars: number } | { kind: "over"; limit: ManifestLimit; text: string };

const OVER_TEXT: Record<ManifestLimit, string> = {
  depth: `package.json nests deeper than ${MANIFEST_LIMITS.depth} levels`,
  values: `package.json holds more than ${MANIFEST_LIMITS.values.toLocaleString("en-US")} values`,
  chars: `package.json is longer than ${MANIFEST_LIMITS.chars / (1024 * 1024)} MB of text`,
};

/**
 * The reading of `manifest`, walked with an explicit stack. `charged` (the default) charges the installed meter one unit
 * per value and its text as it reads it, so a meter that runs out stops the walk; uncharged, it is still bounded by the
 * limits, for an analysis built on a spent meter.
 */
export function measureManifest(manifest: Manifest, opts: { charged?: boolean } = {}): ManifestReading {
  const charged = opts.charged ?? true;
  const stack: { v: unknown; depth: number }[] = [{ v: manifest, depth: 0 }];
  let values = 0;
  let chars = 0;

  const over = (limit: ManifestLimit): ManifestReading => ({ kind: "over", limit, text: OVER_TEXT[limit] });

  for (let top = stack.pop(); top !== undefined; top = stack.pop()) {
    if (++values > MANIFEST_LIMITS.values) return over("values");

    if (charged) charge("score", 1);
    const { v, depth } = top;
    const text = Text.safeParse(v);

    if (text.success) {
      chars += text.data.length;

      if (charged) chargeText("score", text.data.length);
    } else if (v instanceof Object) {
      if (depth >= MANIFEST_LIMITS.depth) return over("depth");

      // one child at a time, so an object with a million keys stops at the limit instead of being listed first
      if (Array.isArray(v)) {
        for (const x of v) {
          if (values + stack.length >= MANIFEST_LIMITS.values) return over("values");
          stack.push({ v: x, depth: depth + 1 });
        }
      } else {
        for (const k in v) {
          if (!Object.hasOwn(v, k)) continue;

          if (values + stack.length >= MANIFEST_LIMITS.values) return over("values");
          chars += k.length;
          // the value as stored, without running a getter
          stack.push({ v: Object.getOwnPropertyDescriptor(v, k)?.value, depth: depth + 1 });
        }
      }
    }

    if (chars > MANIFEST_LIMITS.chars) return over("chars");
  }

  return { kind: "ok", values, chars };
}

/** Thrown by a reader of package.json (entryPoints) handed one past MANIFEST_LIMITS, instead of recursing into it. */
export class ManifestTooLargeError extends Error {
  override readonly name = "ManifestTooLargeError";

  constructor(readonly limit: ManifestLimit) {
    super(OVER_TEXT[limit]);
  }
}

/**
 * `manifest` when it is within MANIFEST_LIMITS, else only its top-level fields that are not objects or arrays: what a
 * report of a version apm did not finish reading can still say (its license, its main file) without reading the rest.
 * Charges nothing.
 */
export function boundedManifest(manifest: Manifest): Manifest {
  if (measureManifest(manifest, { charged: false }).kind === "ok") return manifest;
  const out: Manifest = {};
  let n = 0;

  for (const k in manifest) {
    if (++n > MANIFEST_LIMITS.values) break;
    const v = manifest[k];

    if (!(v instanceof Object)) out[k] = v;
  }

  return out;
}
