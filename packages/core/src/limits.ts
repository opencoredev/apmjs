// Limits on how much of a package apm reads, and how it reports what it could not read.

/** Files larger than this are not read by the score or the secret scan; they are listed as skipped. */
export const MAX_ANALYZED_FILE_BYTES = 32 * 1024 * 1024;

export type SkipReason = "too-large";

/** A file an analysis did not read. Its presence makes the analysis incomplete, never clean. */
export type SkippedFile = { path: string; size: number; reason: SkipReason };

export function describeSkip(s: SkippedFile): string {
  switch (s.reason) {
    case "too-large":
      return `${s.path} (${(s.size / (1024 * 1024)).toFixed(1)} MB, over the ${MAX_ANALYZED_FILE_BYTES / (1024 * 1024)} MB limit)`;
    default: {
      const _exhaustive: never = s.reason;
      return _exhaustive;
    }
  }
}
