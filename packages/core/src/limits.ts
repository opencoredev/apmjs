// Limits on how much of a package apm reads, and how it reports what it could not read.

/** Files larger than this are not read by the score or the secret scan; they are listed as skipped. */
export const MAX_ANALYZED_FILE_BYTES = 32 * 1024 * 1024;

/**
 * Bytes of file content one analysis reads, across all files. Equal to the most a tarball may unpack to,
 * so a tarball apm accepts is read in full; callers analyzing file lists of their own pass a smaller one.
 * What runs (install targets, entry points and what they load) is read first.
 */
export const MAX_SCANNED_BYTES = 200 * 1024 * 1024;

/**
 * Wall-clock time one analysis may take. Every step of the analysis is bounded by input size and by work budgets, so
 * this is a backstop: a file reached after it is not read, and the analysis says so (incomplete or unanalyzed-files).
 */
export const MAX_ANALYSIS_MS = 90_000;

/**
 * "too-large": one file over MAX_ANALYZED_FILE_BYTES. "over-budget": the analysis had read MAX_SCANNED_BYTES already.
 * "compressed": an archive (gzip, zip, bzip2, xz, 7z, zstd) whose contents the secret scan cannot read.
 * "over-time": the analysis had run for MAX_ANALYSIS_MS already.
 */
export const SKIP_REASONS = ["too-large", "over-budget", "compressed", "over-time"] as const;

export type SkipReason = (typeof SKIP_REASONS)[number];

/** A file an analysis did not read. Its presence makes the analysis incomplete, never clean. */
export type SkippedFile = { path: string; size: number; reason: SkipReason };

export function describeSkip(s: SkippedFile): string {
  const mb = (s.size / (1024 * 1024)).toFixed(1);

  switch (s.reason) {
    case "too-large":
      return `${s.path} (${mb} MB, over the ${MAX_ANALYZED_FILE_BYTES / (1024 * 1024)} MB limit)`;
    case "over-budget":
      return `${s.path} (${mb} MB, past the analysis budget)`;
    case "compressed":
      return `${s.path} (a compressed archive; its contents are not read)`;
    case "over-time":
      return `${s.path} (${mb} MB, reached after the analysis's ${MAX_ANALYSIS_MS / 1000} s time limit)`;
    default: {
      const _exhaustive: never = s.reason;

      return _exhaustive;
    }
  }
}
