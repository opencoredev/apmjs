// The HTTP contract between the registry and the reviewer process. Both sides parse with these schemas.
import { isPossibleNpmName } from "@apm/core";
import { z } from "zod";
import { SEVERITIES } from "./reply.ts";

const Version = z.string().min(1).max(256);
const Name = z.string().min(1).max(214);

/** "sha512-<hex>" or "sha1-<hex>": the tarball's checksum as the registry knows it. */
export const DigestLabel = z.string().regex(/^(?:sha512-[0-9a-f]{128}|sha1-[0-9a-f]{40})$/);

export const ENQUEUE_REASONS = ["publish", "first-publish", "install-script", "popular", "requested"] as const;

export type EnqueueReason = (typeof ENQUEUE_REASONS)[number];

/**
 * Where the registry serves the tarball, relative to its root ("debug/-/debug-4.4.3.tgz"). The reviewer
 * joins it to its own configured registry URL, so a job can never point it at another host. The name is any
 * name npm can hold, old names included (isPossibleNpmName), so npm's placeholder named "-" leases like any
 * other. Every character is one encodeURIComponent leaves as it is (the file may also carry a version's "+build"),
 * which is checked first because encodeURIComponent throws on a lone surrogate, and no segment is a dot segment.
 */
export const TarballPath = z
  .string()
  .max(600)
  .refine((path) => {
    const m = /^((?:@[\w.!~*'()-]+\/)?[\w.!~*'()-]+)\/-\/([\w.!~*'()+-]+\.tgz)$/.exec(path);

    return m?.[1] !== undefined && isPossibleNpmName(m[1]) && path.split("/").every((segment) => segment !== "." && segment !== "..");
  }, "not a tarball path of an npm name");

const TarballRef = z.object({ version: Version, digest: DigestLabel, tarballPath: TarballPath });

export const ReviewJob = z.object({
  id: z.string().min(1).max(64),
  leaseId: z.string().min(1).max(64),
  leaseExpiresAt: z.iso.datetime(),
  name: Name,
  version: Version,
  digest: DigestLabel,
  tarballPath: TarballPath,
  previous: TarballRef.nullable(),
  reasons: z.array(z.enum(ENQUEUE_REASONS)).max(8),
});

export type ReviewJob = z.infer<typeof ReviewJob>;

export const LeaseResponse = z.object({ jobs: z.array(ReviewJob).max(64) });

export type LeaseResponse = z.infer<typeof LeaseResponse>;

/** A lease as the reviewer reads it: the batch is checked here and each job on its own (readLease). */
const LeaseBatch = z.object({ jobs: z.array(z.unknown()).max(64) });

const LeaseHandle = z.object({ id: ReviewJob.shape.id, leaseId: ReviewJob.shape.leaseId });

/** A leased job this side cannot read: with its lease when that much could be read, so it can be given back. */
export type UnreadableJob = { lease: z.infer<typeof LeaseHandle> | null; why: string };

/**
 * The jobs of a lease response, each parsed on its own, so one job the reviewer cannot read never discards the
 * rest of the batch. Throws only when the response itself is not a lease.
 */
export function readLease(body: unknown): { jobs: ReviewJob[]; unreadable: UnreadableJob[] } {
  const jobs: ReviewJob[] = [];
  const unreadable: UnreadableJob[] = [];

  for (const raw of LeaseBatch.parse(body).jobs) {
    const job = ReviewJob.safeParse(raw);

    if (job.success) {
      jobs.push(job.data);
      continue;
    }

    const handle = LeaseHandle.safeParse(raw);
    const why = job.error.issues.map((i) => `${i.path.join(".") || "job"}: ${i.message}`).join("; ");

    unreadable.push({ lease: handle.success ? handle.data : null, why });
  }

  return { jobs, unreadable };
}

export const WireFinding = z.object({
  file: z.string().min(1).max(1000),
  line: z.number().int().min(1),
  quote: z.string().max(400),
  excerpt: z.string().max(400),
  issue: z.string().max(400),
  severity: z.enum(SEVERITIES),
});

export type WireFinding = z.infer<typeof WireFinding>;

export const WireNotRead = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("file"), path: z.string().min(1).max(1000), reason: z.enum(["budget", "partial", "binary", "too-large"]) }),
  z.object({ kind: z.literal("dependency"), name: z.string().min(1).max(214) }),
]);

export type WireNotRead = z.infer<typeof WireNotRead>;

export const WireCoverage = z.object({
  mode: z.enum(["diff", "files"]),
  previousVersion: Version.nullable(),
  filesInScope: z.number().int().min(0),
  filesRead: z.number().int().min(0),
});

const WireAttempt = z.object({
  result: z.enum(["benign", "malicious", "suspicious", "empty"]),
  kept: z.number().int().min(0),
  dropped: z.number().int().min(0),
  promptTokens: z.number().int().min(0),
  completionTokens: z.number().int().min(0),
  latencyMs: z.number().min(0),
});

/** A stronger reviewer's opinion on a flagged result. Nothing produces one until a second stage is configured. */
export const SecondOpinion = z.object({
  reviewer: z.string().min(1).max(200),
  verdict: z.enum(["malicious", "suspicious", "benign"]),
  summary: z.string().max(2000),
  findings: z.array(WireFinding).max(12),
});

export type SecondOpinion = z.infer<typeof SecondOpinion>;

const Outcome = z.discriminatedUnion("outcome", [
  z.object({ outcome: z.literal("benign") }),
  z.object({ outcome: z.literal("flagged"), verdict: z.enum(["malicious", "suspicious"]), findings: z.array(WireFinding).min(1).max(12) }),
  z.object({ outcome: z.literal("no-answer"), reason: z.enum(["empty", "unsettled"]), findings: z.array(WireFinding).max(12) }),
]);

const ResultFields = z.object({
  model: z.string().min(1).max(200),
  reviewedAt: z.iso.datetime(),
  summary: z.string().max(2000),
  coverage: WireCoverage,
  /** Paths the model saw in full. */
  read: z.array(z.string().min(1).max(1000)).max(5000),
  notRead: z.array(WireNotRead).max(2000),
  attempts: z.array(WireAttempt).min(1).max(2),
  secondOpinion: SecondOpinion.nullable(),
});

export const ReviewResult = z.intersection(Outcome, ResultFields);

export type ReviewResult = z.infer<typeof ReviewResult>;

export const ResultBody = z.object({ leaseId: z.string().min(1).max(64), result: ReviewResult });

export type ResultBody = z.infer<typeof ResultBody>;

/** Give a leased job back: `retryable` false marks it failed (for example, its tarball is gone). */
export const ReleaseBody = z.object({ leaseId: z.string().min(1).max(64), error: z.string().max(500), retryable: z.boolean() });

export type ReleaseBody = z.infer<typeof ReleaseBody>;
