// The second stage: a stronger model that reads a flagged release in full before a person decides.
// The eval recommends it for precision on public actions, not for recall (research/ai-review-eval.md,
// "Is a two-stage design needed?"). It is an interface only: nothing is configured, so flagged results
// go straight to the owner queue, where a person confirms or dismisses them.
import type { PackageFiles, ReviewJob, SecondOpinion, WireFinding } from "@apm/ai-review";

export type SecondStageRequest = {
  job: ReviewJob;
  pkg: PackageFiles;
  previous: PackageFiles | null;
  /** What the first stage found, already citation-checked. */
  firstStage: { verdict: "malicious" | "suspicious" | null; findings: WireFinding[] };
};

export type SecondStage = {
  /** Shown in the owner queue next to its opinion. */
  name: string;
  review: (req: SecondStageRequest) => Promise<SecondOpinion>;
};

/** The configured second stage. None yet: wire a stronger model here, behind its own budget. */
export function configuredSecondStage(): SecondStage | null {
  return null;
}
