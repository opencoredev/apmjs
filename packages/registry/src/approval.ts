// What a person must do to approve a staged version. Pure.
import { coverageText, partialCoverage, SCORE_FLOOR, type ScoreReport } from "@apm/core";

/**
 * Why a person must type the package name to approve this version, or null. The analysis did not finish (no report,
 * or the tarball could not be listed), it read only part of the version (apm-score-v11's partial coverage, which costs
 * no points), or the score is under the floor.
 */
export function typedConfirmationReason(input: { report: Pick<ScoreReport, "score" | "coverage"> | null; filesListed: boolean }): string | null {
  if (input.report === null || !input.filesListed) return "The analysis did not finish, so nothing below was checked.";
  const partial = partialCoverage(input.report);

  if (partial !== null) return `apm read only part of this version (${coverageText(partial)}), so what it did not read was not checked.`;

  if (input.report.score < SCORE_FLOOR) return `The score is ${input.report.score}, under the floor of ${SCORE_FLOOR}.`;

  return null;
}
