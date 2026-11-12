// What a person must do to approve a staged version. Pure.
import { SCORE_FLOOR, type ScoreReport } from "@apm/core";

/**
 * Why a person must type the package name to approve this version, or null. The analysis did not finish
 * (no report, or the tarball could not be listed), or the score is under the floor.
 */
export function typedConfirmationReason(input: { report: Pick<ScoreReport, "score"> | null; filesListed: boolean }): string | null {
  if (input.report === null || !input.filesListed) return "The analysis did not finish, so nothing below was checked.";

  if (input.report.score < SCORE_FLOOR) return `The score is ${input.report.score}, under the floor of ${SCORE_FLOOR}.`;

  return null;
}
