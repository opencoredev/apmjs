// The registry reads a package page makes, started together before the package answer says which version is shown,
// so no read waits for another: the package answer (proxy.ts already checked it exists with a HEAD that builds
// nothing), the public log, the AI review of the asked version or of latest, and an asked version's own score. An
// early review or score is used only for the version shown, and only when it is as restrictive as the package answer
// says that version is (early-answer.ts); each is read from the registry for this view.
import { answerFor, type Shown } from "./early-answer";
import { getEvents, getPackage, getReview, getVersionScore, type Fetched, type PackageEvent, type PackageInfo, type VersionScore } from "./registry";
import type { ReviewAnswer } from "./review-schema";

export type PackageReads = {
  readonly package: Promise<Fetched<PackageInfo>>;
  /** an upstream package's log holds what apm's reviewers did to it (dismissed evidence); none answers 404 */
  readonly events: Promise<Fetched<PackageEvent[]>>;
  /** The AI review of the shown version. */
  readonly review: (shown: Shown) => Promise<Fetched<ReviewAnswer>>;
  /** The shown version's own score (the page asks only for a version other than latest). */
  readonly score: (shown: Shown) => Promise<Fetched<VersionScore>>;
};

/** Starts a package page's reads; `asked` is its `?v=`, a version or a dist-tag. */
export function startPackageReads(input: { name: string; asked: string | undefined }): PackageReads {
  const { name } = input;
  const pkg = getPackage(name);
  const events = getEvents(name);
  const reviewAsked = input.asked ?? "latest";
  const earlyReview = getReview(name, reviewAsked);
  // with no ?v= the page shows latest, whose score is in the package answer
  const earlyScore = input.asked === undefined ? null : { asked: input.asked, answer: getVersionScore(name, input.asked) };

  return {
    package: pkg,
    events,
    review: (shown) => answerFor({ early: earlyReview, asked: reviewAsked, shown, read: () => getReview(name, shown.version) }),
    score: (shown) =>
      earlyScore === null ? getVersionScore(name, shown.version) : answerFor({ early: earlyScore.answer, asked: earlyScore.asked, shown, read: () => getVersionScore(name, shown.version) }),
  };
}
