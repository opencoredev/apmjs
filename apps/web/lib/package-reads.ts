// The registry reads a package page makes, started together before the package answer says which version is shown,
// so no read waits for another: the package answer (proxy.ts already checked it exists with a HEAD that builds
// nothing), the public log, the AI review of the asked version or of latest, and an asked version's own score and
// per-version answer. An early answer is used only for the version shown, and only when it is as restrictive as the
// package answer says that version is (early-answer.ts); each is read from the registry for this view. A version the
// package answer does not list ("unknown") never reuses one: what it is comes from a read after the package answer.
import { answerFor, isWithheld, type Shown } from "./early-answer";
import { getEvents, getPackage, getReview, getVersionInfo, getVersionScore, readVersionInfo, type Fetched, type PackageEvent, type PackageInfo, type VersionDetails, type VersionScore } from "./registry";
import type { ReviewAnswer } from "./review-schema";
import { isVersionNumber } from "./shown-version";

export type PackageReads = {
  readonly package: Promise<Fetched<PackageInfo>>;
  /** an upstream package's log holds what apm's reviewers did to it (dismissed evidence); none answers 404 */
  readonly events: Promise<Fetched<PackageEvent[]>>;
  /** The AI review of the shown version. */
  readonly review: (shown: Shown) => Promise<Fetched<ReviewAnswer>>;
  /** The shown version's own score (the page asks only for a version other than latest). */
  readonly score: (shown: Shown) => Promise<Fetched<VersionScore>>;
  /** The shown version's per-version answer: its facts (the page asks only for a version other than latest). */
  readonly details: (shown: Shown) => Promise<Fetched<VersionDetails>>;
};

/** A per-version answer as answerFor weighs it: withheld when the registry answered for a revoked or revoke-pending version. */
type Weighed = { version: string; redacted: boolean; details: VersionDetails };

const weighed = (read: Promise<Fetched<VersionDetails>>): Promise<Fetched<Weighed>> =>
  read.then((r) => (r.kind === "ok" ? { kind: "ok", value: { version: r.value.version, redacted: isWithheld(r.value.status), details: r.value } } : r));

/**
 * The shown version's per-version answer: the early one under answerFor's rule, else one read now. The read now is never
 * the request's earlier read of the same path (readVersionInfo), so a version revoked in between is read again.
 */
async function detailsFor(input: { early: Promise<Fetched<VersionDetails>>; asked: string; shown: Shown; name: string }): Promise<Fetched<VersionDetails>> {
  const { name, shown } = input;
  const r = await answerFor({ early: weighed(input.early), asked: input.asked, shown, read: () => weighed(readVersionInfo(name, shown.version)) });

  return r.kind === "ok" ? { kind: "ok", value: r.value.details } : r;
}

/** Starts a package page's reads; `asked` is its `?v=`, a version or a dist-tag. */
export function startPackageReads(input: { name: string; asked: string | undefined }): PackageReads {
  const { name } = input;
  const pkg = getPackage(name);
  const events = getEvents(name);
  const reviewAsked = input.asked ?? "latest";
  const earlyReview = getReview(name, reviewAsked);
  // with no ?v= the page shows latest, whose score and facts are in the package answer
  const earlyScore = input.asked === undefined ? null : { asked: input.asked, answer: getVersionScore(name, input.asked) };
  // the per-version endpoint takes a version number only; a dist-tag is resolved by the package answer first. Never
  // the request's kept read (getVersionInfo): a version the package answer does not list takes its state from a read
  // made after that answer (the page's resolveVersion), so one this early, from before a revoke, can never set it
  const earlyDetails = input.asked !== undefined && isVersionNumber(input.asked) ? { asked: input.asked, answer: readVersionInfo(name, input.asked) } : null;

  return {
    package: pkg,
    events,
    review: (shown) => answerFor({ early: earlyReview, asked: reviewAsked, shown, read: () => getReview(name, shown.version) }),
    score: (shown) =>
      earlyScore === null ? getVersionScore(name, shown.version) : answerFor({ early: earlyScore.answer, asked: earlyScore.asked, shown, read: () => getVersionScore(name, shown.version) }),
    details: (shown) => (earlyDetails === null ? getVersionInfo(name, shown.version) : detailsFor({ early: earlyDetails.answer, asked: earlyDetails.asked, shown, name })),
  };
}
