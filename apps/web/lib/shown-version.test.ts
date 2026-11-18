// Launch QA finding: /package/react?v=19.1.0 showed 19.3.1, because 19.1.0 is older than the newest 200 versions the
// package answer lists and the page fell back to latest. Now a version the list does not hold is asked of the
// registry's per-version endpoint, and a version string that can't exist says "no such version" without a read.
import { describe, expect, test } from "bun:test";
import { shownOf } from "./early-answer";
import { chooseVersion, rowsWith } from "./shown-version";
import { unscoredNotice } from "./unscored";
import { pkg } from "./agent/testing";

describe("which version ?v= shows", () => {
  const answer = pkg({ distTags: { latest: "1.3.0", legacy: "1.2.0", old: "0.9.0" } });

  test("no ?v= is latest", () => {
    expect(chooseVersion({ pkg: answer, asked: undefined })).toEqual({ kind: "latest", version: "1.3.0" });
  });

  test("a listed version is shown without another read", () => {
    expect(chooseVersion({ pkg: answer, asked: "1.2.0" })).toEqual({ kind: "listed", version: "1.2.0" });
  });

  test("a dist-tag shows the version it names, listed or not", () => {
    expect(chooseVersion({ pkg: answer, asked: "legacy" })).toEqual({ kind: "listed", version: "1.2.0" });
    expect(chooseVersion({ pkg: answer, asked: "old" })).toEqual({ kind: "unlisted", version: "0.9.0" });
  });

  test("a version number the list does not hold is asked of the per-version endpoint, not replaced by latest", () => {
    expect(chooseVersion({ pkg: answer, asked: "0.1.0" })).toEqual({ kind: "unlisted", version: "0.1.0" });
    expect(chooseVersion({ pkg: answer, asked: "19.3.0-canary-f6a48828-20251019" })).toEqual({ kind: "unlisted", version: "19.3.0-canary-f6a48828-20251019" });
  });

  test("a string that is neither a version nor a dist-tag is no such version, with no read", () => {
    expect(chooseVersion({ pkg: answer, asked: "banana" })).toEqual({ kind: "invalid", asked: "banana" });
    expect(chooseVersion({ pkg: answer, asked: "1.2" })).toEqual({ kind: "invalid", asked: "1.2" });
    expect(chooseVersion({ pkg: answer, asked: "constructor" })).toEqual({ kind: "invalid", asked: "constructor" });
  });

  test("an unlisted version found by the per-version endpoint is active or withheld as that answer says", () => {
    expect(shownOf(rowsWith(answer.versions, { version: "0.1.0", status: "active" }), "0.1.0")).toEqual({ version: "0.1.0", status: "active" });
    expect(shownOf(rowsWith(answer.versions, { version: "0.1.0", status: "revoked" }), "0.1.0")).toEqual({ version: "0.1.0", status: "withheld" });
    // without that row it stays unknown, which makes the page read its answers again (early-answer.ts)
    expect(shownOf(rowsWith(answer.versions, null), "0.1.0")).toEqual({ version: "0.1.0", status: "unknown" });
  });

  test("an unlisted version apm can never score says why, from the per-version answer", () => {
    const rows = rowsWith(answer.versions, { version: "0.1.0", status: "active", unscorable: "apm cannot open this tarball" });
    const notice = unscoredNotice({ pkg: { ...answer, versions: rows }, version: "0.1.0" });

    expect(notice.kind).toBe("unscorable");
    expect(notice.text).toStartWith("apm cannot open this tarball. ");
  });
});
