// Review finding (P2, OG images): a package's card showed the publisher's description and is sent public, max-age=5,
// and the sites that unfurl it keep their own copy for as long as they like, so a description a revoke withdrew could
// outlive it in a shared card. The card now shows the name, latest version, score and grade, and nothing the publisher
// wrote. Rendered to markup with react-dom/server; ImageResponse draws the same element tree.
import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { packageCard, packageCardInput } from "@/components/og-card";
import { pkg } from "./agent/testing";

describe("the package OG card", () => {
  const answer = pkg({ name: "og-widget", latest: "2.4.1", description: "LEAKMARK-og-description", score: { score: 82, grade: "B", signals: [], notChecked: [], scorer: "apm-score-v9", digest: "sha512-abc", dismissed: [], redacted: false, capabilities: [] } });

  test("shows the name, latest version, score and grade, and not the description", () => {
    const input = packageCardInput({ name: "og-widget", pkg: answer });
    const markup = renderToStaticMarkup(packageCard(input));

    expect(input).toEqual({ name: "og-widget", version: "2.4.1", score: 82, grade: "B" });
    expect(markup).toContain("og-widget");
    expect(markup).toContain("2.4.1");
    expect(markup).toContain(">82<");
    expect(markup).toContain("grade B");
    expect(markup).not.toContain("LEAKMARK");
  });

  test("with the registry down: the name asked for, unscored", () => {
    const markup = renderToStaticMarkup(packageCard(packageCardInput({ name: "og-widget", pkg: null })));

    expect(markup).toContain("og-widget");
    expect(markup).toContain("not scored");
  });
});

// HOME-502 Sol review finding 8: a package with only a prerelease tagged next drew a versionless card
test("a package with no latest: the card names the tagged default and its own score", () => {
  const prerelease = pkg({ name: "pre", latest: null, score: null, distTags: { next: "0.0.2-test.2" }, versions: [{ version: "0.0.2-test.2", publishedAt: "2026-11-25T19:00:00.000Z", publishedBy: "me", status: "active", statusReason: null, deprecated: null, score: 64, grade: "C" }] });

  expect(packageCardInput({ name: "pre", pkg: prerelease })).toEqual({ name: "pre", version: "0.0.2-test.2", score: 64, grade: "C" });
});
