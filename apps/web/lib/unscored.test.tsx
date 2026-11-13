// A version with no score: the page says queued only while it is queued, and says why when it can never be scored.
import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { ScoreBadge } from "@/components/score-badge";
import type { PackageInfo } from "./registry";
import { scoreLine, scoreLineText } from "./score-summary";
import { REFRESH_EVERY_MS, REFRESH_FOR_MS, refreshStep } from "./queued-refresh";
import { unscoredNotice } from "./unscored";

type Row = PackageInfo["versions"][number];

const row = (version: string, unscorable: string | null = null): Row => ({ version, publishedAt: "2026-10-01T00:00:00Z", publishedBy: "a", status: "active", statusReason: null, deprecated: null, score: null, grade: null, unscorable });

const TOO_LARGE = "apm cannot score this version: it is too large for apm to analyze (the tarball (43.7 MB) is larger than the 32 MiB apm downloads)";

describe("unscoredNotice", () => {
  test("the latest version that can never be scored gives the registry's reason, and that installs warn about it", () => {
    const n = unscoredNotice({ pkg: { latest: "16.4.6", unscored: { kind: "unscorable", reason: "too-large", text: TOO_LARGE }, versions: [row("16.4.6", TOO_LARGE)] }, version: "16.4.6" });

    expect(n.kind).toBe("unscorable");
    expect(n.text).toBe(`${TOO_LARGE}. Installs through apm refuse it.`);
    expect(n.text).not.toContain("queued");
  });

  test("an older version reads its own row", () => {
    const n = unscoredNotice({ pkg: { latest: "2.0.0", unscored: null, versions: [row("2.0.0"), row("1.0.0", TOO_LARGE)] }, version: "1.0.0" });

    expect(n.kind).toBe("unscorable");
    expect(n.text).toContain("32 MiB");
  });

  test("queued says queued; a registry that sends neither field keeps the old words", () => {
    expect(unscoredNotice({ pkg: { latest: "1.0.0", unscored: { kind: "queued", text: "not scored yet: queued for analysis" }, versions: [row("1.0.0")] }, version: "1.0.0" })).toEqual({
      kind: "queued",
      text: "Not scored yet: its tarball is queued for analysis.",
    });
    expect(unscoredNotice({ pkg: { latest: "1.0.0", versions: [row("1.0.0")] }, version: "1.0.0" })).toEqual({ kind: "unknown", text: "Not scored yet." });
  });

  test("the phone's line and the badge tell unscorable from not yet", () => {
    expect(scoreLineText(scoreLine(null, true))).toBe("Cannot be scored; installs warn about it");
    expect(scoreLineText(scoreLine(null))).toBe("Not scored yet");
    expect(renderToStaticMarkup(<ScoreBadge score={null} unscorable />)).toContain('title="Cannot be scored"');
    expect(renderToStaticMarkup(<ScoreBadge score={null} />)).toContain('title="Not scored yet"');
  });
});

describe("the queued notice refreshes the page", () => {
  test("every few seconds while queued, and no longer than five minutes", () => {
    expect(refreshStep({ startedAt: 0, now: 0 })).toEqual({ kind: "wait", ms: REFRESH_EVERY_MS });
    expect(refreshStep({ startedAt: 0, now: REFRESH_FOR_MS - 1_000 })).toEqual({ kind: "wait", ms: 1_000 });
    expect(refreshStep({ startedAt: 0, now: REFRESH_FOR_MS })).toEqual({ kind: "stop" });
    expect(REFRESH_FOR_MS).toBe(5 * 60_000);
  });
});
