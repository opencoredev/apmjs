// Everywhere else a visitor or a link preview reads the score of a version apm did not read in full (grade P): the
// title tag, the description, the JSON-LD, the OG image, the Markdown view and MCP search. Each says the number is what
// the files apm read scored and that apm did not read every file, never "partial" and never a lone "(P)". The grade
// field itself stays "P" for agents and the CLI.
import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { packageCard } from "@/components/og-card";
import { scoreLine } from "./agent/package-md";
import { packageJsonLd, packageMetadata } from "./agent/seo";
import { Coverage } from "./coverage";

const NEXT = { name: "next", description: "The React Framework", latest: "16.4.6", score: { score: 98, grade: "P" } };

describe("the package page's metadata for a version apm did not read in full", () => {
  const meta = packageMetadata(NEXT);

  test("the title says not all read, not (P)", () => {
    // before: "next 16.4.6: score 98/100 (P) · apm"
    expect(meta.title).toBe("next 16.4.6: score 98/100, not all read · apm");
  });

  test("the description and the image's alt text say the number is only what apm read", () => {
    expect(meta.description).toBe("The React Framework. next 16.4.6 scores 98/100 on the files apm read; apm did not read every file. See every risk signal with its cited line, the AI review…");
    expect(JSON.stringify(meta.openGraph)).toContain("apm security score 98/100 on the files apm read, not every file read");
    expect(JSON.stringify(meta)).not.toContain("(P)");
    expect(JSON.stringify(meta)).not.toContain("grade P");
  });

  test("the JSON-LD's score says not every file was read, not grade P", () => {
    const ld = packageJsonLd({ ...NEXT, license: "MIT", repository: null, homepage: null, maintainers: [] });

    expect(ld.additionalProperty).toEqual({ "@type": "PropertyValue", name: "apm security score", value: 98, maxValue: 100, description: "not every file read" });
  });

  test("a complete reading keeps its letter", () => {
    expect(packageMetadata({ ...NEXT, score: { score: 98, grade: "A" } }).title).toBe("next 16.4.6: score 98/100 (A) · apm");
  });
});

describe("the OG image of a version apm did not read in full", () => {
  test("shows the number in the warning tone with not all read, never partial and never a grade letter", () => {
    const markup = renderToStaticMarkup(packageCard({ name: "next", version: "16.4.6", score: 98, grade: "P" }));

    expect(markup).toContain(">98<");
    expect(markup).toContain("<div>of 100</div>");
    expect(markup).toContain(">not all read</div>");
    expect(markup).not.toContain("partial");
    expect(markup).not.toContain("grade");
  });
});

describe("the Markdown view's score line", () => {
  const score = {
    score: 98,
    grade: "P",
    signals: [],
    notChecked: [],
    coverage: Coverage.parse({ kind: "partial", omittedFiles: 2656, omittedBytes: 74_038_961, reasons: ["over-budget"], notes: [] }),
    scorer: "apm-score-v11",
    digest: "sha512-abc",
    dismissed: [],
    redacted: false,
    capabilities: [],
  };

  test("says what was skipped and what installs do, with no letter", () => {
    // before: "98/100, grade P"
    expect(scoreLine({ name: "next", score, unpackedSize: 192_293_410 })).toBe(
      "98/100 on the files apm read. Not fully checked: next is 183.4 MB unpacked, more than apm reads of one package, so apm skipped 2,656 files (70.6 MB). Nothing in them was checked. The skipped files alone don't stop an install through apm: it installs with a warning that not every file was checked. Strict mode (`--strict`) refuses it.",
    );
  });

  test("a complete reading keeps its letter", () => {
    expect(scoreLine({ name: "x", score: { ...score, grade: "A", coverage: { kind: "complete" } }, unpackedSize: null })).toBe("98/100, grade A");
  });
});
