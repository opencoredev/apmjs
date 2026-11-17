// apm-score-v11: a partial reading scores only the code apm read, so it can score 98. Wherever the site shows a score,
// a partial one reads "Partial analysis" or "partial" in the warning tone, never a grade letter and a green number that
// look like a pass. Rendered to HTML with react-dom/server, no browser.
import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { ScoreBadge, toneOf } from "@/components/score-badge";
import { ScoreHeadline } from "@/components/score-headline";
import { Coverage } from "./coverage";

const TONE = { text: "text-inverse-ok", bar: "bg-inverse-ok" };
const PARTIAL = Coverage.parse({ kind: "partial", omittedFiles: 2656, omittedBytes: 74_038_961, reasons: ["over-budget"], notes: [] });

describe("a partial reading on the site", () => {
  test("the score panel leads with Partial analysis, and gives the number only for the code apm read", () => {
    const html = renderToStaticMarkup(<ScoreHeadline score={98} grade="P" coverage={PARTIAL} tone={TONE} version="16.4.6" />);

    expect(html).toContain("Partial analysis");
    expect(html).toContain("98/100 on the code apm read; 2,656 files not read");
    // no score in the pass tone
    expect(html).not.toContain("text-inverse-ok");
  });

  test("a complete reading leads with its score, as before", () => {
    const html = renderToStaticMarkup(<ScoreHeadline score={98} grade="A" coverage={{ kind: "complete" }} tone={TONE} version="1.0.0" />);

    expect(html).not.toContain("Partial analysis");
    expect(html).toContain("text-inverse-ok");
    expect(html).toContain(">98<");
  });

  test("the score badge in every list says partial in the warning tone, never A 98 in green", () => {
    const partial = renderToStaticMarkup(<ScoreBadge score={98} grade="P" />);
    const whole = renderToStaticMarkup(<ScoreBadge score={98} grade="A" />);

    expect(partial).toContain(">partial<");
    expect(partial).toContain("bg-warn-soft");
    expect(partial).not.toContain("bg-ok-soft");
    expect(whole).toContain("bg-ok-soft");
    expect(toneOf(98, "P")).toBe("warn");
  });
});

describe("an analysis that stopped before it finished", () => {
  test("says it did not finish, with no count of files not read", () => {
    const stopped = Coverage.parse({ kind: "partial", omittedFiles: 0, omittedBytes: 0, reasons: ["stopped"], notes: [] });
    const html = renderToStaticMarkup(<ScoreHeadline score={39} grade="F" coverage={stopped} tone={TONE} version="1.0.0" />);

    // on e8616ca: "39/100 on the code apm read; 0 files not read", and that they were left unread for their size
    expect(html).toContain("Analysis did not finish");
    expect(html).toContain("39/100: apm stopped before it finished reading this version");
    expect(html).not.toContain("files not read");
    expect(html).not.toContain("for their size");
  });
});

// review of c456c92, finding 4: only a reading graded P (whole files left unread for their size, nothing else
// unfinished) leads with "Partial analysis"; one incomplete for another reason shows its score and letter, as always
describe("a partial coverage that is not graded P", () => {
  test("an incomplete re-run that read at most 4 MB shows 39 and F, not Partial analysis", () => {
    const html = renderToStaticMarkup(<ScoreHeadline score={39} grade="F" coverage={PARTIAL} tone={TONE} version="1.0.0" />);

    expect(html).not.toContain("Partial analysis");
    expect(html).toContain(">39<");
  });
});
