// apm-score-v11: a version apm did not read in full scores only the files apm read, so it can score 98. Wherever the
// site shows a score, such a version reads "Not fully checked" or "98 · not all read" in the warning tone, never a
// grade letter and a green number that look like a pass, and never the word "partial" or a lone "P", which visitors
// did not understand. Rendered to HTML with react-dom/server, no browser.
import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { ScoreBadge, toneOf } from "@/components/score-badge";
import { ScoreHeadline } from "@/components/score-headline";
import { Coverage, OmittedFolder } from "./coverage";

const TONE = { text: "text-inverse-ok", bar: "bg-inverse-ok" };

// next@16.4.6 as production scored it on 2026-11-19: 192,293,410 bytes unpacked, 2,656 files left out of the byte budget
const NEXT = Coverage.parse({ kind: "partial", omittedFiles: 2656, omittedBytes: 74_038_961, reasons: ["over-budget"], notes: [] });
const NEXT_SIZE = 192_293_410;

// packages/core omittedFolders over that analysis's 2,656 skipped paths
const NEXT_FOLDERS = OmittedFolder.array().parse([
  { path: "dist/compiled", files: 762, bytes: 61_045_711 },
  { path: "dist/esm", files: 1305, bytes: 7_795_660 },
  { path: "dist/bundle-analyzer", files: 10, bytes: 1_714_243 },
]);

/** The text a visitor reads, tags and the screen-reader-only label kept apart from what is shown. */
function visibleText(html: string): string {
  return html
    .replace(/<span class="sr-only">[^<]*<\/span>/g, "")
    .replace(/<\/?code[^>]*>/g, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/&#x27;/g, "'")
    .replace(/\s+/g, " ")
    .trim();
}

function nextHeadline(input: { folders?: readonly OmittedFolder[]; unpackedSize?: number | null } = {}): string {
  return renderToStaticMarkup(<ScoreHeadline score={98} grade="P" coverage={NEXT} tone={TONE} version="16.4.6" name="next" unpackedSize={input.unpackedSize === undefined ? NEXT_SIZE : input.unpackedSize} folders={input.folders ?? NEXT_FOLDERS} />);
}

describe("a version apm did not read in full, on the score panel", () => {
  test("leads with Not fully checked, says what apm skipped and why, and where most of it is", () => {
    const text = visibleText(nextHeadline());

    expect(text).toBe(
      "Version 16.4.6 Not fully checked 98/100 on the files apm read next is 183.4 MB unpacked, more than apm reads of one package, so apm skipped 2,656 files (70.6 MB). Nothing in them was checked. Most of them are in dist/compiled (762 files, 58.2 MB) and dist/esm (1,305 files, 7.4 MB). The skipped files alone don't stop an install through apm: it installs with a warning that not every file was checked. Strict mode (--strict) refuses it.",
    );
  });

  test("never says partial, never shows a lone P, and never uses the pass tone", () => {
    const html = nextHeadline();

    expect(visibleText(html).toLowerCase()).not.toContain("partial");
    expect(visibleText(html)).not.toMatch(/\bP\b/);
    expect(html).not.toContain("text-inverse-ok");
  });

  test("a folder holding under a twentieth of what was skipped is not named", () => {
    expect(visibleText(nextHeadline())).not.toContain("dist/bundle-analyzer");
  });

  test("without folders from the registry (one deployed before them), it names none and invents none", () => {
    const text = visibleText(nextHeadline({ folders: [] }));

    expect(text).toContain("so apm skipped 2,656 files (70.6 MB). Nothing in them was checked. The skipped files alone");
    expect(text).not.toContain("dist/");
  });

  test("without the unpacked size, it still says why", () => {
    expect(visibleText(nextHeadline({ unpackedSize: null, folders: [] }))).toContain("apm skipped 2,656 files (70.6 MB), past the amount apm reads of one package. Nothing in them was checked.");
  });

  test("one file over the size apm reads says so, in the singular", () => {
    const one = Coverage.parse({ kind: "partial", omittedFiles: 1, omittedBytes: 40 * 1024 * 1024, reasons: ["too-large"], notes: [] });
    const text = visibleText(renderToStaticMarkup(<ScoreHeadline score={100} grade="P" coverage={one} tone={TONE} version="1.0.0" name="big-data" unpackedSize={null} folders={[{ path: ".", files: 1, bytes: 40 * 1024 * 1024 }]} />));

    expect(text).toContain("apm skipped 1 file (40.0 MB): it is over 32 MB, the largest file apm reads. Nothing in it was checked. It is in the top folder.");
  });

  test("files skipped for both reasons say both", () => {
    const both = Coverage.parse({ kind: "partial", omittedFiles: 3, omittedBytes: 90_000_000, reasons: ["too-large", "over-budget"], notes: [] });
    const text = visibleText(renderToStaticMarkup(<ScoreHeadline score={97} grade="P" coverage={both} tone={TONE} version="1.0.0" name="x" unpackedSize={NEXT_SIZE} folders={[]} />));

    expect(text).toContain("apm skipped 3 files (85.8 MB): some are over 32 MB, the largest file apm reads, and the rest are past the amount apm reads of one package. Nothing in them was checked.");
  });

  test("a complete reading leads with its score, as before", () => {
    const html = renderToStaticMarkup(<ScoreHeadline score={98} grade="A" coverage={{ kind: "complete" }} tone={TONE} version="1.0.0" name="x" unpackedSize={null} folders={[]} />);

    expect(html).not.toContain("Not fully checked");
    expect(html).toContain("text-inverse-ok");
    expect(html).toContain(">98<");
  });
});

describe("a version apm did not read in full, on its badge", () => {
  test("reads 98 · not all read in the warning tone, never partial and never A 98 in green", () => {
    const html = renderToStaticMarkup(<ScoreBadge score={98} grade="P" />);
    const whole = renderToStaticMarkup(<ScoreBadge score={98} grade="A" />);

    expect(visibleText(html)).toBe("98 · not all read");
    expect(html).not.toContain("partial");
    expect(html).toContain("bg-warn-soft");
    expect(html).not.toContain("bg-ok-soft");
    expect(whole).toContain("bg-ok-soft");
    expect(toneOf(98, "P")).toBe("warn");
  });

  test("a screen reader and a hover hear the whole sentence", () => {
    const html = renderToStaticMarkup(<ScoreBadge score={98} grade="P" />);

    expect(html).toContain('title="98/100 on the files apm read; apm did not read every file"');
    expect(html).toContain('<span class="sr-only">98/100 on the files apm read; apm did not read every file</span>');
  });
});

describe("an analysis that stopped before it finished", () => {
  test("says it did not finish, with no count of files not read", () => {
    const stopped = Coverage.parse({ kind: "partial", omittedFiles: 0, omittedBytes: 0, reasons: ["stopped"], notes: [] });
    const html = renderToStaticMarkup(<ScoreHeadline score={39} grade="F" coverage={stopped} tone={TONE} version="1.0.0" name="x" unpackedSize={null} folders={[]} />);

    // on e8616ca: "39/100 on the code apm read; 0 files not read", and that they were left unread for their size
    expect(html).toContain("Analysis did not finish");
    expect(html).toContain("39/100: apm stopped before it finished reading this version");
    expect(html).not.toContain("files not read");
    expect(html).not.toContain("skipped");
  });
});

// review of c456c92, finding 4: only a reading graded P (whole files left unread for their size, nothing else
// unfinished) leads with "Not fully checked"; one incomplete for another reason shows its score and letter, as always
describe("a partial coverage that is not graded P", () => {
  test("an incomplete re-run that read at most 4 MB shows 39 and F, not Not fully checked", () => {
    const html = renderToStaticMarkup(<ScoreHeadline score={39} grade="F" coverage={NEXT} tone={TONE} version="1.0.0" name="x" unpackedSize={null} folders={[]} />);

    expect(html).not.toContain("Not fully checked");
    expect(html).toContain(">39<");
  });
});
