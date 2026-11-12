// A dismissed evidence item stays on the version page, struck through, with "Dismissed by an apm reviewer: <reason>"
// and the date; a visitor who is not a reviewer gets no undo control. Rendered with react-dom/server, no browser.
import { expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { DismissedEvidence } from "@/components/dismissed-evidence";

const d = {
  signal: "credential-access",
  file: "dist/node/chunks/config.js",
  line: 25134,
  evidence: ["dist/node/chunks/config.js:25134: deny: ['.env', '.env.*', '**/.npmrc'] (text match: counted unless it sits in a comment, a regex or a type)"],
  reason: "A deny list: the dev server refuses to serve these files.",
  at: Date.parse("2026-11-12T10:00:00Z"),
};

const item = { name: "vite", version: "8.3.8", digest: "sha512-x", scorer: "apm-score-v8", signal: d.signal, file: d.file, line: d.line };

test("a dismissed item is struck through, with the reviewer's reason and the date", () => {
  const html = renderToStaticMarkup(<DismissedEvidence d={d} item={item} />);

  expect(html).toContain("line-through");
  expect(html).toContain("dist/node/chunks/config.js:25134");
  expect(html).toContain("Dismissed by an apm reviewer: A deny list: the dev server refuses to serve these files.");
  expect(html).toContain("2026-11-12");
  // outside a reviewer's session the undo control renders nothing
  expect(html).not.toContain("Undo");
});
