// re-check of 5212041: folders apm does not name (a publisher's own names) can hold more than the ones it names, so a
// minority is "Some of them are", never "The biggest groups"
import { expect, test } from "bun:test";
import { foldersSentence } from "@/lib/coverage";

test("named folders holding a minority are 'some', not 'the biggest'", () => {
  const text = foldersSentence([{ path: "dist/compiled", files: 1, bytes: 1_000 }], { files: 10, bytes: 9_001_000 });

  expect(text.startsWith("Some of them are in dist/compiled")).toBe(true);
  expect(text).not.toContain("biggest");
});

test("named folders holding most files and bytes are 'most'; all of them are 'all'", () => {
  expect(foldersSentence([{ path: "dist", files: 8, bytes: 900 }], { files: 10, bytes: 1_000 }).startsWith("Most of them are in dist")).toBe(true);
  expect(foldersSentence([{ path: "dist", files: 10, bytes: 1_000 }], { files: 10, bytes: 1_000 }).startsWith("All of them are in dist")).toBe(true);
});
