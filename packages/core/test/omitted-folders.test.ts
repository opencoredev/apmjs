// omittedFolders: where the files apm did not read are, for the package page to name them. Grouped by their first two
// folders, biggest first, at most three; a top-level file under ".".
import { expect, test } from "bun:test";
import { omittedFolders, OMITTED_FOLDERS_SHOWN } from "../src/score.ts";

test("groups unread files by their first two folders, biggest first, at most three", () => {
  const skipped = [
    { path: "dist/compiled/webpack/bundle5.js", size: 2_600_000 },
    { path: "dist/compiled/react-dom/cjs/a.js", size: 1_000_000 },
    { path: "dist/esm/server/a.js", size: 300_000 },
    { path: "dist/esm/b.js", size: 300_000 },
    { path: "lib/x.js", size: 50_000 },
    { path: "README.md", size: 100_000 },
  ];

  expect(omittedFolders(skipped)).toEqual([
    { path: "dist/compiled", files: 2, bytes: 3_600_000 },
    { path: "dist/esm", files: 2, bytes: 600_000 },
    { path: ".", files: 1, bytes: 100_000 },
  ]);
  expect(OMITTED_FOLDERS_SHOWN).toBe(3);
});

test("a path listed twice (skipped by two walks) counts once", () => {
  const twice = [
    { path: "dist/a.js", size: 10 },
    { path: "dist/a.js", size: 10 },
  ];

  expect(omittedFolders(twice)).toEqual([{ path: "dist", files: 1, bytes: 10 }]);
});

test("nothing skipped names nothing", () => {
  expect(omittedFolders([])).toEqual([]);
});

// review of c93d72e, finding 1: a version's summary can be public while its tarball is not (confirmed malicious,
// unpublished upstream), so a folder name the publisher chose freely is never repeated, only common layout names
test("only common folder names are named; any other folder is left out, whatever its size", () => {
  const secret = ["sk", "live", "Q8vT2mLw9XyZ4bN7cR1dF6gH3jK5pS0uV"].join("_");

  const skipped = [
    { path: `${secret}/a.js`, size: 9_000_000 },
    { path: `dist/${secret}/b.js`, size: 8_000_000 },
    { path: "dist/compiled/c.js", size: 1_000 },
  ];

  const named = omittedFolders(skipped);

  expect(named).toEqual([{ path: "dist/compiled", files: 1, bytes: 1_000 }]);
  expect(JSON.stringify(named)).not.toContain(secret);
});
