// The public view of an AI review depends on no free text from the model or the publisher (independent re-checks of
// 7207ea0 and 70dc3df). Rows are built directly without running ReviewRow's redaction transform, and secrets seeded in
// the quote, the excerpt, the model's sentence and summary, the second opinion, the coverage paths and the file names
// still reach no public field. A confirmed finding is public as `file N`, line, severity and a fixed label: never a
// file name.
import { describe, expect, test } from "bun:test";
import { ReviewResult } from "@apm/ai-review";
import { publicView, type StoredReview } from "../src/review.ts";
import { FINDING_LABELS, labelOf } from "../src/public-finding.ts";

// built at run time so no secret-shaped literal sits in the repository
const KEY = ["sk", "proj", "Q8vT2mLw9XyZ4bN7cR1dF6gH3jK5pS0uV"].join("-");
const SPACED = ["fictional", "password", "with", "spaces"].join(" ");
const DIGITS = "1234567890123456";
const SHORT = "hunter";
const SECRETS = [KEY, SPACED, DIGITS];

const finding = (file: string) => ({
  file,
  line: 3,
  quote: `apiKey: "${KEY}" password = "${SPACED}"`,
  excerpt: `const ai = new OpenAI({ apiKey: "${KEY}" }); const password = "${SPACED}";`,
  // the re-check's case: the model's own sentence quotes a credential no masking rule knows
  issue: `Sends the database password "${DIGITS}" and ${KEY} to a remote host.`,
  severity: "high",
});

const SEEDED_FILES = ["index.js", `config/${KEY}.json`, `notes/password = "${SPACED}".txt`, `dump/${DIGITS}${DIGITS}.bin`, `config/${KEY}.json`];

const row = (humanState: "pending" | "confirmed" | "dismissed", files: readonly string[] = SEEDED_FILES): StoredReview => ({
  package: "shop",
  version: "1.0.0",
  digest: "sha512-x",
  outcome: "flagged",
  result: ReviewResult.parse({
    outcome: "flagged",
    verdict: "malicious",
    findings: files.map(finding),
    model: "fake-flash",
    reviewedAt: "2026-11-18T10:00:00.000Z",
    summary: `Summary that quotes ${KEY}, "${SPACED}" and ${DIGITS}`,
    coverage: { mode: "files", previousVersion: null, filesInScope: 56, filesRead: 36 },
    read: ["index.js", `cache/${KEY}.js`, `${SHORT}-${DIGITS}.txt`],
    notRead: [
      { kind: "file", path: `backup/${SPACED}.json`, reason: "binary" },
      { kind: "file", path: `keys/${DIGITS}.pem`, reason: "too-large" },
      { kind: "dependency", name: "left-pad" },
    ],
    attempts: [{ result: "malicious", kept: 1, dropped: 0, promptTokens: 1, completionTokens: 1, latencyMs: 1 }],
    secondOpinion: { reviewer: "strong", verdict: "malicious", summary: KEY, findings: [finding(`second/${KEY}`)] },
  }),
  reviewed_at: 1,
  human_state: humanState,
  human_by: humanState === "pending" ? null : "octo-admin",
  human_at: humanState === "pending" ? null : 2,
  human_note: humanState === "pending" ? null : "Checked by hand.",
});

describe("the public view with masking stubbed out", () => {
  test("the stub is in force: the parsed row still holds every secret", () => {
    const text = JSON.stringify(row("confirmed"));

    for (const s of SECRETS) expect(text).toContain(s);
  });

  for (const state of ["pending", "confirmed", "dismissed"] as const) {
    for (const hold of [true, false]) {
      test(`${state}, flags ${hold ? "hold" : "do not hold"}: no secret, quote, excerpt, sentence, summary or path`, () => {
        const text = JSON.stringify(publicView(row(state), hold));

        for (const s of SECRETS) expect(text, s).not.toContain(s);
        expect(text).not.toContain("Sends the database password");
        expect(text).not.toContain("Summary that quotes");

        for (const field of ['"quote"', '"excerpt"', '"read"', '"notRead"', '"summary"', '"secondOpinion"']) expect(text, field).not.toContain(field);
      });
    }
  }

  test("a confirmed finding is file N, line, severity and a fixed label; coverage is counts", () => {
    const view = publicView(row("confirmed"), true);

    expect(view.findings).toEqual([
      { file: "file 1", line: 3, severity: "high", label: "sends data out", issue: "sends data out" },
      { file: "file 2", line: 3, severity: "high", label: "sends data out", issue: "sends data out" },
      { file: "file 3", line: 3, severity: "high", label: "sends data out", issue: "sends data out" },
      { file: "file 4", line: 3, severity: "high", label: "sends data out", issue: "sends data out" },
      // the same path keeps its number
      { file: "file 2", line: 3, severity: "high", label: "sends data out", issue: "sends data out" },
    ]);
    expect(view.coverage).toEqual({ mode: "files", previousVersion: null, filesInScope: 56, filesRead: 36 });
    expect(view.notReadCounts).toEqual({ files: 2, dependencies: 1 });
    expect(view.note).toBe("Checked by hand.");
  });
});

describe("labels and paths", () => {
  test("every label comes from the fixed list, whatever the sentence", () => {
    for (const sentence of ["Posts process.env to a remote host.", "postinstall runs curl | sh", "Reads ~/.npmrc", "eval of a decoded string", "Opens a socket", "base64 blob", "rm -rf ~", "", `"${DIGITS}"`, KEY]) {
      expect(FINDING_LABELS).toContain(labelOf(sentence));
    }

    expect(labelOf(`"${DIGITS}"`)).toBe("flagged code");
  });

  // re-check of ef953ed: a publisher's file literally named "file 2" is numbered like any other path
  test("a file named like a reference is numbered, not passed through", () => {
    const view = publicView(row("confirmed", ["index.js", "file 2", "other.js"]), true);

    expect(view.findings?.map((f) => f.file)).toEqual(["file 1", "file 2", "file 3"]);
  });

  // re-check of d38f704: a UUID or hyphen-separated token passed every file-name shape test, so names never go public
  test("no file name reaches the public view, whatever its shape", () => {
    const uuid = ["3f2a9c1b", "8d4e", "4b7a", "9c2d", "1e5f6a7b8c9d"].join("-");
    const hyphened = ["abcd1234efgh", "5678ijkl9012", "mnop3456qrst"].join("-");
    const view = publicView(row("confirmed", ["index.js", `keys/${uuid}`, hyphened]), true);
    const text = JSON.stringify(view);

    for (const s of ["index.js", uuid, hyphened]) expect(text, s).not.toContain(s);
  });
});
