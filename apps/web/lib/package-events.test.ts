// The package page's public log: a dismissal shows its reason, and an undo shows both why it was undone and why the
// item had been dismissed.
import { describe, expect, test } from "bun:test";
import { describeEvent } from "./package-events";

const item = { version: "1.0.0", digest: "sha512-x", scorer: "apm-score-v8", signal: "credential-access", file: "index.js", line: 1 };
const at = "2026-11-12T00:00:00.000Z";

describe("evidence entries in the public log", () => {
  test("a dismissal shows its reason", () => {
    expect(describeEvent({ kind: "evidence-dismissed", actor: "octo-admin", at, detail: { ...item, reason: "A deny list." } })).toBe(
      "dismissed credential-access evidence (index.js:1) in 1.0.0: A deny list.",
    );
  });

  test("an undo shows the undo's reason and the dismissal's", () => {
    const detail = { ...item, reason: "The list is read after all.", dismissal: { reason: "A deny list.", by: "octo-admin", at: 1 } };

    expect(describeEvent({ kind: "evidence-restored", actor: "octo-admin", at, detail })).toBe(
      "restored credential-access evidence (index.js:1) in 1.0.0: The list is read after all. (it had been dismissed: A deny list.)",
    );
  });

  test("an undo logged before undos needed a reason still shows the dismissal's reason, and its note", () => {
    expect(describeEvent({ kind: "evidence-restored", actor: "octo-admin", at, detail: { ...item, reason: "A deny list.", note: "Reopened." } })).toBe(
      "restored credential-access evidence (index.js:1) in 1.0.0: Reopened. (it had been dismissed: A deny list.)",
    );
    expect(describeEvent({ kind: "evidence-restored", actor: "octo-admin", at, detail: { ...item, reason: "A deny list.", note: null } })).toBe(
      "restored credential-access evidence (index.js:1) in 1.0.0 (it had been dismissed: A deny list.)",
    );
  });
});
