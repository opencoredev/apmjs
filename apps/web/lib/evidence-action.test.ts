// A reviewer's undo needs a public reason, like a dismissal, and a passkey check confirms that exact item and reason.
import { describe, expect, test } from "bun:test";
import { evidenceRequest } from "./evidence-action";

const item = { name: "a", version: "1.0.0", digest: "sha512-x", scorer: "apm-score-v8", signal: "credential-access", file: "index.js", line: 1 };

describe("evidence requests", () => {
  test("an undo without a reason is not sent", () => {
    expect(evidenceRequest({ mode: "restore", item, reason: "  " })).toEqual({ kind: "error", message: "Say why you are undoing this dismissal; the reason is shown in public." });
    expect(evidenceRequest({ mode: "dismiss", item, reason: "" }).kind).toBe("error");
  });

  test("an undo sends its reason, and the action a passkey confirms names the same item and reason", () => {
    expect(evidenceRequest({ mode: "restore", item, reason: " The list is read. " })).toEqual({
      kind: "ok",
      action: { kind: "evidence-restore", ...item, reason: "The list is read." },
      body: { ...item, reason: "The list is read." },
    });
  });
});
