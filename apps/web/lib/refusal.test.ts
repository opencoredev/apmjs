// resolve's 200 can pick a sibling of equal precedence (1.0.0+b for 1.0.0+a) and skip the version asked for: only an
// answer that picked exactly the shown version says it installs.
import { describe, expect, test } from "bun:test";
import type { ResolveOutcome } from "./agent/source";
import { resolveRefusal } from "./refusal";

const ok = (version: string, skipped: { version: string; reason: string }[] = []): ResolveOutcome => ({
  kind: "ok",
  version,
  source: "local",
  report: null,
  skipped,
  deps: { unchecked: 0, uncheckedDeps: [], reviews: { kind: "unknown" }, warnings: [], risks: [] },
});

describe("a resolve 200 for exactly the shown version", () => {
  test("picking that version installs it", () => {
    expect(resolveRefusal({ name: "pkg", version: "1.0.0+a", outcome: ok("1.0.0+a") })).toBeNull();
  });

  test("skipping it as confirmed malicious refuses it, though a sibling was picked", () => {
    const outcome = ok("1.0.0+b", [{ version: "1.0.0+a", reason: "confirmed malicious by an apm reviewer" }]);

    expect(resolveRefusal({ name: "pkg", version: "1.0.0+a", outcome })).toEqual({ kind: "confirmed-malicious" });
  });

  test("picking another version without a word about this one is unknown, not installs", () => {
    expect(resolveRefusal({ name: "pkg", version: "1.0.0+a", outcome: ok("1.0.0+b") })).toBe("unknown");
  });
});
