// The website's timeouts for a resolve against the registry's own wait for queued analyses. Staging, before this:
// explain gave resolve 25 s, the registry waited 20 s plus two walks of vite's tree, and explain answered "the
// registry did not answer" after 24 s instead of saying vite was still being analysed.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { RESOLVE_WAIT, WAIT_PARAM, parseWait } from "../../../../packages/registry/src/resolve-wait";
import { FORWARD_TIMEOUT_MS } from "../registry-proxy";
import { EXPLAIN_RESOLVE_WAIT_MS, RESOLVE_TIMEOUT_MS, RESOLVE_WALK_ALLOWANCE_MS } from "./resolve-budget";

describe("resolve timeouts", () => {
  test("explain's resolve asks for a wait it can sit out, with room for two walks of the tree", () => {
    expect(EXPLAIN_RESOLVE_WAIT_MS + RESOLVE_WALK_ALLOWANCE_MS).toBeLessThan(RESOLVE_TIMEOUT_MS);
  });

  test("explain asks the registry for its short wait, which the registry honours", () => {
    const source = readFileSync(join(import.meta.dir, "registry-source.ts"), "utf8");

    expect(WAIT_PARAM).toBe("wait");
    expect(source).toContain("wait: String(EXPLAIN_RESOLVE_WAIT_MS)");
    expect(source).toContain("withTimeout(RESOLVE_TIMEOUT_MS)");
    expect(parseWait(String(EXPLAIN_RESOLVE_WAIT_MS))).toEqual({ kind: "ok", maxMs: EXPLAIN_RESOLVE_WAIT_MS });
  });

  test("a resolve forwarded through the website may wait the registry's whole wait", () => {
    expect(RESOLVE_WAIT.maxMs + RESOLVE_WALK_ALLOWANCE_MS).toBeLessThan(FORWARD_TIMEOUT_MS);
  });

  test("a caller can only shorten the registry's wait", () => {
    expect(parseWait(null)).toEqual({ kind: "ok", maxMs: RESOLVE_WAIT.maxMs });
    expect(parseWait("999999")).toEqual({ kind: "ok", maxMs: RESOLVE_WAIT.maxMs });
    expect(parseWait("-1").kind).toBe("invalid");
    expect(parseWait("soon").kind).toBe("invalid");
  });
});
