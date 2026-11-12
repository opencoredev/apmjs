// `apm explain` and `apm search`: the verdict rules, and the real CLI against a stand-in registry printing one
// JSON document with --json and exiting with the verdict's code.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { EXIT, explain, type ResolvedInput } from "../src/explain.ts";

const NETWORK = { id: "network", label: "Uses the network", points: -10, evidence: ["a.js:1: fetch(x)"], confidence: "confirmed" as const };
const ok = (score: number): ResolvedInput => ({ kind: "ok", version: "1.0.0", report: { score, grade: score >= 90 ? "A" : "C", signals: [NETWORK] }, skipped: [], unchecked: [] });

describe("explain", () => {
  test("clean and past the policy: install with exact commands, exit 0", () => {
    const v = explain({ name: "zod", range: null, resolved: ok(92), review: { kind: "reviewed", state: "found-nothing", findings: 0 } });

    expect(v.verdict).toBe("install");
    expect(v.commands?.apm).toBe("apm add zod@1.0.0");
    expect(EXIT[v.verdict]).toBe(0);
  });

  test("a low score or an open AI flag: review first, exit 3", () => {
    expect(explain({ name: "x", range: null, resolved: ok(60), review: { kind: "none" } }).verdict).toBe("review-first");
    expect(explain({ name: "x", range: null, resolved: ok(95), review: { kind: "reviewed", state: "under-review", findings: 1 } }).verdict).toBe("review-first");
    expect(EXIT["review-first"]).toBe(3);
  });

  test("refused, confirmed malicious or unknown name: no commands, exit 1", () => {
    expect(explain({ name: "x", range: "2", resolved: { kind: "refused", reason: "revoked: token stolen", newest: "2.0.0", skipped: [] }, review: { kind: "none" } })).toMatchObject({ verdict: "do-not-install", commands: null });
    expect(explain({ name: "x", range: null, resolved: ok(95), review: { kind: "reviewed", state: "confirmed", findings: 1 } }).verdict).toBe("do-not-install");
    expect(explain({ name: "reakt", range: null, resolved: { kind: "missing", reason: "No package named reakt." }, review: { kind: "none" } }).verdict).toBe("not-found");
    expect(EXIT["not-found"]).toBe(1);
  });

  test("a registry that did not answer: unknown, exit 4", () => {
    expect(explain({ name: "x", range: null, resolved: { kind: "unavailable", reason: "HTTP 502" }, review: { kind: "none" } }).verdict).toBe("unknown");
    expect(EXIT.unknown).toBe(4);
  });
});

describe("the CLI against a stand-in registry", () => {
  let server: ReturnType<typeof Bun.serve>;
  let home: string;

  beforeAll(() => {
    home = mkdtempSync(join(tmpdir(), "apm-explain-"));
    server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        const url = new URL(req.url);

        if (url.pathname === "/-/apm/v1/resolve") {
          const name = url.searchParams.get("name");

          if (name === "good") return Response.json({ name, range: "latest", source: "local", version: "1.2.3", report: { score: 95, grade: "A", signals: [] }, skipped: [], tree: { unchecked: 0, uncheckedDeps: [], packages: [] } });

          if (name === "fresh") return Response.json({ error: "fresh@2.0.0: published 2h ago (cooldown 24h)", name, range: "latest", version: null, skipped: [{ version: "2.0.0", reason: "published 2h ago (cooldown 24h)" }], newest: { version: "2.0.0", report: null } }, { status: 422 });

          return Response.json({ error: `No package named ${name}.` }, { status: 404 });
        }

        if (url.pathname.startsWith("/-/apm/v1/review/")) return Response.json({ name: "good", version: "1.2.3", status: "reviewed", review: { state: "found-nothing", findings: [] } });

        if (url.pathname === "/-/v1/search") {
          return Response.json({ total: 1, upstreamFailed: false, objects: [{ source: "npm", package: { name: "good", version: "1.2.3", description: "A good one" }, apmScore: { score: 95, grade: "A", signals: [] }, downloads: { weekly: 10 } }] });
        }

        return Response.json({ error: "not found" }, { status: 404 });
      },
    });
  });

  afterAll(() => {
    server.stop(true);
    rmSync(home, { recursive: true, force: true });
  });

  async function apm(args: string[]): Promise<{ code: number; json: z.core.util.JSONType }> {
    const proc = Bun.spawn(["bun", join(import.meta.dir, "..", "src", "main.ts"), ...args, "--json"], {
      cwd: home,
      env: { PATH: process.env.PATH ?? "", HOME: home, APM_REGISTRY: server.url.toString(), NO_COLOR: "1" },
      stdout: "pipe",
      stderr: "pipe",
    });

    const [out, code] = await Promise.all([new Response(proc.stdout).text(), proc.exited]);
    const lines = out.trim().split("\n");

    // exactly one JSON document on stdout
    expect(lines).toHaveLength(1);

    return { code, json: z.json().parse(JSON.parse(lines[0] ?? "null")) };
  }

  test("apm explain good --json: install, exit 0", async () => {
    const r = await apm(["explain", "good"]);

    expect(r.code).toBe(0);
    expect(r.json).toMatchObject({ ok: true, verdict: "install", version: "1.2.3", commands: { apm: "apm add good@1.2.3" } });
  });

  test("apm explain fresh --json: do not install, exit 1, with the registry's reason", async () => {
    const r = await apm(["explain", "fresh"]);

    expect(r.code).toBe(1);
    expect(r.json).toMatchObject({ ok: false, verdict: "do-not-install", summary: "Do not install fresh: fresh@2.0.0: published 2h ago (cooldown 24h)" });
  });

  test("apm explain on an unknown name: not-found", async () => {
    expect((await apm(["explain", "nope"])).json).toMatchObject({ verdict: "not-found" });
  });

  test("apm search --json: the hits with their scores", async () => {
    const r = await apm(["search", "good"]);

    expect(r.code).toBe(0);
    expect(r.json).toEqual({ ok: true, query: "good", total: 1, upstreamFailed: false, hits: [{ name: "good", version: "1.2.3", description: "A good one", source: "npm", score: { score: 95, grade: "A" }, weeklyDownloads: 10 }] });
  });
});
