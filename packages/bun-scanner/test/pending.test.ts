// Review of d49bf6e, finding 4, the scanner's half: for a version the registry had queued for analysis the scanner
// printed a warning and returned no advisories, so `bun install` went ahead with a package nobody had scored. It now
// asks again while the version is pending. Since the owner's warn-not-block policy (2026-11), what is still pending
// at the end is a warning in default mode and fatal with APM_SCANNER_STRICT=1. A warning is a `warn` advisory where
// bun can ask about it (a terminal) and printed elsewhere, since bun cancels on a `warn` it cannot ask about. The
// registry is a local recording stub.
import { afterEach, describe, expect, test } from "bun:test";
import { z } from "zod";
import { scanPackages } from "../src/index.ts";

type Stub = { url: string; asked: string[][]; stricts: boolean[]; stop: () => void };

const ScanBody = z.object({ packages: z.array(z.object({ name: z.string() })), strict: z.boolean().optional() });

/**
 * A scan API that answers `pending` for the versions in `pendingFor` until it has been asked `rounds` times, then
 * (with `thenAdvisory`) an advisory at the level the registry gives the mode: warn, or fatal when asked for strict.
 */
function stubRegistry(input: { pendingFor: string[]; rounds: number; thenAdvisory?: boolean; thenDescription?: (name: string) => string; level?: "fatal" | "warn" }): Stub {
  const asked: string[][] = [];
  const stricts: boolean[] = [];

  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req): Promise<Response> {
      const body = ScanBody.parse(await req.json());
      const names = body.packages.map((p) => p.name);

      asked.push(names);
      stricts.push(body.strict === true);

      const stillPending = asked.length <= input.rounds;
      const pending = stillPending ? names.filter((n) => input.pendingFor.includes(n)).map((n) => ({ package: n, version: "1.0.0" })) : [];

      const advisories =
        !stillPending && input.thenAdvisory
          ? names.filter((n) => input.pendingFor.includes(n)).map((n) => ({ package: n, version: "1.0.0", level: input.level ?? (body.strict ? "fatal" : "warn"), description: input.thenDescription?.(n) ?? `${n}@1.0.0 has apm score 10/100`, url: null }))
          : [];

      return Response.json({ advisories, unchecked: pending.map((p) => ({ ...p, reason: "not scored yet: queued for analysis" })), pending });
    },
  });

  return { url: server.url.href, asked, stricts, stop: () => server.stop(true) };
}

let stub: Stub | null = null;

afterEach(() => {
  stub?.stop();
  stub = null;
});

const pkg = (name: string, registry: string): Bun.Security.Package => ({ name, version: "1.0.0", tarball: `${registry}${name}/-/${name}-1.0.0.tgz`, requestedRange: "^1.0.0" });

async function scan(input: { strict: boolean; waitMs: number; names: string[]; interactive?: boolean }) {
  if (!stub) throw new Error("no stub");
  const warnings: string[] = [];
  const registry = stub.url;
  const t0 = performance.now();

  try {
    const env = input.strict ? { APM_REGISTRY: registry, APM_SCANNER_STRICT: "1" } : { APM_REGISTRY: registry };
    const out = await scanPackages({ packages: input.names.map((n) => pkg(n, registry)), env, cwd: "/nonexistent", warn: (l) => warnings.push(l), waitMs: input.waitMs, pollMs: 20, interactive: input.interactive ?? false });

    return { kind: "advisories" as const, out, warnings, ms: performance.now() - t0 };
  } catch (e) {
    return { kind: "threw" as const, message: e instanceof Error ? e.message : String(e), warnings, ms: performance.now() - t0 };
  }
}

describe("a queued version is pending: waited for, then a warning (strict: blocked), never clean", () => {
  test("default mode, outside a terminal: still pending after the wait, printed with why, and the install goes ahead", async () => {
    stub = stubRegistry({ pendingFor: ["cold"], rounds: 1_000 });
    const r = await scan({ strict: false, waitMs: 200, names: ["cold", "fine"] });

    expect(r.kind).toBe("advisories");

    if (r.kind !== "advisories") return;
    // bun cancels on a warn it cannot ask about: nothing is returned, and the warning is printed
    expect(r.out).toEqual([]);
    expect(r.warnings.some((w) => w.includes("cold@1.0.0: not scored yet") && w.includes("APM_SCANNER_STRICT=1 refuses it"))).toBe(true);
    expect(r.warnings.some((w) => w.includes("waiting for 1 package"))).toBe(true);
    // asked again for the pending one only
    expect(stub.asked.slice(1).every((names) => names.length === 1 && names[0] === "cold")).toBe(true);
    expect(stub.stricts.every((x) => !x)).toBe(true);
  });

  test("default mode, in a terminal: a warn advisory, which bun shows and asks about", async () => {
    stub = stubRegistry({ pendingFor: ["cold"], rounds: 1_000 });
    const r = await scan({ strict: false, waitMs: 100, names: ["cold"], interactive: true });

    expect(r.kind === "advisories" ? r.out.map((a) => [a.level, a.package]) : ["threw"]).toEqual([["warn", "cold"]]);
  });

  test("strict mode: blocked, and the registry is asked for strict answers", async () => {
    stub = stubRegistry({ pendingFor: ["cold"], rounds: 1_000 });
    const r = await scan({ strict: true, waitMs: 100, names: ["cold"] });

    expect(r.kind === "advisories" ? r.out.map((a) => a.level) : ["threw"]).toEqual(["fatal"]);
    expect(r.kind === "advisories" ? r.out[0]?.description : "").toContain("try again in a minute");
    expect(stub.stricts.every((x) => x)).toBe(true);
  });

  test("scored while the scanner waits: its real verdict is used", async () => {
    stub = stubRegistry({ pendingFor: ["cold"], rounds: 2, thenAdvisory: true });
    const r = await scan({ strict: true, waitMs: 5_000, names: ["cold"] });

    expect(r.kind).toBe("advisories");

    if (r.kind !== "advisories") return;
    expect(r.out.map((a) => [a.level, a.description])).toEqual([["fatal", "cold@1.0.0 has apm score 10/100"]]);
    expect(r.ms).toBeLessThan(4_000);
  });

  test("scored clean while it waits: nothing blocks", async () => {
    stub = stubRegistry({ pendingFor: ["cold"], rounds: 1 });
    const r = await scan({ strict: true, waitMs: 5_000, names: ["cold"] });

    expect(r).toMatchObject({ kind: "advisories", out: [] });
  });

  test("a low score, default mode: printed outside a terminal, the install goes ahead", async () => {
    stub = stubRegistry({ pendingFor: ["low"], rounds: 0, thenAdvisory: true, thenDescription: (n) => `${n}@1.0.0: scores 12/100 (F), under the floor of 40\n  - Sends data out: index.js:3: fetch(…)\n  http://web.test/package/low/v/1.0.0` });
    const r = await scan({ strict: false, waitMs: 0, names: ["low"] });

    expect(r).toMatchObject({ kind: "advisories", out: [] });
    expect(r.warnings.join("\n")).toContain("apm scanner: warning: low@1.0.0: scores 12/100 (F)");
    expect(r.warnings.join("\n")).toContain("index.js:3");
  });

  // review of 5b5b492, finding 2: an outage gave no advisory, only "not checked"; it is its own warning now
  test("a package the registry could not look up: printed by default, fatal in strict mode", async () => {
    const outage = (n: string): string => `${n}@1.0.0: could not be checked: registry or upstream unavailable`;

    stub = stubRegistry({ pendingFor: ["down"], rounds: 0, thenAdvisory: true, thenDescription: outage });
    const warned = await scan({ strict: false, waitMs: 0, names: ["down"] });
    const strict = await scan({ strict: true, waitMs: 0, names: ["down"] });

    expect(warned).toMatchObject({ kind: "advisories", out: [] });
    expect(warned.warnings.join("\n")).toContain("could not be checked: registry or upstream unavailable");
    expect(strict.kind === "advisories" ? strict.out.map((a) => [a.level, a.description]) : []).toEqual([["fatal", outage("down")]]);
  });

  // review of 9913a74, finding 2: a version that went from pending to a terminal outcome (analysis-limit) came back as
  // only unchecked; the registry now answers it with an advisory (warn by default, fatal in strict mode)
  for (const strict of [false, true]) {
    test(`decided unscorable while the scanner waits: ${strict ? "blocked in strict mode" : "a warning in default mode"}, naming why`, async () => {
      const why = (n: string): string => `${n}@1.0.0: apm cannot score this version: its analysis runs past the registry's limits (stand-in)`;

      stub = stubRegistry({ pendingFor: ["cold"], rounds: 1, thenAdvisory: true, thenDescription: why });
      const r = await scan({ strict, waitMs: 5_000, names: ["cold"], interactive: true });

      expect(r.kind).toBe("advisories");

      if (r.kind !== "advisories") return;
      expect(r.out).toEqual([{ level: strict ? "fatal" : "warn", package: "cold", url: null, description: why("cold") }]);
    });
  }

  test("a fatal advisory (revoked, or confirmed malicious) is returned in every mode", async () => {
    stub = stubRegistry({ pendingFor: ["bad"], rounds: 0, thenAdvisory: true, level: "fatal", thenDescription: (n) => `${n}@1.0.0 was revoked by its maintainer: stand-in` });
    const r = await scan({ strict: false, waitMs: 0, names: ["bad"] });

    expect(r.kind === "advisories" ? r.out.map((a) => a.level) : []).toEqual(["fatal"]);
  });
});
