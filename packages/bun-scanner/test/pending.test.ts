// Review of d49bf6e, finding 4, the scanner's half: for a version the registry had queued for analysis the scanner
// printed a warning and returned no advisories, so `bun install` went ahead with a package nobody had scored. Now it
// asks again while the version is pending and blocks what is still pending at the end, in default and strict mode.
// The registry is a local recording stub.
import { afterEach, describe, expect, test } from "bun:test";
import { z } from "zod";
import { scanPackages } from "../src/index.ts";

type Stub = { url: string; asked: string[][]; stop: () => void };

const ScanBody = z.object({ packages: z.array(z.object({ name: z.string() })) });

/** A scan API that answers `pending` for the versions in `pendingFor` until it has been asked `rounds` times. */
function stubRegistry(input: { pendingFor: string[]; rounds: number; thenAdvisory?: boolean }): Stub {
  const asked: string[][] = [];

  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req): Promise<Response> {
      const names = ScanBody.parse(await req.json()).packages.map((p) => p.name);

      asked.push(names);

      const stillPending = asked.length <= input.rounds;
      const pending = stillPending ? names.filter((n) => input.pendingFor.includes(n)).map((n) => ({ package: n, version: "1.0.0" })) : [];

      const advisories =
        !stillPending && input.thenAdvisory
          ? names.filter((n) => input.pendingFor.includes(n)).map((n) => ({ package: n, version: "1.0.0", level: "fatal", description: `${n}@1.0.0 has apm score 10/100`, url: null }))
          : [];

      return Response.json({ advisories, unchecked: pending.map((p) => ({ ...p, reason: "not scored yet: queued for analysis" })), pending });
    },
  });

  return { url: server.url.href, asked, stop: () => server.stop(true) };
}

let stub: Stub | null = null;

afterEach(() => {
  stub?.stop();
  stub = null;
});

const pkg = (name: string, registry: string): Bun.Security.Package => ({ name, version: "1.0.0", tarball: `${registry}${name}/-/${name}-1.0.0.tgz`, requestedRange: "^1.0.0" });

async function scan(input: { strict: boolean; waitMs: number; names: string[] }) {
  if (!stub) throw new Error("no stub");
  const warnings: string[] = [];
  const registry = stub.url;
  const t0 = performance.now();

  try {
    const env = input.strict ? { APM_REGISTRY: registry, APM_SCANNER_STRICT: "1" } : { APM_REGISTRY: registry };
    const out = await scanPackages({ packages: input.names.map((n) => pkg(n, registry)), env, cwd: "/nonexistent", warn: (l) => warnings.push(l), waitMs: input.waitMs, pollMs: 20 });

    return { kind: "advisories" as const, out, warnings, ms: performance.now() - t0 };
  } catch (e) {
    return { kind: "threw" as const, message: e instanceof Error ? e.message : String(e), warnings, ms: performance.now() - t0 };
  }
}

describe("a queued version is pending, and the scanner never lets it through", () => {
  test("default mode: still pending after the wait, the install is cancelled with why and when to retry", async () => {
    stub = stubRegistry({ pendingFor: ["cold"], rounds: 1_000 });
    const r = await scan({ strict: false, waitMs: 200, names: ["cold", "fine"] });

    // on d49bf6e: [] and a warning, so bun installed it
    expect(r.kind).toBe("advisories");

    if (r.kind !== "advisories") return;
    expect(r.out).toHaveLength(1);
    expect(r.out[0]).toMatchObject({ level: "fatal", package: "cold" });
    expect(r.out[0]?.description).toContain("still being analysed");
    expect(r.out[0]?.description).toContain("try again in a minute");
    expect(r.warnings.some((w) => w.includes("waiting for 1 package"))).toBe(true);
    // asked again for the pending one only
    expect(stub.asked.slice(1).every((names) => names.length === 1 && names[0] === "cold")).toBe(true);
  });

  test("strict mode: blocked the same way", async () => {
    stub = stubRegistry({ pendingFor: ["cold"], rounds: 1_000 });
    const r = await scan({ strict: true, waitMs: 100, names: ["cold"] });

    expect(r.kind === "advisories" ? r.out.map((a) => a.level) : ["threw"]).toEqual(["fatal"]);
  });

  test("scored while the scanner waits: its real verdict is used", async () => {
    stub = stubRegistry({ pendingFor: ["cold"], rounds: 2, thenAdvisory: true });
    const r = await scan({ strict: false, waitMs: 5_000, names: ["cold"] });

    expect(r.kind).toBe("advisories");

    if (r.kind !== "advisories") return;
    expect(r.out.map((a) => a.description)).toEqual(["cold@1.0.0 has apm score 10/100"]);
    expect(r.ms).toBeLessThan(4_000);
  });

  test("scored clean while it waits: nothing blocks", async () => {
    stub = stubRegistry({ pendingFor: ["cold"], rounds: 1 });
    const r = await scan({ strict: true, waitMs: 5_000, names: ["cold"] });

    expect(r).toMatchObject({ kind: "advisories", out: [] });
  });
});
