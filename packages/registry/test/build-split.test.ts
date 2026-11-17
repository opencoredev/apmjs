// The registry's build keeps Better Auth out of the entry module (scripts/build.ts, auth-engine.ts): a cold isolate
// parses and runs only the entry before its first answer, and Better Auth with the libraries only sign-in uses is about
// half the Worker. The chunk is loaded by one dynamic import, and workerModules lists every module the deploy uploads.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { buildWorker, workerModules } from "../scripts/build.ts";

let dir: string;
let entry: string;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "apm-build-split-"));
  entry = await buildWorker("worker", dir);
}, 120_000);

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("the registry build", () => {
  test("the entry carries none of Better Auth, which a dynamic import loads from a chunk of its own", () => {
    const code = readFileSync(entry, "utf8");
    const modules = workerModules(entry);
    const engine = modules.filter((m) => basename(m.path).startsWith("auth-engine-"));

    // Better Auth reads its secret from these variables: their names are in its code, and only there
    expect(code).not.toContain("BETTER_AUTH_SECRET");
    expect(engine).toHaveLength(1);
    expect(readFileSync(engine[0]?.path ?? "", "utf8")).toContain("BETTER_AUTH_SECRET");
    expect(code).toContain(`import(\`./worker-chunks/${basename(engine[0]?.path ?? "")}\`)`);
    // a minified entry of about half the size it had with Better Auth inlined (2.7 MB)
    expect(code.length).toBeLessThan(1_800_000);
  });

  test("workerModules lists the entry first, then every chunk it may load, under the entry's directory", () => {
    const modules = workerModules(entry);

    expect(modules[0]).toEqual({ type: "ESModule", path: entry });
    expect(modules.length).toBeGreaterThan(1);

    for (const m of modules.slice(1)) {
      expect(m.type).toBe("ESModule");
      expect(m.path.startsWith(join(dir, "worker-chunks/"))).toBe(true);
    }
  });

  test("a build leaves no chunk of an earlier one beside its own", async () => {
    const before = workerModules(entry);
    const stale = join(dir, "worker-chunks", "auth-engine-stale.js");

    writeFileSync(stale, "export {};\n");
    await buildWorker("worker", dir);
    expect(existsSync(stale)).toBe(false);
    expect(workerModules(entry)).toEqual(before);
  }, 120_000);
});
