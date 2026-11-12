// Spec: the registry refuses the publishes people regret, with an error that names the cause.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startRegistry, addUser, makeSandbox, writePackage, run, getJson, dig, type Registry } from "./harness";

let reg: Registry;
let alice: string;
let work: string;

beforeAll(async () => {
  reg = await startRegistry();
  alice = await addUser(reg, "alice");
  work = mkdtempSync(join(tmpdir(), "apm-guard-"));
});
afterAll(async () => {
  await reg?.stop();
});

async function tryPublish(name: string, version: string, files: Record<string, string>, extra: Record<string, unknown> = {}, args: string[] = []): Promise<{ code: number; out: string }> {
  const sb = makeSandbox(reg, alice);
  const d = writePackage(work, { name, version, files, extra }, reg, alice);
  return run(["npm", "publish", ...args], { cwd: d, env: sb.env });
}

describe("publish guardrails", () => {
  test("a tarball with a .env holding an AWS key is refused and the error names the file", async () => {
    const r = await tryPublish("leaky", "1.0.0", { "index.js": "module.exports = 1;\n", ".env": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n" });
    expect(r.code).not.toBe(0);
    expect(r.out).toContain(".env");
    const { status } = await getJson(`${reg.url}leaky`);
    expect(status).toBe(404);
  });

  test("a private key anywhere in the tarball is refused", async () => {
    const r = await tryPublish("leaky-key", "1.0.0", { "index.js": "module.exports = 1;\n", "certs/deploy.pem": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n-----END OPENSSH PRIVATE KEY-----\n" });
    expect(r.code).not.toBe(0);
    expect(r.out).toContain("deploy.pem");
  });

  test("an npm token in source is refused", async () => {
    const r = await tryPublish("leaky-token", "1.0.0", { "index.js": "const t = 'npm_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8';\nmodule.exports = t;\n" });
    expect(r.code).not.toBe(0);
    expect(r.out).toContain("index.js");
  });

  test("a new name one typo away from a popular package is refused", async () => {
    const r = await tryPublish("lodahs", "1.0.0", { "index.js": "module.exports = 1;\n" });
    expect(r.code).not.toBe(0);
    expect(r.out).toContain("lodash");
    const r2 = await tryPublish("expres", "1.0.0", { "index.js": "module.exports = 1;\n" });
    expect(r2.code).not.toBe(0);
    expect(r2.out).toContain("express");
  });

  test("a distinct name close to nothing popular is fine", async () => {
    const r = await tryPublish("quietly-useful-thing", "1.0.0", { "index.js": "module.exports = 1;\n" });
    expect(r.code, r.out).toBe(0);
  });

  test("a prerelease never becomes latest by accident", async () => {
    const ok = await tryPublish("stable-thing", "1.0.0", { "index.js": "module.exports = 1;\n" });
    expect(ok.code, ok.out).toBe(0);
    const pre = await tryPublish("stable-thing", "2.0.0-beta.1", { "index.js": "module.exports = 2;\n" }, {}, ["--tag", "latest"]);
    expect(pre.code, pre.out).toBe(0);
    const { body } = await getJson(`${reg.url}stable-thing`);
    expect(dig(body, "dist-tags", "latest")).toBe("1.0.0");
    expect(dig(body, "dist-tags", "next")).toBe("2.0.0-beta.1");
  });

  test("main, types and bin entries must exist in the tarball", async () => {
    const r = await tryPublish("missing-main", "1.0.0", { "lib/other.js": "module.exports = 1;\n" }, { main: "dist/index.js", types: "dist/index.d.ts" });
    expect(r.code).not.toBe(0);
    expect(r.out).toContain("dist/index.js");
  });
});

describe("manifest confusion", () => {
  test("a publish whose manifest hides the tarball's install script is refused", async () => {
    const sb = makeSandbox(reg, alice);
    const d = writePackage(work, { name: "two-faced", version: "1.0.0", scripts: { postinstall: "node evil.js" }, files: { "index.js": "module.exports=1;\n", "evil.js": "1;\n" } }, reg, alice);
    const pack = await run(["bun", "pm", "pack"], { cwd: d, env: sb.env });
    expect(pack.code, pack.out).toBe(0);
    const tgzName = readdirSync(d).find((f) => f.endsWith(".tgz"));
    expect(tgzName).toBeTruthy();
    const tgz = readFileSync(join(d, String(tgzName)));
    const body = {
      _id: "two-faced",
      name: "two-faced",
      "dist-tags": { latest: "1.0.0" },
      versions: { "1.0.0": { name: "two-faced", version: "1.0.0", main: "index.js", dependencies: {} } },
      _attachments: { "two-faced-1.0.0.tgz": { content_type: "application/octet-stream", data: tgz.toString("base64"), length: tgz.length } },
    };
    const r = await getJson(`${reg.url}two-faced`, { method: "PUT", headers: { "content-type": "application/json", authorization: `Bearer ${alice}` }, body: JSON.stringify(body) });
    expect(r.status).toBe(422);
    expect(JSON.stringify(r.body)).toContain("postinstall");
    const { status } = await getJson(`${reg.url}two-faced`);
    expect(status).toBe(404);
  });

  test("served metadata comes from the tarball's package.json", async () => {
    const sb = makeSandbox(reg, alice);
    const d = writePackage(work, { name: "honest-meta", version: "1.0.0", scripts: { postinstall: "node build.js" }, files: { "index.js": "module.exports=1;\n", "build.js": "1;\n" } }, reg, alice);
    const r = await run(["bun", "publish"], { cwd: d, env: sb.env });
    expect(r.code, r.out).toBe(0);
    const { body } = await getJson(`${reg.url}honest-meta`);
    expect(dig(body, "versions", "1.0.0", "scripts", "postinstall")).toBe("node build.js");
    expect(dig(body, "versions", "1.0.0", "hasInstallScript")).toBe(true);
  });
});

describe("name availability (domain-search style)", () => {
  test("reports availability, scoped alternatives and typo-close popular names", async () => {
    const { status, body } = await getJson(`${reg.url}-/apm/v1/names?q=reactt&user=alice`);
    expect(status).toBe(200);
    expect(dig(body, "query")).toBe("reactt");
    expect(dig(body, "available")).toBe(false);
    expect(JSON.stringify(dig(body, "conflicts"))).toContain("react");
    const alts = JSON.stringify(dig(body, "suggestions"));
    expect(alts).toContain("@alice/reactt");
  });

  test("a taken name is reported as taken with its owner", async () => {
    const { body } = await getJson(`${reg.url}-/apm/v1/names?q=stable-thing`);
    expect(dig(body, "available")).toBe(false);
    expect(dig(body, "taken")).toBe(true);
    expect(JSON.stringify(body)).toContain("alice");
  });

  test("a free name is available", async () => {
    const { body } = await getJson(`${reg.url}-/apm/v1/names?q=zebra-quantum-toaster`);
    expect(dig(body, "available")).toBe(true);
  });
});
