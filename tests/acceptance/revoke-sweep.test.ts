// Spec: a revoked or revoke-pending version's text is shown nowhere. One package carries a unique marker in every
// free-text place a publisher controls (readme, manifest fields, every kind of script, dependency specs and keys, bin
// and exports, file contents, file names, a deprecation message). It is scored, reviewed by a stub model whose
// findings quote marker lines and name a marked file, has evidence dismissed, and one version arrives through a staged
// upload a signed-in owner approves. Then one version is revoked and another goes revoke-pending, and every GET route
// the registry serves is asked, as an anonymous visitor, the maintainer's token, the signed-in owner and an admin,
// plain and under /~safe/. Every answer must have the status its probe expects and a body, and no marker may come back,
// in a body or a header, except where ALLOWED names the exact route, status, field and marker.
//
// The website's agent views (apps/web/lib/agent: the Markdown view, and the MCP tools check_package, search_packages
// and get_file_excerpt) are asked too, through their real registry port against this Worker, before and after.
//
// The routes come from the registry's own GET table (packages/registry/src/routes.ts), which the router enforces: a
// GET the table does not list is refused before any module sees it. The sweep probes every entry, so a new GET route
// is either swept here or never answered.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { DailyBudget } from "../../apps/reviewer/src/budget.ts";
import { silentLogger } from "../../apps/reviewer/src/log.ts";
import { modelClient } from "../../apps/reviewer/src/model.ts";
import { registryClient } from "../../apps/reviewer/src/registry.ts";
import { runOnce, type WorkerDeps } from "../../apps/reviewer/src/worker.ts";
import { WITHHELD_ISSUE } from "../../packages/registry/src/withheld.ts";
import { GET_ROUTES, getRouteOf, NO_GET_ROUTE, type GetRouteName } from "../../packages/registry/src/routes.ts";
import {
  addUser,
  approvalId,
  deviceLogin,
  dig,
  enableTotp,
  getJson,
  putPublish,
  signInWithGitHub,
  startFakeGitHub,
  startRegistry,
  totp,
  type Browser,
  type FakeGitHub,
  type RawManifest,
  type Registry,
} from "./harness";

const DAY = 24 * 60 * 60 * 1000;
const HOUR = 60 * 60 * 1000;
const PASSWORD = "correct-horse-battery";
const NAME = "sweep-fixture";
const MAINTAINER = "sweep-owner";
const SITE_OWNER = "sweep-site";
const ADMIN = "sweep-admin";
const SERVICE_TOKEN = `svc_${randomBytes(24).toString("base64url")}`;
const MARK = /LEAKMARK-[A-Za-z0-9-]+/g;

/** The version revoked at once (new, no dependents), the one whose revoke is pending (older than 72h), and a clean one. */
const REVOKED = "1.1.0";
const PENDING = "1.0.0";
const CLEAN = "0.9.0";
const VERSIONS = [CLEAN, PENDING, REVOKED] as const;

/**
 * Tags left on the withheld versions after the revoke. The revoke moves every tag off a version, so the sweep would
 * otherwise never ask a tag route about a withheld target; these are written to the row afterwards, the way a tag
 * the move missed would stay, and each tag route must answer for that version as it answers for its number.
 */
const STALE_TAGS = { "stale-revoked": REVOKED, "stale-pending": PENDING } as const;

// ---------- the marked package ----------
// the last line names a credential file, so apm-score-v10 (where eval is a capability, not a signal) has a risk signal
// whose evidence quotes a marker for the admin to dismiss
const INDEX_JS = ['// LEAKMARK-js-comment', 'module.exports = "LEAKMARK-js-string";', 'eval("LEAKMARK-js-eval");', 'const rc = "~/.npmrc LEAKMARK-js-npmrc";', ""].join("\n");

/** Binary-ish: NUL bytes around a marker, so a text check that stops at NUL would miss it. */
const BLOB = new Uint8Array([0, 1, 2, 0, ...new TextEncoder().encode("LEAKMARK-binary"), 0, 255, 0]);

const FILES = {
  "index.js": INDEX_JS,
  "README.md": "# LEAKMARK-readme-file\n",
  "index.d.ts": 'export declare const marker: "LEAKMARK-dts";\n',
  "data.json": '{ "note": "LEAKMARK-json" }\n',
  "cli.js": '#!/usr/bin/env node\nconsole.log("LEAKMARK-bin-file");\n',
  "lib/LEAKMARK-filename.js": "module.exports = 2;\n",
  "assets/blob.bin": BLOB,
} satisfies Record<string, string | Uint8Array>;

function marked(version: string): RawManifest {
  return {
    name: NAME,
    version,
    description: "LEAKMARK-description",
    keywords: ["LEAKMARK-keyword"],
    license: "LEAKMARK-license",
    author: "LEAKMARK-author",
    homepage: "https://example.invalid/LEAKMARK-homepage",
    repository: { type: "git", url: "https://example.invalid/LEAKMARK-repository.git" },
    readme: "# LEAKMARK-readme\n\nSee LEAKMARK-readme-body.",
    main: "index.js",
    types: "index.d.ts",
    bin: { "LEAKMARK-bin-name": "cli.js" },
    exports: { ".": "./index.js", "./LEAKMARK-export-key": "./lib/LEAKMARK-filename.js" },
    scripts: {
      // a shell wrapper, a nested npm run chain through a colon-named script, and a plain script
      preinstall: "sh -c 'echo LEAKMARK-script-shell'",
      postinstall: "npm run chain:LEAKMARK-script-colon",
      "chain:LEAKMARK-script-colon": "npm run leaf",
      leaf: "node -e \"console.log('LEAKMARK-script-leaf')\"",
      test: "echo LEAKMARK-script-test",
    },
    dependencies: {
      "dep-url": "https://collector.example.invalid/LEAKMARK-dep-url.tgz",
      "dep-git": "github:someone/LEAKMARK-dep-git",
      "dep-tag": "LEAKMARK-dep-tag",
      // a URL dependency's key is not checked at publish: any text the publisher wrote
      "LEAKMARK-dep-key": "https://collector.example.invalid/x.tgz",
    },
    optionalDependencies: { "opt-url": "https://collector.example.invalid/LEAKMARK-optional.tgz" },
    peerDependencies: { "peer-dep": "LEAKMARK-peer" },
  };
}

const CLEAN_MANIFEST: RawManifest = { name: NAME, version: CLEAN, description: "A clean version.", license: "MIT", main: "index.js", readme: "# clean" };

/**
 * A clean package whose range takes in every version of NAME, so resolving it walks into the marked versions while
 * they are shown and must stop at them once they are withheld (tree.blocks, tree.uncheckedDeps, tree.reviews).
 */
const DEPENDENT = "sweep-dependent";
const DEPENDENT_MANIFEST: RawManifest = { name: DEPENDENT, version: "1.0.0", description: "Depends on the fixture.", license: "MIT", main: "index.js", dependencies: { [NAME]: `>=${CLEAN}` } };

/** Every path in the marked tarball, for the file routes. */
const FILE_PATHS = ["package.json", ...Object.keys(FILES)];

/**
 * A second package, revoked with the first: its one marked file is over the 32 MB the score reads of a file, so the
 * score lists it as skipped by its path. The skip scores it under the floor, so it is a package of its own: the first
 * one's resolve answers stay as they are. The file compresses to a few KB.
 */
const SKIPPED_PKG = "sweep-skipped";
const SKIPPED_FILES = { "index.js": "module.exports = 1;\n", "lib/LEAKMARK-skipped-file.js": "// filler line\n".repeat(2_400_000) };

// ---------- the stub model: flags anything marked, quotes the marked line, and words its finding with a marker ----------
const FLAG = {
  verdict: "malicious",
  confidence: 0.9,
  summary: 'Line 2 exports "LEAKMARK-js-string" on import.',
  findings: [
    { file: "index.js", line: 2, quote: 'module.exports = "LEAKMARK-js-string";', issue: 'Exports "LEAKMARK-review-issue" on import.', severity: "high" },
    { file: "lib/LEAKMARK-filename.js", line: 1, quote: "module.exports = 2;", issue: "Exports a number.", severity: "low" },
  ],
};

const BENIGN = { verdict: "benign", confidence: 0.8, summary: "Nothing harmful.", findings: [] };

function startStubModel() {
  return Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      const content = JSON.stringify(await req.json());
      const reply = content.includes("LEAKMARK") ? FLAG : BENIGN;

      return Response.json({ choices: [{ message: { content: JSON.stringify(reply) }, finish_reason: "stop" }], usage: { prompt_tokens: 100, completion_tokens: 10 } });
    },
  });
}

// ---------- who asks, and when ----------
/** The maintainer's CLI token, the signed-in owner who staged and approved REVOKED, an admin, and nobody. */
const CALLERS = ["anonymous", "maintainer", "site-owner", "admin"] as const;

type CallerName = (typeof CALLERS)[number];

type Phase = "before" | "after";

/** One request of the sweep: who, how, and whether the revokes have happened. */
type Ask = { caller: CallerName; safe: boolean; phase: Phase };

/**
 * One GET the sweep sends: the route it exercises (from routes.ts), and the status it must get. Every answer must have
 * a body, or a Location when it is a redirect; `emptyBody` names the one probe whose answer has neither, and why.
 */
type Probe = { route: GetRouteName; path: string; status: number | ((a: Ask) => number); headers?: Record<string, string>; emptyBody?: string };

/** A marker found in an answer: where (a JSON path, "text", "tarball" or "header:<name>"), and the answer's route. */
type Hit = { caller: CallerName; url: string; route: GetRouteName; status: number; marker: string; where: string };

/**
 * Where a marker may appear, and why: one route, one status, one field and one marker each. Each must be used at least
 * once, so a stale exception fails the test too. Names and versions carry no marker here: they are the package's
 * identity and appear everywhere by design.
 */
type Allowed = { name: string; reason: string; route: GetRouteName; status: number; where: RegExp; marker: string };

const REASON = "LEAKMARK-revoke-reason";

const ALLOWED: readonly Allowed[] = [
  // the owner's own words when revoking, not the package's text, each in the one field that holds them
  ...(
    [
      ["events", 200, /^events\.\d+\.detail\.reason$/],
      ["recent", 200, /^events\.\d+\.reason$/],
      ["package", 200, /^versions\.\d+\.statusReason$/],
      ["versions", 200, /^statusReason$/],
      // the `revoked` signal's one evidence line is the reason (withheld.ts drops every other evidence line)
      ["score", 200, /^signals\.\d+\.evidence\.0$/],
      ["versions", 200, /^score\.signals\.\d+\.evidence\.0$/],
      ["resolve", 422, /^newest\.report\.signals\.\d+\.evidence\.0$/],
      ["resolve", 422, /^skipped\.\d+\.revokeReason$/],
      ["resolve", 200, /^skipped\.\d+\.revokeReason$/],
      ["tarball", 410, /^revokeReason$/],
      // npm prints a refused download's `error` and nothing else from the body
      ["tarball", 410, /^error$/],
      ["file", 410, /^revokeReason$/],
      ["readme", 410, /^revokeReason$/],
    ] as const
  ).map(
    ([route, status, where]): Allowed => ({
      name: `revoke reason (${route} ${status} ${where.source})`,
      reason: "the owner's words about the revoke, in the field that holds them",
      route,
      status,
      where,
      marker: REASON,
    }),
  ),
  {
    name: "request echo",
    reason: "a 404 that names the file the request asked for repeats the asker's own input, not the package's",
    route: "file",
    status: 404,
    where: /^error$/,
    marker: "LEAKMARK-filename",
  },
  {
    name: "pending tarball",
    reason: "while a revoke is pending, the tarball stays downloadable for existing lockfiles; no other route shows its contents",
    route: "tarball",
    status: 200,
    where: /^tarball$/,
    marker: "*",
  },
];

/** Whether an exception covers a hit; the pending tarball's covers every marker in that one tarball, outside /~safe/. */
function allows(a: Allowed, h: Hit): boolean {
  if (a.route !== h.route || a.status !== h.status || !a.where.test(h.where)) return false;

  if (a.marker !== "*") return h.marker === a.marker;
  const path = new URL(h.url).pathname;

  return path.endsWith(`/${NAME}/-/${NAME}-${PENDING}.tgz`) && !path.includes("/~safe/");
}

// ---------- reading an answer for markers ----------
const looksBase64 = (s: string): boolean => s.length >= 16 && s.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(s);

function markersOf(text: string): string[] {
  return [...text.matchAll(MARK)].map((m) => m[0]);
}

/** Every marker in a JSON value, with the path it sits at; keys count, and base64 strings are read decoded too. */
// oxlint-disable-next-line anti-slop/no-unknown-parameters -- the sweep reads every answer's JSON as data, whatever its shape; no schema could name every route's answer
function walk(v: unknown, at: string, out: { marker: string; where: string }[]): void {
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- the sweep reads every answer's JSON as data, whatever its shape; no schema could name every route's answer
  if (typeof v === "string") {
    for (const marker of markersOf(v)) out.push({ marker, where: at });

    if (looksBase64(v)) for (const marker of markersOf(Buffer.from(v, "base64").toString("latin1"))) out.push({ marker, where: `${at}(base64)` });

    return;
  }

  if (Array.isArray(v)) {
    v.forEach((x, i) => walk(x, at === "" ? String(i) : `${at}.${i}`, out));

    return;
  }

  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- the sweep reads every answer's JSON as data, whatever its shape; no schema could name every route's answer
  if (typeof v === "object" && v !== null) {
    for (const [k, x] of Object.entries(v)) {
      const here = at === "" ? k : `${at}.${k}`;

      for (const marker of markersOf(k)) out.push({ marker, where: `${here}#key` });
      walk(x, here, out);
    }
  }
}

function markersInBody(bytes: Uint8Array<ArrayBuffer>): { marker: string; where: string }[] {
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) return markersOf(Buffer.from(Bun.gunzipSync(bytes)).toString("latin1")).map((marker) => ({ marker, where: "tarball" }));
  const text = Buffer.from(bytes).toString("latin1");
  let parsed: unknown;

  try {
    parsed = JSON.parse(text);
  } catch {
    return markersOf(text).map((marker) => ({ marker, where: "text" }));
  }

  const out: { marker: string; where: string }[] = [];
  walk(parsed, "", out);

  return out;
}

/** Every marker in a response's headers, each where "header:<name>". */
function markersInHeaders(headers: Headers): { marker: string; where: string }[] {
  return [...headers].flatMap(([k, v]) => [...markersOf(k), ...markersOf(v)].map((marker) => ({ marker, where: `header:${k}` })));
}

// ---------- setup ----------
let reg: Registry;
let model: ReturnType<typeof startStubModel>;
let gh: FakeGitHub;
let stateDir: string;
let clock = Date.parse("2026-06-01T10:00:00Z");
let owner: string;
let site: Browser;
let admin: Browser;
let adminSecret: string;

/** The staged upload of REVOKED that the signed-in owner approved: the version it became is revoked below. */
let stagedId: string;

const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");

function reviewer(): WorkerDeps {
  return {
    registry: registryClient({ url: reg.url, token: SERVICE_TOKEN }),
    model: modelClient({ url: `${model.url.toString().replace(/\/$/, "")}/v1`, model: "stub", key: () => "stub-key", concurrency: 2, log: silentLogger, sleep: (ms) => Bun.sleep(Math.min(ms, 50)) }),
    budget: new DailyBudget(stateDir, 10_000_000),
    log: silentLogger,
    secondStage: null,
    budgetTokens: 16_000,
  };
}

function headersFor(caller: CallerName): Headers {
  switch (caller) {
    case "anonymous":
      return new Headers();
    case "maintainer":
      return new Headers({ authorization: `Bearer ${owner}` });
    case "site-owner":
      return new Headers({ cookie: site.cookie(), origin: new URL(reg.url).origin });
    case "admin":
      return new Headers({ cookie: admin.cookie(), origin: new URL(reg.url).origin });
    default: {
      const _exhaustive: never = caller;

      return _exhaustive;
    }
  }
}

const Score = z.object({ digest: z.string(), scorer: z.string(), signals: z.array(z.object({ id: z.string(), evidence: z.array(z.string()) })) });
const Queue = z.object({ pending: z.array(z.object({ name: z.string(), version: z.string(), digest: z.string() })) });

/** Dismisses one evidence line of one version (eval under apm-score-v9, the credential mention since v10), as an admin. */
async function dismissEval(version: string): Promise<void> {
  const s = Score.parse((await getJson(`${reg.url}-/apm/v1/score/${NAME}/${version}`)).body);
  const signal = s.signals.find((x) => x.id === "eval") ?? s.signals.find((x) => x.id === "credential-mention");
  const line = signal?.evidence.find((e) => /^[^:]+:\d+:/.test(e)) ?? "";
  const m = /^([^:]+):(\d+):/.exec(line);

  if (!signal || !m?.[1] || !m[2]) throw new Error(`no dismissable evidence on ${version}: ${JSON.stringify(s)}`);
  const item = { name: NAME, version, digest: s.digest, scorer: s.scorer, signal: signal.id, file: m[1], line: Number(m[2]) };
  const r = await admin.json("-/apm/v1/evidence-admin/dismiss", { method: "POST", body: { ...item, reason: "A fixture line, not a threat.", code: totp(adminSecret) } });

  if (r.status !== 200) throw new Error(`dismiss ${version}: ${r.status} ${JSON.stringify(r.body)}`);
}

/** Fails setup with the answer when a step does not get the status it needs. */
function must(step: string, r: { status: number; body: unknown }, status: number): void {
  if (r.status !== status) throw new Error(`${step}: ${r.status} ${JSON.stringify(r.body)}`);
}

beforeAll(async () => {
  model = startStubModel();
  gh = startFakeGitHub();
  stateDir = mkdtempSync(join(tmpdir(), "apm-sweep-reviewer-"));
  reg = await startRegistry({ now: () => clock, github: gh, review: { serviceTokenHash: sha256(SERVICE_TOKEN), admins: [ADMIN] } });
  owner = await addUser(reg, MAINTAINER, PASSWORD);
  admin = await signInWithGitHub(reg, gh, ADMIN);
  adminSecret = await enableTotp(admin);
  site = await signInWithGitHub(reg, gh, SITE_OWNER);
  const siteSecret = await enableTotp(site);
  const siteToken = (await deviceLogin(site)).token;

  for (const [manifest, files] of [
    [CLEAN_MANIFEST, { "index.js": "module.exports = 0;\n" }],
    [marked(PENDING), FILES],
  ] as const) {
    must(`publish ${manifest.version}`, await putPublish(reg, owner, manifest, { files }), 201);
  }

  // the signed-in owner: added by the maintainer, then stages REVOKED from `apm login`'s token and approves it
  must(
    "owner add",
    await getJson(`${reg.url}-/apm/v1/owners`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${owner}` },
      body: JSON.stringify({ name: NAME, user: SITE_OWNER, password: PASSWORD }),
    }),
    200,
  );

  // four days later, so the first marked version is past 72 hours when both are revoked
  clock += 4 * DAY;
  must(`publish ${SKIPPED_PKG}`, await putPublish(reg, owner, { name: SKIPPED_PKG, version: CLEAN, license: "MIT", main: "index.js" }, { files: SKIPPED_FILES }), 201);
  const staged = await putPublish(reg, siteToken, marked(REVOKED), { files: FILES });
  const id = approvalId(JSON.stringify(staged.body));

  if (!id) throw new Error(`no approval link: ${staged.status} ${JSON.stringify(staged.body)}`);
  stagedId = id;
  must("approve", await site.json(`-/apm/v1/staged/${stagedId}/approve`, { method: "POST", body: { code: totp(siteSecret) } }), 200);
  must(`publish ${DEPENDENT}`, await putPublish(reg, owner, DEPENDENT_MANIFEST, { files: { "index.js": "module.exports = 3;\n" } }), 201);

  // the revoked version's deprecation message is the publisher's text, and lands in the package's log
  must(
    "deprecate",
    await getJson(`${reg.url}${NAME}`, {
      method: "PUT",
      headers: { "content-type": "application/json", authorization: `Bearer ${owner}` },
      body: JSON.stringify({ name: NAME, versions: { [REVOKED]: { deprecated: "LEAKMARK-deprecation" } } }),
    }),
    200,
  );

  for (let n = await runOnce(reviewer(), 4); n > 0; n = await runOnce(reviewer(), 4)) await Bun.sleep(0);
  // the revoked version's flag is confirmed (decided); the pending one's stays in the queue (pending)
  const queue = Queue.parse((await admin.json("-/apm/v1/review-admin/queue")).body);
  const flagged = queue.pending.find((p) => p.name === NAME && p.version === REVOKED);

  if (!flagged) throw new Error(`no pending review for ${REVOKED}: ${JSON.stringify(queue)}`);

  must(
    "decide",
    await admin.json("-/apm/v1/review-admin/decide", {
      method: "POST",
      body: { name: NAME, version: REVOKED, digest: flagged.digest, decision: "confirm", note: "Checked by hand.", code: totp(adminSecret) },
    }),
    200,
  );

  for (const v of [PENDING, REVOKED]) await dismissEval(v);
}, 120_000);

afterAll(async () => {
  agent?.stop();
  await reg?.stop();
  await model?.stop(true);
  await gh?.stop();
  rmSync(stateDir, { recursive: true, force: true });
});

// ---------- the route list ----------
const signedIn = (a: Ask): boolean => a.caller === "site-owner" || a.caller === "admin";

/** 401 to a request without a session cookie, else `status`. */
const sessionOnly = (status: number) => (a: Ask) => (signedIn(a) ? status : 401);

/** Every GET the sweep sends, each naming the route (routes.ts) it exercises and the status it must get. */
function probes(): Probe[] {
  const specs = [...VERSIONS, "latest"];
  const v1 = (rest: string, route: GetRouteName, status: Probe["status"]): Probe => ({ path: `-/apm/v1/${rest}`, route, status });
  // after the revokes; `latest` then points at the clean version, as the revoke moves tags off a withheld one
  const withheld = (v: string): boolean => v === PENDING || v === REVOKED;
  // REVOKED was published an hour ago: inside the 24-hour cooldown, so /~safe/ leaves it out (a plain resolve warns)
  const cooling = (v: string): boolean => v === REVOKED;

  /**
   * What resolve answers: 422 when every version the range allows is refused (withheld, cooling without an override,
   * or, before the revoke, REVOKED, whose flag an apm reviewer confirmed: skipped in every mode).
   */
  const resolveStatus = (range: string, _override: boolean) => (a: Ask) => {
    if (a.phase === "after") return [PENDING, REVOKED, "^1.0.0"].includes(range) ? 422 : 200;

    return range === REVOKED ? 422 : 200;
  };

  // a withheld version's files answer 410; a shown one's 200, and a path it does not have 404
  const fileStatus = (v: string, p: string) => (a: Ask) => (a.phase === "after" && withheld(v) ? 410 : v === CLEAN && p !== "package.json" && p !== "index.js" ? 404 : 200);
  // tags the sweep writes after the revoke (STALE_TAGS), still on the withheld versions: none exists before it
  const staleStatus = (a: Ask) => (a.phase === "after" ? 200 : 404);

  const files = VERSIONS.flatMap((v) =>
    FILE_PATHS.flatMap((p) => [v1(`file/${NAME}/${v}?path=${encodeURIComponent(p)}`, "file", fileStatus(v, p)), v1(`file/${NAME}/${v}?path=${encodeURIComponent(p)}&line=1`, "file", fileStatus(v, p))]),
  );

  // the staged upload: only its uploader or an owner may read it, and only from the website
  const stagedRead = (status: (a: Ask) => number) => (a: Ask) => (a.caller === "site-owner" ? status(a) : a.caller === "admin" ? 403 : 401);

  const staged = [
    v1(`staged/${stagedId}`, "staged detail", stagedRead(() => 200)),
    ...FILE_PATHS.map((p) => v1(`staged/${stagedId}/file?path=${encodeURIComponent(p)}`, "staged file", stagedRead((a) => (a.phase === "after" ? 410 : 200)))),
  ];

  return [
    // the npm protocol (server.ts)
    { path: "", route: "root", status: 200 },
    { path: "-/ping", route: "ping", status: 200 },
    { path: "-/whoami", route: "whoami", status: (a) => (a.caller === "maintainer" ? 200 : 401) },
    { path: `-/user/org.couchdb.user:${MAINTAINER}`, route: "user", status: 200 },
    { path: `-/v1/search?text=${NAME}`, route: "search", status: 200 },
    { path: "-/v1/search?text=LEAKMARK", route: "search", status: 200 },
    { path: `-/package/${NAME}/dist-tags`, route: "dist-tags", status: 200 },
    { path: NAME, route: "packument", status: 200 },
    { path: NAME, route: "packument", status: 200, headers: { accept: "application/vnd.npm.install-v1+json" } },
    // REVOKED's flag is confirmed before the revoke, so its manifest is withheld in both phases (confirmed.ts)
    ...specs.map((s): Probe => ({ path: `${NAME}/${s}`, route: "version", status: (a) => ((a.phase === "after" && withheld(s)) || s === REVOKED || (a.safe && cooling(s)) ? 404 : 200) })),
    // a revoked tarball is 410, and so is a confirmed malicious one, in /~safe/ too; a pending one stays for lockfiles,
    // outside /~safe/, which serves only what passes
    ...VERSIONS.map(
      (v): Probe => ({
        path: `${NAME}/-/${NAME}-${v}.tgz`,
        route: "tarball",
        status: (a) => (v === REVOKED ? 410 : a.safe && (cooling(v) || (a.phase === "after" && withheld(v))) ? 404 : 200),
      }),
    ),
    // apm's API (apm.ts)
    v1(`names?q=${NAME}`, "names", 200),
    ...["exact", "lookalike", "alternatives"].map((part) => v1(`names?q=${NAME}&part=${part}`, "names", 200)),
    v1("recent?limit=50", "recent", 200),
    ...[...specs, "^1.0.0", "*"].flatMap((range) => [
      v1(`resolve?name=${NAME}&range=${encodeURIComponent(range)}`, "resolve", resolveStatus(range, false)),
      v1(`resolve?name=${NAME}&range=${encodeURIComponent(range)}&floor=0&cooldown=0`, "resolve", resolveStatus(range, true)),
    ]),
    // the package whose score skipped a marked file: it scores under the floor, and resolve embeds its report
    v1(`score/${SKIPPED_PKG}/${CLEAN}`, "score", 200),
    v1(`packages/${SKIPPED_PKG}`, "package", 200),
    // inside its cooldown and under the floor: both warn, so it installs until it is revoked (review of 2fbf383,
    // finding 1; before, the cooldown refused it in every mode)
    v1(`resolve?name=${SKIPPED_PKG}&range=${CLEAN}`, "resolve", (a) => (a.phase === "after" ? 422 : 200)),
    v1(`resolve?name=${SKIPPED_PKG}&range=${CLEAN}&floor=0&cooldown=0`, "resolve", (a) => (a.phase === "after" ? 422 : 200)),
    v1("me", "me", (a) => (a.caller === "maintainer" ? 200 : 401)),
    v1(`score/${NAME}`, "score", 200),
    ...specs.map((s) => v1(`score/${NAME}/${s}`, "score", 200)),
    v1(`packages/${NAME}`, "package", 200),
    v1(`packages/${NAME}/events`, "events", 200),
    ...VERSIONS.map((v) => v1(`packages/${NAME}/versions/${v}`, "versions", 200)),
    v1(`popular-scores?names=${NAME},${DEPENDENT}`, "popular-scores", 200),
    v1("recent-packages?limit=50", "recent-packages", 200),
    // the dependency walk and the AI review standings of what it walked (tree.reviews); DEPENDENT is inside its
    // cooldown, which warns (review of 2fbf383, finding 1): its tree decides, as with the cooldown lifted below
    v1(`resolve?name=${DEPENDENT}`, "resolve", (a) => (a.phase === "after" ? 200 : 422)),
    // before the revoke, the dependency's newest version is REVOKED, confirmed malicious: refused in every mode
    v1(`resolve?name=${DEPENDENT}&floor=0&cooldown=0`, "resolve", (a) => (a.phase === "after" ? 200 : 422)),
    // files and readmes (files.ts)
    ...files,
    // the clean version's tarball has no README file
    ...VERSIONS.map((v) => v1(`readme/${NAME}/${v}`, "readme", (a) => (v === CLEAN ? 404 : a.phase === "after" ? 410 : 200))),
    // the AI review (review.ts) and evidence (evidence.ts)
    ...specs.map((v) => v1(`review/${NAME}/${v}`, "review", 200)),
    ...Object.keys(STALE_TAGS).flatMap((t) => [v1(`review/${NAME}/${t}`, "review", staleStatus), v1(`score/${NAME}/${t}`, "score", staleStatus)]),
    v1("review-admin/queue", "review queue", (a) => (a.caller === "admin" ? 200 : a.caller === "anonymous" ? 401 : 403)),
    v1("review-jobs?max=5", "review lease", 401),
    v1("evidence-admin/me", "reviewer", 200),
    // the account (account.ts)
    v1("auth/config", "auth config", 200),
    v1("account", "account", sessionOnly(200)),
    v1("staged", "staged list", sessionOnly(200)),
    v1("staged/no-such-id", "staged detail", sessionOnly(404)),
    v1("staged/no-such-id/file?path=index.js", "staged file", sessionOnly(404)),
    ...staged,
    // Better Auth's GET routes (auth.ts)
    { path: "api/auth/get-session", route: "auth get-session", status: 200 },
    { path: "api/auth/error", route: "auth error", status: 200 },
    { path: "api/auth/ok", route: "auth ok", status: 200 },
    { path: "api/auth/passkey/generate-register-options", route: "auth passkey register options", status: sessionOnly(200) },
    { path: "api/auth/passkey/generate-authenticate-options", route: "auth passkey sign-in options", status: 200 },
    { path: "api/auth/device", route: "auth device", status: 400 },
    { path: "api/auth/callback/github", route: "auth callback", status: 302 },
    {
      path: "api/auth/oauth2/callback/github",
      route: "auth oauth2 callback",
      status: 404,
      emptyBody: "no generic OAuth provider is configured in this registry, and Better Auth answers an unknown one's callback 404 with no body",
    },
  ];
}

// ---------- the sweep ----------
/** A probe that did not get its status, or got an empty body. */
type Wrong = { caller: CallerName; url: string; want: number; got: number; bytes: number };

async function sweep(phase: Phase): Promise<{ hits: Hit[]; wrong: Wrong[] }> {
  const hits: Hit[] = [];
  const wrong: Wrong[] = [];
  const list = probes();

  for (const caller of CALLERS) {
    for (const safe of [false, true]) {
      for (const p of list) {
        // Better Auth's routes take no /~safe/ prefix: the router answers that as a package named "api"
        if (safe && p.route.startsWith("auth ")) continue;
        const url = `${reg.url}${safe ? "~safe/" : ""}${p.path}`;
        const headers = headersFor(caller);

        for (const [k, v] of Object.entries(p.headers ?? {})) headers.set(k, v);
        const res = await fetch(url, { headers, redirect: "manual" });
        const bytes = new Uint8Array(await res.arrayBuffer());
        // oxlint-disable-next-line anti-slop/no-runtime-typeof -- a probe's status is a number or a rule of who asks
        const want = typeof p.status === "number" ? p.status : p.status({ caller, safe, phase });

        // an error page must not pass as a clean answer: the status is the probe's, and there is a body to read
        const redirect = res.status >= 300 && res.status < 400 && res.headers.has("location");

        if (res.status !== want || (bytes.length === 0 && !redirect && p.emptyBody === undefined)) wrong.push({ caller, url, want, got: res.status, bytes: bytes.length });

        for (const { marker, where } of [...markersInBody(bytes), ...markersInHeaders(res.headers)]) hits.push({ caller, url, route: p.route, status: res.status, marker, where });
      }
    }
  }

  return { hits, wrong };
}

const short = (url: string): string => url.slice(reg.url.length - 1);
const show = (hits: readonly Hit[]): string[] => [...new Set(hits.map((h) => `${h.caller} ${h.status} ${short(h.url)} ${h.where}: ${h.marker}`))];
const showWrong = (w: readonly Wrong[]): string[] => w.map((x) => `${x.caller} ${short(x.url)}: wanted ${x.want}, got ${x.got} with ${x.bytes} bytes`);

// ---------- the website's agent views, against this registry ----------
/**
 * One agent answer (apps/web/scripts/agent-views.ts): which view and request, its text and structured data as sent,
 * and the exact phrases in which it repeats the asker's own input, which are not the package's text.
 */
const AgentAnswers = z.array(z.object({ view: z.string(), text: z.string(), echoes: z.array(z.string()) }));

type AgentAnswer = z.infer<typeof AgentAnswers>[number];

const SEARCHES = [NAME, "LEAKMARK", "LEAKMARK-description", "LEAKMARK-keyword"];

const WEB_DIR = join(import.meta.dir, "../../apps/web");

/** What agent-views.ts reads: the package, the versions and file paths to ask about, and the searches to run. */
type AgentViewsInput = { name: string; versions: readonly string[]; paths: readonly string[]; searches: readonly string[] };

/** The website's agent views in a process of their own (apps/web/scripts/agent-views.ts), pointed at this registry. */
type AgentProcess = { ask: (input: AgentViewsInput) => Promise<string>; stop: () => void };

function startAgentViews(registryUrl: string): AgentProcess {
  const child = Bun.spawn(["bun", "--conditions=react-server", "scripts/agent-views.ts"], { cwd: WEB_DIR, env: { ...process.env, APM_REGISTRY: registryUrl }, stdin: "pipe", stdout: "pipe", stderr: "inherit" });
  const reader = child.stdout.getReader();
  const decoder = new TextDecoder();
  let buffered = "";

  const line = async (): Promise<string> => {
    for (;;) {
      const nl = buffered.indexOf("\n");

      if (nl >= 0) {
        const out = buffered.slice(0, nl);
        buffered = buffered.slice(nl + 1);

        return out;
      }

      const { done, value } = await reader.read();

      if (done) throw new Error(`agent-views exited ${await child.exited} before answering`);
      buffered += decoder.decode(value, { stream: true });
    }
  };

  return {
    ask: async (input) => {
      void child.stdin.write(`${JSON.stringify(input)}\n`);
      void child.stdin.flush();

      return line();
    },
    stop: () => child.kill(),
  };
}

let agent: AgentProcess | null = null;

/**
 * Every agent view of the marked package, read the way the website reads it: the registry's answer now, except where
 * the site may keep one (search), from the same process before and after the revoke, so a kept answer would show.
 */
async function agentViews(): Promise<AgentAnswer[]> {
  agent ??= startAgentViews(reg.url);

  return AgentAnswers.parse(JSON.parse(await agent.ask({ name: NAME, versions: [...VERSIONS], paths: FILE_PATHS, searches: SEARCHES })));
}

/** Each marker an agent answer carries, with the view it came from. */
const agentMarkers = (answers: readonly AgentAnswer[]): { view: string; marker: string }[] =>
  answers.flatMap((a) => markersOf(a.echoes.reduce((t, e) => t.replaceAll(e, ""), a.text)).map((marker) => ({ view: a.view, marker })));

describe("a revoked or revoke-pending version's text", () => {
  test("is shown on the routes the sweep asks before the revoke, so the sweep would see a leak", async () => {
    const { hits, wrong } = await sweep("before");

    expect(showWrong(wrong)).toEqual([]);
    expect(show(hits.filter((h) => h.where.startsWith("header:")))).toEqual([]);
    const seen = new Set(hits.filter((h) => h.where !== "tarball").map((h) => h.marker));

    // the version answer shows the deprecation message while the version is active, so the sweep would see it kept
    expect(hits.some((h) => h.route === "versions" && h.where === "deprecated" && h.marker === "LEAKMARK-deprecation")).toBe(true);

    // the dependent's walk reaches a marked version while it is shown, so the sweep would see it keep doing so
    expect(hits.some((h) => h.url.includes(`resolve?name=${DEPENDENT}`) && h.where.startsWith("tree."))).toBe(true);

    // each kind of place a publisher writes reaches some answer while the version is active
    for (const m of [
      "LEAKMARK-readme",
      "LEAKMARK-readme-file",
      "LEAKMARK-description",
      "LEAKMARK-keyword",
      "LEAKMARK-license",
      "LEAKMARK-author",
      "LEAKMARK-homepage",
      "LEAKMARK-repository",
      "LEAKMARK-script-shell",
      "LEAKMARK-script-colon",
      "LEAKMARK-script-leaf",
      "LEAKMARK-dep-url",
      "LEAKMARK-dep-git",
      "LEAKMARK-dep-key",
      "LEAKMARK-optional",
      "LEAKMARK-peer",
      "LEAKMARK-bin-name",
      "LEAKMARK-export-key",
      "LEAKMARK-js-string",
      "LEAKMARK-js-eval",
      "LEAKMARK-dts",
      "LEAKMARK-json",
      "LEAKMARK-bin-file",
      "LEAKMARK-filename",
      "LEAKMARK-skipped-file",
      "LEAKMARK-review-issue",
      "LEAKMARK-deprecation",
    ]) {
      expect(seen.has(m), m).toBe(true);
    }

    // the approved upload's own routes show its files to the owner before the revoke
    expect(hits.some((h) => h.route === "staged file" && h.caller === "site-owner" && h.marker === "LEAKMARK-js-string")).toBe(true);
    expect(hits.some((h) => h.route === "staged detail" && h.caller === "site-owner" && h.marker === "LEAKMARK-description")).toBe(true);
  }, 120_000);

  test("is shown by the website's agent views before the revoke, so the check after it would see a leak", async () => {
    const seen = agentMarkers(await agentViews());
    const by = (view: string) => new Set(seen.filter((m) => m.view.startsWith(view)).map((m) => m.marker));

    // the Markdown view and check_package quote the description, the deprecation, the AI finding and the cited code
    for (const view of ["markdown 1.1.0", 'check_package {"name":"sweep-fixture","version":"1.1.0"}']) {
      for (const m of ["LEAKMARK-description", "LEAKMARK-deprecation", "LEAKMARK-review-issue", "LEAKMARK-js-string", "LEAKMARK-license"]) expect(by(view).has(m), `${view}: ${m}`).toBe(true);
    }

    expect(by("search_packages").has("LEAKMARK-description")).toBe(true);
    expect(by("get_file_excerpt").has("LEAKMARK-js-string")).toBe(true);
    expect(by("get_file_excerpt").has("LEAKMARK-dts")).toBe(true);
  }, 120_000);

  test("is shown on no GET route after the revoke, to anyone, except where ALLOWED says why", async () => {
    for (const [name, version, status] of [
      [NAME, PENDING, "revoke-pending"],
      [NAME, REVOKED, "revoked"],
      [SKIPPED_PKG, CLEAN, "revoked"],
    ] as const) {
      const r = await getJson(`${reg.url}-/apm/v1/revoke`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${owner}` },
        body: JSON.stringify({ name, version, reason: `posts the environment (${REASON})`, password: PASSWORD }),
      });

      expect(dig(r.body, "status"), JSON.stringify(r.body)).toBe(status);
    }

    await reg.query("UPDATE packages SET dist_tags = dist_tags || $1::jsonb WHERE name = $2", [JSON.stringify(STALE_TAGS), NAME]);
    clock += HOUR;
    const { hits, wrong } = await sweep("after");
    const leaks = hits.filter((h) => !ALLOWED.some((a) => allows(a, h)));
    const unused = ALLOWED.flatMap((a) => (hits.some((h) => allows(a, h)) ? [] : [a.name]));

    expect({ wrong: showWrong(wrong), leaks: show(leaks), unused }).toEqual({ wrong: [], leaks: [], unused: [] });
  }, 120_000);

  test("is shown by none of the website's agent views after the revoke, except the owner's revoke reason", async () => {
    const answers = await agentViews();
    const leaks = agentMarkers(answers).filter((m) => m.marker !== REASON);
    const md = answers.find((a) => a.view.startsWith(`markdown ${REVOKED} `));
    const checked = answers.find((a) => a.view === `check_package ${JSON.stringify({ name: NAME, version: REVOKED })}`);
    const excerpt = answers.find((a) => a.view === `get_file_excerpt ${JSON.stringify({ name: NAME, version: REVOKED, path: "index.js", line: 1 })}`);

    expect([...new Set(leaks.map((m) => `${m.view}: ${m.marker}`))]).toEqual([]);
    // the views answered, and the review is the registry's withheld one: its sentence and a file reference
    expect(md?.view).toBe(`markdown ${REVOKED} (200)`);
    expect(md?.text).toContain(`: \`${WITHHELD_ISSUE}\``);
    expect(md?.text).toMatch(/Finding 1 \(high\) at `file \d+:2`/);
    expect(checked?.text).toContain(`"issue":"${WITHHELD_ISSUE}"`);
    expect(checked?.text).toContain('"deprecated":null');
    expect(excerpt?.text).toContain(`${NAME}@\`${REVOKED}\` is revoked: apm shows none of its files.`);
  }, 120_000);
});

describe("the GET table (routes.ts)", () => {
  test("every GET route is swept, and every probe's path is the route it names", () => {
    const list = probes();
    const swept = new Set(list.map((p) => p.route));

    expect(GET_ROUTES.map((r) => r.name).filter((n) => !swept.has(n))).toEqual([]);
    // a probe named for one route but answered by another would leave its route unswept
    expect(list.filter((p) => getRouteOf(new URL(`/${p.path}`, "http://x").pathname) !== p.route).map((p) => `${p.route}: ${p.path}`)).toEqual([]);
  });

  test("a GET or HEAD of a path no entry lists is refused by the router, before any route module answers it", async () => {
    // POST-only routes a module matches by path: a GET added to one of them answers nothing until it is in the table
    const notGet = [
      "-/apm/v1/scan",
      "-/apm/v1/revoke",
      "-/apm/v1/owners",
      "-/apm/v1/login/device",
      "-/apm/v1/verify",
      "-/apm/v1/evidence-admin/dismiss",
      "-/apm/v1/review-admin/decide",
      "-/apm/v1/review-jobs/abc/result",
      `-/apm/v1/staged/${stagedId}/approve`,
      `-/apm/v1/review/${NAME}/${REVOKED}/request`,
      "-/npm/v1/security/advisories/bulk",
      "-/user/token/abc",
      `${NAME}/-rev/1-abc`,
      "api/auth/sign-in/social",
      "api/auth/two-factor/verify-totp",
      "-/apm/v1/no-such-route",
    ];

    for (const caller of CALLERS) {
      for (const method of ["GET", "HEAD"] as const) {
        for (const p of notGet) {
          const res = await fetch(`${reg.url}${p}`, { method, headers: headersFor(caller), redirect: "manual" });
          const body = method === "GET" ? await res.text() : "";

          expect(`${method} ${p} ${res.status}`).toBe(`${method} ${p} 404`);

          if (method === "GET") expect(body, `${caller} GET ${p}`).toContain(NO_GET_ROUTE);
        }
      }
    }
  });
});

// Each finding of the review, checked by what the answer still says, after the revoke above.
describe("after the revoke, each answer keeps what was found", () => {
  const QueueItem = z.object({
    name: z.string(),
    version: z.string(),
    redacted: z.boolean(),
    private: z.object({ summary: z.string(), findings: z.array(z.object({ file: z.string(), line: z.number(), issue: z.string(), severity: z.string(), quote: z.string(), excerpt: z.string() })) }),
  });

  const AdminQueue = z.object({ pending: z.array(QueueItem), decided: z.array(QueueItem) });

  test("resolve: a withheld version's report is the score answer's allowlist, and no cache keeps it", async () => {
    for (const prefix of ["", "~safe/"]) {
      for (const version of [PENDING, REVOKED]) {
        const res = await fetch(`${reg.url}${prefix}-/apm/v1/resolve?name=${NAME}&range=${version}`);
        const body: unknown = await res.json();

        expect(res.status).toBe(422);
        expect(res.headers.get("cache-control")).toBe("private, no-store");
        expect(dig(body, "newest", "report", "redacted")).toBe(true);
        // the rules that fired, with no evidence line
        const signals = dig(body, "newest", "report", "signals");

        const list = z.array(z.object({ id: z.string(), evidence: z.array(z.string()) })).parse(signals);

        expect(list.some((s) => s.id === "install-script")).toBe(true);
        // only the revoke's own reason is left as evidence
        expect(list.filter((s) => s.id !== "revoked").flatMap((s) => s.evidence)).toEqual([]);
      }
    }
  });

  test("a dist-tag still on a withheld version: the review and score asked by the tag answer for it, redacted", async () => {
    // the row still points the stale tags at the withheld versions, so the tag routes below resolve to them
    expect(await reg.query("SELECT dist_tags->>'stale-revoked' AS r, dist_tags->>'stale-pending' AS p FROM packages WHERE name = $1", [NAME])).toEqual([{ r: REVOKED, p: PENDING }]);

    for (const caller of ["anonymous", "maintainer", "admin"] as const) {
      for (const [tag, version] of Object.entries(STALE_TAGS)) {
        for (const route of ["review", "score"]) {
          const res = await fetch(`${reg.url}-/apm/v1/${route}/${NAME}/${tag}`, { headers: headersFor(caller) });
          const body: unknown = await res.json();

          expect(res.status, `${caller} ${route} ${tag}`).toBe(200);
          expect(dig(body, "version"), `${caller} ${route} ${tag}`).toBe(version);
          expect(dig(body, "redacted"), `${caller} ${route} ${tag}`).toBe(true);
        }
      }
    }
  });

  test("the admin queue: decided and pending items of withheld versions keep a file reference, line and severity, not the source", async () => {
    const queue = AdminQueue.parse((await admin.json("-/apm/v1/review-admin/queue")).body);
    const items = [...queue.pending, ...queue.decided].filter((i) => i.name === NAME);

    expect(items.map((i) => i.version).toSorted()).toEqual([PENDING, REVOKED]);

    for (const i of items) {
      expect(i.redacted).toBe(true);
      expect(i.private.summary).toBe("");
      // the model's sentence can quote the package, so it is fixed wording; each path is a numbered reference
      expect(i.private.findings.map((f) => ({ ...f, file: /^file \d+$/.test(f.file) ? "file <n>" : f.file }))).toEqual([
        { file: "file <n>", line: 2, issue: WITHHELD_ISSUE, severity: "high", quote: "", excerpt: "" },
        { file: "file <n>", line: 1, issue: WITHHELD_ISSUE, severity: "low", quote: "", excerpt: "" },
      ]);
      // two paths, two references
      expect(new Set(i.private.findings.map((f) => f.file)).size).toBe(2);
    }
  });

  test("the score: a withheld version's not-checked list names each dependency and why, not its spec", async () => {
    for (const version of [PENDING, REVOKED]) {
      const s = await getJson(`${reg.url}-/apm/v1/score/${NAME}/${version}`);

      expect(dig(s.body, "facts", "license")).toBeNull();
      const notChecked = z.array(z.string()).parse(dig(s.body, "notChecked"));

      expect(notChecked).toContain("dependency dep-url: tarball URL: installs code from outside any registry");
      expect(notChecked).toContain("dependency dep-git: git dependency: installs code from a repository, outside any registry");
      expect(notChecked).toContain("dependency dep-tag: apm could not check it at publish");
      expect(notChecked).toContain("dependency opt-url: tarball URL: installs code from outside any registry");
    }

    // a shown version keeps its list as stored
    const clean = await getJson(`${reg.url}-/apm/v1/score/${NAME}/${CLEAN}`);

    expect(dig(clean.body, "facts", "license")).toBe("MIT");
  });

  test("the score and resolve: a withheld version's skipped files keep their size and reason, each by a file reference", async () => {
    const size = SKIPPED_FILES["lib/LEAKMARK-skipped-file.js"].length;
    const want = [{ path: "file 1", size, reason: "too-large" }];
    const score = await getJson(`${reg.url}-/apm/v1/score/${SKIPPED_PKG}/${CLEAN}`);
    const resolve = await getJson(`${reg.url}-/apm/v1/resolve?name=${SKIPPED_PKG}&range=${CLEAN}`);

    expect(dig(score.body, "skipped")).toEqual(want);
    expect(dig(resolve.body, "newest", "report", "skipped")).toEqual(want);
  });

  test("the version answer: a withheld version's license and not-checked list are the score answer's, its deprecation is null, and no cache keeps it", async () => {
    for (const version of [PENDING, REVOKED]) {
      const res = await fetch(`${reg.url}-/apm/v1/packages/${NAME}/versions/${version}`);
      const body: unknown = await res.json();
      const score = await getJson(`${reg.url}-/apm/v1/score/${NAME}/${version}`);

      expect(res.status).toBe(200);
      expect(res.headers.get("cache-control")).toBe("private, no-store");
      expect(dig(body, "score", "redacted")).toBe(true);
      expect(dig(body, "facts")).toEqual(dig(score.body, "facts"));
      expect(dig(body, "facts", "license")).toBeNull();
      // the publisher's deprecation message is withheld with the version, as in the package answer's version list
      expect(dig(body, "deprecated")).toBeNull();
      expect(dig(body, "score", "notChecked")).toEqual(dig(score.body, "notChecked"));
      expect(dig(body, "score", "notChecked")).toContain("dependency dep-url: tarball URL: installs code from outside any registry");
    }

    const clean = await getJson(`${reg.url}-/apm/v1/packages/${NAME}/versions/${CLEAN}`);

    expect(dig(clean.body, "score", "redacted")).toBe(false);
    expect(dig(clean.body, "facts", "license")).toBe("MIT");
  });

  test("resolve walks a dependent into the clean version only, and its review standings name no withheld version", async () => {
    const res = await getJson(`${reg.url}-/apm/v1/resolve?name=${DEPENDENT}&floor=0&cooldown=0`);
    const walked = z.array(z.object({ name: z.string(), version: z.string() })).parse(dig(res.body, "tree", "packages"));

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(walked).toEqual([{ name: NAME, version: CLEAN }]);
    const reviews = z.record(z.string(), z.unknown()).parse(dig(res.body, "tree", "reviews"));

    expect(reviews.kind).toBe("on");
    expect(JSON.stringify(reviews)).not.toContain(PENDING);
    expect(JSON.stringify(reviews)).not.toContain(REVOKED);
  });

  test("a revoke-pending version's manifest is refused like a revoked one's; its tarball stays for lockfiles", async () => {
    expect((await fetch(`${reg.url}${NAME}/${PENDING}`)).status).toBe(404);
    expect((await fetch(`${reg.url}${NAME}/${REVOKED}`)).status).toBe(404);
    expect((await fetch(`${reg.url}${NAME}/${CLEAN}`)).status).toBe(200);
    expect((await fetch(`${reg.url}${NAME}/-/${NAME}-${PENDING}.tgz`)).status).toBe(200);
    expect((await fetch(`${reg.url}${NAME}/-/${NAME}-${REVOKED}.tgz`)).status).toBe(410);
  });

  test("the package's description and keywords are the newest shown version's, in the packument, search and package answer", async () => {
    const packument = await getJson(`${reg.url}${NAME}`);

    expect(dig(packument.body, "description")).toBe("A clean version.");
    expect(dig(packument.body, "keywords")).toEqual([]);
    expect(dig((await getJson(`${reg.url}-/apm/v1/packages/${NAME}`)).body, "description")).toBe("A clean version.");
    expect(dig((await getJson(`${reg.url}-/v1/search?text=${NAME}`)).body, "objects", 0, "package", "description")).toBe("A clean version.");
    // and search no longer finds it by the withheld text
    expect(dig((await getJson(`${reg.url}-/v1/search?text=LEAKMARK-description`)).body, "total")).toBe(0);
  });
});
