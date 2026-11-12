// Spec: a revoked or revoke-pending version's text is shown nowhere. One package carries a unique marker in every
// free-text place a publisher controls (readme, manifest fields, every kind of script, dependency specs, bin and
// exports, file contents, file names). It is scored, reviewed by a stub model whose findings quote marker lines,
// and has evidence dismissed. Then one version is revoked and another goes revoke-pending, and every GET route the
// registry serves is asked, as an anonymous visitor, the maintainer and an admin, plain and under /~safe/. No marker
// may come back except where ALLOWED says why.
//
// The router is a chain of hand-written matchers (router.ts), so the route list cannot be read off it. Instead the
// last test scans the route modules for every path literal a matcher compares against and fails when one is neither
// swept here nor named as a non-GET route, so a new route cannot be forgotten.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { DailyBudget } from "../../apps/reviewer/src/budget.ts";
import { silentLogger } from "../../apps/reviewer/src/log.ts";
import { modelClient } from "../../apps/reviewer/src/model.ts";
import { registryClient } from "../../apps/reviewer/src/registry.ts";
import { runOnce, type WorkerDeps } from "../../apps/reviewer/src/worker.ts";
import {
  addUser,
  dig,
  enableTotp,
  getJson,
  putPublish,
  ROOT,
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
const INDEX_JS = ['// LEAKMARK-js-comment', 'module.exports = "LEAKMARK-js-string";', 'eval("LEAKMARK-js-eval");', ""].join("\n");

/** Binary-ish: NUL bytes around a marker, so a text check that stops at NUL would miss it. */
const BLOB = new Uint8Array([0, 1, 2, 0, ...new TextEncoder().encode("LEAKMARK-binary"), 0, 255, 0]);

const FILES = {
  "index.js": INDEX_JS,
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
    },
    optionalDependencies: { "opt-url": "https://collector.example.invalid/LEAKMARK-optional.tgz" },
    peerDependencies: { "peer-dep": "LEAKMARK-peer" },
  };
}

const CLEAN_MANIFEST: RawManifest = { name: NAME, version: CLEAN, description: "A clean version.", license: "MIT", main: "index.js", readme: "# clean" };

/** Every path in the marked tarball, for the file routes. */
const FILE_PATHS = ["package.json", ...Object.keys(FILES)];

// ---------- the stub model: flags anything marked and quotes the marked line ----------
const FLAG = {
  verdict: "malicious",
  confidence: 0.9,
  summary: 'Line 2 exports "LEAKMARK-js-string" on import.',
  findings: [{ file: "index.js", line: 2, quote: 'module.exports = "LEAKMARK-js-string";', issue: "Exports a fixed string on import.", severity: "high" }],
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

// ---------- who asks ----------
type CallerName = "anonymous" | "maintainer" | "admin";

/** One GET the sweep sends. `keys` are the route literals (see SOURCE_KEYS) it exercises. */
type Probe = { path: string; keys: readonly string[]; headers?: Record<string, string> };

/** A marker found in an answer, and where: a JSON path, "text" or "tarball". */
type Hit = { caller: CallerName; url: string; status: number; marker: string; where: string };

/**
 * Where a marker may appear, and why. Each must be used at least once, so a stale exception fails the test too.
 * Names and versions carry no marker here: they are the package's identity and appear everywhere by design.
 */
const ALLOWED: readonly { name: string; reason: string; allows: (h: Hit) => boolean }[] = [
  {
    name: "revoke reason",
    reason: "the owner's own words when revoking, not the package's text; the audit log, version list and 410 answers quote it",
    allows: (h) => h.marker === "LEAKMARK-revoke-reason",
  },
  {
    name: "file paths",
    reason: "withheld.ts keeps paths so a finding or a skipped file can still say where it is; a path is never file content",
    allows: (h) => h.marker === "LEAKMARK-filename" && /(^|\.)(file|path)$|(^|\.)read\.\d+$/.test(h.where),
  },
  {
    name: "request echo",
    reason: "an error that names the file the request asked for repeats the asker's own input, not the package's",
    allows: (h) => h.where === "error" && decodeURIComponent(h.url).includes(h.marker),
  },
  {
    name: "pending tarball",
    reason: "while a revoke is pending, the tarball stays downloadable for existing lockfiles; no other route shows its contents",
    allows: (h) => h.where === "tarball" && new URL(h.url).pathname.endsWith(`/${NAME}/-/${NAME}-${PENDING}.tgz`) && !new URL(h.url).pathname.includes("/~safe/"),
  },
];

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

// ---------- setup ----------
let reg: Registry;
let model: ReturnType<typeof startStubModel>;
let gh: FakeGitHub;
let stateDir: string;
let clock = Date.parse("2026-06-01T10:00:00Z");
let owner: string;
let admin: Browser;
let adminSecret: string;

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

/** Dismisses the eval evidence of one version, as an admin on the website. */
async function dismissEval(version: string): Promise<void> {
  const s = Score.parse((await getJson(`${reg.url}-/apm/v1/score/${NAME}/${version}`)).body);
  const line = s.signals.find((x) => x.id === "eval")?.evidence[0] ?? "";
  const m = /^([^:]+):(\d+):/.exec(line);

  if (!m?.[1] || !m[2]) throw new Error(`no eval evidence on ${version}: ${JSON.stringify(s)}`);
  const item = { name: NAME, version, digest: s.digest, scorer: s.scorer, signal: "eval", file: m[1], line: Number(m[2]) };
  const r = await admin.json("-/apm/v1/evidence-admin/dismiss", { method: "POST", body: { ...item, reason: "A fixture line, not a threat.", code: totp(adminSecret) } });

  if (r.status !== 200) throw new Error(`dismiss ${version}: ${r.status} ${JSON.stringify(r.body)}`);
}

beforeAll(async () => {
  model = startStubModel();
  gh = startFakeGitHub();
  stateDir = mkdtempSync(join(tmpdir(), "apm-sweep-reviewer-"));
  reg = await startRegistry({ now: () => clock, github: gh, review: { serviceTokenHash: sha256(SERVICE_TOKEN), admins: [ADMIN] } });
  owner = await addUser(reg, MAINTAINER, PASSWORD);
  admin = await signInWithGitHub(reg, gh, ADMIN);
  adminSecret = await enableTotp(admin);

  for (const [manifest, files] of [
    [CLEAN_MANIFEST, { "index.js": "module.exports = 0;\n" }],
    [marked(PENDING), FILES],
  ] as const) {
    const r = await putPublish(reg, owner, manifest, { files });

    if (r.status !== 201) throw new Error(`publish ${manifest.version}: ${r.status} ${JSON.stringify(r.body)}`);
  }

  // four days later, so the first marked version is past 72 hours when both are revoked
  clock += 4 * DAY;
  const r = await putPublish(reg, owner, marked(REVOKED), { files: FILES });

  if (r.status !== 201) throw new Error(`publish ${REVOKED}: ${r.status} ${JSON.stringify(r.body)}`);

  for (let n = await runOnce(reviewer(), 4); n > 0; n = await runOnce(reviewer(), 4)) await Bun.sleep(0);
  // the revoked version's flag is confirmed (decided); the pending one's stays in the queue (pending)
  const queue = Queue.parse((await admin.json("-/apm/v1/review-admin/queue")).body);
  const flagged = queue.pending.find((p) => p.name === NAME && p.version === REVOKED);

  if (!flagged) throw new Error(`no pending review for ${REVOKED}: ${JSON.stringify(queue)}`);

  const decide = await admin.json("-/apm/v1/review-admin/decide", {
    method: "POST",
    body: { name: NAME, version: REVOKED, digest: flagged.digest, decision: "confirm", note: "Checked by hand.", code: totp(adminSecret) },
  });

  if (decide.status !== 200) throw new Error(`decide: ${decide.status} ${JSON.stringify(decide.body)}`);

  for (const v of [PENDING, REVOKED]) await dismissEval(v);
}, 120_000);

afterAll(async () => {
  await reg?.stop();
  await model?.stop(true);
  await gh?.stop();
  rmSync(stateDir, { recursive: true, force: true });
});

// ---------- the route list ----------
/** Every GET the sweep sends, each naming the route literals it exercises. */
function probes(): Probe[] {
  const specs = [...VERSIONS, "latest", ...Object.keys(STALE_TAGS)];
  const v1 = (rest: string, keys: readonly string[]): Probe => ({ path: `-/apm/v1/${rest}`, keys });

  const files = VERSIONS.flatMap((v) =>
    FILE_PATHS.flatMap((p) => [v1(`file/${NAME}/${v}?path=${encodeURIComponent(p)}`, ["files.ts: \"/-/apm/v1/file/\""]), v1(`file/${NAME}/${v}?path=${encodeURIComponent(p)}&line=1`, ["files.ts: \"/-/apm/v1/file/\""])]),
  );

  return [
    // the npm protocol (server.ts)
    { path: "", keys: [] },
    { path: "-/ping", keys: ['server.ts: "/-/ping"'] },
    { path: "-/whoami", keys: ['server.ts: "/-/whoami"'] },
    { path: `-/user/org.couchdb.user:${MAINTAINER}`, keys: ['server.ts: "/-/user/org.couchdb.user:"', 'server.ts: "/-/user/"'] },
    { path: `-/v1/search?text=${NAME}`, keys: ['server.ts: "/-/v1/search"', 'apm.ts: "/-/v1/search"'] },
    { path: "-/v1/search?text=LEAKMARK", keys: ['server.ts: "/-/v1/search"'] },
    { path: `-/package/${NAME}/dist-tags`, keys: ['server.ts: "/-/package/"', 'server.ts: "/-/package"'] },
    { path: NAME, keys: [] },
    { path: NAME, keys: [], headers: { accept: "application/vnd.npm.install-v1+json" } },
    ...specs.map((s): Probe => ({ path: `${NAME}/${s}`, keys: [] })),
    ...VERSIONS.map((v): Probe => ({ path: `${NAME}/-/${NAME}-${v}.tgz`, keys: ['server.ts: rest[0] === "-"', 'apm.ts: sp.rest[0] === "-"'] })),
    // apm's API (apm.ts)
    v1(`names?q=${NAME}`, ['apm.ts: rest === "names"']),
    ...["exact", "lookalike", "alternatives"].map((part) => v1(`names?q=${NAME}&part=${part}`, ['apm.ts: rest === "names"'])),
    v1("recent?limit=50", ['apm.ts: rest === "recent"']),
    ...[...specs, "^1.0.0", "*"].flatMap((range) => [
      v1(`resolve?name=${NAME}&range=${encodeURIComponent(range)}`, ['apm.ts: rest === "resolve"']),
      v1(`resolve?name=${NAME}&range=${encodeURIComponent(range)}&floor=0&cooldown=0`, ['apm.ts: rest === "resolve"']),
    ]),
    v1("me", ['apm.ts: rest === "me"']),
    v1(`score/${NAME}`, ['apm.ts: rest.startsWith("score/")']),
    ...specs.map((s) => v1(`score/${NAME}/${s}`, ['apm.ts: rest.startsWith("score/")'])),
    v1(`packages/${NAME}`, ['apm.ts: rest.startsWith("packages/")']),
    v1(`packages/${NAME}/events`, ['apm.ts: rest.startsWith("packages/")', 'apm.ts: sp.rest[0] === "events"']),
    // files and readmes (files.ts)
    ...files,
    ...VERSIONS.map((v) => v1(`readme/${NAME}/${v}`, ['files.ts: "/-/apm/v1/readme/"'])),
    // the AI review (review.ts) and evidence (evidence.ts)
    ...specs.map((s) => v1(`review/${NAME}/${s}`, ['review.ts: "/-/apm/v1/review/"', 'review.ts: "/-/apm/v1/review"'])),
    v1("review-admin/queue", ['review.ts: "/-/apm/v1/review-admin/queue"']),
    v1("review-jobs?max=5", ['review.ts: "/-/apm/v1/review-jobs"']),
    v1("evidence-admin/me", ['evidence.ts: "/-/apm/v1/evidence-admin/me"']),
    // the account (account.ts)
    v1("auth/config", ['account.ts: rest === "auth/config"']),
    v1("account", ['account.ts: rest === "account"']),
    v1("staged", ['account.ts: rest === "staged"']),
    v1("staged/no-such-id", ["account.ts: /^staged\\/([A-Za-z0-9_-]+)(?:\\/(approve|reject|file))?$/"]),
    v1("staged/no-such-id/file?path=index.js", ["account.ts: /^staged\\/([A-Za-z0-9_-]+)(?:\\/(approve|reject|file))?$/"]),
    // Better Auth's GET routes (auth.ts)
    ...["get-session", "error", "ok", "passkey/generate-register-options", "passkey/generate-authenticate-options", "device"].map(
      (r): Probe => ({ path: `api/auth/${r}`, keys: [`auth.ts: ${r} [GET]`] }),
    ),
    { path: "api/auth/callback/github", keys: ["auth.ts: callback/"] },
    { path: "api/auth/oauth2/callback/github", keys: ["auth.ts: oauth2/callback/"] },
  ];
}

/** The route literals that are not GET routes, or only dispatch to others, and why the sweep does not send them. */
const NOT_SWEPT = {
  'apm.ts: "/-/"': "prefix: everything under it is one of the routes here",
  'apm.ts: "/-/apm/v1/"': "prefix",
  'account.ts: "/-/apm/v1/"': "prefix",
  'router.ts: "/-/apm/v1/"': "prefix",
  'server.ts: "/-/"': "prefix: unknown /-/ paths answer 404",
  'evidence.ts: "/-/apm/v1/evidence-admin/"': "prefix",
  'review.ts: "/-/apm/v1/review-admin/"': "prefix",
  'review.ts: "/-/apm/v1/review-jobs/"': "prefix of the POST result and release routes",
  'apm.ts: "/-/npm/v1/security/advisories/bulk"': "POST only",
  'apm.ts: rest === "yank"': "POST only",
  'apm.ts: rest === "unyank"': "POST only",
  'apm.ts: rest === "revoke"': "POST only",
  'apm.ts: rest === "restore"': "POST only",
  'apm.ts: rest === "incident"': "POST only",
  'apm.ts: rest === "owners"': "POST and DELETE only",
  'apm.ts: rest === "scan"': "POST only",
  'apm.ts: rest === "audit"': "POST only",
  'account.ts: rest === "account/tokens/revoke"': "POST only",
  'account.ts: rest === "factor/confirm"': "POST only",
  'account.ts: rest === "factor/passkey-challenge"': "POST only",
  'account.ts: rest === "login/device"': "POST only",
  'account.ts: rest === "login/device/token"': "POST only",
  'account.ts: rest === "verify"': "POST only",
  'server.ts: "/-/user/token/"': "DELETE only",
  'server.ts: rest[0] === "-rev"': "PUT only",
  'evidence.ts: "/-/apm/v1/evidence-admin/dismiss"': "POST only",
  'evidence.ts: "/-/apm/v1/evidence-admin/restore"': "POST only",
  'review.ts: "/-/apm/v1/review-admin/decide"': "POST only",
  "review.ts: /^\\/-\\/apm\\/v1\\/review-jobs\\/([A-Za-z0-9_-]{1,64})\\/(result|release)$/": "POST only",
  'review.ts: sp.rest[1] === "request"': "POST only",
  "auth.ts: sign-in/social [POST]": "POST only",
  "auth.ts: sign-out [POST]": "POST only",
  "auth.ts: link-social [POST]": "POST only",
  "auth.ts: two-factor/enable [POST]": "POST only",
  "auth.ts: two-factor/disable [POST]": "POST only",
  "auth.ts: passkey/verify-registration [POST]": "POST only",
  "auth.ts: passkey/verify-authentication [POST]": "POST only",
  "auth.ts: device/approve [POST]": "POST only",
  "auth.ts: device/deny [POST]": "POST only",
} satisfies Readonly<Record<string, string>>;

/** The modules router.ts dispatches to, which the scan reads; anything else it imports must be a helper named here. */
const ROUTE_MODULES = ["account.ts", "apm.ts", "auth.ts", "evidence.ts", "files.ts", "review.ts", "server.ts", "router.ts"];
const ROUTER_HELPERS = ["clock.ts", "http.ts"];

/** Every literal a route matcher compares a path against, as "<file>: <literal>". */
function sourceKeys(): Set<string> {
  const keys = new Set<string>();
  const src = (f: string): string => readFileSync(join(ROOT, "packages", "registry", "src", f), "utf8");

  for (const f of ROUTE_MODULES) {
    const text = src(f);

    for (const m of text.matchAll(/"\/-\/[^"]*"/g)) keys.add(`${f}: ${m[0]}`);

    for (const m of text.matchAll(/\b(?:sp\.)?rest(?:\[\d\])? === "[^"]+"/g)) keys.add(`${f}: ${m[0]}`);

    for (const m of text.matchAll(/\brest\.startsWith\("[^"]+"\)/g)) keys.add(`${f}: ${m[0]}`);

    for (const m of text.matchAll(/(\/\^[^\n]*?\$\/)\.exec\((?:rest|p)\)/g)) keys.add(`${f}: ${m[1]}`);
  }

  const auth = src("auth.ts");

  for (const m of auth.matchAll(/\["([^"]+)",\s*\{\s*methods:\s*\[([^\]]*)\]/g)) keys.add(`auth.ts: ${m[1]} [${(m[2] ?? "").replace(/"/g, "").replace(/\s/g, "")}]`);
  const callbacks = /const CALLBACK_PREFIXES = \[([^\]]*)\]/.exec(auth)?.[1] ?? "";

  for (const m of callbacks.matchAll(/"([^"]+)"/g)) keys.add(`auth.ts: ${m[1]}`);

  return keys;
}

// ---------- the sweep ----------
async function sweep(): Promise<Hit[]> {
  const hits: Hit[] = [];
  const list = probes();

  for (const caller of ["anonymous", "maintainer", "admin"] as const) {
    for (const safe of [false, true]) {
      for (const p of list) {
        const url = `${reg.url}${safe ? "~safe/" : ""}${p.path}`;
        const headers = headersFor(caller);

        for (const [k, v] of Object.entries(p.headers ?? {})) headers.set(k, v);
        const res = await fetch(url, { headers, redirect: "manual" });
        const bytes = new Uint8Array(await res.arrayBuffer());

        for (const { marker, where } of markersInBody(bytes)) hits.push({ caller, url, status: res.status, marker, where });
      }
    }
  }

  return hits;
}

const show = (hits: readonly Hit[]): string[] => [...new Set(hits.map((h) => `${h.caller} ${h.status} ${h.url.slice(reg.url.length - 1)} ${h.where}: ${h.marker}`))];

describe("a revoked or revoke-pending version's text", () => {
  test("is shown on the routes the sweep asks before the revoke, so the sweep would see a leak", async () => {
    const seen = new Set((await sweep()).filter((h) => h.where !== "tarball").map((h) => h.marker));

    // each kind of place a publisher writes reaches some answer while the version is active
    for (const m of [
      "LEAKMARK-readme",
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
    ]) {
      expect(seen.has(m), m).toBe(true);
    }
  }, 120_000);

  test("is shown on no GET route after the revoke, to anyone, except where ALLOWED says why", async () => {
    for (const version of [PENDING, REVOKED]) {
      const r = await getJson(`${reg.url}-/apm/v1/revoke`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${owner}` },
        body: JSON.stringify({ name: NAME, version, reason: "posts the environment (LEAKMARK-revoke-reason)", password: PASSWORD }),
      });

      expect(dig(r.body, "status"), JSON.stringify(r.body)).toBe(version === PENDING ? "revoke-pending" : "revoked");
    }

    await reg.query("UPDATE packages SET dist_tags = dist_tags || $1::jsonb WHERE name = $2", [JSON.stringify(STALE_TAGS), NAME]);
    clock += HOUR;
    const hits = await sweep();
    const leaks = hits.filter((h) => !ALLOWED.some((a) => a.allows(h)));

    expect(show(leaks)).toEqual([]);

    for (const a of ALLOWED) expect(hits.some((h) => a.allows(h)), `exception "${a.name}" is never used`).toBe(true);
  }, 120_000);

  test("every route literal in the router's modules is swept here or named as not a GET route", () => {
    const found = sourceKeys();
    const swept = new Set(probes().flatMap((p) => p.keys));
    const named = new Set([...swept, ...Object.keys(NOT_SWEPT)]);

    // a matcher literal nobody listed: a new route, or a new GET on an old one
    expect([...found].filter((k) => !named.has(k))).toEqual([]);
    // a listed literal that is gone: the list is stale
    expect([...named].filter((k) => !found.has(k))).toEqual([]);

    // a route module router.ts gains is read by the scan only once it is named
    const router = readFileSync(join(ROOT, "packages", "registry", "src", "router.ts"), "utf8");
    const imports = [...router.matchAll(/from "\.\/([^"]+)"/g)].map((m) => m[1] ?? "");

    expect(imports.filter((f) => !ROUTE_MODULES.includes(f) && !ROUTER_HELPERS.includes(f))).toEqual([]);
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

  test("the admin queue: decided and pending items of withheld versions keep path, line and sentence, not the source", async () => {
    const queue = AdminQueue.parse((await admin.json("-/apm/v1/review-admin/queue")).body);
    const items = [...queue.pending, ...queue.decided].filter((i) => i.name === NAME);

    expect(items.map((i) => i.version).toSorted()).toEqual([PENDING, REVOKED]);

    for (const i of items) {
      expect(i.redacted).toBe(true);
      expect(i.private.summary).toBe("");
      expect(i.private.findings).toEqual([{ file: "index.js", line: 2, issue: "Exports a fixed string on import.", severity: "high", quote: "", excerpt: "" }]);
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
