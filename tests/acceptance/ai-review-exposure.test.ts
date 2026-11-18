// What the AI review's answers hand out, after the independent review of 17be3f6: the owner view is for apm's own
// packages only (a matching npm scope grants nothing), and no string in any public, owner or admin answer carries a
// secret from a seeded set, wherever the model or the tarball put it (summaries, findings, file names, coverage paths,
// the second opinion, the reviewer's note).
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { z } from "zod";
import { digestLabel, digestOf } from "../../packages/registry/src/digest.ts";
import { dig, getJson, signInWithGitHub, startFakeGitHub, startRegistry, type Browser, type FakeGitHub, type Registry } from "./harness";

const SERVICE_TOKEN = `svc_${randomBytes(24).toString("base64url")}`;
const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");
const UPSTREAM_SCOPED = "@alice/unrelated-npm-package";

// every value is built at run time, so no secret-shaped literal sits in the repository. Each is seeded in a shape a
// secret takes (a key's own form, or a value given to a secret-named key): a bare phrase in prose names no secret, and
// nothing can mask it.
const S = {
  openai: ["sk", "proj", "Q8vT2mLw9XyZ4bN7cR1dF6gH3jK5pS0uV"].join("-"),
  github: `ghp_${"a1B2c3D4e5".repeat(4)}`,
  aws: `AKIA${"QWERTYUIOPASDFGH"}`,
  jwt: ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJmaWN0aW9uYWwtdXNlciJ9", "c2lnbmF0dXJlLW9mLWZpY3Rpb24"].join("."),
  mongo: ["Fict10nal", "M0ngo", "Pw"].join(""),
  spaced: ["fictional", "password", "with", "spaces"].join(" "),
  single: ["single", "quoted", "fiction", "words"].join(" "),
  multi: ["first fictional line", "second fictional line"].join("\n"),
  env: ["alpha", "bravo", "charlie", "delta"].join(" "),
  yaml: ["yankee", "zulu", "x-ray", "whiskey"].join(" "),
  pem: "MIIEowIBAAKCAQEAfictionalKeyBodyLineOne",
};

/** The text each seeded secret is searched for: for a value with spaces, enough of it that a partial mask still fails. */
const FIND = [S.openai, S.github, S.aws, S.jwt, S.mongo, S.spaced, S.single, "second fictional line", "charlie delta", "x-ray whiskey", S.pem];

const SOURCE = [
  `const ai = new OpenAI({ apiKey: "${S.openai}" });`,
  `mongoose.connect("mongodb://shop:${S.mongo}@db.example.invalid/shop");`,
  `const password = "${S.spaced}";`,
  `const dbPassword = '${S.single}';`,
  "const token = `" + S.multi + "`;",
  `export SMTP_PASSWORD=${S.env}`,
  `password: ${S.yaml}`,
  `-----BEGIN RSA PRIVATE KEY-----\n${S.pem}\n-----END RSA PRIVATE KEY-----`,
  `// ${S.github} ${S.aws} ${S.jwt}`,
].join("\n");

let reg: Registry;
let gh: FakeGitHub;
let npm: ReturnType<typeof Bun.serve>;
const clock = Date.parse("2026-11-18T10:00:00Z");
let alice: string;
let bob: string;
let admin: Browser;
let aliceSite: Browser;

// ---------- a tar writer (as in ai-review.test.ts) ----------
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

function tgz(files: Record<string, string>): Uint8Array {
  const parts: Uint8Array[] = [];

  for (const [path, text] of Object.entries(files)) {
    const data = new TextEncoder().encode(text);

    parts.push(tarHeader(`package/${path}`, data.length), data);
    const pad = (512 - (data.length % 512)) % 512;

    if (pad > 0) parts.push(new Uint8Array(pad));
  }

  parts.push(new Uint8Array(1024));

  return Bun.gzipSync(Buffer.concat(parts));
}

async function publish(token: string, name: string): Promise<void> {
  const manifest = { name, version: "1.0.0", license: "MIT", main: "index.js" };
  const bytes = tgz({ "package.json": JSON.stringify(manifest), "index.js": "module.exports = 1;\n" });

  const body = {
    _id: name,
    name,
    "dist-tags": { latest: "1.0.0" },
    versions: { "1.0.0": manifest },
    _attachments: { [`${name}-1.0.0.tgz`]: { content_type: "application/octet-stream", data: Buffer.from(bytes).toString("base64"), length: bytes.length } },
  };

  const res = await fetch(`${reg.url}${encodeURIComponent(name)}`, { method: "PUT", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify(body) });

  if (res.status !== 201) throw new Error(`publish ${name}: ${res.status} ${await res.text()}`);
}

const upstreamTarball = tgz({ "package.json": JSON.stringify({ name: UPSTREAM_SCOPED, version: "1.0.0" }), "index.js": "module.exports = 1;\n" });

/** The digest label a version's review is keyed by: a local version's from its row, the upstream one's from its bytes. */
async function digestFor(name: string): Promise<string> {
  if (name === UPSTREAM_SCOPED) return digestLabel({ algo: "sha512", hex: createHash("sha512").update(upstreamTarball).digest("hex") });

  const rows = z.array(z.object({ integrity: z.string(), shasum: z.string() })).parse(await reg.query("SELECT integrity, shasum FROM versions WHERE package = $1 AND version = '1.0.0'", [name]));
  const [row] = rows;
  const d = row ? digestOf(row) : null;

  if (!d) throw new Error(`no digest for ${name}`);

  return digestLabel(d);
}

/** A flag that quotes every seeded secret in every field a review result has. */
async function seededFlag(name: string, humanState: "pending" | "confirmed"): Promise<void> {
  const finding = (file: string) => ({ file, line: 1, quote: SOURCE.slice(0, 400), excerpt: SOURCE.slice(0, 400), issue: `Ships password = "${S.spaced}" and ${S.openai}.`, severity: "high" });

  const result = {
    outcome: "flagged",
    verdict: "suspicious",
    findings: [finding("index.js"), finding(`config/${S.openai}.json`), { ...finding("env.js"), excerpt: SOURCE.slice(400, 800), quote: SOURCE.slice(400, 800) }],
    model: "fake-flash",
    reviewedAt: new Date(clock).toISOString(),
    summary: `Hardcodes credentials: ${SOURCE}`.slice(0, 2000),
    coverage: { mode: "files", previousVersion: null, filesInScope: 3, filesRead: 2 },
    read: ["index.js", `cache/${S.openai}.js`, `keys/${S.github}.txt`],
    notRead: [
      { kind: "file", path: `backup/${S.aws}.json`, reason: "binary" },
      { kind: "file", path: `notes/password = "${S.spaced}".txt`, reason: "too-large" },
      { kind: "dependency", name: "left-pad" },
    ],
    attempts: [{ result: "suspicious", kept: 1, dropped: 0, promptTokens: 10, completionTokens: 10, latencyMs: 5 }],
    secondOpinion: { reviewer: "fake-strong", verdict: "suspicious", summary: `Agrees: ${S.jwt} and dbPassword = '${S.single}'.`, findings: [finding(`keys/${S.github}.pem`)] },
  };

  await reg.query(
    `INSERT INTO reviews (package, version, digest, outcome, result, reviewed_at, human_state, human_by, human_at, human_note)
     VALUES ($1, '1.0.0', $2, 'flagged', $3::jsonb, $4, $5, $6, $7, $8)`,
    [name, await digestFor(name), JSON.stringify(result), clock, humanState, humanState === "confirmed" ? "octo-admin" : null, humanState === "confirmed" ? clock : null, humanState === "confirmed" ? `Confirmed: it sets password = "${S.spaced}".` : null],
  );
}

/** Every string in a JSON document, keys and values, decoded: each string literal of its text, parsed on its own. */
function stringsIn(json: string): string[] {
  return [...json.matchAll(/"(?:\\.|[^"\\])*"/g)].map((m) => z.string().parse(JSON.parse(m[0])));
}

const review = (name: string, token?: string) => getJson(`${reg.url}-/apm/v1/review/${encodeURIComponent(name)}/1.0.0`, token ? { headers: { authorization: `Bearer ${token}` } } : undefined);

beforeAll(async () => {
  npm = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const u = new URL(req.url);

      if (u.pathname.endsWith(".tgz")) return new Response(upstreamTarball);

      if (decodeURIComponent(u.pathname.slice(1)) !== UPSTREAM_SCOPED) return Response.json({ error: "Not found" }, { status: 404 });
      const dist = { tarball: `${npm.url}${encodeURIComponent(UPSTREAM_SCOPED)}/-/unrelated-npm-package-1.0.0.tgz`, shasum: createHash("sha1").update(upstreamTarball).digest("hex"), integrity: `sha512-${createHash("sha512").update(upstreamTarball).digest("base64")}` };

      return Response.json({ name: UPSTREAM_SCOPED, "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": { name: UPSTREAM_SCOPED, version: "1.0.0", dist } }, time: { "1.0.0": "2026-11-01T00:00:00Z" } });
    },
  });
  gh = startFakeGitHub();
  reg = await startRegistry({ now: () => clock, github: gh, upstream: npm.url.toString(), review: { serviceTokenHash: sha256(SERVICE_TOKEN), admins: ["octo-admin"] } });
  alice = await reg.mintToken({ user: "alice", scope: "publish" });
  bob = await reg.mintToken({ user: "bob", scope: "publish" });
  admin = await signInWithGitHub(reg, gh, "octo-admin");
  aliceSite = await signInWithGitHub(reg, gh, "alice");
});

afterAll(async () => {
  await reg.stop();
  await gh.stop();
  await npm.stop(true);
});

describe("who sees an unconfirmed flag's findings", () => {
  test("a matching npm scope grants nothing: an upstream @alice package is public to the apm user alice", async () => {
    await seededFlag(UPSTREAM_SCOPED, "pending");
    const res = await review(UPSTREAM_SCOPED, alice);

    expect(res.status).toBe(200);
    expect(dig(res.body, "review", "state")).toBe("under-review");
    expect(dig(res.body, "viewer")).toBe("public");
    expect(dig(res.body, "private")).toBeNull();
    // nor through "Your packages"
    expect(JSON.stringify((await aliceSite.json("-/apm/v1/account/packages")).body)).not.toContain(UPSTREAM_SCOPED);
  });

  test("apm's own packages: the scope's owner and a package's owners see them, nobody else", async () => {
    await publish(alice, "@alice/own-scoped");
    await publish(alice, "alice-owned");
    await seededFlag("@alice/own-scoped", "pending");
    await seededFlag("alice-owned", "pending");

    for (const name of ["@alice/own-scoped", "alice-owned"]) {
      expect(dig((await review(name, alice)).body, "viewer"), name).toBe("maintainer");
      expect(dig((await review(name, bob)).body, "private"), name).toBeNull();
      expect(dig((await review(name)).body, "private"), name).toBeNull();
    }
  });
});

describe("no seeded secret in any string of any answer", () => {
  test("public, stranger, owner, admin, Your packages, the status, and a confirmed version's public findings", async () => {
    await publish(alice, "alice-confirmed");
    await seededFlag("alice-confirmed", "confirmed");

    const answers = {
      "anonymous review": await review("alice-owned"),
      "stranger review": await review("alice-owned", bob),
      "owner review": await review("alice-owned", alice),
      "owner review, scoped": await review("@alice/own-scoped", alice),
      "upstream review as alice": await review(UPSTREAM_SCOPED, alice),
      "confirmed, public": await review("alice-confirmed"),
      "confirmed, owner": await review("alice-confirmed", alice),
      "admin queue": await admin.json("-/apm/v1/review-admin/queue"),
      "Your packages": await aliceSite.json("-/apm/v1/account/packages"),
      "public status": await getJson(`${reg.url}-/apm/v1/reviews`),
    };

    // the answers really carry the seeded fields: findings for the owner, coverage paths for everyone
    expect(dig(answers["owner review"].body, "private", "findings", 0, "excerpt")).toContain("[redacted, ");
    // in public a file named with a secret is `file N`, and the paths read are counts; the owner reads them masked
    expect(dig(answers["confirmed, public"].body, "review", "findings", 1, "file")).toBe("file 2");
    expect(dig(answers["anonymous review"].body, "review", "read")).toBeUndefined();
    expect(dig(answers["owner review"].body, "private", "read", 1)).toContain("[redacted, ");

    for (const [who, a] of Object.entries(answers)) {
      expect(a.status, who).toBe(200);

      for (const s of stringsIn(JSON.stringify(a.body))) for (const secret of FIND) expect(s.includes(secret), `${who}: ${JSON.stringify(s).slice(0, 120)}`).toBe(false);
    }
  });
});

// the independent re-check of 7207ea0: a numeric password beside a masked key reached the public through a confirmed
// finding's quote. The public now gets no quoted text at all, so what it sees does not depend on masking.
describe("public answers carry no quoted text", () => {
  test("a confirmed finding is public as file, line and sentence, with no quote or excerpt field anywhere", async () => {
    await publish(alice, "alice-confirmed-quotes");
    await seededFlag("alice-confirmed-quotes", "confirmed");
    const digits = "1234567890123456";

    // a secret masking does not catch: digits given to a key no rule names
    await reg.query("UPDATE reviews SET result = jsonb_set(jsonb_set(result, '{findings,0,excerpt}', $1::jsonb), '{findings,0,quote}', $1::jsonb) WHERE package = 'alice-confirmed-quotes'", [JSON.stringify(`const pin = ${digits};`)]);

    const answers = {
      anonymous: await review("alice-confirmed-quotes"),
      stranger: await review("alice-confirmed-quotes", bob),
      "public status": await getJson(`${reg.url}-/apm/v1/reviews`),
    };

    expect(dig(answers.anonymous.body, "review", "state")).toBe("confirmed");
    expect(dig(answers.anonymous.body, "review", "findings", 0)).toEqual({ file: "file 1", line: 1, label: "credential read", issue: "credential read", severity: "high" });

    for (const [who, a] of Object.entries(answers)) {
      const text = JSON.stringify(a.body);

      expect(a.status, who).toBe(200);
      expect(text, who).not.toContain('"quote"');
      expect(text, who).not.toContain('"excerpt"');
      expect(text, who).not.toContain(digits);
    }

    // the owner still reads the quoted line
    expect(dig((await review("alice-confirmed-quotes", alice)).body, "private", "findings", 0, "excerpt")).toBe(`const pin = ${digits};`);
  });
});

// the independent re-check of 70dc3df: the model's public sentence quoted a credential no masking rule knows, and a
// file name with a secret in it was public before any confirmation. The public now gets a fixed label and counts.
describe("public answers carry no free text from the model or the publisher", () => {
  test("a sentence quoting an unrecognised credential reaches no public answer; the label replaces it", async () => {
    await publish(alice, "sentence-quotes");
    await seededFlag("sentence-quotes", "confirmed");
    const digits = "9876543210987654";
    const sentence = `Sends the database password "${digits}" to a remote host.`;

    await reg.query("UPDATE reviews SET result = jsonb_set(result, '{findings,0,issue}', $1::jsonb) WHERE package = 'sentence-quotes'", [JSON.stringify(sentence)]);

    for (const token of [undefined, bob]) {
      const a = await review("sentence-quotes", token);
      const text = JSON.stringify(a.body);

      expect(a.status).toBe(200);
      expect(text).not.toContain(digits);
      expect(text).not.toContain("Sends the database password");
      expect(dig(a.body, "review", "findings", 0, "label")).toBe("sends data out");
    }

    // the owner still reads the model's sentence
    expect(dig((await review("sentence-quotes", alice)).body, "private", "findings", 0, "issue")).toBe(sentence);
  });

  test("a secret in a file name is not public before confirmation, nor after", async () => {
    await publish(alice, "filename-secret");
    await seededFlag("filename-secret", "pending");
    const named = `secrets/${"Zq9".repeat(9)}.json`;

    await reg.query(
      "UPDATE reviews SET result = jsonb_set(jsonb_set(jsonb_set(result, '{read}', $1::jsonb), '{notRead}', $2::jsonb), '{findings,0,file}', $3::jsonb) WHERE package = 'filename-secret'",
      [JSON.stringify([named]), JSON.stringify([{ kind: "file", path: named, reason: "binary" }]), JSON.stringify(named)],
    );

    const pending = await review("filename-secret");

    expect(JSON.stringify(pending.body)).not.toContain("Zq9Zq9");
    expect(dig(pending.body, "review", "notReadCounts")).toEqual({ files: 1, dependencies: 0 });

    await reg.query("UPDATE reviews SET human_state = 'confirmed', human_at = $1 WHERE package = 'filename-secret'", [clock]);
    const confirmed = await review("filename-secret");

    expect(JSON.stringify(confirmed.body)).not.toContain("Zq9Zq9");
    expect(dig(confirmed.body, "review", "findings", 0, "file")).toBe("file 1");
  });
});
