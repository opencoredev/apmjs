// Spec: the GET table (packages/registry/src/routes.ts) answers every URL form the registry answered before the table
// existed. The router refuses a GET or HEAD whose path the table does not list, so a form the old dispatch read (a
// trailing slash, `%40` for `@`, `%2f` inside a scoped name, a doubled slash, a segment a handler ignored) must still
// reach its route module.
//
// The old dispatch is 19a99eb, the commit before the table. Its statuses for every form below are recorded in
// fixtures/route-compat-19a99eb.json: running this file with APM_ROUTE_COMPAT_RECORD=<file> in a checkout of 19a99eb
// writes them there instead of comparing. The registry, packages and clock are the same in both runs.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { addUser, putPublish, startRegistry, type Registry } from "./harness";

const FIXTURE = join(import.meta.dir, "fixtures", "route-compat-19a99eb.json");
const RECORD = process.env.APM_ROUTE_COMPAT_RECORD;

const DAY = 24 * 60 * 60 * 1000;
const OWNER = "compat-owner";
const PLAIN = "compat-pkg";
const SCOPE = `@${OWNER}`;
const BARE = "compat-scoped";
const VERSION = "1.0.0";

/** Each package by every spelling of its name a client or a person typing a URL sends, and its tarball's file name. */
const NAMES = [
  { forms: [PLAIN], tarball: `${PLAIN}-${VERSION}.tgz` },
  { forms: [`${SCOPE}/${BARE}`, `%40${OWNER}/${BARE}`, `${SCOPE}%2f${BARE}`, `${SCOPE}%2F${BARE}`, `%40${OWNER}%2F${BARE}`], tarball: `${BARE}-${VERSION}.tgz` },
] as const;

/** The routes that name a package, for one spelling of its name. */
function namedRoutes(n: string, tarball: string): string[] {
  return [
    n,
    `${n}/${VERSION}`,
    `${n}/latest`,
    `${n}/-/${tarball}`,
    `-/package/${n}/dist-tags`,
    `-/package/${n}/dist-tags/latest`,
    `-/apm/v1/packages/${n}`,
    `-/apm/v1/packages/${n}/events`,
    `-/apm/v1/score/${n}`,
    `-/apm/v1/score/${n}/${VERSION}`,
    `-/apm/v1/file/${n}/${VERSION}?path=package.json`,
    `-/apm/v1/readme/${n}/${VERSION}`,
    `-/apm/v1/review/${n}/${VERSION}`,
  ];
}

/** Segments a handler read past, or refused: the old dispatch answered some of these. */
function extraSegments(n: string, tarball: string): string[] {
  return [
    `${n}/${VERSION}/extra`,
    `${n}/-/${tarball}/extra`,
    `-/package/${n}/dist-tags/latest/extra`,
    `-/apm/v1/score/${n}/${VERSION}/extra`,
    `-/apm/v1/packages/${n}/events/extra`,
    `-/apm/v1/packages/${n}/extra`,
    `-/apm/v1/file/${n}/${VERSION}/extra?path=package.json`,
    `-/apm/v1/readme/${n}/${VERSION}/extra`,
  ];
}

/** A path as is, with a trailing slash, and with its last slash doubled; a query string stays at the end. */
function spellings(p: string): string[] {
  const q = p.indexOf("?");
  const path = q === -1 ? p : p.slice(0, q);
  const query = q === -1 ? "" : p.slice(q);
  const last = path.lastIndexOf("/");
  const doubled = last === -1 ? [] : [`${path.slice(0, last)}//${path.slice(last + 1)}${query}`];

  return [p, `${path}/${query}`, ...doubled];
}

/** Routes that name no package. */
const FIXED = [
  "",
  "-/ping",
  "-/whoami",
  "-/v1/search?text=compat",
  `-/user/org.couchdb.user:${OWNER}`,
  `-/user/org.couchdb.user%3A${OWNER}`,
  "-/apm/v1/names?q=compat",
  "-/apm/v1/recent",
  `-/apm/v1/resolve?name=${PLAIN}&range=${VERSION}`,
  `-/apm/v1/resolve?name=%40${OWNER}%2F${BARE}&range=${VERSION}`,
  "-/apm/v1/me",
  "-/apm/v1/auth/config",
  "-/apm/v1/evidence-admin/me",
  "-/apm/v1/account",
  "-/apm/v1/staged",
  "-/apm/v1/staged/no-such-id",
  // a scope without a name: the old protocol route read no package in it and answered as the root does
  SCOPE,
  `%40${OWNER}`,
  "api/auth/get-session",
  "api/auth/ok",
  "api/auth/error",
  "api/auth/device",
  "api/auth/passkey/generate-authenticate-options",
  "api/auth/callback/github",
  "api/auth/callback/github/extra",
  "api/auth/oauth2/callback/github",
];

/** Every path this file asks, without the leading slash. */
function forms(): string[] {
  const named = NAMES.flatMap(({ forms: ns, tarball }) => ns.flatMap((n) => [...namedRoutes(n, tarball).flatMap(spellings), ...extraSegments(n, tarball)]));
  const all = [...FIXED.flatMap(spellings), ...named];

  return [...new Set([...all, ...all.map((p) => `~safe/${p}`), "~safe", "~safe/"])];
}

const CALLERS = ["anonymous", "maintainer"] as const;
const METHODS = ["GET", "HEAD"] as const;

const Statuses = z.record(z.string(), z.number().int());

type Statuses = z.infer<typeof Statuses>;

let reg: Registry;
let token: string;
const clock = { at: Date.parse("2026-06-01T10:00:00Z") };

beforeAll(async () => {
  reg = await startRegistry({ now: () => clock.at });
  token = await addUser(reg, OWNER);

  for (const name of [PLAIN, `${SCOPE}/${BARE}`]) {
    const r = await putPublish(reg, token, { name, version: VERSION, license: "MIT", main: "index.js", readme: "# compat" }, { files: { "index.js": "module.exports = 1;\n", "README.md": "# compat\n" } });

    if (r.status !== 201) throw new Error(`publish ${name}: ${r.status} ${JSON.stringify(r.body)}`);
  }

  // past the 24-hour cooldown, so /~safe/ serves the versions too
  clock.at += 3 * DAY;
}, 60_000);

afterAll(async () => {
  await reg?.stop();
});

/** The status of every form, by "<caller> <method> /<path>". */
async function statuses(): Promise<Statuses> {
  const out: Statuses = {};

  for (const caller of CALLERS) {
    const headers: Record<string, string> = caller === "maintainer" ? { authorization: `Bearer ${token}` } : {};

    for (const method of METHODS) {
      for (const p of forms()) {
        const res = await fetch(`${reg.url}${p}`, { method, headers, redirect: "manual" });

        await res.arrayBuffer();
        out[`${caller} ${method} /${p}`] = res.status;
      }
    }
  }

  return out;
}

describe("the GET table and the dispatch before it (19a99eb)", () => {
  test("answer every URL form with the same status, and every form that answered 200 still does", async () => {
    const now = await statuses();

    if (RECORD) {
      writeFileSync(RECORD, `${JSON.stringify(now, null, 2)}\n`);

      return;
    }

    const before = Statuses.parse(JSON.parse(readFileSync(FIXTURE, "utf8")));

    // the fixture and this file ask the same forms: a form added here needs its status from 19a99eb
    expect(Object.keys(now).toSorted()).toEqual(Object.keys(before).toSorted());

    const changed = Object.keys(before).flatMap((k) => (now[k] === before[k] ? [] : [`${k}: ${before[k]} before, ${now[k]} now`]));
    const lost = Object.keys(before).flatMap((k) => (before[k] === 200 && now[k] !== 200 ? [`${k}: ${now[k]}`] : []));

    expect(lost).toEqual([]);
    expect(changed).toEqual([]);
    // the list reaches the forms the finding named, so a fixture that lost them would not pass quietly
    expect(before[`anonymous HEAD /-/apm/v1/packages/%40${OWNER}/${BARE}`]).toBe(200);
    expect(before[`anonymous GET /~safe/${PLAIN}/${VERSION}/`]).toBe(200);
  }, 300_000);
});
