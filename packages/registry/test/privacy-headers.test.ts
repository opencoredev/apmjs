// The registry's one place that marks answers private (http.ts, withPrivacyHeaders): an answer to a request that carried
// credentials (an Authorization header or a cookie) is never one a shared cache may keep or hand to someone else,
// whatever route made it and whatever caching it asked for, and an answer that can carry a version's source is never
// kept even for an anonymous request. A signed-in owner sees more on a review than anyone else does, so their answer
// must never be stored where an anonymous reader's request would find it, nor the other way round.
import { describe, expect, test } from "bun:test";
import { withPrivacyHeaders } from "../src/http.ts";

const BASE = "https://registry.apmjs.dev";

/** What a route answered before the wrapper: here, one that asks to be cached by everyone. */
const cacheable = (): Response => new Response("{}", { status: 200, headers: { "content-type": "application/json", "cache-control": "public, max-age=60, s-maxage=60", vary: "Accept-Encoding" } });

const CREDENTIALS: readonly { label: string; headers: Record<string, string> }[] = [
  { label: "a bearer token", headers: { authorization: "Bearer apm_x" } },
  { label: "a session cookie", headers: { cookie: "__Secure-better-auth.session_token=s" } },
  { label: "both", headers: { authorization: "Bearer apm_x", cookie: "a=b" } },
];

/** Every /-/ read the website and agents make, the ones that carry a version's source and the ones that do not. */
const READS = [
  "/-/apm/v1/packages/next",
  "/-/apm/v1/packages/next/versions/16.4.6",
  "/-/apm/v1/packages/next/events",
  "/-/apm/v1/review/next/16.4.6",
  "/-/apm/v1/score/next/16.4.6",
  "/-/apm/v1/readme/next/16.4.6",
  "/-/apm/v1/file/next/16.4.6?path=package.json",
  "/-/apm/v1/popular-scores?names=react",
  "/-/apm/v1/recent",
  "/-/apm/v1/resolve?name=react",
  "/-/v1/search?text=react",
  "/-/apm/v1/health",
  "/~safe/-/apm/v1/packages/next",
] as const;

const SOURCE_BEARING = ["/-/apm/v1/packages/next", "/-/apm/v1/packages/next/versions/16.4.6", "/-/apm/v1/score/next/16.4.6", "/-/apm/v1/readme/next/16.4.6", "/-/apm/v1/file/next/16.4.6?path=package.json", "/-/apm/v1/resolve?name=react"];

function marked(res: Response) {
  const vary = (res.headers.get("vary") ?? "").split(",").map((v) => v.trim().toLowerCase());

  return { cacheControl: res.headers.get("cache-control"), varyAuthorization: vary.includes("authorization"), varyCookie: vary.includes("cookie") };
}

const PRIVATE = { cacheControl: "private, no-store", varyAuthorization: true, varyCookie: true };

describe("withPrivacyHeaders", () => {
  for (const { label, headers } of CREDENTIALS) {
    test(`every /-/ answer to a request with ${label} is private, no-store and varies on Authorization and Cookie`, () => {
      for (const path of READS) {
        const res = withPrivacyHeaders(new Request(`${BASE}${path}`, { headers }), cacheable());

        expect(marked(res), path).toEqual(PRIVATE);
      }
    });
  }

  test("an answer that can carry a version's source is private even for an anonymous request", () => {
    for (const path of SOURCE_BEARING) expect(marked(withPrivacyHeaders(new Request(`${BASE}${path}`), cacheable())), path).toEqual(PRIVATE);
  });

  test("the vary list a route set is kept, with Authorization and Cookie added once", () => {
    const res = withPrivacyHeaders(new Request(`${BASE}/-/apm/v1/review/next/16.4.6`, { headers: { cookie: "a=b" } }), cacheable());

    expect(res.headers.get("vary")).toBe("Accept-Encoding, Authorization, Cookie");
  });

  test("the body and status pass through unchanged", async () => {
    const res = withPrivacyHeaders(new Request(`${BASE}/-/apm/v1/review/next/16.4.6`, { headers: { authorization: "Bearer x" } }), new Response('{"a":1}', { status: 203 }));

    expect(res.status).toBe(203);
    expect(await res.text()).toBe('{"a":1}');
  });

  test("an anonymous source-free answer keeps the caching its route chose", () => {
    const res = withPrivacyHeaders(new Request(`${BASE}/-/apm/v1/popular-scores?names=react`), cacheable());

    expect(res.headers.get("cache-control")).toBe("public, max-age=60, s-maxage=60");
  });
});
