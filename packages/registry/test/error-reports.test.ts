// The registry's error reports (src/error-reports.ts): a fixed code by the failure's class, a static label from the
// route tables (routes.ts), and nothing the request or the error carried. The payload's closed forms are checked in
// packages/core's test.
import { afterEach, describe, expect, test } from "bun:test";
import type { ErrorCode } from "@apm/core/error-report";
import { Cause } from "effect";
import { DatabaseUnavailable, StatementTimeout } from "../src/db-health.ts";
import { errorCode, reportFailure, resetReporter, type Failure } from "../src/error-reports.ts";
import { AuthError, BlobError, QueueError, StoreError } from "../src/errors.ts";
import { GET_ROUTES, routeLabel, WRITE_ROUTES, type RouteLabel } from "../src/routes.ts";

afterEach(() => resetReporter());

/** Every label routeLabel can return: built from the tables, so a test can say "this label is one of them". */
const ALL_LABELS: ReadonlySet<string> = new Set([
  "unknown",
  ...GET_ROUTES.flatMap((r) => [`GET ${r.name}`, `HEAD ${r.name}`]),
  ...WRITE_ROUTES.flatMap((r) => r.methods.map((m) => `${m} ${r.name}`)),
]);

describe("routeLabel", () => {
  test("a GET or HEAD is labelled by its route in the GET table, never by the package, version, id or file", () => {
    expect(routeLabel("GET", "/react")).toBe("GET packument");
    expect(routeLabel("GET", "/@scope/secret-name/-/secret-name-1.0.0.tgz")).toBe("GET tarball");
    expect(routeLabel("GET", "/-/apm/v1/staged/AbCdEf123456")).toBe("GET staged detail");
    expect(routeLabel("GET", "/api/auth/callback/github?code=abc&state=def")).toBe("GET auth callback");
    expect(routeLabel("HEAD", "/-/apm/v1/file/left-pad/1.3.0")).toBe("HEAD file");
    expect(routeLabel("GET", "/~safe/react")).toBe("GET packument");
    expect(routeLabel("GET", "/-/nothing/here")).toBe("unknown");
  });

  test("every write handler's path has its own label", () => {
    const cases: [string, string, RouteLabel][] = [
      ["POST", "/-/apm/v1/login/device", "POST login device"],
      ["POST", "/-/apm/v1/login/device/token", "POST login device token"],
      ["POST", "/-/apm/v1/account/tokens/revoke", "POST tokens revoke"],
      ["POST", "/-/apm/v1/account/passkeys/remove", "POST passkey remove"],
      ["POST", "/-/apm/v1/factor/passkey-challenge", "POST factor passkey-challenge"],
      ["POST", "/-/apm/v1/factor/confirm", "POST factor confirm"],
      ["POST", "/-/apm/v1/verify", "POST verify"],
      ["POST", "/-/apm/v1/staged/stg_AbCdEf123456/approve", "POST staged approve"],
      ["POST", "/-/apm/v1/staged/stg_AbCdEf123456/reject", "POST staged reject"],
      ["POST", "/-/apm/v1/yank", "POST yank"],
      ["POST", "/-/apm/v1/unyank", "POST unyank"],
      ["POST", "/-/apm/v1/revoke", "POST revoke"],
      ["POST", "/-/apm/v1/restore", "POST restore"],
      ["POST", "/-/apm/v1/incident", "POST incident"],
      ["POST", "/-/apm/v1/owners", "POST owners"],
      ["DELETE", "/-/apm/v1/owners", "DELETE owners"],
      ["POST", "/-/apm/v1/scan", "POST scan"],
      ["POST", "/-/apm/v1/audit", "POST audit"],
      ["POST", "/-/npm/v1/security/advisories/bulk", "POST advisories bulk"],
      ["POST", "/-/apm/v1/review-jobs/job_123/result", "POST review result"],
      ["POST", "/-/apm/v1/review-jobs/job_123/release", "POST review release"],
      ["POST", "/-/apm/v1/review-admin/decide", "POST review decide"],
      ["POST", "/-/apm/v1/review-admin/dismiss", "POST review dismiss many"],
      ["POST", "/-/apm/v1/review-admin/unlock", "POST review unlock"],
      ["POST", "/-/apm/v1/review-admin/lock", "POST review lock"],
      ["POST", "/-/apm/v1/review-admin/switch", "POST review switch"],
      ["POST", "/-/apm/v1/review/@scope/name/1.0.0/request", "POST review request"],
      ["POST", "/-/apm/v1/evidence-admin/dismiss", "POST evidence dismiss"],
      ["POST", "/-/apm/v1/evidence-admin/restore", "POST evidence restore"],
      ["PUT", "/-/package/secret-name/dist-tags/beta", "PUT dist-tags"],
      ["POST", "/-/package/secret-name/dist-tags/beta", "POST dist-tags"],
      ["DELETE", "/-/package/@scope%2fsecret/dist-tags/beta", "DELETE dist-tags"],
      ["DELETE", "/-/user/token/npm_AbCdEf1234567890", "DELETE token delete"],
      ["PUT", "/-/user/org.couchdb.user:someone", "PUT adduser"],
      ["PUT", "/@scope%2fsecret-name", "PUT publish"],
      ["PUT", "/secret-name/-rev/3-abc", "PUT rev"],
      ["DELETE", "/secret-name/-rev/3-abc", "DELETE unpublish"],
      ["DELETE", "/secret-name/-/secret-name-1.0.0.tgz/-rev/3-abc", "DELETE unpublish"],
      ["POST", "/api/auth/sign-in/social", "POST auth sign-in social"],
      ["POST", "/api/auth/sign-out", "POST auth sign-out"],
      ["POST", "/api/auth/link-social", "POST auth link-social"],
      ["POST", "/api/auth/two-factor/enable", "POST auth two-factor enable"],
      ["POST", "/api/auth/two-factor/disable", "POST auth two-factor disable"],
      ["POST", "/api/auth/two-factor/verify-totp", "POST auth two-factor verify-totp"],
      ["POST", "/api/auth/passkey/verify-registration", "POST auth passkey verify-registration"],
      ["POST", "/api/auth/passkey/verify-authentication", "POST auth passkey verify-authentication"],
      ["POST", "/api/auth/device/approve", "POST auth device approve"],
      ["POST", "/api/auth/device/deny", "POST auth device deny"],
      ["POST", "/api/auth/callback/github", "POST auth callback"],
      ["POST", "/api/auth/oauth2/callback/x", "POST auth oauth2 callback"],
    ];

    for (const [method, path, label] of cases) expect(routeLabel(method, path), `${method} ${path}`).toBe(label);
    // every write route in the table is exercised above
    expect([...new Set(cases.map((c): string => c[2]))].toSorted()).toEqual([...new Set(WRITE_ROUTES.flatMap((r) => r.methods.map((m) => `${m} ${r.name}`)))].toSorted());
  });

  test("an unrecognized route or method is unknown, and no segment of the path is ever copied into a label", () => {
    expect(routeLabel("POST", "/-/apm/v1/secretword")).toBe("unknown");
    expect(routeLabel("POST", "/-/apm/v1/AbC123")).toBe("unknown");
    expect(routeLabel("POST", "/api/auth/device%3Fuser_code%3DABCD")).toBe("unknown");
    expect(routeLabel("POST", "/-/someone@example.com")).toBe("unknown");
    expect(routeLabel("PATCH", "/-/apm/v1/yank")).toBe("unknown");
    expect(routeLabel("OPTIONS", "/react")).toBe("unknown");
    expect(routeLabel("X-SECRET-abc123", "/react")).toBe("unknown");
    // a GET-only route under another method
    expect(routeLabel("POST", "/-/apm/v1/staged/stg_AbCdEf123456")).toBe("unknown");

    const words = ["react", "secretword", "abcdefgh", "someone@example.com", "stg_AbCdEf123456", "%2e%2e", "~safe", "-", "api", "auth", "v1", "apm", "x".repeat(300)];

    for (const method of ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "secret"]) {
      for (const a of words) {
        for (const b of words) {
          for (const path of [`/${a}`, `/${a}/${b}`, `/-/apm/v1/${a}/${b}`, `/api/auth/${a}/${b}`, `/-/${a}`, `/-/package/${a}/${b}`]) {
            const label = routeLabel(method, path);

            expect(ALL_LABELS.has(label), `${method} ${path} -> ${label}`).toBe(true);

            if (label !== "unknown") expect(label).not.toContain("secretword");
          }
        }
      }
    }
  });
});

describe("errorCode", () => {
  test("is chosen by the failure's class, never by its text", () => {
    const down = new DatabaseUnavailable({ reason: "connect", cause: new Error("postgres://user:pw@db/device?code=ABCD-1234") });

    const cases: [Failure, ErrorCode][] = [
      [{ kind: "misconfigured" }, "misconfigured"],
      [{ kind: "infra", error: new StoreError({ operation: "read staged stg_secret", cause: down }) }, "db_unavailable"],
      [{ kind: "infra", error: new StoreError({ operation: "read staged stg_secret", cause: new Error("syntax error near 'secret'") }) }, "db_error"],
      [{ kind: "infra", error: new BlobError({ operation: "get", key: "tarballs/secret.tgz", cause: null }) }, "blob_error"],
      [{ kind: "infra", error: new AuthError({ operation: "session", cause: "token=abc" }) }, "auth_error"],
      [{ kind: "infra", error: new QueueError({ operation: "send", cause: null }) }, "queue_error"],
      [{ kind: "defect", cause: Cause.die(new TypeError("cannot read /device?code=ABCD-1234")) }, "internal"],
      [{ kind: "defect", cause: Cause.die(Object.assign(new Error("x"), { name: "SecretName" })) }, "internal"],
      [{ kind: "defect", cause: Cause.die(down) }, "db_unavailable"],
      [{ kind: "defect", cause: Cause.die(new StatementTimeout({ ms: 5000 })) }, "db_unavailable"],
      [{ kind: "defect", cause: Cause.die("a thrown string with apm_secret_123") }, "unknown"],
      [{ kind: "defect", cause: Cause.die({ message: "a plain object" }) }, "unknown"],
    ];

    for (const [failure, code] of cases) expect(errorCode(failure)).toBe(code);
  });
});

type Sent = { url: string; init: RequestInit };

/** A collector stand-in: records each send and answers 204. */
/** A collector stand-in: what was sent, and the fetch that records it. */
type Collector = { sent: Sent[]; fetch: (url: string, init: RequestInit) => Promise<Response> };

function collector(): Collector {
  const sent: Sent[] = [];

  return {
    sent,
    fetch: async (url, init) => {
      sent.push({ url, init });

      return new Response(null, { status: 204 });
    },
  };
}

const SECRET_REQ = new Request("https://registry.apmjs.dev/-/apm/v1/staged/AbCdEf123456?token=apm_secret_1234567890abcdef", {
  method: "GET",
  headers: { authorization: "Bearer apm_secret_1234567890abcdef", cookie: "s=1" },
});

const DEFECT: Failure = { kind: "defect", cause: Cause.die(new TypeError("boom at /device?code=ABCD-1234 for someone@example.com")) };

const ENV = { APM_DATABUDDY_CLIENT_ID: "client-1", APM_BUILD: "b1" };

/** Runs the report's microtasks and the sends waitUntil was handed. */
async function settle(waited: Promise<unknown>[]): Promise<void> {
  await Promise.all(waited);
}

describe("reportFailure", () => {
  test("sends nothing without APM_DATABUDDY_CLIENT_ID", async () => {
    const c = collector();
    const waited: Promise<unknown>[] = [];

    resetReporter({ fetch: c.fetch });
    reportFailure({ req: SECRET_REQ, env: { APM_BUILD: "b1" }, waitUntil: (w) => waited.push(w), failure: DEFECT });
    reportFailure({ req: SECRET_REQ, env: { APM_DATABUDDY_CLIENT_ID: "  " }, waitUntil: (w) => waited.push(w), failure: DEFECT });
    await settle(waited);
    expect(waited).toHaveLength(0);
    expect(c.sent).toHaveLength(0);
  });

  test("sends exactly the code, the label, the status, the build and the colo, and nothing the request or error carried", async () => {
    const c = collector();
    const waited: Promise<unknown>[] = [];
    // request.cf, as Cloudflare sets it
    const req = Object.defineProperty(new Request(SECRET_REQ), "cf", { value: { colo: "SJC" } });

    resetReporter({ fetch: c.fetch, now: () => 1_700_000_000_000 });
    reportFailure({ req, env: ENV, waitUntil: (w) => waited.push(w), failure: DEFECT });
    await settle(waited);
    expect(c.sent).toHaveLength(1);
    const [only] = c.sent;

    expect(only?.url).toBe("https://basket.databuddy.cc/errors?client_id=client-1");
    expect(only?.init.redirect).toBe("manual");
    expect(new Headers(only?.init.headers).get("origin")).toBe("https://registry.apmjs.dev");
    expect(JSON.parse(String(only?.init.body))).toEqual([
      {
        timestamp: 1_700_000_000_000,
        path: "https://registry.apmjs.dev/_server/GET_staged_detail",
        message: "internal",
        errorType: "internal",
        filename: "registry@b1",
        stack: "worker=registry code=internal status=500 route=GET_staged_detail colo=SJC build=b1",
      },
    ]);
  });

  test("one limit for the isolate, whatever hostname the requests came in on", async () => {
    const c = collector();
    const waited: Promise<unknown>[] = [];

    resetReporter({ fetch: c.fetch, now: () => 0 });

    for (let i = 0; i < 30; i += 1) {
      const host = ["registry.apmjs.dev", "apmjs-registry-production.example.workers.dev", `h${i}.example`][i % 3];

      reportFailure({ req: new Request(`https://${host}/react`), env: ENV, waitUntil: (w) => waited.push(w), failure: DEFECT });
    }

    await settle(waited);
    expect(c.sent).toHaveLength(10);

    // and each names the canonical origin, not the host it came in on
    for (const s of c.sent) expect(String(s.init.body)).toContain('"path":"https://registry.apmjs.dev/_server/GET_packument"');
  });

  test("the send starts only after waitUntil holds it, and never when waitUntil throws", async () => {
    const c = collector();
    let sentWhenHeld = -1;
    const waited: Promise<unknown>[] = [];

    resetReporter({ fetch: c.fetch });
    reportFailure({
      req: SECRET_REQ,
      env: ENV,
      waitUntil: (w) => {
        sentWhenHeld = c.sent.length;
        waited.push(w);
      },
      failure: DEFECT,
    });
    await settle(waited);
    expect(sentWhenHeld).toBe(0);
    expect(c.sent).toHaveLength(1);

    reportFailure({
      req: SECRET_REQ,
      env: ENV,
      waitUntil: () => {
        throw new Error("no context");
      },
      failure: DEFECT,
    });
    await new Promise((r) => setTimeout(r, 10));
    expect(c.sent).toHaveLength(1);
  });

  test("never throws, and sends nothing, when what it reads throws: the request, the env or the defect", async () => {
    const c = collector();
    const waited: Promise<unknown>[] = [];
    const hold = (w: Promise<unknown>): number => waited.push(w);

    resetReporter({ fetch: c.fetch });

    const throwing = {
      get() {
        throw new Error("getter");
      },
    };

    const badReq = Object.defineProperties(new Request(SECRET_REQ), { url: throwing, method: throwing });

    const badEnv = Object.defineProperty({ APM_DATABUDDY_CLIENT_ID: "client-1" }, "APM_BUILD", {
      get() {
        throw new Error("getter");
      },
    });

    const badClientId = Object.defineProperty({}, "APM_DATABUDDY_CLIENT_ID", {
      get() {
        throw new Error("getter");
      },
    });

    const hostile = new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error("trap");
        },
        get() {
          throw new Error("trap");
        },
      },
    );

    expect(() => reportFailure({ req: badReq, env: ENV, waitUntil: hold, failure: DEFECT })).not.toThrow();
    expect(() => reportFailure({ req: SECRET_REQ, env: badEnv, waitUntil: hold, failure: DEFECT })).not.toThrow();
    expect(() => reportFailure({ req: SECRET_REQ, env: badClientId, waitUntil: hold, failure: DEFECT })).not.toThrow();
    expect(() => reportFailure({ req: SECRET_REQ, env: ENV, waitUntil: hold, failure: { kind: "defect", cause: Cause.die(hostile) } })).not.toThrow();
    await settle(waited);
    expect(c.sent).toHaveLength(0);
  });

  test("reports nothing without an execution context: no task, no send, and the failure is never read", async () => {
    const c = collector();
    let read = false;

    const watched: Failure = {
      get kind(): "misconfigured" {
        read = true;

        return "misconfigured";
      },
    };

    resetReporter({ fetch: c.fetch });
    expect(() => reportFailure({ req: SECRET_REQ, env: ENV, waitUntil: null, failure: watched })).not.toThrow();
    await new Promise((r) => setTimeout(r, 10));
    expect(read).toBe(false);
    expect(c.sent).toHaveLength(0);
  });

  test("classifies and serializes the failure in the waitUntil task, not before reportFailure returns", async () => {
    const c = collector();
    const waited: Promise<unknown>[] = [];
    let read = false;

    const watched: Failure = {
      get kind(): "misconfigured" {
        read = true;

        return "misconfigured";
      },
    };

    resetReporter({ fetch: c.fetch });
    reportFailure({ req: SECRET_REQ, env: ENV, waitUntil: (w) => waited.push(w), failure: watched });
    expect(read).toBe(false);
    expect(waited).toHaveLength(1);
    await settle(waited);
    expect(read).toBe(true);
    expect(c.sent).toHaveLength(1);
    expect(String(c.sent[0]?.init.body)).toContain("code=misconfigured");
  });

  test("a network failure stays inside the send", async () => {
    const waited: Promise<unknown>[] = [];

    resetReporter({
      fetch: () => {
        throw new Error("no network");
      },
    });
    expect(() => reportFailure({ req: SECRET_REQ, env: ENV, waitUntil: (w) => waited.push(w), failure: DEFECT })).not.toThrow();
    expect(waited).toHaveLength(1);
    await settle(waited);
  });
});
