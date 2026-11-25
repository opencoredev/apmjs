// Leasing reads each job on its own: a job the reviewer cannot read is failed by itself and the rest of its batch is
// reviewed. npm's placeholder for the package named "-" once sank every batch it was leased in.
import { afterEach, describe, expect, test } from "bun:test";
import type { LogFields } from "../src/log.ts";
import { registryClient } from "../src/registry.ts";

const digest = `sha1-${"0".repeat(40)}`;

function job(n: number, name: string, version: string): Record<string, unknown> {
  return {
    id: `job-${n}`,
    leaseId: `lease-${n}`,
    leaseExpiresAt: new Date(0).toISOString(),
    name,
    version,
    digest,
    tarballPath: `${name}/-/${name.replace(/^@[^/]+\//, "")}-${version}.tgz`,
    previous: null,
    reasons: ["publish"],
  };
}

type Released = { id: string; body: unknown };

let server: ReturnType<typeof Bun.serve> | null = null;

afterEach(async () => {
  await server?.stop(true);
  server = null;
});

function registry(jobs: unknown[]): { url: string; released: Released[] } {
  const released: Released[] = [];

  server = Bun.serve({
    port: 0,
    async fetch(req) {
      const url = new URL(req.url);

      if (req.method === "GET" && url.pathname === "/-/apm/v1/review-jobs") return Response.json({ jobs });
      const release = /^\/-\/apm\/v1\/review-jobs\/([^/]+)\/release$/.exec(url.pathname);

      if (req.method === "POST" && release?.[1]) {
        released.push({ id: decodeURIComponent(release[1]), body: await req.json() });

        return Response.json({ ok: true });
      }

      return new Response("not found", { status: 404 });
    },
  });

  return { url: server.url.toString(), released };
}

function client(url: string): { lease: (max: number) => Promise<{ name: string }[]>; logged: { event: string; fields: LogFields }[] } {
  const logged: { event: string; fields: LogFields }[] = [];
  const c = registryClient({ url, token: "t", log: (_level, event, fields = {}) => logged.push({ event, fields }) });

  return { lease: c.lease, logged };
}

describe("leasing", () => {
  test("npm's legacy names lease: the placeholder named \"-\", uppercase and URL-safe punctuation", async () => {
    const reg = registry([job(0, "-", "0.0.1-security.1"), job(1, "JSONStream", "1.3.5"), job(2, "@scope/x!y", "1.0.0"), job(3, "debug", "4.4.3")]);
    const c = client(reg.url);

    expect((await c.lease(4)).map((j) => j.name)).toEqual(["-", "JSONStream", "@scope/x!y", "debug"]);
    expect(reg.released).toEqual([]);
    expect(c.logged).toEqual([]);
  });

  test("a batch with one unreadable job leases the good ones and fails the bad one on its own", async () => {
    const bad = { ...job(1, "evil", "1.0.0"), tarballPath: "../../-/evil-1.0.0.tgz" };
    const reg = registry([job(0, "left-pad", "1.3.0"), bad, job(2, "debug", "4.4.3")]);
    const c = client(reg.url);

    expect((await c.lease(3)).map((j) => j.name)).toEqual(["left-pad", "debug"]);
    expect(reg.released).toHaveLength(1);
    expect(reg.released[0]?.id).toBe("job-1");
    expect(reg.released[0]?.body).toMatchObject({ leaseId: "lease-1", retryable: false });
    expect(c.logged.map((l) => [l.event, l.fields.job])).toEqual([["job.unreadable", "job-1"]]);
  });

  test("a job without a readable lease is skipped and left to expire", async () => {
    const reg = registry([{ id: 7 }, job(0, "left-pad", "1.3.0")]);
    const c = client(reg.url);

    expect((await c.lease(2)).map((j) => j.name)).toEqual(["left-pad"]);
    expect(reg.released).toEqual([]);
    expect(c.logged.map((l) => [l.event, l.fields.job])).toEqual([["job.unreadable", null]]);
  });

  test("a response that is not a lease still fails the whole lease", async () => {
    const c = client(registry([]).url);

    server?.reload({ fetch: () => Response.json({ nope: true }) });
    await expect(c.lease(1)).rejects.toThrow();
  });
});
