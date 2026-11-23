// A job whose upstream registry is unreachable is put back in the queue ("later"); polling during the outage must not
// use up its attempts, or the outage permanently fails the job as "too many attempts" without a reviewer ever seeing it.
import { afterAll, beforeAll, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { z } from "zod";
import { startRegistry, type Registry } from "../../../tests/acceptance/harness";

const SERVICE_TOKEN = `svc_${randomBytes(24).toString("base64url")}`;
let reg: Registry;
let outage: ReturnType<typeof Bun.serve>;
let clock = Date.parse("2026-11-18T10:00:00Z");

beforeAll(async () => {
  outage = Bun.serve({ port: 0, fetch: () => new Response("down", { status: 503 }) });
  reg = await startRegistry({
    now: () => clock,
    upstream: outage.url.href,
    review: { serviceTokenHash: createHash("sha256").update(SERVICE_TOKEN).digest("hex"), admins: [] },
  });
});

afterAll(async () => {
  await reg.stop();
  await outage.stop(true);
});

test("polling while upstream is down does not exhaust a job's attempts", async () => {
  await reg.query(
    `INSERT INTO review_jobs (id, package, version, digest, source, reasons, priority, state, enqueued_at, updated_at)
     VALUES ('job1', 'ghost-lib', '1.0.0', 'sha512-x', 'upstream', '["popular"]'::jsonb, 1, 'queued', $1, $1)`,
    [clock],
  );

  // the default is 5 attempts; a reviewer polls every few seconds
  for (let i = 0; i < 8; i++) {
    clock += 1000;
    const res = await fetch(`${reg.url}-/apm/v1/review-jobs?max=4`, { headers: { authorization: `Bearer ${SERVICE_TOKEN}` } });

    expect(res.status).toBe(200);
  }

  const [job] = z.array(z.object({ state: z.string(), attempts: z.number() })).parse(await reg.query("SELECT state, attempts FROM review_jobs WHERE id = 'job1'"));

  expect(job?.state).toBe("queued");
  expect(job?.attempts).toBe(0);
});
