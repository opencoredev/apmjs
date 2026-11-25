// deploy.ts reads every secret the stack needs before it touches the database: a missing GitHub OAuth key or an empty
// auth-secret file found after migrating would leave the database ahead of the Workers. A plan takes the same path to the
// database as a deploy, without the release lock or checkout snapshot, so a plan runs here against a stand-in Postgres
// port that only counts connections, with its own secrets folder, so nothing real is reached.
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const DEPLOY = join(import.meta.dir, "..", "deploy.ts");
let connections = 0;
let server: Bun.TCPSocketListener;
let dir: string;

beforeAll(() => {
  server = Bun.listen({
    hostname: "127.0.0.1",
    port: 0,
    socket: {
      open(socket) {
        connections += 1;
        socket.end();
      },
      data() {},
    },
  });
});

afterAll(() => {
  server.stop(true);
});

beforeEach(() => {
  connections = 0;
  dir = mkdtempSync(join(tmpdir(), "apm-deploy-secrets-"));
  writeFileSync(join(dir, "cloudflare.env"), "CLOUDFLARE_ACCOUNT_ID=0123456789abcdef0123456789abcdef\n");
  writeFileSync(join(dir, "cloudflare-token"), "fake-token\n");
  writeFileSync(join(dir, "neon-url"), `postgres://u:p@127.0.0.1:${server.port}/neondb\n`);
  writeFileSync(join(dir, "github-oauth.env"), "APM_GITHUB_CLIENT_ID=id\nAPM_GITHUB_CLIENT_SECRET=secret\n");
  writeFileSync(join(dir, "auth-secret-staging"), "an-auth-secret\n");
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

async function plan(): Promise<{ code: number; out: string }> {
  const proc = Bun.spawn(["bun", DEPLOY, "plan", "--stage", "staging"], {
    env: { PATH: process.env.PATH ?? "", HOME: dir, APM_SECRETS_DIR: dir, APM_RELEASE_LOCK: join(dir, "release.lock"), APM_CLOUDFLARE_API: "http://127.0.0.1:1/client/v4" },
    stdout: "pipe",
    stderr: "pipe",
  });

  const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);

  return { code, out: out + err };
}

describe("deploy.ts checks its secrets before the database", () => {
  test("the stand-in is reached when the secrets are complete, so the checks below are meaningful", async () => {
    const r = await plan();

    expect(r.code).not.toBe(0);
    expect(connections).toBeGreaterThan(0);
  });

  test("a github-oauth.env without APM_GITHUB_CLIENT_SECRET stops the run before any database connection", async () => {
    writeFileSync(join(dir, "github-oauth.env"), "APM_GITHUB_CLIENT_ID=id\n");
    const r = await plan();

    expect(r.code).not.toBe(0);
    expect(r.out).toContain("github-oauth.env has no APM_GITHUB_CLIENT_SECRET");
    expect(connections).toBe(0);
  });

  test("an empty auth-secret file stops the run before any database connection", async () => {
    writeFileSync(join(dir, "auth-secret-staging"), "\n");
    const r = await plan();

    expect(r.code).not.toBe(0);
    expect(r.out).toContain("auth-secret-staging is empty");
    expect(connections).toBe(0);
  });
});
