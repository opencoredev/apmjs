// The release lock (release-lock.ts) on a lock file of its own (APM_RELEASE_LOCK): a run holds it and records itself; a
// second run, or one while another process's flock holds it, refuses at once; a child the run started holds it too, so
// killing the run mid-child leaves it held until the child ends; no environment variable makes a run the holder; and the
// CLI the incident helper calls asks the kernel, not the record.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let dir: string;
let lock: string;
const HOLDER = join(import.meta.dir, "fixtures", "lock-holder.ts");
const CLI = join(import.meta.dir, "..", "release-lock.ts");

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "apm-release-lock-"));
  lock = join(dir, "release.lock");
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

const env = () => ({ PATH: process.env.PATH ?? "", HOME: dir, APM_RELEASE_LOCK: lock });

function start(args: string[], extra: Record<string, string> = {}) {
  return Bun.spawn(["bun", HOLDER, ...args], { env: { ...env(), ...extra }, stdout: "pipe", stderr: "pipe" });
}

async function firstLine(stream: ReadableStream<Uint8Array>): Promise<string> {
  const reader = stream.getReader();
  let text = "";

  while (!text.includes("\n")) {
    const chunk = await reader.read();

    if (chunk.done) break;
    text += new TextDecoder().decode(chunk.value);
  }

  reader.releaseLock();

  return text.split("\n")[0] ?? "";
}

async function run(cmd: string[], extra: Record<string, string> = {}): Promise<{ code: number; out: string }> {
  const proc = Bun.spawn(cmd, { env: { ...env(), ...extra }, stdout: "pipe", stderr: "pipe" });
  const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);

  return { code, out: out + err };
}

/** Whether a fresh flock on the lock file fails without waiting: the kernel's answer. */
function kernelHeld(): boolean {
  return Bun.spawnSync(["flock", "-n", "-E", "75", lock, "true"]).exitCode === 75;
}

/** Another process holding the flock itself, with no holder record: what the reviewer's external holder is. */
function externalHolder() {
  return Bun.spawn(["python3", "-c", `import fcntl, time\nf = open(${JSON.stringify(lock)}, "a+")\nfcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)\nprint("held", flush=True)\ntime.sleep(20)`], { stdout: "pipe" });
}

describe("the release lock", () => {
  test("a run holds it and records itself; a second run refuses at once and names the holder", async () => {
    const holder = start(["production", "20"]);

    try {
      expect(await firstLine(holder.stdout)).toMatch(/^inside \d+$/);
      const record = JSON.parse(readFileSync(`${lock}.json`, "utf8"));

      expect(record).toMatchObject({ pid: holder.pid, stage: "production", command: [expect.any(String), HOLDER, "production", "20"] });
      expect(record.sha).toMatch(/^[0-9a-f]{40}$/);
      expect(Number.isNaN(Date.parse(record.started))).toBe(false);
      const second = await run(["bun", HOLDER, "staging", "0"]);

      expect(second.code).toBe(6);
      expect(second.out).toContain(`is held by pid ${record.pid}`);
      expect(second.out).toContain("APM_RELEASE_LOCK");
    } finally {
      holder.kill();
      await holder.exited;
    }

    expect(kernelHeld()).toBe(false);
  }, 30_000);

  test("another process's flock on the same file keeps a run out", async () => {
    const helper = externalHolder();

    try {
      await firstLine(helper.stdout);
      expect((await run(["bun", HOLDER, "production", "0"])).code).toBe(6);
    } finally {
      helper.kill();
      await helper.exited;
    }
  }, 30_000);

  test("killing the run while a child it started is still working leaves the lock held until the child ends", async () => {
    const holder = start(["production", "30", "child"]);
    const line = await firstLine(holder.stdout);
    const child = Number(/child (\d+)/.exec(line)?.[1]);

    expect(child).toBeGreaterThan(0);
    holder.kill(9);
    await holder.exited;
    await Bun.sleep(200);
    // the run is gone, its upload is not: nobody else may start
    expect(kernelHeld()).toBe(true);
    expect((await run(["bun", HOLDER, "production", "0"])).code).toBe(6);
    process.kill(child, "SIGKILL");
    await Bun.sleep(300);
    expect(kernelHeld()).toBe(false);
  }, 30_000);

  test("no environment variable makes a run the holder: with an external holder and no record, it refuses", async () => {
    const helper = externalHolder();

    try {
      await firstLine(helper.stdout);
      const leaked = await run(["bun", HOLDER, "production", "0"], { APM_RELEASE_LOCK_HELD: lock });

      expect(leaked.code).toBe(6);
      expect(leaked.out).toContain("a process without a live holder record");
    } finally {
      helper.kill();
      await helper.exited;
    }
  }, 30_000);

  test("the CLI the incident helper calls asks the kernel: an external holder without a record is HELD", async () => {
    expect(await run(["bun", CLI, "path"])).toEqual({ code: 0, out: `${lock}\n${lock}.json\n` });
    expect(await run(["bun", CLI, "status"])).toEqual({ code: 0, out: "FREE\n" });
    const helper = externalHolder();

    try {
      await firstLine(helper.stdout);
      const status = await run(["bun", CLI, "status"]);

      expect(status.code).toBe(6);
      expect(status.out).toContain("HELD");
      expect((await run(["bun", CLI, "wait", "--timeout", "1"])).code).toBe(6);
      // asking never took it: a run still refuses
      expect((await run(["bun", HOLDER, "staging", "0"])).code).toBe(6);
    } finally {
      helper.kill();
      await helper.exited;
    }

    expect(await run(["bun", CLI, "wait", "--timeout", "5"])).toEqual({ code: 0, out: "FREE\n" });
    // a run's record names its holder while the run holds the lock
    const holder = start(["production", "20"]);

    try {
      await firstLine(holder.stdout);
      expect((await run(["bun", CLI, "status"])).out).toContain('"stage":"production"');
    } finally {
      holder.kill();
      await holder.exited;
    }
  }, 40_000);
});
