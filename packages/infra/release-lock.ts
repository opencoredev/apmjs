// The release lock: one exclusive lock that every change to apm's Workers or database takes, shared with the incident
// agent's helper. The contract, agreed with that helper:
//
// - an exclusive flock(LOCK_EX|LOCK_NB) on /home/leo/.config/apmjs/release.lock by default (~/.config/apmjs/release.lock
//   for whoever runs it), or on the path in the APM_RELEASE_LOCK environment variable;
// - a run that finds it held refuses (exit 6), naming the holder; nothing waits for it, and nothing releases it on a
//   timer;
// - it is held for the whole run: deploy.ts through its migrations, builds, upload, smoke check and release record;
//   rollback.ts (with --yes) through the rollback. The children a run starts to change
//   anything (Alchemy's upload, the smoke check) hold it too;
// - the holder is recorded in release.lock.json next to the lock: pid, start time, command, git SHA and stage. The record
//   only describes the holder: whether the lock is held is the kernel's answer, never the record's.
//
// How: Bun's standard library has no flock, so a run opens the lock file and has util-linux's flock(1) lock that open
// file description (`flock -n 3`, the descriptor handed to it as fd 3). A flock belongs to the open file description,
// not to a process, so the lock stays held while any process has that description open: the run itself, and every child
// it starts with lockedSpawn, which hands the same description to the child as its fd 3 (Bun closes other descriptors
// in children). Killing the run while a child it started is still uploading leaves the lock held until that child ends.
// There is no other way to hold it: no environment variable makes a run the holder.
//
// The lock is machine-local: it serializes runs on one machine, and every production deploy runs on evo-1 from
// /home/leo/code/apmjs (docs/DEPLOY.md, "The release lock").
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { z } from "zod";

/** The variable naming the lock file; deploy.ts and rollback.ts honour it, and the incident helper looks for it. */
export const LOCK_ENV = "APM_RELEASE_LOCK";

/** flock(1)'s exit code when the lock is held by someone else (its -E). */
const BUSY_EXIT = 75;

/** What deploy.ts and rollback.ts exit with when the lock is held. */
export const BUSY_CODE = 6;

/** The descriptor number a locked child receives the lock on. */
export const LOCK_FD = 3;

export function releaseLockPath(): string {
  const given = process.env[LOCK_ENV];

  return given !== undefined && given !== "" ? given : join(homedir(), ".config", "apmjs", "release.lock");
}

export function holderPath(lock: string = releaseLockPath()): string {
  return `${lock}.json`;
}

const Holder = z.object({ pid: z.number().int(), started: z.string(), command: z.array(z.string()), sha: z.string(), stage: z.string() });

export type Holder = z.infer<typeof Holder>;

/** The holder record, when there is one that parses. It says who took the lock; it does not say the lock is held. */
export function recordedHolder(lock: string = releaseLockPath()): Holder | null {
  const path = holderPath(lock);

  if (!existsSync(path)) return null;

  try {
    const parsed = Holder.safeParse(JSON.parse(readFileSync(path, "utf8")));

    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);

    return true;
  } catch {
    return false;
  }
}

/** The holder record when its process still lives (a run killed with -9 leaves its record behind); it only describes. */
export function liveHolder(lock: string = releaseLockPath()): Holder | null {
  const holder = recordedHolder(lock);

  return holder !== null && alive(holder.pid) ? holder : null;
}

/**
 * Whether anyone holds the lock, by the kernel: a non-blocking exclusive flock on a fresh descriptor fails. When it is
 * free the attempt holds it for the instant flock(1) takes to exit.
 */
export function isHeld(lock: string = releaseLockPath()): boolean {
  if (!existsSync(lock)) return false;

  return Bun.spawnSync(["flock", "-n", "-E", String(BUSY_EXIT), lock, "true"]).exitCode === BUSY_EXIT;
}

/** A held release lock: the open file description that holds it. */
export type ReleaseLock = { readonly path: string; readonly fd: number };

export type TakeResult = { kind: "held"; lock: ReleaseLock } | { kind: "busy"; text: string };

function gitSha(dir: string): string {
  const head = Bun.spawnSync(["git", "rev-parse", "HEAD"], { cwd: dir }).stdout.toString().trim();

  return head === "" ? "unknown" : head;
}

/**
 * Takes the release lock without waiting, for the rest of this process's life (and its locked children's). `script`'s
 * checkout gives the git SHA in the holder record.
 */
export function takeReleaseLock(input: { script: string; argv: readonly string[]; stage: string }): TakeResult {
  const path = releaseLockPath();

  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const fd = openSync(path, "a+", 0o600);
  const take = Bun.spawnSync(["flock", "-n", "-E", String(BUSY_EXIT), String(LOCK_FD)], { stdio: ["ignore", "ignore", "pipe", fd] });

  if (take.exitCode === BUSY_EXIT) {
    closeSync(fd);

    return { kind: "busy", text: busyText(path) };
  }

  if (take.exitCode !== 0) {
    closeSync(fd);
    throw new Error(`flock(1) could not take ${path} (exit ${take.exitCode}): ${take.stderr.toString().trim()}. Is util-linux's flock installed?`);
  }

  const mine: Holder = { pid: process.pid, started: new Date().toISOString(), command: [process.execPath, input.script, ...input.argv], sha: gitSha(dirname(input.script)), stage: input.stage };

  writeFileSync(holderPath(path), `${JSON.stringify(mine)}\n`, { mode: 0o600 });
  process.on("exit", () => {
    if (recordedHolder(path)?.pid === process.pid) rmSync(holderPath(path), { force: true });
  });

  return { kind: "held", lock: { path, fd } };
}

type Stdio = "inherit" | "ignore" | "pipe";

/** Starts a child that holds the lock too: it receives the lock's open file description as its fd 3. */
export function lockedSpawn(lock: ReleaseLock, cmd: string[], options: { cwd: string; env: Record<string, string | undefined>; stdin?: Stdio; stdout?: Stdio; stderr?: Stdio }) {
  return Bun.spawn(cmd, { cwd: options.cwd, env: options.env, stdio: [options.stdin ?? "inherit", options.stdout ?? "inherit", options.stderr ?? "inherit", lock.fd] });
}

/** The sentence for a held lock. */
export function busyText(lock: string = releaseLockPath()): string {
  const holder = liveHolder(lock);
  const who = holder === null ? "a process without a live holder record (one it started may still be running)" : `pid ${holder.pid} (${holder.command.slice(1).join(" ")}, stage ${holder.stage}, commit ${holder.sha.slice(0, 12)}) since ${holder.started}`;

  return `refused: the release lock ${lock} (${LOCK_ENV}) is held by ${who}; nothing was changed.`;
}

/** What status and wait print: the kernel's answer, and the live record when there is one. */
type LockState = { held: boolean; line: string };

function describe(lock: string): LockState {
  if (!isHeld(lock)) return { held: false, line: "FREE" };
  const holder = liveHolder(lock);

  return { held: true, line: `HELD ${JSON.stringify(holder ?? { holder: "unknown: no live holder record" })}` };
}

/**
 * The CLI the incident agent's helper calls. It never holds the lock longer than the instant it takes to ask the kernel.
 *
 *   bun packages/infra/release-lock.ts path                      the lock file and its holder record
 *   bun packages/infra/release-lock.ts status                    FREE (exit 0), or HELD and the holder record as JSON (exit 6)
 *   bun packages/infra/release-lock.ts wait [--timeout SECONDS]  until it is free (exit 0), or HELD at the timeout (exit 6); default 1800
 *
 * Free when it answers is not a reservation: deploy.ts and rollback.ts take the lock themselves, atomically, and refuse
 * with exit 6 if someone got there first.
 */
async function cli(argv: readonly string[]): Promise<number> {
  const lock = releaseLockPath();

  switch (argv[0]) {
    case "path":
      process.stdout.write(`${lock}\n${holderPath(lock)}\n`);

      return 0;
    case "status": {
      const now = describe(lock);

      process.stdout.write(`${now.line}\n`);

      return now.held ? BUSY_CODE : 0;
    }

    case "wait": {
      const at = argv.indexOf("--timeout");
      const timeoutS = at > 0 ? Number(argv[at + 1]) : 1800;

      if (!Number.isFinite(timeoutS) || timeoutS < 0) {
        process.stdout.write("--timeout takes seconds\n");

        return 2;
      }

      const end = Date.now() + timeoutS * 1000;

      for (;;) {
        const now = describe(lock);

        if (!now.held || Date.now() >= end) {
          process.stdout.write(`${now.line}\n`);

          return now.held ? BUSY_CODE : 0;
        }

        await Bun.sleep(2_000);
      }
    }

    default:
      process.stdout.write("usage: release-lock.ts path | status | wait [--timeout SECONDS]\n");

      return 2;
  }
}

if (import.meta.main) process.exit(await cli(process.argv.slice(2)));
