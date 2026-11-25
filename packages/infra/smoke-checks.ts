// The decisions smoke.ts makes that do not need a network: how long a request or a command may take, whether a 404 from
// /install can pass, and whether the package check's answer for a very large package is a real verdict.
import { existsSync, readFileSync } from "node:fs";
import { z } from "zod";
import { CliRelease, readCliReleases } from "./cli-ledger.ts";

export type SmokeTimeouts = { httpMs: number; commandMs: number };

/**
 * One PASS or FAIL line. A detail carries text the stage under test wrote (a verdict's summary, an error body), so line
 * breaks and other control characters become spaces: the stage cannot print a line of its own, such as a forged PASS.
 */
export function resultLine(ok: boolean, name: string, detail: string): string {
  const printable = (c: string): boolean => {
    const code = c.codePointAt(0) ?? 0;

    return code >= 0x20 && !(code >= 0x7f && code <= 0x9f) && code !== 0x2028 && code !== 0x2029;
  };

  const oneLine = (s: string): string => [...s].map((c) => (printable(c) ? c : " ")).join("");

  return `${ok ? "PASS" : "FAIL"}: ${oneLine(name)} (${oneLine(detail)})\n`;
}

/**
 * One HTTP request (headers and body) and one command smoke.ts runs. A hung endpoint fails its check after these
 * instead of holding the deploy, which waits on smoke under the release lock. APM_SMOKE_HTTP_TIMEOUT_MS and
 * APM_SMOKE_COMMAND_TIMEOUT_MS override them.
 */
export function smokeTimeouts(env: Readonly<Record<string, string | undefined>>): SmokeTimeouts {
  const ms = (name: string, fallback: number): number => {
    const given = env[name];

    if (given === undefined || given === "") return fallback;
    const n = Number(given);

    if (!Number.isInteger(n) || n <= 0) throw new Error(`${name} must be a whole number of milliseconds above 0, not ${JSON.stringify(given)}`);

    return n;
  };

  // apm add of a version not scored yet waits on the registry's queue (about 20 s) and a cold analysis can take longer
  return { httpMs: ms("APM_SMOKE_HTTP_TIMEOUT_MS", 30_000), commandMs: ms("APM_SMOKE_COMMAND_TIMEOUT_MS", 600_000) };
}

/**
 * What this machine's CLI release record says: absent (smoke.ts running away from the deploy machine), unreadable (a
 * line that does not parse, such as one torn by a crash, so the record cannot vouch that a release never happened), or
 * read.
 */
export type CliRecord = { kind: "absent"; path: string } | { kind: "unreadable"; path: string; broken: number } | { kind: "read"; releases: readonly CliRelease[] };

function parsesAsRelease(line: string): boolean {
  try {
    return CliRelease.safeParse(JSON.parse(line)).success;
  } catch {
    return false;
  }
}

/** The record at `path` for `stage`. readCliReleases drops a broken line; here one makes the whole record unreadable. */
export function cliRecordOf(stage: CliRelease["stage"], path: string): CliRecord {
  if (!existsSync(path)) return { kind: "absent", path };

  const broken = readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => l.trim() !== "" && !parsesAsRelease(l)).length;

  return broken > 0 ? { kind: "unreadable", path, broken } : { kind: "read", releases: readCliReleases(stage, path) };
}

export type InstallStep = { kind: "install" } | { kind: "skip"; detail: string } | { kind: "fail"; detail: string };

/**
 * A stage with no CLI release yet answers /install with 404, which passes only while a readable record says so. Without
 * one a 404 proves nothing: a stage that never had a CLI release cannot be told from one whose install broke. The record
 * is read only for a 404: a stage that serves its installer is checked by installing, whatever this machine's record says.
 */
export function installStep(input: { status: number; stage: string; readRecord: () => CliRecord }): InstallStep {
  if (input.status !== 404) return { kind: "install" };
  const record = input.readRecord();

  if (record.kind === "absent") {
    return { kind: "fail", detail: `/install answers 404 and this machine has no CLI release record (${record.path}), so a stage that never had a CLI release cannot be told from a broken install. Run the smoke check where release-cli.ts runs, or set APM_CLI_RELEASES_LEDGER to that record` };
  }

  if (record.kind === "unreadable") {
    return { kind: "fail", detail: `/install answers 404 and the CLI release record (${record.path}) has ${record.broken} line(s) that do not parse, so it cannot show that ${input.stage} never had a CLI release` };
  }

  if (record.releases.length === 0) return { kind: "skip", detail: `skipped: no CLI release on ${input.stage} yet (bun packages/infra/release-cli.ts --stage ${input.stage})` };

  return { kind: "install" };
}

/** What the command printed and how it ended; `stopped` when it ran past its time and was killed. */
export type Ran = { code: number; stdout: string; stderr: string; stopped: boolean };

/** Process groups spawnBounded started that have not ended yet. */
const running = new Set<number>();

/** Kills every group still running. smoke.ts calls it on exit: a detached group outlives its parent and its timer. */
export function killRunning(): void {
  for (const pid of running) {
    try {
      process.kill(-pid, "SIGKILL");
    } catch {
      // the group already ended
    }
  }
}

/**
 * Runs `cmd` in a process group of its own and kills the whole group with SIGKILL after `ms`. Bun's spawn timeout sends
 * one signal to one process: npm ignores SIGTERM while a request hangs, and in `curl | sh` the pipeline's children
 * outlive their shell and keep the output open, so either would hold the run.
 */
export async function spawnBounded(cmd: string[], options: { cwd: string; env: Record<string, string> }, ms: number): Promise<Ran> {
  const proc = Bun.spawn(cmd, { ...options, stdout: "pipe", stderr: "pipe", detached: true });
  let stopped = false;

  running.add(proc.pid);

  const timer = setTimeout(() => {
    stopped = true;

    try {
      process.kill(-proc.pid, "SIGKILL");
    } catch {
      // the group already ended
    }
  }, ms);

  try {
    const [stdout, stderr, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);

    return { code, stdout, stderr, stopped };
  } finally {
    clearTimeout(timer);
    running.delete(proc.pid);
  }
}

/**
 * Packages big enough that their check walks a large tree: issue #1, where they answered "unknown" for over 90 minutes.
 * next is smoke-probes.ts's largeExplain, which must answer install for a pinned version.
 */
export const LARGE_PACKAGES = ["firebase"] as const;

const DECIDED = new Set(["install", "review-first", "do-not-install"]);

/** The part of GET /api/explain's answer this check reads. */
const ExplainAnswer = z.object({ verdict: z.string(), version: z.string().nullish(), summary: z.string().nullish() });

export type CheckAnswer = { ok: boolean; detail: string };

/** Whether the package check's answer for `name` is a real verdict with a version, and what it said. */
export function largePackageAnswer(input: { name: string; status: number; body: unknown }): CheckAnswer {
  if (input.status !== 200) return { ok: false, detail: `${input.name}: HTTP ${input.status}` };
  const parsed = ExplainAnswer.safeParse(input.body);

  if (!parsed.success) return { ok: false, detail: `${input.name}: verdict missing` };
  const { verdict, version, summary } = parsed.data;

  if (!DECIDED.has(verdict)) return { ok: false, detail: `${input.name}: verdict ${verdict}${summary ? ` (${summary.slice(0, 160)})` : ""}` };

  return version ? { ok: true, detail: `${verdict} ${version}` } : { ok: false, detail: `${input.name}: verdict ${verdict} with no version` };
}
