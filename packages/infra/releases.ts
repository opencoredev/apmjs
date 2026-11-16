// The release ledger: what each deploy run left live, kept where only the deploy machine's owner can write it.
// deploy.ts appends one line per run, while it holds the release lock (release-lock.ts), once its smoke check passed:
// the run's build id, git SHA, stage, migration manifest and each Worker's live version (deploy-record.ts). A rollback
// only ever routes traffic to versions this ledger names, and only leaves a registry and a website live together when
// one canonical line names both: a version whose variables say the same build (a dashboard edit that kept them, or
// invented ones) is not in it, so it is never trusted.
//
// The file is /home/leo/.config/apmjs/releases.jsonl by default (~/.config/apmjs/releases.jsonl for whoever runs it), or
// the path in APM_RELEASES_LEDGER; mode 0600. A line that does not parse vouches for nothing.
import { appendFileSync, chmodSync, closeSync, existsSync, fstatSync, mkdirSync, openSync, readFileSync, readSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { z } from "zod";

export const LEDGER_ENV = "APM_RELEASES_LEDGER";

export function ledgerPath(): string {
  const given = process.env[LEDGER_ENV];

  return given !== undefined && given !== "" ? given : join(homedir(), ".config", "apmjs", "releases.jsonl");
}

const LiveVersion = z.object({ script: z.string().min(1), versionId: z.string().min(1) });

const Release = z.object({
  build: z.string().min(1),
  sha: z.string().min(1),
  stage: z.enum(["staging", "production"]),
  at: z.string(),
  manifest: z.array(z.string()),
  workers: z.object({ registry: LiveVersion.optional(), web: LiveVersion.optional(), docs: LiveVersion.optional() }),
});

export type Release = z.infer<typeof Release>;

/** Whether the file at `path` ends with a newline, or is empty: an append then starts a line of its own. */
function endsLine(path: string): boolean {
  if (!existsSync(path)) return true;
  const fd = openSync(path, "r");

  try {
    const size = fstatSync(fd).size;

    if (size === 0) return true;
    const last = Buffer.alloc(1);

    readSync(fd, last, 0, 1, size - 1);

    return last[0] === 0x0a;
  } finally {
    closeSync(fd);
  }
}

/**
 * Appends one run's line. Call it while holding the release lock. A last line left unterminated (a write cut short) is
 * ended first, so it stays a broken line of its own and the new record is never glued to it.
 */
export function appendRelease(release: Release, path: string = ledgerPath()): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const line = `${JSON.stringify(Release.parse(release))}\n`;

  appendFileSync(path, endsLine(path) ? line : `\n${line}`, { mode: 0o600 });
  chmodSync(path, 0o600);
}

/**
 * The canonical lines for `stage`, oldest first: every well-formed line, once per build id. A build id that two lines
 * give different contents (a copied or edited line) vouches for nothing: all its lines are left out.
 */
export function readReleases(stage: Release["stage"], path: string = ledgerPath()): Release[] {
  const lines = wellFormed(stage, path);
  const byBuild = new Map<string, string>();
  const conflicted = new Set<string>();

  for (const r of lines) {
    const text = JSON.stringify(r);
    const seen = byBuild.get(r.build);

    if (seen === undefined) byBuild.set(r.build, text);
    else if (seen !== text) conflicted.add(r.build);
  }

  const emitted = new Set<string>();

  return lines.filter((r) => {
    if (conflicted.has(r.build) || emitted.has(r.build)) return false;
    emitted.add(r.build);

    return true;
  });
}

/** The build ids readReleases leaves out because their lines disagree. */
export function conflictingBuilds(stage: Release["stage"], path: string = ledgerPath()): string[] {
  const all = wellFormed(stage, path);
  const kept = new Set(readReleases(stage, path).map((r) => r.build));

  return [...new Set(all.map((r) => r.build).filter((b) => !kept.has(b)))];
}

function wellFormed(stage: Release["stage"], path: string): Release[] {
  if (!existsSync(path)) return [];
  const out: Release[] = [];

  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (line.trim() === "") continue;

    try {
      const parsed = Release.safeParse(JSON.parse(line));

      if (parsed.success && parsed.data.stage === stage) out.push(parsed.data);
    } catch {
      // a broken line vouches for nothing
    }
  }

  return out;
}

/** Whether `release` names `versionId` as `script`. */
export function names(release: Release, script: string, versionId: string): boolean {
  return Object.values(release.workers).some((w) => w !== undefined && w.script === script && w.versionId === versionId);
}

/** The newest line that names `versionId` as `script`, or null when none does. */
export function releaseOf(releases: readonly Release[], script: string, versionId: string): Release | null {
  return releases.findLast((r) => names(r, script, versionId)) ?? null;
}

/** The newest line that names every one of `pairs` (script, version): one deploy's record of all of them; null when none does. */
export function releaseNamingAll(releases: readonly Release[], pairs: readonly { script: string; versionId: string }[]): Release | null {
  return releases.findLast((r) => pairs.every((p) => names(r, p.script, p.versionId))) ?? null;
}
