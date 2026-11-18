// The CLI's release record: one line per release-cli.ts run that changed what a stage serves, beside the deploy
// ledger (releases.ts) and kept the same way: ~/.config/apmjs/cli-releases.jsonl, or the path in
// APM_CLI_RELEASES_LEDGER; mode 0600; appended while the release lock is held. A separate file, so rollback.ts, which
// trusts releases.jsonl, never reads a CLI line. smoke.ts reads it: once a stage has a CLI release on record, its
// /install must work.
import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { z } from "zod";
import { CliSum, CliVersion } from "./cli-install.ts";

export const CLI_LEDGER_ENV = "APM_CLI_RELEASES_LEDGER";

export function cliLedgerPath(): string {
  const given = process.env[CLI_LEDGER_ENV];

  return given !== undefined && given !== "" ? given : join(homedir(), ".config", "apmjs", "cli-releases.jsonl");
}

export const CliRelease = z.object({
  version: CliVersion,
  stage: z.enum(["staging", "production"]),
  at: z.string(),
  /** The commit this run ran from ("-dirty" with uncommitted changes); with binaries "republished", not the one they were built from. */
  sha: z.string().min(1),
  /** The site the install script downloads from. */
  site: z.string().url(),
  /** "built" when this run built and uploaded the binaries; "republished" when they were already released. */
  binaries: z.enum(["built", "republished"]),
  sums: z.array(CliSum),
  /** The SHA-256 of the install script this run published. */
  script: z.string().regex(/^[0-9a-f]{64}$/),
});

export type CliRelease = z.infer<typeof CliRelease>;

export function appendCliRelease(release: CliRelease, path: string = cliLedgerPath()): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  appendFileSync(path, `${JSON.stringify(CliRelease.parse(release))}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
}

/** The well-formed lines for `stage`, oldest first. A line that does not parse vouches for nothing. */
export function readCliReleases(stage: CliRelease["stage"], path: string = cliLedgerPath()): CliRelease[] {
  if (!existsSync(path)) return [];
  const out: CliRelease[] = [];

  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (line.trim() === "") continue;

    try {
      const parsed = CliRelease.safeParse(JSON.parse(line));

      if (parsed.success && parsed.data.stage === stage) out.push(parsed.data);
    } catch {
      // a broken line vouches for nothing
    }
  }

  return out;
}
