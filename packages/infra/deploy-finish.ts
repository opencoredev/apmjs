// What deploy.ts does once Alchemy has exited, still under the release lock: the stage's smoke check, once, then the
// release record (deploy-record.ts). Any failure leaves nothing recorded and rolls nothing back, and prints what to do
// next (recoveryAdvice): the rollback.ts command to the last recorded build when every live version is one the record
// names, or fix forward when this run left a version live that it did not record, since rollback.ts never replaces a
// version it cannot identify.
import { join } from "node:path";
import type { Recording } from "./deploy-record.ts";
import { fixForward, listDeployments, scriptName, unrecordedVersions, WORKERS, type Cloudflare, type Log, type Stage, type WorkerKind } from "./rollback.ts";
import type { Release } from "./releases.ts";

/** The smoke check deploy.ts runs: the run's build, which the answering versions must report, and the subdomain it resolved. */
export function smokeCommand(infra: string, stage: Stage, build: string, subdomain: string): string[] {
  return ["bun", join(infra, "smoke.ts"), "--stage", stage, "--build", build, "--subdomain", subdomain];
}

function rollbackCommand(stage: Stage, releases: readonly Release[]): string {
  const last = releases.at(-1);

  return last === undefined
    ? `no build of ${stage} is in the release record yet, so there is nothing recorded to roll back to: ${fixForward(stage)}`
    : `to go back to the last recorded build (${last.build}, ${last.sha.slice(0, 12)}, ${last.at}): bun packages/infra/rollback.ts to --stage ${stage} --build ${last.build} (plan), then again with --yes`;
}

/** What to do after a failed deploy, judged by what is live now. */
export async function recoveryAdvice(input: { cf: Cloudflare; stage: Stage; releases: readonly Release[] }): Promise<string> {
  const unknown: { kind: WorkerKind; text: string }[] = [];

  try {
    for (const kind of WORKERS) {
      const script = scriptName(kind, input.stage);
      const live = (await listDeployments(input.cf, script))?.[0];

      if (live !== undefined) for (const v of unrecordedVersions(script, live, input.releases)) unknown.push({ kind, text: `${script} ${v}` });
    }
  } catch (e) {
    return `What is live could not be read (${e instanceof Error ? e.message : String(e)}). Look with bun packages/infra/rollback.ts list --stage ${input.stage}: a live version marked "not in the release record" cannot be rolled back, so ${fixForward(input.stage)}; otherwise, ${rollbackCommand(input.stage, input.releases)}`;
  }

  if (unknown.length === 0) return rollbackCommand(input.stage, input.releases);
  const named = `Live now: ${unknown.map((u) => u.text).join(", ")}, which no line of the release record names (an upload not recorded). rollback.ts does not replace a version it cannot identify`;

  // the registry and the website go back together, without the docs: an unrecorded docs version alone does not stop them
  if (unknown.every((u) => u.kind === "docs")) return `${named}, so the docs stay as they are. For the registry and the website, ${rollbackCommand(input.stage, input.releases)}`;

  return `${named}, so there is no rollback from here: ${fixForward(input.stage)}`;
}

/** Runs the steps after Alchemy and returns deploy.ts's exit code. The smoke check runs once, and only after Alchemy succeeded. */
export async function finishDeploy(input: { alchemyExit: number; smoke: () => Promise<number>; record: () => Promise<Recording>; advice: () => Promise<string>; log: Log }): Promise<number> {
  const failed = async (what: string): Promise<number> => {
    let advice: string;

    try {
      advice = await input.advice();
    } catch (e) {
      advice = `What to do next could not be worked out (${e instanceof Error ? e.message : String(e)}); look with rollback.ts list.`;
    }

    input.log(`deploy FAILED: ${what}; nothing recorded, nothing rolled back. ${advice}`);

    return 1;
  };

  if (input.alchemyExit !== 0) return failed(`Alchemy exited ${input.alchemyExit}`);

  if ((await input.smoke()) !== 0) return failed("the smoke check failed");
  let recording: Recording;

  try {
    recording = await input.record();
  } catch (e) {
    return failed(`the smoke check passed, but recording the release failed (${e instanceof Error ? e.message : String(e)})`);
  }

  if (recording.kind === "not-recorded") return failed(`the smoke check passed, but this build was NOT recorded (${recording.why})`);
  const { release } = recording;

  input.log(`deploy: smoke check passed; release record: build ${release.build} (install checks ${release.installChecks ?? "database"}): ${Object.entries(release.workers).map(([k, w]) => `${k} ${w.versionId}`).join(", ")}`);

  return 0;
}
