// What deploy.ts writes to the release record after a deploy whose smoke check passed, still under the release lock:
// the live deployment of each Worker, read from Cloudflare, as one line with the run's build id, git SHA, stage and
// migration manifest (releases.ts). A line must name every Worker, so that a rollback can trust it whole; a run that
// cannot be recorded leaves no line.
//
// What is live is confirmed to be this run's before it is written: Cloudflare's deployment list can lag an upload and
// still name the previous version at 100%, and labelling that version with this run's manifest would let a rollback
// trust old code with a schema it was never built for. So the registry's and the website's live versions must each
// carry this run's stamp in their settings: APM_BUILD, APM_REVISION and the sealed migration manifest, exactly
// (rollback.ts, provenanceVars). A read that does not show them yet is tried again until RECORD_DEADLINE_MS has passed;
// that one deadline bounds every request (each is cut short when the time left runs out) and every wait, and is checked
// again just before the line is appended, so the run is either recorded within it or not recorded at all. The stamp corroborates this run at this moment; later, rollback.ts trusts only the
// record, never a version's variables.
//
// The docs Worker is assets-only: Cloudflare keeps no variables on its versions, and Alchemy uploads it only when its
// pages change, so its live version is recorded as it is. It runs no code against the database.
import { appendRelease, type Release } from "./releases.ts";
import { listDeployments, provenanceVars, receiving, scriptName, versionVariables, WORKERS, type Cloudflare, type Stage, type WorkerKind } from "./rollback.ts";

export type Recording = { kind: "recorded"; release: Release } | { kind: "not-recorded"; why: string };

/** How long recording waits for Cloudflare to show this run's versions as live. */
export const RECORD_DEADLINE_MS = 60_000;

/** The Workers whose live version must carry this run's stamp. */
const STAMPED: readonly WorkerKind[] = ["registry", "web"];

type Attempt = { kind: "live"; workers: Release["workers"] } | { kind: "not-yet"; why: string };

async function attempt(input: { cf: Cloudflare; stage: Stage; stamp: Readonly<Record<string, string>>; left: () => number }): Promise<Attempt> {
  const workers: Release["workers"] = {};

  for (const kind of WORKERS) {
    const script = scriptName(kind, input.stage);
    const live = (await listDeployments(input.cf, script, input.left()))?.[0];
    const versions = live === undefined ? [] : receiving(live.versions);
    const only = versions[0];

    if (only === undefined || versions.length !== 1 || only.percentage !== 100) {
      return { kind: "not-yet", why: `${script} does not route all its traffic to one version (${versions.map((v) => `${v.version_id}@${v.percentage}%`).join(", ") || "no deployment"})` };
    }

    if (STAMPED.includes(kind)) {
      const vars = await versionVariables(input.cf, script, only.version_id, input.left());
      const wrong = Object.entries(input.stamp).filter(([name, value]) => vars[name] !== value);

      if (wrong.length > 0) {
        const build = vars.APM_BUILD ?? "none";
        const why = build === input.stamp.APM_BUILD ? `says build ${build} but differs from this run's stamp in ${wrong.map(([name]) => name).join(", ")}` : `says build ${build}, not this run's ${input.stamp.APM_BUILD}`;

        return { kind: "not-yet", why: `${script} version ${only.version_id} ${why}` };
      }
    }

    workers[kind] = { script, versionId: only.version_id };
  }

  return { kind: "live", workers };
}

export async function recordLiveRelease(input: {
  cf: Cloudflare;
  stage: Stage;
  build: string;
  sha: string;
  manifest: readonly string[];
  append?: (release: Release) => void;
  deadlineMs?: number;
  intervalMs?: number;
}): Promise<Recording> {
  const stamp = provenanceVars(input.sha, input.build, input.manifest);
  const deadline = input.deadlineMs ?? RECORD_DEADLINE_MS;
  const end = Date.now() + deadline;
  const left = (): number => end - Date.now();
  let last = "nothing was read in time";
  const expired = (): Recording => ({ kind: "not-recorded", why: `this run's versions were not confirmed live within ${deadline} ms (${last})` });

  for (;;) {
    if (left() <= 0) return expired();
    let now: Attempt;

    try {
      now = await attempt({ cf: input.cf, stage: input.stage, stamp, left });
    } catch (e) {
      // a request cut short by the time left is a read that did not come back in time, not a failure of its own
      if (!(e instanceof Error && e.name === "TimeoutError") && left() > 0) throw e;
      now = { kind: "not-yet", why: "a Cloudflare read timed out" };
    }

    if (now.kind === "live") {
      if (left() <= 0) return expired();
      const release: Release = { build: input.build, sha: input.sha, stage: input.stage, at: new Date().toISOString(), manifest: [...input.manifest], workers: now.workers };

      (input.append ?? appendRelease)(release);

      return { kind: "recorded", release };
    }

    last = now.why;

    if (left() <= 0) return expired();
    await Bun.sleep(Math.min(input.intervalMs ?? 3_000, left()));
  }
}
