// What install reads of npm's packages check on a deploy (registry edge-checks.ts, the Worker's APM_INSTALL_CHECKS):
// "database", one statement each, unless the deploy asks for "edge" with --install-checks edge or
// APM_INSTALL_CHECKS=edge. Edge goes on only in a deploy of its own, once a build with the publish fence is the only
// one serving (docs/DEPLOY.md, "Install checks"); a value that is neither stops the deploy.
import { z } from "zod";

export const InstallChecks = z.enum(["database", "edge"]);

export type InstallChecks = z.infer<typeof InstallChecks>;

/** The read mode `argv` (the flag wins) or `env` asks for; "database" when neither does. */
export function installChecksOf(input: { argv: readonly string[]; env: Readonly<Record<string, string | undefined>> }): InstallChecks {
  const at = input.argv.indexOf("--install-checks");

  // a flag with no value is refused, not read as the default
  if (at >= 0) return InstallChecks.parse(input.argv[at + 1]);

  return InstallChecks.parse(input.env.APM_INSTALL_CHECKS ?? "database");
}
