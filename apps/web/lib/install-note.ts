// What the package page's install box says under each client's command. apm add runs the checks itself; a
// stock client only gets them once it is pointed at apm, so its note names the one setting that does that.
import { z } from "zod";
import "./zod-csp";

export const INSTALL_CLIENTS = ["apm", "bun", "npm", "pnpm"] as const;

export const InstallClient = z.enum(INSTALL_CLIENTS);

export type InstallClient = z.infer<typeof InstallClient>;

export const BUN_SCANNER = "@apm/bun-scanner";

const APM_ADD_CHECKS = "apm add checks the score, cooldown and dependency tree without changing your config.";

export type InstallNote =
  /** apm add: the checks run before the package manager does. */
  | { kind: "checked"; text: string; docs: string }
  /** A stock client: what it skips, the setting that turns the checks on, and what that setting checks. */
  | { kind: "needs-setup"; lead: string; file: string; config: string; checks: string; docs: string };

/** A registry base URL that ends in "/". */
function base(registry: string): string {
  return registry.replace(/\/?$/, "/");
}

export function installCommand({ client, name, version }: { client: InstallClient; name: string; version: string | null }): string {
  const spec = version ? `${name}@${version}` : name;

  switch (client) {
    case "apm":
      return `apm add ${name}`;
    case "bun":
      return `bun add ${spec}`;
    case "npm":
      return `npm install ${spec}`;
    case "pnpm":
      return `pnpm add ${spec}`;
    default: {
      const _exhaustive: never = client;

      return _exhaustive;
    }
  }
}

export function installNote({ client, registry }: { client: InstallClient; registry: string }): InstallNote {
  const url = base(registry);

  switch (client) {
    case "apm":
      return {
        kind: "checked",
        text: "Checks the score, the 24-hour cooldown and the dependency tree first, then runs your project’s own package manager with the exact version.",
        docs: "/docs#cli",
      };
    case "bun":
      return {
        kind: "needs-setup",
        lead: "Plain bun skips apm’s checks. Point it at apm and add the scanner in bunfig.toml:",
        file: "bunfig.toml",
        config: `[install]\nregistry = "${url}"\n\n[install.security]\nscanner = "${BUN_SCANNER}"`,
        checks: `The scanner refuses revoked versions and packages scoring under 40. ${APM_ADD_CHECKS}`,
        docs: "/docs#bun",
      };
    case "npm":
    case "pnpm":
      return {
        kind: "needs-setup",
        lead: `Plain ${client} skips apm’s checks. Set its registry to apm’s ~safe view in .npmrc:`,
        file: ".npmrc",
        config: `registry=${url}~safe/`,
        checks: `~safe hides versions under 24 hours old and versions scoring under 40. ${APM_ADD_CHECKS}`,
        docs: "/docs#npm",
      };
    default: {
      const _exhaustive: never = client;

      return _exhaustive;
    }
  }
}
