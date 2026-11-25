// What the package page's install box says under each client's command. apm add runs the checks itself; a
// stock client only gets them once it is pointed at apm, so its note names the one setting that does that.
import { z } from "zod";
import "./zod-csp";

export const INSTALL_CLIENTS = ["apm", "bun", "npm", "pnpm"] as const;

export const InstallClient = z.enum(INSTALL_CLIENTS);

export type InstallClient = z.infer<typeof InstallClient>;

export const BUN_SCANNER = "@apm/bun-scanner";

const APM_ADD_CHECKS = "apm add checks the score, cooldown and dependency tree without changing your registry settings, and warns about a score under 40 or a version published in the last 24 hours (--strict refuses both).";

export type InstallNote =
  /** apm add: the checks run before the package manager does. */
  | { kind: "checked"; text: string; detail: string; docs: string }
  /**
   * A stock client: what it skips, the setting that turns the checks on, what that setting does (`effect`), and
   * `checks`: the effect followed by what apm add checks, for the Markdown view.
   */
  | { kind: "needs-setup"; lead: string; file: string; config: string; effect: string; checks: string; docs: string };

/** A registry base URL that ends in "/". */
function base(registry: string): string {
  return registry.replace(/\/?$/, "/");
}

/**
 * How the install commands name the version a page shows, the same on the page and in its Markdown view:
 * - default: the version installs get by name (latest). apm add resolves its own (it may pick an older one past the
 *   cooldown); stock clients pin `version`, or take the bare name when it is unknown.
 * - tag: a dist-tag, asked for with ?v=<tag> or the default when no installable version is tagged latest.
 * - exact: a version asked for by number; every command pins it.
 */
export type InstallSpec =
  | { readonly kind: "default"; readonly version: string | null }
  | { readonly kind: "tag"; readonly tag: string }
  | { readonly kind: "exact"; readonly version: string };

/** The version or tag an agent's verdict request names after `name@`, or null for the bare name. */
export function specSuffix(install: InstallSpec): string | null {
  switch (install.kind) {
    case "default":
      return null;
    case "tag":
      return install.tag;
    case "exact":
      return install.version;
    default: {
      const _exhaustive: never = install;

      return _exhaustive;
    }
  }
}

/**
 * Whether a dist-tag name may go into a shell command or the agent prompt as it is. npm's tags reach the web unchecked
 * (apm checks only its own packages' tags), so any other tag is not offered: the command pins the version instead.
 */
export const isSafeTag = (tag: string): boolean => /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(tag);

/** How long apm's cooldown holds a new version back (packages/core DEFAULT_POLICY.cooldownMs). */
export const COOLDOWN_MS = 24 * 60 * 60_000;

/** Whether a version published at `publishedAt` is inside apm's cooldown at `now`; false when the time is unknown. */
export function inCooldown(input: { publishedAt: string | null | undefined; now: number }): boolean {
  const at = Date.parse(input.publishedAt ?? "");

  return Number.isFinite(at) && input.now - at < COOLDOWN_MS;
}

/** What the install box says about a version inside the cooldown, in the words the page uses. */
export const cooldownText = (version: string): string =>
  `${version} was published under 24 hours ago, inside apm's cooldown. apm add warns before it installs it and --strict refuses it; plain bun, npm and pnpm install it without that check.`;

export function installCommand({ client, name, install }: { client: InstallClient; name: string; install: InstallSpec }): string {
  const suffix = specSuffix(install);
  const pinned = install.kind === "default" && install.version !== null ? `${name}@${install.version}` : null;
  const spec = suffix === null ? (pinned ?? name) : `${name}@${suffix}`;

  switch (client) {
    case "apm":
      return `apm add ${suffix === null ? name : spec}`;
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
        text: "With bun, npm or pnpm, apm add checks every package in the dependency tree before anything installs.",
        detail: "It refuses revoked, yanked and confirmed malicious versions, and warns about a score under 40 or a version under 24 hours old. Warnings still install; --strict refuses them too. With yarn 1, apm can only check after yarn installs.",
        docs: "/docs#cli",
      };
    case "bun": {
      const effect = `New installs skip revoked, yanked and confirmed malicious versions. The optional ${BUN_SCANNER} also warns about packages scoring under 40; it is not on a registry yet, so the setup guide installs it from a clone of apm.`;

      return {
        kind: "needs-setup",
        lead: "Plain bun skips apm’s checks. Point its registry at apm in bunfig.toml:",
        file: "bunfig.toml",
        config: `[install]\nregistry = "${url}"`,
        effect,
        checks: `${effect} ${APM_ADD_CHECKS}`,
        docs: "/docs#bun",
      };
    }

    case "npm":
    case "pnpm": {
      const effect = `New installs skip revoked, yanked and confirmed malicious versions. For strict mode use registry=${url}~safe/, which hides versions under 24 hours old, versions scoring under 40 and versions apm has not fully analysed.`;

      return {
        kind: "needs-setup",
        lead: `Plain ${client} skips apm’s checks. Point its registry at apm in .npmrc:`,
        file: ".npmrc",
        config: `registry=${url}`,
        effect,
        checks: `${effect} ${APM_ADD_CHECKS}`,
        docs: "/docs#npm",
      };
    }

    default: {
      const _exhaustive: never = client;

      return _exhaustive;
    }
  }
}
