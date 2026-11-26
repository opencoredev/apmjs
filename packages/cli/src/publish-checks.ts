// What apm publish --dry-run checks before calling a publish fine: the rules the registry and the package manager
// refuse a publish by. manifestChecks needs only package.json (a valid lowercase name, strict semver, not "private");
// registryChecks needs what apm read from the registry (a version not published yet, owners, the rule for new names, a
// name npm has, a reserved or look-alike name). Pure: main.ts reads the registry and prints the result.
import { z } from "zod";
import { isScoped, isValidPublishName, isValidVersion, newNameRuleRefusal, POPULAR_NAMES, typoConflicts, type NamePolicy } from "@apm/core";

/** The name rule apm prints for an invalid name (apm name and apm publish --dry-run). */
export const VALID_NAME_RULE = "a name is lowercase letters, digits and - . _ (and ~ in a scope), starts with a letter or digit, is at most 214 characters, and has at most one scope, as @scope/name";

/**
 * What is already under the package's name: nothing here or on npm, a package on npm that was never published here,
 * a package published here (its owners, and every version it stores, hidden ones included), or no answer.
 */
export type Existing =
  | { kind: "missing" }
  | { kind: "npm" }
  | { kind: "local"; owners: readonly string[]; versions: readonly string[]; complete: boolean }
  | { kind: "unknown" };

/**
 * What apm read from the registry for the checks. `user` is the login of the token apm would publish with, null when
 * there is none or it could not be read; `policy` is the registry's rule for new names, null when it could not be read.
 */
export type RegistryView = { user: string | null; policy: NamePolicy | null; existing: Existing };

/** One finding: the registry or the package manager would refuse the publish, or apm cannot say whether it would. */
export type PublishCheck = { kind: "refused"; reason: string } | { kind: "unconfirmed"; reason: string };

/**
 * What the upload does with a version's build metadata (`+ci.7`): "dropped" when npm uploads it (npm sends the version
 * through semver.clean, the tarball keeps it, and the registry refuses the mismatch); "unknown" for other clients.
 */
export type BuildMetadata = "dropped" | "unknown";

/** The fields of a package.json a publish is refused by, as read: anything may be missing or of the wrong type. */
export type PublishFields = { name: unknown; version: unknown; private: unknown; build: BuildMetadata };

/** manifestChecks' answer: the name and version a publish would carry, or every refusal and warning package.json alone gives. */
export type ManifestVerdict = { kind: "ok"; name: string; version: string; checks: PublishCheck[] } | { kind: "refused"; checks: PublishCheck[] };

/** The version semver compares: build metadata is ignored, so 1.0.0+a and 1.0.0 are one version to a registry. */
export const withoutBuild = (version: string): string => version.split("+")[0] ?? version;

function nameRefusal(name: string): string | null {
  if (isValidPublishName(name)) return null;
  const lower = name.toLowerCase();

  return isValidPublishName(lower) ? `${name} is not a valid name for a new package: npm names are lowercase. Use ${lower}.` : `${name} is not a valid package name: ${VALID_NAME_RULE}.`;
}

function versionCheck(version: string, build: BuildMetadata): PublishCheck | null {
  if (!isValidVersion(version)) return { kind: "refused", reason: `"${version}" is not a version apm accepts: apm takes strict semver only (1.2.3, 1.2.3-beta.1).` };

  if (!version.includes("+")) return null;
  const sent = withoutBuild(version);

  return build === "dropped"
    ? { kind: "refused", reason: `npm uploads ${version} as ${sent}, without its build metadata, and the registry refuses a publish whose version differs from the tarball's. Drop the "+..." part.` }
    : { kind: "unconfirmed", reason: `${version} has build metadata; an upload that sends it as ${sent} (as npm does) is refused for not matching the tarball. Drop the "+..." part to be sure.` };
}

/** What package.json alone says would be refused or is uncertain: no registry answer needed. */
export function manifestChecks(fields: PublishFields): ManifestVerdict {
  const name = z.string().safeParse(fields.name);
  const version = z.string().safeParse(fields.version);
  const named = name.success ? nameRefusal(name.data) : `package.json has no "name" string, so there is nothing to publish under. Set "name", such as "@your-github-login/my-lib".`;
  const versioned: PublishCheck | null = version.success ? versionCheck(version.data, fields.build) : { kind: "refused", reason: `package.json has no "version" string. Set "version", such as "1.0.0".` };

  const checks: PublishCheck[] = [
    ...(fields.private === true || fields.private === "true" ? [{ kind: "refused" as const, reason: `package.json has "private": true, so package managers refuse to publish it. Remove "private" to publish.` }] : []),
    ...(named === null ? [] : [{ kind: "refused" as const, reason: named }]),
    ...(versioned === null ? [] : [versioned]),
  ];

  if (!name.success || !version.success || checks.some((c) => c.kind === "refused")) return { kind: "refused", checks };

  return { kind: "ok", name: name.data, version: version.data, checks };
}

/** The registry's rules for a first publish of `name`: its rule for new names, then reserved, npm's and look-alike names. */
function newNameChecks(name: string, view: RegistryView): PublishCheck[] {
  const { user, policy, existing } = view;
  const out: PublishCheck[] = [];

  if (isScoped(name) && user === null) {
    out.push({ kind: "unconfirmed", reason: `apm cannot confirm that @${name.slice(1, name.indexOf("/"))} is yours: you are not logged in to this registry. Log in, then run the dry run again.` });
  } else if (!isScoped(name) && policy === null) {
    out.push({ kind: "unconfirmed", reason: `apm could not read this registry's rules for new names, so it cannot say whether the bare name ${name} may be published (apm's own registry takes a new package only under your GitHub login).` });
  } else {
    const refused = newNameRuleRefusal({ name, user: user ?? "<your GitHub login>", policy: policy ?? "scoped" });

    if (refused !== null) out.push({ kind: "refused", reason: refused });
  }

  if (POPULAR_NAMES.includes(name)) out.push({ kind: "refused", reason: `${name} is a reserved name (a widely used public package), so the registry refuses it. Pick another name under your scope.` });
  else if (existing.kind === "npm") out.push({ kind: "refused", reason: `${name} already exists on npm, and apm shares one namespace with it, so it cannot be published over here. Pick another name under your scope.` });
  const conflicts = existing.kind === "missing" ? typoConflicts(name) : [];

  if (conflicts.length > 0) out.push({ kind: "refused", reason: `${name} is too close to a popular package (${conflicts.map((c) => c.reason).join("; ")}), and the registry refuses look-alikes. Pick a more distinct name.` });

  return out;
}

function nameChecks(name: string, view: RegistryView): PublishCheck[] {
  const { user, existing } = view;

  switch (existing.kind) {
    case "local":
      if (user === null) return [{ kind: "unconfirmed", reason: `apm cannot confirm that you own ${name}: you are not logged in to this registry. Log in, then run the dry run again.` }];

      return existing.owners.includes(user) ? [] : [{ kind: "refused", reason: `${name} already exists and ${user} is not one of its owners (${existing.owners.join(", ") || "none listed"}); only an owner can publish a new version.` }];
    case "unknown":
      return [{ kind: "unconfirmed", reason: `apm could not read whether ${name} exists on this registry or on npm, so it cannot say whether you may publish it or whether this version is already published.` }];
    case "npm":
    case "missing":
      return newNameChecks(name, view);
    default: {
      const _exhaustive: never = existing;

      return _exhaustive;
    }
  }
}

/** What the registry would refuse this publish for, by what apm read from it. Run after manifestChecks passes. */
export function registryChecks(input: { name: string; version: string; view: RegistryView }): PublishCheck[] {
  const { name, version, view } = input;
  const { existing } = view;
  const same = existing.kind === "local" ? existing.versions.find((v) => withoutBuild(v) === withoutBuild(version)) : undefined;

  const published: PublishCheck[] =
    same !== undefined
      ? [{ kind: "refused", reason: `${name}@${same} is already published (or was, and was yanked or revoked). Versions are immutable; bump the version (apm publish --bump patch).` }]
      : existing.kind === "local" && !existing.complete
        ? [{ kind: "unconfirmed", reason: `apm read only the newest of ${name}'s many versions, so it cannot confirm ${version} is not an older one already published.` }]
        : [];

  return [...published, ...nameChecks(name, view)];
}
