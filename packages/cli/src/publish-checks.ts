// What apm publish --dry-run checks before calling a publish fine: the rules the registry and the package manager
// refuse a publish by (a valid lowercase name, strict semver, not "private", a version not published yet, the
// registry's rule for new names, a name npm already has, a look-alike of a popular name). Pure: main.ts reads the
// registry and prints the result.
import { isScoped, isValidPackageName, isValidVersion, newNameRuleRefusal, typoConflicts, type NamePolicy } from "@apm/core";

/** The name rule apm prints for an invalid name (apm name and apm publish --dry-run). */
export const VALID_NAME_RULE = "a name is lowercase letters, digits and - . _ (and ~ in a scope), starts with a letter or digit, is at most 214 characters, and has at most one scope, as @scope/name";

/**
 * What is already under the package's name: nothing here or on npm, a package on npm that was never published here,
 * a package published here (its owners, and every version it stores, hidden ones included), or no answer.
 */
export type Existing =
  | { kind: "missing" }
  | { kind: "npm" }
  | { kind: "local"; owners: readonly string[]; versions: readonly string[] }
  | { kind: "unknown" };

/**
 * What apm read from the registry for the checks. `user` is the login of the token apm would publish with, null when
 * there is none or it could not be read; `policy` is the registry's rule for new names, null when it could not be read.
 */
export type RegistryView = { user: string | null; policy: NamePolicy | null; existing: Existing };

/** One finding: the registry or the package manager would refuse the publish, or apm cannot say whether it would. */
export type PublishCheck = { kind: "refused"; reason: string } | { kind: "unconfirmed"; reason: string };

/** The version semver compares: build metadata is ignored, so 1.0.0+a and 1.0.0 are one version to a registry. */
export const withoutBuild = (version: string): string => version.split("+")[0] ?? version;

/** The registry's rules for a first publish of `name`: its rule for new names, then npm's names, then look-alikes. */
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

  if (existing.kind === "npm") out.push({ kind: "refused", reason: `${name} already exists on npm, and apm shares one namespace with it, so it cannot be published over here. Pick another name under your scope.` });
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

/** Everything that would stop this publish, in the order a person fixes it: package.json first, then the registry. */
export function publishChecks(input: { name: string; version: string; private: boolean; view: RegistryView }): PublishCheck[] {
  const { name, version, view } = input;
  const out: PublishCheck[] = [];

  if (input.private) out.push({ kind: "refused", reason: `package.json has "private": true, so package managers refuse to publish it. Remove "private" to publish.` });

  if (!isValidPackageName(name)) {
    const lower = name.toLowerCase();
    out.push({ kind: "refused", reason: isValidPackageName(lower) ? `${name} is not a valid name for a new package: npm names are lowercase. Use ${lower}.` : `${name} is not a valid package name: ${VALID_NAME_RULE}.` });
  }

  if (!isValidVersion(version)) out.push({ kind: "refused", reason: `"${version}" is not a version apm accepts: apm takes strict semver only (1.2.3, 1.2.3-beta.1).` });

  if (!isValidPackageName(name)) return out;
  const same = view.existing.kind === "local" && isValidVersion(version) ? view.existing.versions.find((v) => withoutBuild(v) === withoutBuild(version)) : undefined;

  if (same !== undefined) out.push({ kind: "refused", reason: `${name}@${same} is already published (or was, and was yanked or revoked). Versions are immutable; bump the version (apm publish --bump patch).` });

  return [...out, ...nameChecks(name, view)];
}
