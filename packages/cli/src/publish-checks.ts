// What apm publish --dry-run checks before calling a publish fine: the rules the registry and the package manager
// refuse a publish by (a valid lowercase name, strict semver, not "private", a version not published yet, and the
// registry's rule for new names). Pure: main.ts reads the registry and prints the result.
import { isScoped, isValidPackageName, isValidVersion, newNameRuleRefusal, type NamePolicy } from "@apm/core";

/** The name rule apm prints for an invalid name (apm name and apm publish --dry-run). */
export const VALID_NAME_RULE = "a name is lowercase letters, digits and - . _ (and ~ in a scope), starts with a letter or digit, is at most 214 characters, and has at most one scope, as @scope/name";

/** What the registry has under the package's name: nothing, its versions and owners, or no answer. */
export type Existing = { kind: "missing" } | { kind: "found"; versions: readonly string[]; owners: readonly string[] } | { kind: "unknown" };

/**
 * What apm read from the registry for the checks. `user` is the login of the token apm would publish with, null when
 * there is none or it could not be read; `policy` is the registry's rule for new names, null when it could not be read.
 */
export type RegistryView = { user: string | null; policy: NamePolicy | null; existing: Existing };

/** One finding: the registry or the package manager would refuse the publish, or apm cannot say whether it would. */
export type PublishCheck = { kind: "refused"; reason: string } | { kind: "unconfirmed"; reason: string };

/** The version semver compares: build metadata is ignored, so 1.0.0+a and 1.0.0 are one version to a registry. */
const withoutBuild = (version: string): string => version.split("+")[0] ?? version;

function nameChecks(name: string, view: RegistryView): PublishCheck[] {
  const { user, policy, existing } = view;

  if (existing.kind === "found" && user !== null) {
    return existing.owners.includes(user) ? [] : [{ kind: "refused", reason: `${name} already exists and ${user} is not one of its owners (${existing.owners.join(", ") || "none listed"}); only an owner can publish a new version.` }];
  }

  if (isScoped(name)) {
    const scope = name.slice(1, name.indexOf("/"));

    if (user === null) return [{ kind: "unconfirmed", reason: `apm cannot confirm that @${scope} is yours: you are not logged in to this registry. Log in, then run the dry run again.` }];
    const refused = newNameRuleRefusal({ name, user, policy: policy ?? "scoped" });

    return refused === null ? [] : [{ kind: "refused", reason: refused }];
  }

  if (policy === null) return [{ kind: "unconfirmed", reason: `apm could not read this registry's rules for new names, so it cannot say whether the bare name ${name} may be published (apm's own registry takes a new package only under your GitHub login).` }];
  const refused = newNameRuleRefusal({ name, user: user ?? "<your GitHub login>", policy });

  return refused === null ? [] : [{ kind: "refused", reason: refused }];
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

  if (isValidVersion(version)) {
    if (view.existing.kind === "unknown") out.push({ kind: "unconfirmed", reason: `apm could not read ${name} from this registry, so it cannot say whether ${version} is already published.` });
    const same = view.existing.kind === "found" ? view.existing.versions.find((v) => withoutBuild(v) === withoutBuild(version)) : undefined;

    if (same !== undefined) out.push({ kind: "refused", reason: `${name}@${same} is already published. Versions are immutable; bump the version (apm publish --bump patch).` });
  }

  return [...out, ...nameChecks(name, view)];
}
