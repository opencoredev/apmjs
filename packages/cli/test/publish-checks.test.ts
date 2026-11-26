// apm publish --dry-run refuses what the registry and the package manager refuse (HOME-564 item 6: a dry run was green
// for a bare name, an existing version, another account's scope, "1.0", an uppercase name and "private": true).
import { describe, expect, test } from "bun:test";
import { publishChecks, type RegistryView } from "../src/publish-checks.ts";

const missing: RegistryView = { user: "me", policy: "scoped", existing: { kind: "missing" } };
const refused = (input: Parameters<typeof publishChecks>[0]): string[] => publishChecks(input).flatMap((c) => (c.kind === "refused" ? [c.reason] : []));
const unconfirmed = (input: Parameters<typeof publishChecks>[0]): string[] => publishChecks(input).flatMap((c) => (c.kind === "unconfirmed" ? [c.reason] : []));

describe("publishChecks", () => {
  test("a new package under your own scope passes", () => {
    expect(publishChecks({ name: "@me/my-lib", version: "1.0.0", private: false, view: missing })).toEqual([]);
  });

  test("a bare name is refused under the scoped policy with the registry's own words, and passes under the open one", () => {
    expect(refused({ name: "my-lib", version: "1.0.0", private: false, view: missing })).toEqual([
      'New packages on apm are scoped to your GitHub login. Publish this as @me/my-lib (set "name" in package.json). A bare name like "my-lib" always means the npm package, so apm does not hand out bare names.',
    ]);
    expect(refused({ name: "my-lib", version: "1.0.0", private: false, view: { ...missing, user: null } })[0]).toContain("Publish this as @<your GitHub login>/my-lib");
    expect(publishChecks({ name: "my-lib", version: "1.0.0", private: false, view: { ...missing, policy: "open" } })).toEqual([]);
  });

  test("a bare name is unconfirmed, never passed, when the registry's rules could not be read", () => {
    expect(unconfirmed({ name: "my-lib", version: "1.0.0", private: false, view: { ...missing, policy: null } })[0]).toContain("could not read this registry's rules for new names");
  });

  test("another account's scope is refused; logged out it is unconfirmed, not passed", () => {
    expect(refused({ name: "@sindresorhus/probe", version: "1.0.0", private: false, view: missing })).toEqual(["You cannot publish under @sindresorhus. New packages go under your own scope: @me/probe."]);
    const out = publishChecks({ name: "@sindresorhus/probe", version: "1.0.0", private: false, view: { ...missing, user: null } });

    expect(out).toEqual([{ kind: "unconfirmed", reason: "apm cannot confirm that @sindresorhus is yours: you are not logged in to this registry. Log in, then run the dry run again." }]);
  });

  test("a version the registry already has is refused, build metadata ignored", () => {
    const found: RegistryView = { user: null, policy: "scoped", existing: { kind: "found", versions: ["1.2.0", "1.3.0"], owners: ["azer"] } };

    expect(refused({ name: "left-pad", version: "1.3.0", private: false, view: found })).toContain("left-pad@1.3.0 is already published. Versions are immutable; bump the version (apm publish --bump patch).");
    expect(refused({ name: "@me/lib", version: "1.0.0+build.2", private: false, view: { ...found, existing: { kind: "found", versions: ["1.0.0"], owners: ["me"] } } })).toEqual([
      "@me/lib@1.0.0 is already published. Versions are immutable; bump the version (apm publish --bump patch).",
    ]);
  });

  test("an owner's new version passes; someone else's package is refused", () => {
    const mine: RegistryView = { user: "me", policy: "scoped", existing: { kind: "found", versions: ["1.0.0"], owners: ["me"] } };

    expect(publishChecks({ name: "@me/lib", version: "1.0.1", private: false, view: mine })).toEqual([]);
    expect(refused({ name: "@me/lib", version: "1.0.1", private: false, view: { ...mine, user: "you" } })).toEqual(["@me/lib already exists and you is not one of its owners (me); only an owner can publish a new version."]);
  });

  test("an unread package is unconfirmed, not passed", () => {
    expect(unconfirmed({ name: "@me/lib", version: "1.0.0", private: false, view: { ...missing, existing: { kind: "unknown" } } })).toEqual(["apm could not read @me/lib from this registry, so it cannot say whether 1.0.0 is already published."]);
  });

  test("a non-semver version, an uppercase or invalid name and private: true are refused with no registry answer needed", () => {
    const offline: RegistryView = { user: null, policy: null, existing: { kind: "unknown" } };

    expect(refused({ name: "@me/probe", version: "1.0", private: false, view: missing })).toEqual(['"1.0" is not a version apm accepts: apm takes strict semver only (1.2.3, 1.2.3-beta.1).']);
    expect(refused({ name: "@me/My-Lib", version: "1.0.0", private: false, view: offline })).toEqual(["@me/My-Lib is not a valid name for a new package: npm names are lowercase. Use @me/my-lib."]);
    expect(refused({ name: "bad name", version: "1.0.0", private: false, view: offline })[0]).toStartWith("bad name is not a valid package name: a name is lowercase letters");
    expect(refused({ name: "@me/priv", version: "1.0.0", private: true, view: missing })).toEqual(['package.json has "private": true, so package managers refuse to publish it. Remove "private" to publish.']);
  });
});
