// apm publish --dry-run refuses what the registry and the package manager refuse (HOME-564 item 6: a dry run was green
// for a bare name, an existing version, another account's scope, "1.0", an uppercase name and "private": true).
import { describe, expect, test } from "bun:test";
import { manifestChecks, registryChecks, type PublishCheck, type PublishTarget, type RegistryView } from "../src/publish-checks.ts";

const missing: RegistryView = { user: "me", policy: "scoped", existing: { kind: "missing" } };
const mine: RegistryView = { user: "me", policy: "scoped", existing: { kind: "local", owners: ["me"], versions: ["1.0.0"] } };
const ALREADY = "is already published (or was, and was yanked or revoked). Versions are immutable; bump the version (apm publish --bump patch).";

const reasons = (checks: readonly PublishCheck[], kind: PublishCheck["kind"]): string[] => checks.flatMap((c) => (c.kind === kind ? [c.reason] : []));
const refused = (name: string, view: RegistryView, version = "1.0.0"): string[] => reasons(registryChecks({ name, version, view }), "refused");
const unconfirmed = (name: string, view: RegistryView, version = "1.0.0"): string[] => reasons(registryChecks({ name, version, view }), "unconfirmed");
const target = (fields: Partial<PublishTarget>): PublishTarget => ({ name: "@me/lib", version: "1.0.0", private: false, dropsBuild: false, ...fields });

describe("manifestChecks: what package.json alone says", () => {
  test("a valid scoped name and strict semver pass, a ~ in the package part included (the publish route takes it)", () => {
    expect(manifestChecks(target({}))).toEqual([]);
    expect(manifestChecks(target({ name: "@me/a~b" }))).toEqual([]);
  });

  test("a non-semver version, an uppercase or invalid name and private: true are each refused", () => {
    expect(reasons(manifestChecks(target({ name: "@me/My-Lib", version: "1.0", private: true })), "refused")).toEqual([
      'package.json has "private": true, so package managers refuse to publish it. Remove "private" to publish.',
      "@me/My-Lib is not a valid name for a new package: npm names are lowercase. Use @me/my-lib.",
      '"1.0" is not a version apm accepts: apm takes strict semver only (1.2.3, 1.2.3-beta.1).',
    ]);
    expect(reasons(manifestChecks(target({ name: "bad name" })), "refused")[0]).toStartWith("bad name is not a valid package name: a name is lowercase letters");
  });

  test("build metadata is refused only for a package manager that drops it from the version it sends (npm)", () => {
    expect(manifestChecks(target({ version: "1.0.0-rc.1+ci.7" }))).toEqual([]);
    expect(reasons(manifestChecks(target({ version: "1.0.0-rc.1+ci.7", dropsBuild: true })), "refused")).toEqual([
      'npm sends 1.0.0-rc.1+ci.7 as 1.0.0-rc.1, without its build metadata, and the registry refuses a publish whose version differs from the tarball\'s. Drop the "+..." part, or publish with bun or pnpm.',
    ]);
  });
});

describe("registryChecks: what the registry would refuse", () => {
  test("a new package under your own scope passes", () => {
    expect(registryChecks({ name: "@me/my-lib", version: "1.0.0", view: missing })).toEqual([]);
  });

  test("a bare name is refused under the scoped policy with the registry's own words, and passes under the open one", () => {
    expect(refused("my-lib", missing)).toEqual([
      'New packages on apm are scoped to your GitHub login. Publish this as @me/my-lib (set "name" in package.json). A bare name like "my-lib" always means the npm package, so apm does not hand out bare names.',
    ]);
    expect(refused("my-lib", { ...missing, user: null })[0]).toContain("Publish this as @<your GitHub login>/my-lib");
    expect(registryChecks({ name: "my-lib", version: "1.0.0", view: { ...missing, policy: "open" } })).toEqual([]);
  });

  test("a bare name is unconfirmed, never passed, when the registry's rules could not be read", () => {
    expect(unconfirmed("my-lib", { ...missing, policy: null })[0]).toContain("could not read this registry's rules for new names");
  });

  test("another account's scope is refused; logged out it is unconfirmed, not passed", () => {
    expect(refused("@sindresorhus/probe", missing)).toEqual(["You cannot publish under @sindresorhus. New packages go under your own scope: @me/probe."]);
    expect(registryChecks({ name: "@sindresorhus/probe", version: "1.0.0", view: { ...missing, user: null } })).toEqual([
      { kind: "unconfirmed", reason: "apm cannot confirm that @sindresorhus is yours: you are not logged in to this registry. Log in, then run the dry run again." },
    ]);
  });

  test("a name npm has is refused, even when its npm maintainer has your login", () => {
    const npm: RegistryView = { ...missing, existing: { kind: "npm" } };

    expect(refused("is-odd-probe", { ...npm, user: null })).toEqual([
      'New packages on apm are scoped to your GitHub login. Publish this as @<your GitHub login>/is-odd-probe (set "name" in package.json). A bare name like "is-odd-probe" always means the npm package, so apm does not hand out bare names.',
      "is-odd-probe already exists on npm, and apm shares one namespace with it, so it cannot be published over here. Pick another name under your scope.",
    ]);
    expect(refused("left-pad", { ...npm, policy: "open" })).toEqual(["left-pad is a reserved name (a widely used public package), so the registry refuses it. Pick another name under your scope."]);
    expect(refused("@me/on-npm", npm)).toEqual(["@me/on-npm already exists on npm, and apm shares one namespace with it, so it cannot be published over here. Pick another name under your scope."]);
  });

  test("a reserved popular name is refused even on an open registry with npm turned off", () => {
    expect(refused("react", { ...missing, policy: "open" })).toEqual(["react is a reserved name (a widely used public package), so the registry refuses it. Pick another name under your scope."]);
  });

  test("a new look-alike of a popular name is refused", () => {
    expect(refused("@me/hono-js", missing)[0]).toContain("is too close to a popular package");
    expect(refused("@me/hono", missing)).toEqual([]);
  });

  test("a version the registry already stores is refused, build metadata ignored", () => {
    expect(refused("@me/lib", mine)).toEqual([`@me/lib@1.0.0 ${ALREADY}`]);
    expect(refused("@me/lib", mine, "1.0.0+build.2")).toEqual([`@me/lib@1.0.0 ${ALREADY}`]);
  });

  test("an owner's new version passes; someone else's package is refused; logged out it is unconfirmed", () => {
    expect(registryChecks({ name: "@me/lib", version: "1.0.1", view: mine })).toEqual([]);
    expect(refused("@me/lib", { ...mine, user: "you" }, "1.0.1")).toEqual(["@me/lib already exists and you is not one of its owners (me); only an owner can publish a new version."]);
    expect(unconfirmed("@me/lib", { ...mine, user: null }, "1.0.1")).toEqual(["apm cannot confirm that you own @me/lib: you are not logged in to this registry. Log in, then run the dry run again."]);
  });

  test("a co-owner under another scope passes, and an unread package is unconfirmed rather than refused", () => {
    const shared: RegistryView = { user: "octo-cat", policy: "scoped", existing: { kind: "local", owners: ["mona-owner", "octo-cat"], versions: ["1.0.0"] } };

    expect(registryChecks({ name: "@mona-owner/shared", version: "1.1.0", view: shared })).toEqual([]);
    expect(registryChecks({ name: "@mona-owner/shared", version: "1.1.0", view: { ...shared, existing: { kind: "unknown" } } })).toEqual([
      { kind: "unconfirmed", reason: "apm could not read whether @mona-owner/shared exists on this registry or on npm, so it cannot say whether you may publish it or whether this version is already published." },
    ]);
  });
});
