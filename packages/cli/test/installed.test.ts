// Review of 2a098b1, findings 2, 9 and 10, and the strict-workspace rule: what a lockfile asks the check about.
import { describe, expect, test } from "bun:test";
import { isBoundMember, lockGraph } from "../src/installed.ts";
import type { LockNode } from "../src/lockfile.ts";

const node = (key: string, name: string, version: string, extra: Partial<LockNode> = {}): LockNode => ({ key, name, version, integrity: "sha512-AAAA", resolved: null, hasInstallScript: false, platform: false, origin: { kind: "registry" }, bundled: false, optional: false, deps: [], ...extra });

describe("lockGraph", () => {
  test("finding 9: an occurrence with no integrity is unchecked even when another occurrence of that version has one (on 2a098b1: noIntegrity was empty)", () => {
    const g = lockGraph([node("node_modules/a", "a", "1.0.0"), node("node_modules/host/node_modules/a", "a", "1.0.0", { integrity: null })], { integrityKnown: true });

    expect(g.noIntegrity.map((p) => `${p.name}@${p.version}`)).toEqual(["a@1.0.0"]);
    expect(g.packages.map((p) => p.integrity)).toEqual(["sha512-AAAA"]);
  });

  test("finding 10: the same hashes in another order are one artifact, not a conflict (on 2a098b1: refused in every mode)", () => {
    const g = lockGraph([node("node_modules/a", "a", "1.0.0", { integrity: "sha512-AAAA sha1-BBBB" }), node("node_modules/x/node_modules/a", "a", "1.0.0", { integrity: "sha1-BBBB sha512-AAAA" })], { integrityKnown: true });

    expect(g.conflicts).toEqual([]);
    expect(g.packages).toHaveLength(1);
  });

  test("two artifacts under one algorithm conflict; two integrities that cannot be compared are each asked about", () => {
    const conflict = lockGraph([node("node_modules/a", "a", "1.0.0"), node("node_modules/x/node_modules/a", "a", "1.0.0", { integrity: "sha512-ZZZZ" })], { integrityKnown: true });
    const apart = lockGraph([node("node_modules/a", "a", "1.0.0"), node("node_modules/x/node_modules/a", "a", "1.0.0", { integrity: "sha256-CCCC" })], { integrityKnown: true });

    expect(conflict.conflicts.map((c) => c.reason)).toEqual(["the lockfile locks a@1.0.0 to two different artifacts (sha512-AAAA and sha512-ZZZZ)"]);
    expect(apart.conflicts).toEqual([]);
    expect(apart.packages.map((p) => p.integrity).sort()).toEqual(["sha256-CCCC", "sha512-AAAA"]);
  });

  test("finding 2: a bundled version is asked about for its state (on 2a098b1: only counted)", () => {
    const g = lockGraph([node("node_modules/root", "root", "1.0.0"), node("node_modules/root/node_modules/inner", "inner", "9.9.9", { bundled: true, integrity: null })], { integrityKnown: true });

    expect(g.bundled).toEqual([{ name: "inner", version: "9.9.9", integrity: null, platform: false, bundled: true }]);
    expect(g.noIntegrity).toEqual([]);
  });
});

describe("workspace members in strict mode", () => {
  const member = { dir: "packages/app", name: "app", version: "1.0.0" };
  const ws = (over: Partial<{ name: string; dir: string | null; version: string | null }> = {}) => node("packages/app", over.name ?? "app", "1.0.0", { origin: { kind: "workspace", source: "packages/app", dir: over.dir === undefined ? "packages/app" : over.dir, version: over.version === undefined ? "1.0.0" : over.version } });

  test("a member bound to its declared folder, name and version is trusted (on 2a098b1: unchecked, so strict refused every workspace add)", () => {
    expect(isBoundMember(ws(), [member])).toBe(true);
    expect(lockGraph([ws()], { integrityKnown: true, members: [member] }).members.map((m) => m.name)).toEqual(["app"]);
  });

  test("not by name alone: another folder, another name or another version stays unchecked", () => {
    expect(isBoundMember(ws({ dir: "vendor/app" }), [member])).toBe(false);
    expect(isBoundMember(ws({ name: "evil" }), [member])).toBe(false);
    expect(isBoundMember(ws({ version: "6.6.6" }), [member])).toBe(false);
    expect(isBoundMember(ws({ dir: null }), [member])).toBe(false);
    expect(lockGraph([ws({ version: "6.6.6" })], { integrityKnown: true, members: [member] }).local.map((m) => m.name)).toEqual(["app"]);
  });
});
