// The install box: apm add says what it checks; each stock client says it skips apm's checks and shows the one
// setting that turns them on, pointed at this stage's registry.
import { describe, expect, test } from "bun:test";
import { BUN_SCANNER, INSTALL_CLIENTS, installCommand, installNote } from "./install-note";

const registry = "https://registry.example.dev";

describe("installNote", () => {
  test("apm add names the dependency tree, then what it refuses and warns about, and needs no setup", () => {
    const note = installNote({ client: "apm", registry });

    expect(note.kind).toBe("checked");

    if (note.kind !== "checked") return;
    expect(note.text).toContain("dependency tree");
    expect(note.detail).toContain("score under 40");
    expect(note.detail).toContain("24 hours");
    expect(note.detail).toContain("--strict");
    expect(note.text).toContain("dependency tree");
    expect(note.docs).toBe("/docs#cli");
  });

  test("bun gets only the registry line in bunfig.toml, with the unpublished scanner as an optional extra", () => {
    const note = installNote({ client: "bun", registry });

    expect(note.kind).toBe("needs-setup");

    if (note.kind !== "needs-setup") return;
    expect(note.file).toBe("bunfig.toml");
    expect(note.config).toBe(`[install]\nregistry = "${registry}/"`);
    expect(note.lead).toContain("skips apm’s checks");
    expect(note.checks).toContain("apm add checks the score, cooldown and dependency tree");
    expect(note.checks.startsWith(note.effect)).toBe(true);
    expect(note.effect).toContain("New installs skip revoked");
    expect(note.effect).toContain(BUN_SCANNER);
    expect(note.effect).toContain("not on a registry yet");
    expect(note.docs).toBe("/docs#bun");
  });

  test.each(["npm", "pnpm"] as const)("%s gets the plain registry line in .npmrc, with ~safe as strict mode", (client) => {
    const note = installNote({ client, registry: `${registry}/` });

    expect(note.kind).toBe("needs-setup");

    if (note.kind !== "needs-setup") return;
    expect(note.file).toBe(".npmrc");
    expect(note.config).toBe(`registry=${registry}/`);
    expect(note.lead).toBe(`Plain ${client} skips apm’s checks. Point its registry at apm in .npmrc:`);
    expect(note.checks).toContain("apm add checks the score, cooldown and dependency tree");
    expect(note.checks.startsWith(note.effect)).toBe(true);
    expect(note.effect).toContain(`registry=${registry}/~safe/`);
    expect(note.effect).toContain("not fully analysed");
    expect(note.docs).toBe("/docs#npm");
  });

  test("only apm add runs without setup", () => {
    expect(INSTALL_CLIENTS.filter((client) => installNote({ client, registry }).kind === "checked")).toEqual(["apm"]);
  });
});

describe("installCommand", () => {
  test("stock clients pin the shown version; apm add resolves its own", () => {
    expect(INSTALL_CLIENTS.map((client) => installCommand({ client, name: "zod", install: { kind: "default", version: "4.6.7" } }))).toEqual(["apm add zod", "bun add zod@4.6.7", "npm install zod@4.6.7", "pnpm add zod@4.6.7"]);
  });

  test("no version installs the bare name", () => {
    expect(installCommand({ client: "npm", name: "@scope/pkg", install: { kind: "default", version: null } })).toBe("npm install @scope/pkg");
  });

  // HOME-502 D15: a package with only a prerelease tagged next has no latest, so every untagged command failed
  test("a version installed by its tag names the tag in every command, apm add's included", () => {
    expect(INSTALL_CLIENTS.map((client) => installCommand({ client, name: "@s/p", install: { kind: "tag", tag: "next" } }))).toEqual(["apm add @s/p@next", "bun add @s/p@next", "npm install @s/p@next", "pnpm add @s/p@next"]);
  });

  // HOME-502 Sol review finding 5: an exact-version link gave a bare apm add, which installs latest or nothing
  test("an exact version asked for by number is pinned in every command, apm add's included", () => {
    expect(INSTALL_CLIENTS.map((client) => installCommand({ client, name: "@s/p", install: { kind: "exact", version: "0.0.2-test.2" } }))).toEqual([
      "apm add @s/p@0.0.2-test.2",
      "bun add @s/p@0.0.2-test.2",
      "npm install @s/p@0.0.2-test.2",
      "pnpm add @s/p@0.0.2-test.2",
    ]);
  });
});
