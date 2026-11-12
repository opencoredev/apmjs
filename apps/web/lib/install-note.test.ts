// The install box: apm add says what it checks; each stock client says it skips apm's checks and shows the one
// setting that turns them on, pointed at this stage's registry.
import { describe, expect, test } from "bun:test";
import { BUN_SCANNER, INSTALL_CLIENTS, installCommand, installNote } from "./install-note";

const registry = "https://registry.example.dev";

describe("installNote", () => {
  test("apm add names the score, cooldown and dependency tree and needs no setup", () => {
    const note = installNote({ client: "apm", registry });

    expect(note.kind).toBe("checked");

    if (note.kind !== "checked") return;
    expect(note.text).toContain("score");
    expect(note.text).toContain("cooldown");
    expect(note.text).toContain("dependency tree");
    expect(note.docs).toBe("/docs#cli");
  });

  test("bun gets the registry and the scanner in bunfig.toml", () => {
    const note = installNote({ client: "bun", registry });

    expect(note.kind).toBe("needs-setup");

    if (note.kind !== "needs-setup") return;
    expect(note.file).toBe("bunfig.toml");
    expect(note.config).toContain(`registry = "${registry}/"`);
    expect(note.config).toContain("[install.security]");
    expect(note.config).toContain(`scanner = "${BUN_SCANNER}"`);
    expect(note.lead).toContain("skips apm’s checks");
    expect(note.checks).toContain("apm add checks the score, cooldown and dependency tree");
    expect(note.docs).toBe("/docs#bun");
  });

  test.each(["npm", "pnpm"] as const)("%s gets the ~safe registry line in .npmrc", (client) => {
    const note = installNote({ client, registry: `${registry}/` });

    expect(note.kind).toBe("needs-setup");

    if (note.kind !== "needs-setup") return;
    expect(note.file).toBe(".npmrc");
    expect(note.config).toBe(`registry=${registry}/~safe/`);
    expect(note.lead).toBe(`Plain ${client} skips apm’s checks. Set its registry to apm’s ~safe view in .npmrc:`);
    expect(note.checks).toContain("apm add checks the score, cooldown and dependency tree");
    expect(note.docs).toBe("/docs#npm");
  });

  test("only apm add runs without setup", () => {
    expect(INSTALL_CLIENTS.filter((client) => installNote({ client, registry }).kind === "checked")).toEqual(["apm"]);
  });
});

describe("installCommand", () => {
  test("stock clients pin the shown version; apm add resolves its own", () => {
    expect(INSTALL_CLIENTS.map((client) => installCommand({ client, name: "zod", version: "4.6.7" }))).toEqual(["apm add zod", "bun add zod@4.6.7", "npm install zod@4.6.7", "pnpm add zod@4.6.7"]);
  });

  test("no version installs the bare name", () => {
    expect(installCommand({ client: "npm", name: "@scope/pkg", version: null })).toBe("npm install @scope/pkg");
  });
});
