// Review of 2b7767f, finding 3, and of efef668, findings 1 and 3: which dependency groups the package manager installs,
// read the way it reads them. The table in fixtures/omission-cases.ts is what real npm 9 and pnpm 10 do with each
// setting (real-layouts.test.ts installs every case with them); here apm's reading is held to it.
import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { devGroup, omitArgs, releaseOmission } from "../src/groups.ts";
import { decodeIni, type IniValue, text } from "../src/ini.ts";
import { OMISSION_CASES, type OmissionCase } from "./fixtures/omission-cases.ts";

const base = mkdtempSync(join(tmpdir(), "apm-groups-"));

afterAll(() => {
  rmSync(base, { recursive: true, force: true });
});

let n = 0;

/** A project directory and a HOME laid out as the case says, and the environment apm reads it with (no PATH: no npm). */
function project(c: Pick<OmissionCase, "npmrc" | "user" | "global" | "env">) {
  const root = join(base, `p${++n}`);
  const home = join(base, `h${n}`);

  mkdirSync(root, { recursive: true });
  mkdirSync(home, { recursive: true });

  if (c.npmrc !== undefined) writeFileSync(join(root, ".npmrc"), c.npmrc);

  if (c.user !== undefined) writeFileSync(join(home, ".npmrc"), c.user);

  if (c.global !== undefined) writeFileSync(join(home, "global-npmrc"), c.global);

  // the global config is a file of the case's own, there or not
  return { root, env: { HOME: home, npm_config_globalconfig: join(home, "global-npmrc"), ...c.env } };
}

describe("each setting, as real npm and pnpm read it", () => {
  for (const c of OMISSION_CASES) {
    test(`${c.name}: npm ${c.npm}s, pnpm ${c.pnpm}s devDependencies`, () => {
      const p = project(c);

      expect(devGroup({ pm: "npm", root: p.root, env: p.env, production: false }).kind).toBe(c.npm);
      expect(devGroup({ pm: "pnpm", root: p.root, env: p.env, production: false }).kind).toBe(c.pnpm);
    });
  }

  // the three the review of efef668 found apm reading wrongly
  test('omit="dev", npm_config_only=production and production=false over NODE_ENV are read as npm does (on efef668: include, include, omit)', () => {
    const quoted = project({ npmrc: 'omit="dev"\n' });
    const only = project({ env: { npm_config_only: "production" } });
    const off = project({ env: { NODE_ENV: "production", npm_config_production: "false" } });

    expect(devGroup({ pm: "npm", root: quoted.root, env: quoted.env, production: false })).toEqual({ kind: "omit", why: `omit=dev in ${join(quoted.root, ".npmrc")}` });
    expect(devGroup({ pm: "npm", root: only.root, env: only.env, production: false })).toEqual({ kind: "omit", why: "only=production in the environment" });
    expect(devGroup({ pm: "npm", root: off.root, env: off.env, production: false })).toEqual({ kind: "include" });
  });
});

describe("the .npmrc reader", () => {
  test("decodes quotes, comments, lists, bare keys and sections the way npm's ini does", () => {
    const ini = decodeIni(['a="x y"', "b='z'", "c=v ; note", "d=v \\; kept", "e[]=1", "e[]=2", "f", "g=true", 'h="null"', "  i = spaced  ", "[sec]", "j=hidden"].join("\n"));

    const one = (t: string) => ({ kind: "one", item: text(t) }) satisfies IniValue;
    const lit = (value: boolean | null) => ({ kind: "one", item: { kind: "literal", value } }) satisfies IniValue;

    expect(Object.fromEntries(ini)).toEqual({ a: one("x y"), b: one("z"), c: one("v"), d: one("v ; kept"), e: { kind: "list", items: [text("1"), text("2")] }, f: lit(true), g: lit(true), h: lit(null), i: one("spaced") });
  });
});

describe("pnpm and bun", () => {
  test("bun reads none of them; apm add --production asks every package manager", () => {
    const p = project({ npmrc: "omit=dev\nproduction=true\n" });

    expect(devGroup({ pm: "bun", root: p.root, env: { ...p.env, npm_config_omit: "dev", NODE_ENV: "production" }, production: false }).kind).toBe("include");

    for (const pm of ["npm", "pnpm", "bun"] as const) expect(devGroup({ pm, root: p.root, env: p.env, production: true }).kind).toBe("omit");
  });

  test("the install is told explicitly, in each one's own flag", () => {
    const omit = { kind: "omit", why: "x" } as const;

    expect(omitArgs("npm", omit)).toEqual(["--omit=dev"]);
    expect(omitArgs("pnpm", omit)).toEqual(["--prod"]);
    expect(omitArgs("bun", omit)).toEqual(["--production"]);
    expect(omitArgs("npm", { kind: "include" })).toEqual([]);
  });

  test("the release of held scripts is told it again (review of efef668, finding 1)", () => {
    const omit = { kind: "omit", why: "x" } as const;

    expect(releaseOmission("npm", omit)).toEqual({ args: ["--omit=dev"], env: {} });
    expect(releaseOmission("pnpm", omit)).toEqual({ args: [], env: { npm_config_production: "true" } });
    expect(releaseOmission("bun", omit)).toEqual({ args: ["--production"], env: {} });

    for (const pm of ["npm", "pnpm", "bun"] as const) expect(releaseOmission(pm, { kind: "include" })).toEqual({ args: [], env: {} });
  });
});
