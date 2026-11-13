// Review of 2b7767f, finding 3: which dependency groups the package manager installs, read from the same places it
// reads them. The answers match what real npm 9, pnpm 10 and bun 1.4 do (checked by hand against each, and end to end
// in real-layouts.test.ts and the acceptance suite).
import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { devGroup, omitArgs } from "../src/groups.ts";

const base = mkdtempSync(join(tmpdir(), "apm-groups-"));

afterAll(() => {
  rmSync(base, { recursive: true, force: true });
});

let n = 0;

/** A project directory with an optional .npmrc, and a HOME with none, so the user's own config never leaks in. */
function project(npmrc?: string) {
  const root = join(base, `p${++n}`);
  const home = join(base, `h${n}`);

  mkdirSync(root, { recursive: true });
  mkdirSync(home, { recursive: true });

  if (npmrc !== undefined) writeFileSync(join(root, ".npmrc"), npmrc);

  return { root, env: { HOME: home } };
}

describe("npm", () => {
  test("npm_config_omit=dev, any case, omits", () => {
    const p = project();

    expect(devGroup({ pm: "npm", root: p.root, env: { ...p.env, npm_config_omit: "dev" }, production: false }).kind).toBe("omit");
    expect(devGroup({ pm: "npm", root: p.root, env: { ...p.env, NPM_CONFIG_OMIT: "optional dev" }, production: false }).kind).toBe("omit");
  });

  test("NODE_ENV=production omits, unless omit is set otherwise or include=dev wins", () => {
    const p = project();

    expect(devGroup({ pm: "npm", root: p.root, env: { ...p.env, NODE_ENV: "production" }, production: false }).kind).toBe("omit");
    expect(devGroup({ pm: "npm", root: p.root, env: { ...p.env, NODE_ENV: "production", npm_config_omit: "" }, production: false }).kind).toBe("include");
    expect(devGroup({ pm: "npm", root: p.root, env: { ...p.env, npm_config_omit: "dev", npm_config_include: "dev" }, production: false }).kind).toBe("include");
  });

  test("an .npmrc's omit=dev, omit[]=dev or production=true omits", () => {
    for (const rc of ["omit=dev\n", "omit[]=optional\nomit[]=dev\n", "production=true\n"]) {
      const p = project(rc);

      expect(devGroup({ pm: "npm", root: p.root, env: p.env, production: false }).kind, rc).toBe("omit");
    }
  });

  test("nothing set: devDependencies are installed", () => {
    const p = project();

    expect(devGroup({ pm: "npm", root: p.root, env: p.env, production: false })).toEqual({ kind: "include" });
  });
});

describe("pnpm and bun", () => {
  test("pnpm 10 reads production=true from the environment or an .npmrc, and neither omit nor NODE_ENV", () => {
    const p = project();
    const rc = project("production=true\n");

    expect(devGroup({ pm: "pnpm", root: p.root, env: { ...p.env, npm_config_production: "true" }, production: false }).kind).toBe("omit");
    expect(devGroup({ pm: "pnpm", root: rc.root, env: rc.env, production: false }).kind).toBe("omit");
    expect(devGroup({ pm: "pnpm", root: p.root, env: { ...p.env, npm_config_omit: "dev", NODE_ENV: "production" }, production: false }).kind).toBe("include");
  });

  test("bun reads none of them; apm add --production asks every package manager", () => {
    const p = project("omit=dev\nproduction=true\n");

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
});
