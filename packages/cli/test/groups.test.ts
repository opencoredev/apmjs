// Review of 2b7767f, finding 3, and of efef668, findings 1 and 3: which dependency groups the package manager installs,
// read the way it reads them. The table in fixtures/omission-cases.ts is what real npm 9 and pnpm 10 do with each
// setting (real-layouts.test.ts installs every case with them); here apm's reading is held to it.
import { afterAll, describe, expect, test } from "bun:test";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEFAULT_REGISTRY, loadConfig, saveToken } from "../src/config.ts";
import { devGroup, omitArgs, releaseOmission } from "../src/groups.ts";
import { decodeIni, type IniValue, text } from "../src/ini.ts";
import { npmAnswer, OMISSION_CASES, type OmissionCase } from "./fixtures/omission-cases.ts";

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

/**
 * A PATH with an npm on it of `npmVersion` whose ini is `iniVersion`: bundled in npm's node_modules, or (debian) in
 * the shared directory beside npm. apm reads only their package.json files.
 */
function npmOnPath(input: { npmVersion: string; iniVersion: string; layout: "bundled" | "debian"; executable?: boolean }): string {
  const top = join(base, `npm${++n}`);
  const npmRoot = input.layout === "bundled" ? join(top, "lib", "node_modules", "npm") : join(top, "share", "nodejs", "npm");
  const iniDir = input.layout === "bundled" ? join(npmRoot, "node_modules", "ini") : join(top, "share", "nodejs", "ini");
  const bin = join(top, "bin");

  mkdirSync(join(npmRoot, "bin"), { recursive: true });
  mkdirSync(iniDir, { recursive: true });
  mkdirSync(bin, { recursive: true });
  writeFileSync(join(npmRoot, "package.json"), JSON.stringify({ name: "npm", version: input.npmVersion }));
  writeFileSync(join(npmRoot, "bin", "npm-cli.js"), "");
  // as a real npm-cli.js is; a spawn of `npm` passes over one it may not execute
  chmodSync(join(npmRoot, "bin", "npm-cli.js"), input.executable === false ? 0o644 : 0o755);
  writeFileSync(join(iniDir, "package.json"), JSON.stringify({ name: "ini", version: input.iniVersion }));
  symlinkSync(join(npmRoot, "bin", "npm-cli.js"), join(bin, "npm"));

  return bin;
}

const NPM11 = npmOnPath({ npmVersion: "11.16.0", iniVersion: "6.0.0", layout: "bundled" });
const NPM92_DEBIAN = npmOnPath({ npmVersion: "9.2.0", iniVersion: "3.0.1", layout: "debian" });

describe("each setting, as real npm and pnpm read it", () => {
  for (const c of OMISSION_CASES) {
    const npm92 = npmAnswer(c, { major: 9, minor: 2 });
    // with no npm to read, apm omits only what every npm omits
    const unknown = c.npm === "omit" && npm92 === "omit" ? "omit" : "include";

    test(`${c.name}: npm ${c.npm}s (9.2: ${npm92}s), pnpm ${c.pnpm}s devDependencies`, () => {
      const p = project(c);
      const npm = (path: string | undefined) => devGroup({ pm: "npm", root: p.root, env: path === undefined ? p.env : { ...p.env, PATH: path }, production: false }).kind;

      expect(npm(NPM11)).toBe(c.npm);
      expect(npm(NPM92_DEBIAN)).toBe(npm92);
      expect(npm(undefined)).toBe(unknown);
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
    const ini = decodeIni(['a="x y"', "b='z'", "c=v ; note", "d=v \\; kept", "e[]=1", "e[]=2", "f", "g=true", 'h="null"', "  i = spaced  ", "[sec]", "j=hidden"].join("\n"), "exact");

    const one = (t: string) => ({ kind: "one", item: text(t) }) satisfies IniValue;
    const lit = (value: boolean | null) => ({ kind: "one", item: { kind: "literal", value } }) satisfies IniValue;

    expect(Object.fromEntries(ini)).toEqual({ a: one("x y"), b: one("z"), c: one("v"), d: one("v ; kept"), e: { kind: "list", items: [text("1"), text("2")] }, f: lit(true), g: lit(true), h: lit(null), i: one("spaced") });
  });
});

// Review of a24c6aa, finding 1: a section header followed by whitespace is a section to ini 4.1.0 and later (npm 11,
// upstream npm 9.6 on), and a bare key to ini 3 (Debian's npm 9.2) and to pnpm 10. apm reads the files with the
// grammar of the ini the npm on PATH uses, and when it cannot find that ini, omits only when both readings do.
describe("finding 1 of a24c6aa: section headers read with the grammar of npm's own ini", () => {
  const npmWith = (npmrc: string, path: string | undefined) => {
    const p = project({ npmrc });

    return devGroup({ pm: "npm", root: p.root, env: path === undefined ? p.env : { ...p.env, PATH: path }, production: false }).kind;
  };

  test("[section] then a space: npm 11's ini 6 opens a section, ini 3 reads a key (on a24c6aa: omit for ini 6, the install includes)", () => {
    const ini6 = NPM11;
    const ini41 = npmOnPath({ npmVersion: "9.6.7", iniVersion: "4.1.0", layout: "bundled" });
    const ini40 = npmOnPath({ npmVersion: "9.6.0", iniVersion: "4.0.0", layout: "bundled" });
    const debian = NPM92_DEBIAN;

    expect(npmWith("[section] \nproduction=true\n", ini6)).toBe("include");
    expect(npmWith("[section]\t\nonly=prod\n", ini6)).toBe("include");
    expect(npmWith("[section] \nproduction=true\n", ini41)).toBe("include");
    expect(npmWith("[section] \nproduction=true\n", ini40)).toBe("omit");
    expect(npmWith("[section] \nproduction=true\n", debian)).toBe("omit");
    expect(npmWith("[section]\t\nonly=prod\n", debian)).toBe("omit");
  });

  test("the inverse: omit=dev before [section] and production=false omits with ini 6 (on a24c6aa: include, a false refusal)", () => {
    const [ini6, debian] = [NPM11, NPM92_DEBIAN];

    expect(npmWith("omit=dev\n[section] \nproduction=false\n", ini6)).toBe("omit");
    expect(npmWith("omit=dev\n[section] \nproduction=false\n", debian)).toBe("include");
  });

  test("no npm ini to read: omit only when both grammars omit", () => {
    expect(npmWith("[section] \nproduction=true\n", undefined)).toBe("include");
    expect(npmWith("omit=dev\n[section] \nproduction=false\n", undefined)).toBe("include");
    expect(npmWith("production=true\n[section] \nomit=optional\n", undefined)).toBe("omit");
  });

  test("the npm read is the npm a spawn runs: one on PATH it may not execute is passed over (review of 137141c)", () => {
    const stale = npmOnPath({ npmVersion: "11.16.0", iniVersion: "6.0.0", layout: "bundled", executable: false });

    // on 137141c the non-executable npm 11 first on PATH was read (include) while the spawn ran Debian's 9.2 (omit)
    expect(npmWith("[section] \nproduction=true\n", `${stale}:${NPM92_DEBIAN}`)).toBe("omit");
  });

  test("production=${P} with P empty: npm 9.3 and later read the empty text as false and install devDependencies (review of 137141c)", () => {
    const p = project({ npmrc: "production=${P}\n" });

    expect(devGroup({ pm: "npm", root: p.root, env: { ...p.env, P: "", PATH: NPM11 }, production: false }).kind).toBe("include");
    // npm 9.2 types the value first, and an empty one is false there too
    expect(devGroup({ pm: "npm", root: p.root, env: { ...p.env, P: "", PATH: NPM92_DEBIAN }, production: false }).kind).toBe("include");
  });

  test("pnpm 10 reads [section] then a space as a key, so production=true after it is top-level", () => {
    const p = project({ npmrc: "[section] \nproduction=true\n" });

    expect(devGroup({ pm: "pnpm", root: p.root, env: p.env, production: false }).kind).toBe("omit");
  });

  test("the reader: exact and spaced section syntax", () => {
    const src = "[sec] \nj=x\n";

    expect(Object.fromEntries(decodeIni(src, "spaced"))).toEqual({});
    expect([...decodeIni(src, "exact").keys()]).toEqual(["[sec]", "j"]);
  });

  test("apm's registry and token from a user .npmrc follow the same grammar (review of PR #9)", () => {
    const user = "[custom] \nregistry=https://r.example/\n//r.example/:_authToken=apm_tokentokentokentoken\n";

    const config = (path: string | undefined) => {
      const p = project({ user });

      return loadConfig(p.root, path === undefined ? { HOME: p.env.HOME } : { HOME: p.env.HOME, PATH: path });
    };

    // Debian's npm 9.2 reads `[custom] ` as a key, so both lines below it are top-level, as npm itself uses them
    expect(config(NPM92_DEBIAN)).toMatchObject({ registry: "https://r.example/", token: "apm_tokentokentokentoken" });
    // npm 11 opens a section there and reads neither
    expect(config(NPM11)).toMatchObject({ registry: DEFAULT_REGISTRY, token: null });
    // no npm to ask: the settings are kept
    expect(config(undefined)).toMatchObject({ registry: "https://r.example/", token: "apm_tokentokentokentoken" });
  });

  test("a rotated token is the only one either grammar reads, whatever way the old one was written (review of e5d8c47)", () => {
    const key = "//registry.apmjs.dev/:_authToken";
    const OLD = "apm_oldoldoldoldoldold01";
    const NEW = "apm_newnewnewnewnewnew01";

    const cases = [
      `${key} = ${OLD}\n`,
      `  "${key}" =${OLD}\n`,
      `${key}[]=${OLD}\n`,
      // Debian's npm 9.2 reads `[custom] ` as a key, so a token after it is top-level there and, being later, wins
      `[custom] \n${key} = ${OLD}\n`,
      `[custom] \n${key}=${OLD}\n`,
      `${key}=${OLD}\n[custom] \n${key} =${OLD}\nregistry=https://registry.apmjs.dev/\n`,
      `a=1\r${key}=${OLD}\r`,
    ];

    const rotate = (user: string) => {
      const p = project({ user });
      const rc = join(p.env.HOME, ".npmrc");
      const result = saveToken(rc, "https://registry.apmjs.dev/", NEW);

      return { p, result, after: readFileSync(rc, "utf8") };
    };

    for (const user of cases) {
      const { p, result, after } = rotate(user);

      expect(result).toEqual({ kind: "saved" });

      for (const sections of ["exact", "spaced"] as const) expect(decodeIni(after, sections).get(key)).toEqual({ kind: "one", item: text(NEW) });
      expect(after).not.toContain(OLD);

      for (const path of [NPM92_DEBIAN, NPM11]) expect(loadConfig(p.root, { HOME: p.env.HOME, PATH: path }).token).toBe(NEW);
    }

    // a copy under a header both grammars open is no npm's top-level auth, so it stays as it was (review of 5b75caa)
    expect(rotate(`${key}=${OLD}\n[real]\n${key}=${OLD}\n`).after).toBe(`${key}=${NEW}\n[real]\n${key}=${OLD}\n`);
  });

  test("a rotation is refused, and the file left alone, when a top-level key has ${VAR} in it (review of 5b75caa)", () => {
    const user = (s: string) => `registry=https://registry.apmjs.dev/\n${s}`;

    // npm expands the name before it sets it, so ${HOST}:_authToken can be the very key being rotated
    // the line reported is the one an editor shows, blank lines and CRLF endings counted (review of 9e3693b)
    const cases = [
      [user("${HOST}:_authToken=apm_oldoldoldoldoldold01\n"), 2],
      [user("[custom] \n${HOST}:_authToken = apm_oldoldoldoldoldold01\n"), 3],
      [user("\n\n# note\n\n${HOST}:_authToken=apm_oldoldoldoldoldold01\n"), 6],
      [user("\r\n\r\n${HOST}:_authToken=apm_oldoldoldoldoldold01\r\n").replace("\n", "\r\n"), 4],
    ] as const;

    for (const [src, line] of cases) {
      const p = project({ user: src });
      const rc = join(p.env.HOME, ".npmrc");

      expect(saveToken(rc, "https://registry.apmjs.dev/", "apm_newnewnewnewnewnew01")).toMatchObject({ kind: "refused", line });
      expect(readFileSync(rc, "utf8")).toBe(src);
    }

    // under a header both grammars open it is not top-level to any npm, and the rotation goes ahead
    const p = project({ user: user("[real]\n${HOST}:_authToken=apm_oldoldoldoldoldold01\n") });

    expect(saveToken(join(p.env.HOME, ".npmrc"), "https://registry.apmjs.dev/", "apm_newnewnewnewnewnew01")).toEqual({ kind: "saved" });
  });

  test("APM_TOKEN is withheld, whatever npm is on PATH, when the grammars read the user registry differently (review of 5b75caa)", () => {
    const user = "[custom] \nregistry=https://r.example/\n";

    const env = (path: string | undefined, extra: Record<string, string> = {}) => {
      const p = project({ user });

      const base = { HOME: p.env.HOME, APM_TOKEN: "apm_envenvenvenvenvenv01", ...extra };

      return loadConfig(p.root, path === undefined ? base : { ...base, PATH: path });
    };

    for (const path of [NPM92_DEBIAN, NPM11, undefined]) {
      expect(env(path)).toMatchObject({ token: null, withheld: { kind: "ambiguous", exact: "https://r.example/", spaced: DEFAULT_REGISTRY } });
      // naming the registry settles it
      expect(env(path, { APM_REGISTRY: "https://r.example/" })).toMatchObject({ registry: "https://r.example/", token: "apm_envenvenvenvenvenv01", withheld: null });
    }
  });

  test("the warning that APM_TOKEN was withheld names registries by origin only, never a credential in the URL", async () => {
    // a refused port: whoami fails at once, after the warning
    const p = project({ user: "[custom] \nregistry=http://127.0.0.1:9/SECRET_PATH_TOKEN/?key=SECRET_QUERY_KEY\n" });

    const proc = Bun.spawn([process.execPath, join(import.meta.dir, "..", "src", "main.ts"), "whoami"], {
      cwd: p.root,
      env: { HOME: p.env.HOME, APM_TOKEN: "apm_envenvenvenvenvenv01", NO_COLOR: "1", PATH: "/usr/bin:/bin" },
      stdin: "ignore",
      stdout: "pipe",
      stderr: "pipe",
    });

    const [out, err] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);

    expect(err).toContain("APM_TOKEN is not sent");
    expect(err).toContain("http://127.0.0.1:9/");
    expect(out + err).not.toContain("SECRET_");
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
