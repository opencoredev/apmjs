// On 0.1.3 `apm publish --help` packed, scored and ran `bun publish`, because --help was read only as the first
// argument. Every command apm runs itself now prints its own help for --help or -h anywhere in its arguments, and
// refuses a flag it does not read, before anything else. Each run here is in a fresh folder, with a recording registry
// and a package manager stand-in on PATH that logs every call: help and a refusal must reach neither, and change no file.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { COMMANDS } from "../src/commands.ts";

const CLI = join(import.meta.dir, "..", "src", "main.ts");
const PACKAGE_JSON = `${JSON.stringify({ name: "help-probe", version: "1.0.0", main: "index.js" })}\n`;
let requests: string[] = [];
let server: ReturnType<typeof Bun.serve> | null = null;

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req): Response {
      requests.push(`${req.method} ${new URL(req.url).pathname}`);

      return Response.json({ error: "this registry records calls only" }, { status: 500 });
    },
  });
});

afterAll(() => {
  server?.stop(true);
});

type Run = { code: number; out: string; err: string; pmCalls: string[]; files: string[]; packageJson: string };

async function apm(argv: string[], yarnVersion = "4.5.0", packageJson = PACKAGE_JSON, files: Record<string, string> = {}): Promise<Run> {
  const root = mkdtempSync(join(tmpdir(), "apm-help-"));
  const cwd = join(root, "pkg");
  const bin = join(root, "bin");
  const log = join(root, "pm.log");

  mkdirSync(cwd);
  mkdirSync(bin);
  writeFileSync(join(cwd, "package.json"), packageJson);
  writeFileSync(join(cwd, "index.js"), "module.exports = 1;\n");

  for (const [name, text] of Object.entries(files)) writeFileSync(join(cwd, name), text);

  for (const pm of ["bun", "npm", "pnpm", "yarn", "bunx", "npx"]) {
    const version = pm === "yarn" ? `[ "$1" = --version ] && echo ${yarnVersion} && exit 0\n` : pm === "bun" ? `[ "$1" = --version ] && echo 1.4.4 && exit 0\n` : "";

    writeFileSync(join(bin, pm), `#!/bin/sh\n${version}echo "${pm} $*" >> ${JSON.stringify(log)}\nexit 0\n`);
    chmodSync(join(bin, pm), 0o755);
  }

  requests = [];

  try {
    const proc = Bun.spawn([process.execPath, CLI, ...argv], {
      cwd,
      env: { PATH: `${bin}:/usr/bin:/bin`, HOME: root, TMPDIR: root, NO_COLOR: "1", APM_REGISTRY: server?.url.href ?? "" },
      stdin: "ignore",
      stdout: "pipe",
      stderr: "pipe",
    });

    const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);

    return {
      code,
      out,
      err,
      pmCalls: existsSync(log) ? readFileSync(log, "utf8").trim().split("\n") : [],
      files: readdirSync(cwd).sort(),
      packageJson: readFileSync(join(cwd, "package.json"), "utf8"),
    };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function expectNothingRan(r: Run): void {
  const context = r.out + r.err;

  expect(requests, context).toEqual([]);
  expect(r.pmCalls, context).toEqual([]);
  expect(r.files, context).toEqual(["index.js", "package.json"]);
  expect(r.packageJson, context).toBe(PACKAGE_JSON);
}

/** Arguments each command would act on, so help is asked for among real ones and not only alone. */
const REAL = new Map(Object.entries({
  add: ["zod", "-D", "--pm", "bun"],
  install: ["zod", "--strict"],
  i: ["zod"],
  x: ["--pm", "bun", "cowsay"],
  exec: ["--strict"],
  dlx: ["--force"],
  score: ["zod"],
  name: ["my-name"],
  explain: ["zod", "--strict"],
  search: ["http", "client", "--size", "5"],
  audit: [],
  yank: ["help-probe@1.0.0", "--reason", "broken"],
  unyank: ["help-probe@1.0.0"],
  revoke: ["help-probe@1.0.0", "--reason", "malware", "--otp", "123456"],
  restore: ["help-probe@1.0.0"],
  incident: ["--since", "2026-11-01T00:00:00Z"],
  publish: ["--bump", "patch", "--tag", "next"],
  login: ["--no-browser"],
  whoami: [],
}));

const NAMES = [...Object.keys(COMMANDS), "exec", "dlx"];

describe("--help and -h", () => {
  test("every command apm runs itself has arguments here", () => {
    expect([...REAL.keys()].sort()).toEqual([...NAMES].sort());
  });

  for (const cmd of NAMES) {
    const real = REAL.get(cmd) ?? [];

    const placements: [string, string[]][] = [
      ["first", ["--help", ...real]],
      ["-h first", ["-h", ...real]],
      ["last", [...real, "--help"]],
      ["-h last", [...real, "-h"]],
      // after --, apm x's arguments are the binary's (apm x tool -- --help is the binary's help)
      ...(["x", "exec", "dlx"].includes(cmd) ? [] : ([["after --", [...real, "--", "--help"]]] satisfies [string, string[]][])),
      ["with --json", ["--json", "--help", ...real]],
    ];

    for (const [where, rest] of placements) {
      test(`apm ${cmd} ${rest.join(" ")} prints its help (${where}) and runs nothing`, async () => {
        const r = await apm([cmd, ...rest]);

        expect(r.code, r.out + r.err).toBe(0);
        expect(r.out).toStartWith("usage: apm ");
        expectNothingRan(r);
      });
    }
  }

  test("apm publish --tag --help prints help instead of publishing with the tag --help", async () => {
    const r = await apm(["publish", "--tag", "--help"]);

    expect(r.code).toBe(0);
    expect(r.out).toStartWith("usage: apm publish");
    expectNothingRan(r);
  });

  test("apm publish --dry-run --bump minor -h writes no version", async () => {
    const r = await apm(["publish", "--dry-run", "--bump", "minor", "-h"]);

    expect(r.code).toBe(0);
    expectNothingRan(r);
  });

  test.each([["publish"], ["exec"], ["dlx"], ["i"]])("apm help %s is apm %s --help", async (cmd) => {
    const [a, b] = [await apm(["help", cmd]), await apm([cmd, "--help"])];

    expect(a.out).toBe(b.out);
    expect(a.out).toStartWith("usage: apm ");
    expectNothingRan(a);
  });

  test("apm x tool --help is apm x's help; the binary's help is after --", async () => {
    const r = await apm(["x", "cowsay", "--help"]);

    expect(r.out).toStartWith("usage: apm x");
    expect(r.out).toContain("apm x tool -- --help");
    expectNothingRan(r);
  });
});

describe("a flag a command does not read", () => {
  for (const cmd of NAMES) {
    for (const bad of ["--bogus", "-E", "--yes=1"]) {
      test(`apm ${cmd} ${bad} is refused before anything runs`, async () => {
        const r = await apm([cmd, bad, ...(REAL.get(cmd) ?? [])]);

        expect(r.code, r.out + r.err).toBe(2);
        expect(r.err).toContain("Nothing was run");
        expectNothingRan(r);
      });
    }
  }

  test.each([
    [["publish", "--dry-run=no"], "--dry-run takes no value"],
    [["publish", "--tag"], "--tag needs a value"],
    [["publish", "./dist"], "apm publish takes no arguments"],
    [["revoke", "a@1.0.0", "b@1.0.0", "--reason", "x"], "apm revoke takes one argument"],
    [["audit", "--reason", "x"], "unknown flag --reason for apm audit"],
    [["add", "zod", "--save-prod"], "unknown flag --save-prod for apm add"],
    [["add", "zod", "--tag", "next"], "--tag is read only by your package manager's own install"],
    [["publish", "--bump", "patch", "--tag", "--dry-run"], "--tag needs a value"],
    [["publish", "--tag", "--bogus"], "--tag needs a value"],
    [["incident", "--since", "2026-11-01T00:00:00Z", "--reason", "--dry-run"], "--reason needs a value"],
    [["publish", "--constructor", "--bump", "patch"], "unknown flag --constructor for apm publish"],
    [["publish", "--__proto__"], "unknown flag --__proto__ for apm publish"],
    [["add", "zod", "--", "zod2"], "unknown flag -- for apm add"],
    [["install", "--size", "zod"], "unknown flag --size for apm install"],
    [["install", "--pm"], "--pm needs a value"],
    [["publish", "--tag="], "--tag needs a value"],
    [["publish", "--pm="], "--pm needs a value"],
    [["publish", "--tag=--registry=http://127.0.0.1:9/"], "--tag cannot start with -"],
    [["run", "dev", "--pm"], "--pm needs a value"],
    [["install", "--pm="], "--pm needs a value"],
    [["run", "dev", "--pm="], "--pm needs a value"],
  ])("apm %p: %s", async (argv, message) => {
    const r = await apm(argv);

    expect(r.code).toBe(2);
    expect(r.err).toContain(message);
    expectNothingRan(r);
  });

  test("a flag in place of the command is refused: apm --pm npm add zod would reach npm unchecked", async () => {
    const r = await apm(["--pm", "npm", "add", "zod"]);

    expect(r.code).toBe(2);
    expect(r.err).toContain("--pm is not a command");
    expectNothingRan(r);
  });

  test("--json reports the refusal as one JSON document", async () => {
    const r = await apm(["publish", "--bogus", "--json"]);

    expect(r.code).toBe(2);
    expect(JSON.parse(r.out)).toEqual({ ok: false, error: "apm: unknown flag --bogus for apm publish. Nothing was run." });
    expectNothingRan(r);
  });
});

describe("apm itself", () => {
  test.each(["--version", "-v"])("apm %s prints the version", async (flag) => {
    const r = await apm([flag]);

    expect(r.code).toBe(0);
    expect(r.out.trim()).toMatch(/^\d+\.\d+\.\d+$/);
    expectNothingRan(r);
  });

  test.each([[[]], [["--help"]], [["-h"]], [["help"]]])("apm %p prints the command list", async (argv) => {
    const r = await apm(argv);

    expect(r.code).toBe(0);
    expect(r.out).toContain("apm <command> --help");
    expectNothingRan(r);
  });
});

describe("what still goes to the package manager", () => {
  test("apm install with no packages is the package manager's install, its flags included", async () => {
    const r = await apm(["install", "--frozen-lockfile"]);

    expect(r.code).toBe(0);
    expect(r.pmCalls).toEqual(["bun install --frozen-lockfile"]);
  });

  test("apm constructor --help is refused like any command apm does not pass on, not a crash", async () => {
    const r = await apm(["constructor", "--help"]);

    expect(r.code, r.out + r.err).toBe(2);
    expect(r.err).toContain("apm does not pass constructor on to bun");
    expect(r.pmCalls).toEqual([]);
  });

  test("apm's --pm is read only before --; after it, it is the package manager's", async () => {
    const r = await apm(["run", "--pm", "npm", "dev", "--", "--pm", "pnpm"]);

    expect(r.pmCalls).toEqual(["npm run dev -- --pm pnpm"]);
  });

  test("apm install --tag next with no packages is the package manager's install, as on 0.1.3", async () => {
    const r = await apm(["install", "--pm", "npm", "--tag", "next"]);

    expect(r.code, r.out + r.err).toBe(0);
    expect(r.pmCalls).toEqual(["npm install --tag next"]);
  });

  // a bare install checks nothing, so no word of it may reach the package manager as a package: bun 1.1 to 1.3 install
  // the word after an option they do not know, npm reads --audit=off as a package off, and an option that takes a value
  // takes the next one as its value. Plain switches pass, and npm's --tag and --omit with a checked value.
  const refusedBare = (word: string, pm: string) => `apm install with no packages does not pass ${word} on to ${pm}`;

  test.each([
    [["install", "--tag", "left-pad"], refusedBare("--tag", "bun")],
    [["i", "--tag", "left-pad"], "apm i with no packages does not pass --tag on to bun"],
    [["install", "--pm", "bun", "--tag", "left-pad"], refusedBare("--tag", "bun")],
    [["install", "--pm", "pnpm", "--tag", "left-pad"], refusedBare("--tag", "pnpm")],
    [["install", "--pm=yarn", "--tag", "left-pad"], refusedBare("--tag", "yarn")],
    [["install", "--tag=next"], refusedBare("--tag=next", "bun")],
    [["install", "--omit", "dev"], refusedBare("--omit", "bun")],
    [["install", "--omit=dev"], refusedBare("--omit=dev", "bun")],
    [["install", "--cooldown", "left-pad"], refusedBare("--cooldown", "bun")],
    [["install", "--pm", "npm", "--floor", "left-pad"], refusedBare("--floor", "npm")],
    [["install", "--pm", "npm", "--audit=off"], refusedBare("--audit=off", "npm")],
    [["install", "--pm", "npm", "--prefix", "--tag", "left-pad"], refusedBare("--prefix", "npm")],
    [["install", "--pm", "npm", "--registry", "--pm", "npm", "--omit", "dev"], refusedBare("--registry", "npm")],
    [["install", "--pm", "npm", "---", "left-pad"], "unknown flag - for apm install"],
    [["install", "--pm", "npm", "---"], refusedBare("---", "npm")],
    [["install", "--pm", "npm", "--tag", "1.x"], refusedBare("--tag", "npm")],
    [["install", "--pm", "npm", "--omit", "left-pad"], refusedBare("--omit", "npm")],
    [["install", "--pm", "pnpm", "--force=off"], refusedBare("--force=off", "pnpm")],
    [["install", "-P"], refusedBare("-P", "bun")],
    [["install", "--pm", "--pm", "npm", "--tag", "left-pad"], "--pm needs a value"],
    [["install", "--pm=", "--pm", "npm"], "--pm needs a value"],
    [["install", "--pm", "", "--pm", "npm"], "--pm needs a value"],
    [["install", "--pm", "npm", "--loglevel", "--tag=next"], refusedBare("--loglevel", "npm")],
    [["install", "--pm", "npm", "--global"], "does not pass --global on to npm"],
    [["install", "--global", "--frozen-lockfile"], "does not pass --global on to bun"],
    [["install", "--pm", "pnpm", "--global"], "does not pass --global on to pnpm"],
    [["install", "--pm", "npm", "--location", "--force"], "does not pass --location on to npm"],
    [["install", "-g"], refusedBare("-g", "bun")],
    [["install", "--pm", "npm", "--g"], "does not pass --g on to npm"],
    [["install", "--pm", "npm", "--no-no-global"], "does not pass --no-no-global on to npm"],
    [["install", "--pm", "npm", "--loca", "--force"], "does not pass --loca on to npm"],
    [["install", "--pm", "npm", "--global=true"], "does not pass --global=true on to npm"],
    [["install", "--pm", "pnpm", "--frozen-lockfile=off"], refusedBare("--frozen-lockfile=off", "pnpm")],
    [["install", "--pm", "pnpm", "--frozen-lockfile=true"], refusedBare("--frozen-lockfile=true", "pnpm")],
    [["install", "--pm", "npm", "--gf"], refusedBare("--gf", "npm")],
    [["install", "--pm", "pnpm", "--local=false"], refusedBare("--local=false", "pnpm")],
    [["install", "--pm", "npm", "--quiet=false"], refusedBare("--quiet=false", "npm")],
    [["install", "--pm", "npm", "--prefix=true"], refusedBare("--prefix=true", "npm")],
    [["install", "--cwd=true"], refusedBare("--cwd=true", "bun")],
    [["install", "--pm", "yarn", "--immutable=true"], refusedBare("--immutable=true", "yarn")],
    [["install", "--pm", "npm", "--global-style"], refusedBare("--global-style", "npm")],
    [["install", "--pm", "npm", "--frozen-lockfile"], "npm ignores --frozen-lockfile and may rewrite package-lock.json"],
    [["install", "--pm", "pnpm", "--frozen-lockfile", "--fix-lockfile"], refusedBare("--fix-lockfile", "pnpm")],
    [["install", "--pm", "yarn", "--frozen-lockfile", "--force"], refusedBare("--force", "yarn")],
    [["install", "--pm", "pnpm", "--no-frozen-lockfile"], refusedBare("--no-frozen-lockfile", "pnpm")],
    [["install", "--pm", "pnpm", "--lockfile-only"], refusedBare("--lockfile-only", "pnpm")],
    [["install", "--pm", "npm", "--no-package-lock"], refusedBare("--no-package-lock", "npm")],
    [["install", "--pm", "npm", "--workspaces"], refusedBare("--workspaces", "npm")],
    [["install", "--pm", "yarn", "--pure-lockfile"], refusedBare("--pure-lockfile", "yarn")],
    [["install", "--no-save"], refusedBare("--no-save", "bun")],
    [["install", "--pm", "pnpm", "--ignore-pnpmfile"], refusedBare("--ignore-pnpmfile", "pnpm")],
    [["install", "--pm", "pnpm", "--legacy-peer-deps"], refusedBare("--legacy-peer-deps", "pnpm")],
    [["install", "--pm", "yarn", "--check-cache"], "passes on only switches of yarn's own install such as --frozen-lockfile"],
    [["install", "--", "left-pad"], "unknown flag -- for apm install"],
    [["install", "--pm", "npm", "--", "left-pad"], "unknown flag -- for apm install"],
    [["install", "--", "--cooldown", "left-pad"], refusedBare("--", "bun")],
    [["i", "--frozen-lockfile", "--"], "apm i with no packages does not pass -- on to bun"],
  ])("apm %p is refused: %s", async (argv, message) => {
    const r = await apm(argv);

    expect(r.code, r.out + r.err).toBe(2);
    expect(r.err).toContain(message);
    expectNothingRan(r);
  });

  // everyday forms 0.1.5 passed on still run (HOME-355's matrix and common CI flags)
  test.each([
    [["install"], "bun install"],
    [["install", "--pm", "npm"], "npm install"],
    [["install", "--pm", "npm", "--tag", "next"], "npm install --tag next"],
    [["install", "--pm", "npm", "--omit", "dev"], "npm install --omit dev"],
    [["install", "--pm", "npm", "--omit=peer", "--tag=beta", "--no-audit"], "npm install --omit=peer --tag=beta --no-audit"],
    [["install", "--pm", "npm", "--legacy-peer-deps", "--tag", "next", "--force"], "npm install --legacy-peer-deps --tag next --force"],
    [["install", "--pm", "npm", "--silent", "--tag", "next", "--no-audit", "--omit", "dev"], "npm install --silent --tag next --no-audit --omit dev"],
    [["i", "--frozen-lockfile", "--production"], "bun install --frozen-lockfile --production"],
    [["install", "--force"], "bun install --force"],
    [["install", "--json"], "bun install --json"],
    [["install", "--pm=pnpm", "--frozen-lockfile", "--prod"], "pnpm install --frozen-lockfile --prod"],
    [["install", "--pm", "yarn", "--frozen-lockfile", "--ignore-engines"], "yarn install --frozen-lockfile --ignore-engines"],
    [["install", "--pm", "yarn", "--immutable"], "yarn install --immutable"],
    [["install", "--pm", "pnpm", "--force", "--ignore-scripts"], "pnpm install --force --ignore-scripts"],
    [["install", "--pm", "yarn", "--frozen-lockfile", "--json", "--production"], "yarn install --frozen-lockfile --json --production"],
    [["install", "--pm", "npm", "--tag", "next", "--force"], "npm install --tag next --force"],
    [["install", "--pm", "npm", "--package-lock-only", "--omit", "dev"], "npm install --package-lock-only --omit dev"],
    [["install", "--pm", "npm", "--json", "--omit", "dev"], "npm install --json --omit dev"],
  ])("apm %p is the package manager's install: no word of it can be a package", async (argv, call) => {
    const r = await apm(argv);

    expect(r.code, r.out + r.err).toBe(0);
    expect(r.pmCalls).toEqual([call]);
  });

  test("apm install --immutable is refused on yarn 1, which ignores it and rewrites a stale yarn.lock", async () => {
    const r = await apm(["install", "--pm", "yarn", "--immutable"], "1.22.22");

    expect(r.code, r.out + r.err).toBe(2);
    expect(r.err).toContain("yarn 1.22.22 ignores --immutable and may rewrite yarn.lock; use --frozen-lockfile");
    expectNothingRan(r);
  });

  const WITH_ZOD = `${JSON.stringify({ name: "help-probe", version: "1.0.0", dependencies: { zod: "^4.0.0" }, devDependencies: { "@types/node": "^24.0.0" } })}\n`;

  test.each([
    [["update"]],
    [["update", "--latest"]],
    [["update", "zod"]],
    [["update", "left-pad"]],
    [["update", "--tag", "left-pad"]],
    [["up", "--cooldown", "left-pad"]],
    [["upgrade", "--", "left-pad"]],
    [["upgrade", "--pm", "bun", "--help"]],
    [["up", "--pm", "pnpm", "-L", "-r", "zod"]],
    [["upgrade", "--pm=yarn", "--latest", "zod"]],
    [["update", "--pm", "npm", "--save", "zod"]],
  ])("apm %p is refused: an update fetches versions apm cannot check", async (argv) => {
    const r = await apm(argv, "4.5.0", WITH_ZOD);

    expect(r.code, r.out + r.err).toBe(2);
    expect(r.err).toContain("would fetch new versions apm cannot check. Nothing was run.");
    expect(r.out + r.err).toContain("apm add <package>@latest");
    expect(r.pmCalls).toEqual([]);
    expect(r.packageJson).toBe(WITH_ZOD);
  });

  test.each([[["udpate"]], [["upd"]], [["upgr"]], [["UPDATE"]], [["Up", "zod"]]])("apm %p is refused as an update", async (argv) => {
    const r = await apm(argv, "4.5.0", WITH_ZOD);

    expect(r.code, r.out + r.err).toBe(2);
    expect(r.err).toContain("would fetch new versions apm cannot check. Nothing was run.");
    expect(r.pmCalls).toEqual([]);
  });

  test("apm upgrade with yarn names both of yarn's own update commands", async () => {
    const r = await apm(["upgrade", "--pm", "yarn"], "4.5.0", WITH_ZOD);

    expect(r.code, r.out + r.err).toBe(2);
    expect(r.out + r.err).toContain("yarn upgrade (yarn 1) or yarn up (yarn 2 and later)");
  });

  test.each([[["ADD", "zod"]], [["Install", "zod"]], [["CI"]], [["Remove", "zod"]], [["LINK", "left-pad"]], [["EXEC", "cowsay"]], [["u", "zod"]], [["upgrade-interactive"]], [["recursive", "update"]], [["link", "left-pad"]], [["rebuild"]], [["create", "vite"]], [["init", "vite"]]])("apm %p is refused: apm passes on only commands that cannot install an unchecked package", async (argv) => {
    const r = await apm(argv, "4.5.0", WITH_ZOD);

    expect(r.code, r.out + r.err).toBe(2);
    expect(r.err).toContain(`apm does not pass ${argv[0]} on to bun: it could install packages apm cannot check`);
    expect(r.pmCalls).toEqual([]);
  });

  test.each([
    [["ci", "--pm", "npm", "left-pad"], "apm ci with no packages does not pass left-pad on to npm"],
    [["ci", "--pm", "npm", "--audit=off"], "apm ci with no packages does not pass --audit=off on to npm"],
    [["ci", "--pm", "yarn"], "yarn has no ci apm can pass on; for a frozen install run apm install --frozen-lockfile"],
    [["ci"], "bun has no ci apm can pass on; for a frozen install run apm install --frozen-lockfile"],
    [["ci", "--pm", "pnpm", "--prod"], "pnpm has no ci apm can pass on; for a frozen install run apm install --frozen-lockfile"],
    [["run", "-i", "build.ts"], "apm does not pass bun's -i on"],
    [["run", "--install=force", "build.ts"], "apm does not pass bun's --install=force on"],
    [["run", "--bun", "dev"], "apm does not pass bun's --bun on"],
    [["run", "--silent", "--bun", "dev"], "apm does not pass bun's --bun on"],
    [["test", "--install=force"], "apm does not pass bun's --install=force on"],
    [["start"], "apm does not pass start on to bun"],
    [["ls"], "apm does not pass ls on to bun"],
    [["why", "zod"], "apm does not pass why on to bun"],
    [["/abs/dev"], "apm does not pass /abs/dev on to bun"],
    [["rm", "--pm", "yarn", "zod"], "apm cannot read yarn's lockfile, so it cannot check that a removal installs nothing new"],
    [["ls", "--pm", "yarn"], "apm does not pass ls on to yarn"],
    [["remove", "--pm", "npm", "zod", "--no-package-lock"], "apm remove takes only the names of the packages to remove, not --no-package-lock"],
    [["rm", "zod", "--", "--force"], "apm rm takes only the names of the packages to remove, not --force"],
    [["index"], "apm does not pass index on to bun"],
    [["info", "left-pad"], "apm does not pass info on to bun"],
  ])("apm %p is refused: %s", async (argv, message) => {
    const r = await apm(argv);

    expect(r.code, r.out + r.err).toBe(2);
    expect(r.err).toContain(message);
    expectNothingRan(r);
  });

  test.each([
    [["ci", "--pm", "npm", "--omit", "dev"], "npm ci --omit dev"],
    [["ci", "--pm", "npm", "--omit=dev", "--ignore-scripts"], "npm ci --omit=dev --ignore-scripts"],
  ])("apm %p is the package manager's clean install", async (argv, call) => {
    const r = await apm(argv);

    expect(r.code, r.out + r.err).toBe(0);
    expect(r.pmCalls).toEqual([call]);
  });

  test.each([
    [["why", "--pm", "npm", "zod"], "npm why zod"],
    [["outdated", "--pm", "pnpm"], "pnpm --config.verify-deps-before-run=false outdated"],
    [["dev", "--pm", "pnpm"], "pnpm --config.verify-deps-before-run=false run dev"],
    [["start", "--pm", "npm"], "npm start"],
    [["run", "dev", "-i"], "bun run --no-install dev -i"],
    [["run", "--silent", "dev"], "bun run --no-install --silent dev"],
    [["run", "--help"], "bun run --no-install --help"],
    [["test", "--watch"], "bun test --watch"],
    [["dev", "--port", "3000"], "bun run --no-install dev --port 3000"],
    [["run", "build.ts", "a"], "bun run --no-install build.ts a"],
    [["run", "--pm", "npm", "dev"], "npm run dev"],
  ])("apm %p is passed on: it installs nothing new, or it is a project script", async (argv, call) => {
    const r = await apm(argv, "4.5.0", `${JSON.stringify({ name: "help-probe", version: "1.0.0", scripts: { dev: "vite" }, dependencies: { zod: "^4.0.0" } })}\n`);

    expect(r.code, r.out + r.err).toBe(0);
    expect(r.pmCalls).toEqual([call]);
  });

  test("apm dev is refused while a bunfig.toml runs node as bun", async () => {
    const r = await apm(["dev"], "4.5.0", `${JSON.stringify({ name: "help-probe", version: "1.0.0", scripts: { dev: "node dev.mjs" } })}\n`, { "bunfig.toml": "[run]\nbun = true\n" });

    expect(r.code, r.out + r.err).toBe(2);
    expect(r.err).toContain("a bunfig.toml sets run.bun");
    expect(r.pmCalls).toEqual([]);
  });

  test.each([["[\"run\"]\nbun = true\n"], ["run = { bun = true }\n"]])("apm dev is refused while bunfig.toml %p may run node as bun", async (bunfig) => {
    const r = await apm(["dev"], "4.5.0", `${JSON.stringify({ name: "help-probe", version: "1.0.0", scripts: { dev: "node dev.mjs" } })}\n`, { "bunfig.toml": bunfig });

    expect(r.code, r.out + r.err).toBe(2);
    expect(r.err).toContain("a bunfig.toml sets run.bun");
    expect(r.pmCalls).toEqual([]);
  });

  test("apm dev runs under a bunfig.toml that leaves run.bun off", async () => {
    const r = await apm(["dev"], "4.5.0", `${JSON.stringify({ name: "help-probe", version: "1.0.0", scripts: { dev: "node dev.mjs" } })}\n`, { "bunfig.toml": "[run]\nbun = false\nsilent = true\n" });

    expect(r.code, r.out + r.err).toBe(0);
    expect(r.pmCalls).toEqual(["bun run --no-install dev"]);
  });

  test.each([[["help", "remove"]], [["remove", "--help"]], [["rm", "-h"]]])("apm %p prints removal's help on stdout and runs nothing", async (argv) => {
    const r = await apm(argv);

    expect(r.code, r.out + r.err).toBe(0);
    expect(r.out).toContain("usage: apm remove <package>...");
    expect(r.pmCalls).toEqual([]);
  });

  test.each([[["help", "ci"]], [["ci", "--json", "--help"]]])("apm %p prints ci's help on stdout and runs nothing", async (argv) => {
    const r = await apm(argv);

    expect(r.code, r.out + r.err).toBe(0);
    expect(r.out).toContain("usage: apm ci");
    expect(r.pmCalls).toEqual([]);
  });

  const ZOD_LOCKS: [string, string, string][] = [
    ["bun", "bun.lock", JSON.stringify({ lockfileVersion: 1, workspaces: { "": { name: "help-probe", dependencies: { zod: "^4.0.0" } } }, packages: { zod: ["zod@4.1.0", "", {}, "sha512-zod"] } })],
    ["npm", "package-lock.json", JSON.stringify({ name: "help-probe", lockfileVersion: 3, requires: true, packages: { "": { name: "help-probe", dependencies: { zod: "^4.0.0" } }, "node_modules/zod": { version: "4.1.0", resolved: "https://registry.npmjs.org/zod/-/zod-4.1.0.tgz", integrity: "sha512-zod" } } })],
    ["pnpm", "pnpm-lock.yaml", JSON.stringify({ lockfileVersion: "9.0", importers: { ".": { dependencies: { zod: { specifier: "^4.0.0", version: "4.1.0" } } } }, packages: { "zod@4.1.0": { resolution: { integrity: "sha512-zod" } } }, snapshots: { "zod@4.1.0": {} } })],
    ["yarn", "yarn.lock", 'zod@^4.0.0:\n  version "4.1.0"\n'],
  ];

  const withDeps = (dependencies: Record<string, string>): string => `${JSON.stringify({ name: "help-probe", version: "1.0.0", dependencies })}\n`;

  test.each(ZOD_LOCKS.filter(([pm]) => pm !== "yarn"))("apm remove with %s refuses when the package manager did not compute a new lockfile in the copy", async (pm, file, lock) => {
    const r = await apm(["remove", "--pm", pm, "zod"], "1.22.22", withDeps({ zod: "^4.0.0" }), { [file]: lock });

    expect(r.code, r.out + r.err).toBe(1);
    expect(r.err).toContain(`${pm} did not rewrite ${file} for the removal`);
    expect(r.pmCalls.some((call) => call.includes(" remove ") || call.includes(" uninstall "))).toBe(false);
  });

  test.each([
    [["remove", "zod"], withDeps({ zod: "^4.0.0" }), {}, "apm remove needs a lockfile it can read (there is no bun.lock)"],
    [["remove", "--pm", "npm", "zod"], withDeps({ zod: "^4.0.0" }), {}, "apm remove needs a lockfile it can read (there is no package-lock.json)"],
    [["remove", "--pm", "yarn", "zod"], withDeps({ zod: "^4.0.0" }), { "yarn.lock": ZOD_LOCKS[3]?.[2] ?? "" }, "apm cannot read yarn's lockfile, so it cannot check that a removal installs nothing new"],
    [["remove", "left-pad"], withDeps({ zod: "^4.0.0" }), { "bun.lock": ZOD_LOCKS[0]?.[2] ?? "" }, "refused: left-pad is not in package.json. Nothing was run."],
    [["remove"], withDeps({ zod: "^4.0.0" }), { "bun.lock": ZOD_LOCKS[0]?.[2] ?? "" }, "apm remove needs the names of the packages to remove"],
  ] as const)("apm %p is refused", async (argv, packageJson, files, message) => {
    const r = await apm([...argv], "1.22.22", packageJson, files);

    expect(r.code, r.out + r.err).not.toBe(0);
    expect(r.err).toContain(message);
    expect(r.pmCalls).toEqual([]);
  });

  test("apm dev runs under a bunfig.toml whose run table leaves bun unset", async () => {
    const r = await apm(["dev"], "4.5.0", `${JSON.stringify({ name: "help-probe", version: "1.0.0", scripts: { dev: "node dev.mjs" } })}\n`, { "bunfig.toml": "[run]\nsilent = true\n" });

    expect(r.code, r.out + r.err).toBe(0);
    expect(r.pmCalls).toEqual(["bun run --no-install dev"]);
  });

  test("apm remove with bun gets past a bunfig.toml whose lockfile table leaves save unset", async () => {
    const r = await apm(["remove", "zod"], "1.22.22", withDeps({ zod: "^4.0.0" }), { "bun.lock": ZOD_LOCKS[0]?.[2] ?? "", "bunfig.toml": "[install.lockfile]\nprint = \"yarn\"\n" });

    expect(r.err).not.toContain("install.lockfile.save");
    expect(r.err).toContain("bun did not rewrite bun.lock for the removal");
  });

  test("apm remove with pnpm is refused when the project has a .pnpmfile.cjs", async () => {
    const r = await apm(["remove", "--pm", "pnpm", "zod"], "1.22.22", withDeps({ zod: "^4.0.0" }), { "pnpm-lock.yaml": ZOD_LOCKS[2]?.[2] ?? "", ".pnpmfile.cjs": "module.exports = {};\n" });

    expect(r.code, r.out + r.err).toBe(1);
    expect(r.err).toContain("the project has a .pnpmfile.cjs");
    expect(r.pmCalls).toEqual([]);
  });

  test.each([
    [{ react: { optional: true } }, false],
    [{}, true],
  ])("apm remove with npm and a peer the lockfile lacks, peerDependenciesMeta %p: refused as unpinned %p", async (peerDependenciesMeta, refused) => {
    const packageJson = `${JSON.stringify({ name: "help-probe", version: "1.0.0", dependencies: { zod: "^4.0.0" }, peerDependencies: { react: "^19.0.0" }, peerDependenciesMeta })}\n`;
    const r = await apm(["remove", "--pm", "npm", "zod"], "1.22.22", packageJson, { "package-lock.json": ZOD_LOCKS[1]?.[2] ?? "" });

    expect(r.code, r.out + r.err).toBe(1);
    expect(r.err.includes("package.json lists react@^19.0.0, which package-lock.json does not pin")).toBe(refused);
    expect(r.pmCalls.some((call) => call.includes(" remove ") || call.includes(" uninstall "))).toBe(false);
  });

  test.each([["rm"], ["uninstall"]])("apm %s with yarn is refused like remove, even with a script of that name", async (cmd) => {
    const r = await apm([cmd, "--pm", "yarn", "zod"], "1.22.22", `${JSON.stringify({ name: "help-probe", version: "1.0.0", scripts: { [cmd]: "echo ran" } })}\n`);

    expect(r.code, r.out + r.err).toBe(2);
    expect(r.err).toContain("apm cannot read yarn's lockfile");
    expect(r.pmCalls).toEqual([]);
  });

  test("apm uninstall with yarn points to yarn remove, not yarn's own uninstall", async () => {
    const r = await apm(["uninstall", "--pm", "yarn", "zod"]);

    expect(r.code, r.out + r.err).toBe(2);
    expect(r.out + r.err).toContain("apm cannot check a removal with yarn; run yarn remove <package> yourself.");
    expect(r.out + r.err).not.toContain("yarn uninstall");
    expect(r.pmCalls).toEqual([]);
  });

  test("apm ci --help prints ci's help and runs nothing", async () => {
    const r = await apm(["ci", "--help"]);

    expect(r.code, r.out + r.err).toBe(0);
    expect(r.out).toContain("usage: apm ci");
    expect(r.pmCalls).toEqual([]);
  });

  test("apm run dev --help is the package manager's", async () => {
    const r = await apm(["run", "dev", "--help"]);

    expect(r.pmCalls).toEqual(["bun run --no-install dev --help"]);
  });
});
