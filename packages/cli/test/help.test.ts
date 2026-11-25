// On 0.1.3 `apm publish --help` packed, scored and ran `bun publish`, because --help was read only as the first
// argument. Every command apm runs itself now prints its own help for --help or -h anywhere in its arguments, and
// refuses a flag it does not read, before anything else. Each run here is in a fresh folder, with a recording registry
// and a package manager stand-in on PATH that logs every call: help and a refusal must reach neither, and change no file.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
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

async function apm(argv: string[]): Promise<Run> {
  const root = mkdtempSync(join(tmpdir(), "apm-help-"));
  const cwd = join(root, "pkg");
  const bin = join(root, "bin");
  const log = join(root, "pm.log");

  mkdirSync(cwd);
  mkdirSync(bin);
  writeFileSync(join(cwd, "package.json"), PACKAGE_JSON);
  writeFileSync(join(cwd, "index.js"), "module.exports = 1;\n");

  for (const pm of ["bun", "npm", "pnpm", "yarn", "bunx", "npx"]) {
    writeFileSync(join(bin, pm), `#!/bin/sh\necho "${pm} $*" >> ${JSON.stringify(log)}\nexit 0\n`);
    chmodSync(join(bin, pm), 0o755);
  }

  requests = [];
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
}

function expectNothingRan(r: Run): void {
  const context = r.out + r.err;

  expect(requests, context).toEqual([]);
  expect(r.pmCalls, context).toEqual([]);
  expect(r.files, context).toEqual(["index.js", "package.json"]);
  expect(r.packageJson, context).toBe(PACKAGE_JSON);
}

/** Arguments each command would act on, so help is asked for among real ones and not only alone. */
const REAL: Record<string, string[]> = {
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
};

const NAMES = [...Object.keys(COMMANDS), "exec", "dlx"];

describe("--help and -h", () => {
  test("every command apm runs itself has arguments here", () => {
    expect(Object.keys(REAL).sort()).toEqual([...NAMES].sort());
  });

  for (const cmd of NAMES) {
    const real = REAL[cmd] ?? [];

    // x reads flags only before the package: after it, --help is the binary's (apm x tool --help runs tool --help)
    const placements: [string, string[]][] = [
      ["first", ["--help", ...real]],
      ["-h first", ["-h", ...real]],
      ...(cmd === "x" ? [] : ([["last", [...real, "--help"]], ["-h last", [...real, "-h"]]] satisfies [string, string[]][])),
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

  test("apm help publish is apm publish --help", async () => {
    const [a, b] = [await apm(["help", "publish"]), await apm(["publish", "--help"])];

    expect(a.out).toBe(b.out);
    expectNothingRan(a);
  });
});

describe("a flag a command does not read", () => {
  for (const cmd of NAMES) {
    for (const bad of ["--bogus", "-E", "--yes=1"]) {
      test(`apm ${cmd} ${bad} is refused before anything runs`, async () => {
        const r = await apm([cmd, bad, ...(REAL[cmd] ?? [])]);

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
    [["add", "zod", "--save-dev"], "unknown flag --save-dev for apm add"],
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

  test("apm run dev --help is the package manager's", async () => {
    const r = await apm(["run", "dev", "--help"]);

    expect(r.pmCalls).toEqual(["bun run dev --help"]);
  });
});
