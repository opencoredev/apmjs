// The /publish page's install lines (apps/web/lib/publish-prompt.ts), run for real by sh against the real install
// script, with an older, unchecked apm already at ~/.apm/bin/apm. Whatever goes wrong (an exported APM_INSTALL, a
// download that fails, comes back empty or is cut short, a binary that does not match), the commands that follow must
// never run that older apm. curl is a stand-in that serves the site from a folder; nothing touches the network.
// Review of 1919be8, findings 1 and 2.
import { afterAll, describe, expect, test } from "bun:test";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { manualSteps, publishPrompt } from "../../../apps/web/lib/publish-prompt.ts";
import { installScript, SiteUrl, TARGETS, type CliSum } from "../cli-install.ts";

const work = mkdtempSync(join(tmpdir(), "apm-publish-install-"));

afterAll(() => rmSync(work, { recursive: true, force: true }));

// a curl that only says it was called, first on PATH in the mktemp test
mkdirSync(join(work, "curl-spy"));

writeFileSync(join(work, "curl-spy", "curl"), '#!/bin/sh\necho CURL-CALLED >&2\nexit 22\n', { mode: 0o755 });

const target = { scope: "alice", registry: "https://registry.apmjs.dev/", site: "https://apmjs.dev" };
const NEW = '#!/bin/sh\nif [ "$1" = --version ]; then echo 0.1.0; else echo "NEW $*"; fi\n';
const OLD = '#!/bin/sh\necho "OLD-UNCHECKED $*"\n';
const sha = (text: string) => createHash("sha256").update(text).digest("hex");
const index: CliSum[] = TARGETS.map((t) => ({ version: "0.1.0", target: t.target, sha256: sha(NEW) }));
const SCRIPT = installScript({ site: SiteUrl.parse(target.site), index });

type Download = "ok" | "fails" | "empty" | "cut" | "tampered" | "hollow";

/** A script that lost its middle but kept valid syntax and its last line: it exits 0 and installs nothing. */
const HOLLOW = '#!/bin/sh\nset -eu\nmain() {\n  :\n}\n\nmain "$@"\n';

let n = 0;

/** A HOME holding an older apm, and a curl that serves the site as `download` says. Returns the env to run in. */
function machine(download: Download, env: Record<string, string> = {}) {
  const dir = join(work, `m-${n++}`);
  const home = join(dir, "home");
  const tools = join(dir, "tools");
  const site = join(dir, "site");

  mkdirSync(join(home, ".apm", "bin"), { recursive: true });
  mkdirSync(tools);
  mkdirSync(join(site, "cli", "0.1.0"), { recursive: true });
  writeFileSync(join(home, ".apm", "bin", "apm"), OLD, { mode: 0o755 });
  writeFileSync(join(site, "install"), download === "empty" ? "" : download === "cut" ? SCRIPT.slice(0, Math.floor(SCRIPT.length * 0.3)) : download === "hollow" ? HOLLOW : SCRIPT);

  for (const t of TARGETS) writeFileSync(join(site, "cli", "0.1.0", `apm-${t.target}`), download === "tampered" ? `${NEW}# changed\n` : NEW);
  const curl = download === "fails" ? "exit 22" : `out=""; url=""\nwhile [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2 ;; -*) shift ;; *) url="$1"; shift ;; esac; done\nf="${site}/\${url#${target.site}/}"\n[ -f "$f" ] || exit 22\nif [ -n "$out" ]; then cat "$f" > "$out"; else cat "$f"; fi`;

  writeFileSync(join(tools, "curl"), `#!/bin/sh\n${curl}\n`);
  chmodSync(join(tools, "curl"), 0o755);

  return { home, env: { PATH: `${tools}:/usr/local/bin:/usr/bin:/bin`, HOME: home, TMPDIR: dir, ...env } };
}

function sh(script: string, env: Record<string, string>) {
  const r = Bun.spawnSync(["/bin/sh", "-c", script], { env });

  return { code: r.exitCode, out: r.stdout.toString() + r.stderr.toString() };
}

/** The shell lines step 1 of the prompt gives the agent: its indented lines that start a command. */
function promptInstall(prompt: string): string {
  const step1 = prompt.slice(prompt.indexOf("1. "), prompt.indexOf("\n2. "));

  return step1
    .split("\n")
    .filter((l) => /^ {3}APM_DIR=/.test(l))
    .map((l) => l.trim())
    .join("\n");
}

/** What step 1 says "apm" means. */
function promptApm(prompt: string): string {
  const m = /"apm" means: (.+)$/m.exec(prompt);

  if (m?.[1] === undefined) throw new Error("the prompt does not say what apm means");

  return m[1];
}

const FAILURES: Download[] = ["fails", "empty", "cut", "tampered", "hollow"];

describe("the agent prompt's install", () => {
  const prompt = publishPrompt(target);

  /** An agent that follows the prompt: it runs the install, and runs apm only when that succeeded. */
  function agent(m: { env: Record<string, string> }) {
    const install = sh(promptInstall(prompt), m.env);
    const apm = install.code === 0 ? sh(`${promptApm(prompt)} whoami`, m.env) : null;

    return { install, apm };
  }

  test("with APM_INSTALL exported elsewhere, apm is the binary just checked, not the older one", () => {
    const m = machine("ok", { APM_INSTALL: join(work, "elsewhere") });
    const r = agent(m);

    expect(r.install.code).toBe(0);
    expect(r.install.out).toContain(`installed to ${m.home}/.apm/bin/apm\n`);
    expect(r.install.out).toContain(`SHA-256 ${sha(NEW)}, checked against this script`);
    expect(r.apm?.out).toBe("NEW whoami\n");
  });

  test.each(FAILURES)("a %s download fails the install command, so the older apm never runs", (download) => {
    const r = agent(machine(download));

    expect(r.install.code).not.toBe(0);
    expect(r.install.out).not.toContain("OLD-UNCHECKED");
    expect(r.apm).toBeNull();
  });

  // review of 042013a, finding 1: a failed mktemp must stop the command, not save the script to /install.sh
  test("a failed mktemp stops the install before curl runs", () => {
    const m = machine("ok");
    const r = sh(promptInstall(prompt), { ...m.env, TMPDIR: join(work, "no-such-dir"), PATH: `${join(work, "curl-spy")}:${m.env.PATH ?? ""}` });

    expect(r.code).not.toBe(0);
    expect(r.out).not.toContain("CURL-CALLED");
  });

  test("tells the agent to stop unless both success lines were printed", () => {
    expect(prompt).toContain('Continue only if the command succeeded and printed both "apm <version> (<platform>) installed to <your home>/.apm/bin/apm" and "SHA-256 <hash>, checked against this script"');
    expect(prompt).toContain("Otherwise stop, show me its output, and do not run apm.");
    expect(prompt).toContain('APM_INSTALL="$HOME/.apm" sh "$APM_SCRIPT"');
  });
});

describe("the manual steps", () => {
  /** The whole block a person pastes, with the package.json edit as the comment it is. */
  const steps = manualSteps(target);

  test("with APM_INSTALL exported elsewhere, every apm command runs the binary just checked", () => {
    const m = machine("ok", { APM_INSTALL: join(work, "elsewhere-manual") });
    const r = sh(steps, m.env);

    expect(r.out).toContain(`installed to ${m.home}/.apm/bin/apm\n`);
    expect(r.out).toContain("NEW login\n");
    expect(r.out).toContain("NEW publish --dry-run\n");
    expect(r.out).not.toContain("OLD-UNCHECKED");
  });

  test.each(FAILURES)("after a %s download no apm command runs at all", (download) => {
    const r = sh(steps, machine(download).env);

    expect(r.out).not.toContain("OLD-UNCHECKED");
    expect(r.out).not.toContain("NEW ");
    expect(r.out).toContain("apm: the install did not succeed, so nothing was run");
  });

  test("an apm left on PATH from before is not run either", () => {
    const m = machine("fails");
    const r = sh(steps, { ...m.env, PATH: `${m.home}/.apm/bin:${m.env.PATH ?? ""}` });

    expect(r.out).not.toContain("OLD-UNCHECKED");
  });

  test("the script is saved outside the package folder", () => {
    expect(steps).toContain('APM_DIR="$(mktemp -d)" && APM_SCRIPT="$APM_DIR/install.sh" && curl ');
    expect(steps).not.toContain("| sh");
  });
});
