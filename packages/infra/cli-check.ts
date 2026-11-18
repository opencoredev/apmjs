// The install check that release-cli.ts runs after a release and smoke.ts runs on every deploy: the documented
// command, `curl -fsSL <site>/install | sh`, into a fresh HOME, then the installed apm's --version, and the fingerprint
// three ways: what the script printed, the SHA-256 of the file it installed, and the line for this machine in the
// version's published SHA256SUMS.
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CliVersion, parseSums, type Target } from "./cli-install.ts";

export type CheckResult = { ok: boolean; detail: string };

/** This machine's binary, picked the way the install script picks it, or null when apm has none for it. */
export function hostTarget(): Target | null {
  const arch = process.arch === "x64" ? "x64" : process.arch === "arm64" ? "arm64" : null;

  if (arch === null) return null;

  if (process.platform === "darwin") return `darwin-${arch}`;

  if (process.platform !== "linux") return null;
  // the script's own test: musl's ldd says so in its --version output
  const ldd = Bun.spawnSync(["sh", "-c", "ldd --version 2>&1"]);

  if (!/musl/i.test(ldd.stdout.toString())) return `linux-${arch}`;

  return arch === "x64" ? "linux-x64-musl" : null;
}

/** A file's SHA-256, read as a stream (a binary is about 100 MB). */
export async function sha256File(path: string): Promise<string> {
  return sha256Stream(Bun.file(path).stream());
}

/** The SHA-256 of everything a stream yields. */
export async function sha256Stream(stream: ReadableStream<Uint8Array>): Promise<string> {
  const hash = createHash("sha256");
  const reader = stream.getReader();

  for (let r = await reader.read(); !r.done; r = await reader.read()) hash.update(r.value);

  return hash.digest("hex");
}

/**
 * Installs from `site` (an origin, no trailing slash) the way the docs say, in a new HOME under TMPDIR, and checks the
 * result. TMPDIR must not be /tmp on the deploy box (a stray /tmp/package-lock.json there confuses package-manager
 * detection), which deploys already arrange (TMPDIR=/home/leo/.cache/apm-smoke-tmp).
 */
export async function installCheck(site: string): Promise<CheckResult> {
  const home = mkdtempSync(join(tmpdir(), "apm-cli-install-"));

  try {
    const env = { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: home, TMPDIR: tmpdir() };
    const proc = Bun.spawn(["sh", "-c", 'curl -fsSL "$1/install" | sh', "sh", site], { env, cwd: home, stdout: "pipe", stderr: "pipe" });
    const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);

    if (code !== 0) return { ok: false, detail: `the install exited ${code}: ${(err || out).trim().split("\n").at(-1) ?? ""}` };
    const said = /^apm (\S+) \((\S+)\) installed to (\S+)$/m.exec(out);
    const printed = /^SHA-256 ([0-9a-f]{64}), checked against this script$/m.exec(out)?.[1] ?? null;

    if (said === null || printed === null) return { ok: false, detail: `the install printed no version or fingerprint: ${out.trim()}` };
    const [, versionText = "", target = "", installed = ""] = said;
    const bin = join(home, ".apm", "bin", "apm");

    if (installed !== bin || !existsSync(bin)) return { ok: false, detail: `apm was not installed at ${bin} (the script said ${installed})` };
    const version = CliVersion.parse(versionText);
    const ran = Bun.spawnSync([bin, "--version"], { env, cwd: home });
    const reported = ran.stdout.toString().trim();
    const actual = await sha256File(bin);
    const sumsRes = await fetch(`${site}/cli/${version}/SHA256SUMS`);
    const published = sumsRes.ok ? (parseSums(version, await sumsRes.text()).find((s) => s.target === target)?.sha256 ?? null) : null;

    const problems = [
      ran.exitCode === 0 && reported === version ? null : `apm --version exited ${ran.exitCode} and printed "${reported}"`,
      actual === printed ? null : `the installed file's SHA-256 is ${actual}, not the ${printed} the script printed`,
      published === printed ? null : `SHA256SUMS of ${version} lists ${published ?? "nothing"} for ${target} (HTTP ${sumsRes.status})`,
      target === hostTarget() ? null : `the script installed ${target} on a ${hostTarget() ?? "unknown"} machine`,
    ].filter((p) => p !== null);

    return problems.length === 0 ? { ok: true, detail: `apm ${version} ${target}, SHA-256 ${printed.slice(0, 16)}… matches the file and SHA256SUMS` } : { ok: false, detail: problems.join("; ") };
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}
