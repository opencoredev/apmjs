// The apm CLI's install script and its checksum lists, as release-cli.ts writes them. Pure: text in, text out.
//
// The script (https://apmjs.dev/install) pins every released binary by SHA-256, in the list written into it when a
// version was released, and installs a download only when it matches. The same hashes are published beside each
// version as cli/<version>/SHA256SUMS (the format `sha256sum -c` reads) and listed for every version in
// cli/releases.txt, the index release-cli.ts rebuilds the script from.
import { z } from "zod";

/** The platforms apm ships a binary for: the name in its URL (apm-<target>) and the bun --compile target that builds it. */
export const TARGETS = [
  // x64 builds use Bun's baseline runtime: the default one needs AVX2 and crashes on older processors
  { target: "linux-x64", bun: "bun-linux-x64-baseline" },
  { target: "linux-arm64", bun: "bun-linux-arm64" },
  { target: "linux-x64-musl", bun: "bun-linux-x64-musl-baseline" },
  { target: "darwin-x64", bun: "bun-darwin-x64-baseline" },
  { target: "darwin-arm64", bun: "bun-darwin-arm64" },
] as const;

export type Target = (typeof TARGETS)[number]["target"];

// SAFETY: TARGETS is a non-empty literal tuple, so the names mapped from it are a non-empty list of Target values.
const TargetName = z.enum(TARGETS.map((t) => t.target) as [Target, ...Target[]]);

/** A released version: digits only (x.y.z, with an optional -prerelease), so it is safe in a URL, a key and the script. */
export const CliVersion = z.string().regex(/^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/, "a version is x.y.z or x.y.z-pre");

export type CliVersion = z.infer<typeof CliVersion>;

const Sha256 = z.string().regex(/^[0-9a-f]{64}$/, "a SHA-256 is 64 lowercase hex digits");

/** One released binary: its version, platform and SHA-256. */
export const CliSum = z.object({ version: CliVersion, target: TargetName, sha256: Sha256 });

export type CliSum = z.infer<typeof CliSum>;

/** The binary's file name in a version's folder: apm-linux-x64. */
export function binaryName(target: Target): string {
  return `apm-${target}`;
}

/** R2 keys, under the stage's CLI bucket. The website serves cli/* at /cli/* and install.sh at /install. */
export const KEYS = {
  script: "install.sh",
  index: "cli/releases.txt",
  binary: (version: CliVersion, target: Target) => `cli/${version}/${binaryName(target)}`,
  sums: (version: CliVersion) => `cli/${version}/SHA256SUMS`,
} as const;

/** A version's SHA256SUMS: `<sha256>  apm-<target>` lines, as sha256sum prints them, in TARGETS order. */
export function formatSums(sums: readonly CliSum[]): string {
  return `${sums.map((s) => `${s.sha256}  ${binaryName(s.target)}`).join("\n")}\n`;
}

/** Reads a version's SHA256SUMS back. Throws on a line it does not understand: a checksum file is never half-read. */
export function parseSums(version: CliVersion, text: string): CliSum[] {
  return lines(text).map((line) => {
    const m = /^([0-9a-f]{64}) {2}apm-(\S+)$/.exec(line);

    if (m === null) throw new Error(`SHA256SUMS of ${version}: cannot read line "${line}"`);

    return CliSum.parse({ version, target: m[2], sha256: m[1] });
  });
}

/** cli/releases.txt and the script's list: `<version> <target> <sha256>` lines. */
export function formatIndex(sums: readonly CliSum[]): string {
  return `${sums.map((s) => `${s.version} ${s.target} ${s.sha256}`).join("\n")}\n`;
}

export function parseIndex(text: string): CliSum[] {
  return lines(text).map((line) => {
    const [version, target, sha256, ...rest] = line.split(" ");

    if (rest.length > 0) throw new Error(`releases.txt: cannot read line "${line}"`);

    return CliSum.parse({ version, target, sha256 });
  });
}

function lines(text: string): string[] {
  return text.split("\n").filter((l) => l.trim() !== "");
}

/**
 * Adds a version's sums to the index. Refuses when the index already lists that version with other hashes: a released
 * binary never changes. Sorted by version, then TARGETS order, so the same releases always give the same text.
 */
export function mergeIndex(index: readonly CliSum[], added: readonly CliSum[]): CliSum[] {
  const key = (s: CliSum) => `${s.version} ${s.target}`;
  const byKey = new Map(index.map((s) => [key(s), s]));

  for (const s of added) {
    const had = byKey.get(key(s));

    if (had !== undefined && had.sha256 !== s.sha256) throw new Error(`apm ${s.version} ${s.target} is already released with SHA-256 ${had.sha256}, not ${s.sha256}; a released binary never changes`);
    byKey.set(key(s), s);
  }

  const order = (t: Target) => TARGETS.findIndex((x) => x.target === t);

  return [...byKey.values()].sort((a, b) => Bun.semver.order(a.version, b.version) || order(a.target) - order(b.target));
}

/** The version the script installs by default: the highest release without a prerelease tag, else the highest. */
export function latestVersion(index: readonly CliSum[]): CliVersion {
  const versions = [...new Set(index.map((s) => s.version))].sort(Bun.semver.order);
  const latest = versions.filter((v) => !v.includes("-")).at(-1) ?? versions.at(-1);

  if (latest === undefined) throw new Error("no apm version is released yet");

  return latest;
}

/** The site the script downloads from: an http(s) origin with no path, quote or space, so it is safe in the script. */
export const SiteUrl = z
  .string()
  .regex(/^https?:\/\/[A-Za-z0-9.-]+(:\d+)?$/, "an http(s) origin without a trailing slash")
  .brand<"SiteUrl">();

export type SiteUrl = z.infer<typeof SiteUrl>;

/**
 * The install script. POSIX sh for macOS's /bin/sh and Linux's dash: no bashisms, no sudo, no edits to shell startup
 * files. Kept short enough to read in full before running it.
 */
export function installScript(input: { site: SiteUrl; index: readonly CliSum[] }): string {
  const latest = latestVersion(input.index);

  return `#!/bin/sh
# Installs the apm CLI from ${input.site}. Read it before you run it; it is short.
#
#   curl -fsSL ${input.site}/install | sh
#   curl -fsSL ${input.site}/install | sh -s -- --version ${latest}
#
# Or with Homebrew, on macOS or Linux:
#
#   brew install opencoredev/tap/apm
#
# It downloads one apm binary for this machine from ${input.site}/cli/<version>/, checks its
# SHA-256 against the list below (written when that version was released), and installs it
# only if it matches: to ~/.apm/bin/apm, or $APM_INSTALL/bin/apm. It never uses sudo and does
# not edit your shell startup files. --version X or APM_VERSION=X picks a version.
set -eu

site="${input.site}"
version="\${APM_VERSION:-${latest}}"
root="\${APM_INSTALL:-$HOME/.apm}"

# version, platform, SHA-256 of every released binary
sums() {
  cat <<'EOF'
${formatIndex(input.index).trimEnd()}
EOF
}

die() {
  if ! terminal 2; then
    printf 'apm install: %s\\n' "$1" >&2
  elif colors 2; then
    printf '\\n  \\033[1;31merror:\\033[0m %s\\n' "$1" >&2
  else
    printf '\\n  error: %s\\n' "$1" >&2
  fi
  exit 1
}

# Is file descriptor $1 a person's terminal? CI (CI set, other than false or 0) gets the plain lines even on one.
terminal() {
  [ -t "$1" ] || return 1
  case "\${CI:-}" in "" | false | 0) ;; *) return 1 ;; esac
}

# Can file descriptor $1 take color? Only a terminal, and not with NO_COLOR set (no-color.org) or TERM=dumb.
colors() {
  terminal "$1" && [ -z "\${NO_COLOR:-}" ] && [ "\${TERM:-}" != dumb ]
}

# A step that is done, shown only to a person at a terminal.
step() {
  [ -z "$tty" ] || printf '  %s✓%s %s\\n' "$g" "$x" "$1"
}

# A long value (a hash, a path) on its own dim line under a step, so a wrapped line never lands under a mark.
value() {
  [ -z "$tty" ] || printf '    %s%s%s\\n' "$d" "$1" "$x"
}

# Everything runs from main, called on the last line, so a download cut short runs nothing.
main() {
  # A person at a terminal gets a header, steps and next steps; pipes, CI and agents get the plain lines at the end.
  tty="" b="" d="" g="" c="" x=""
  if terminal 1; then
    tty=1
    if colors 1; then
      b=$(printf '\\033[1m') d=$(printf '\\033[2m') g=$(printf '\\033[32m') c=$(printf '\\033[36m') x=$(printf '\\033[0m')
    fi
    printf '\\n  %sapm installer%s  %s%s%s\\n\\n' "$b" "$x" "$d" "$site" "$x"
  fi

  while [ $# -gt 0 ]; do
    case "$1" in
      --version) [ $# -ge 2 ] || die "--version needs a value"; version="$2"; shift 2 ;;
      --version=*) version="\${1#--version=}"; shift ;;
      *) die "unknown option: $1" ;;
    esac
  done

  case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    MINGW* | MSYS* | CYGWIN* | Windows_NT) die "Windows is not supported yet. Run this in WSL, or use the apm registry without the CLI: https://docs.apmjs.dev/quickstart#1-point-your-package-manager-at-apm" ;;
    *) die "$(uname -s) is not supported; apm runs on macOS and Linux." ;;
  esac
  case "$(uname -m)" in
    x86_64 | amd64) arch=x64 ;;
    arm64 | aarch64) arch=arm64 ;;
    *) die "$(uname -m) is not supported; apm runs on x64 and arm64." ;;
  esac
  # an x64 shell under Rosetta on an Apple silicon Mac gets the native arm64 build
  if [ "$os" = darwin ] && [ "$arch" = x64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" = 1 ]; then
    arch=arm64
  fi
  target="$os-$arch"
  hint=""
  # Alpine and other musl Linux systems need the musl build
  if [ "$os" = linux ] && ldd --version 2>&1 | grep -qi musl; then
    target="$target-musl"
    hint=" On musl it needs libstdc++ and libgcc (Alpine: apk add libstdc++ libgcc)."
  fi
  step "Detected $target"

  want=$(sums | awk -v v="$version" -v t="$target" '$1 == v && $2 == t { print $3 }')
  if [ -z "$want" ]; then
    if sums | awk -v v="$version" '$1 == v { found = 1 } END { exit !found }'; then
      die "apm $version has no build for $target."
    fi
    die "apm $version is not a released version. Released: $(sums | awk '{ print $1 }' | uniq | tr '\\n' ' ')"
  fi

  command -v curl >/dev/null 2>&1 || die "curl is required."
  if command -v sha256sum >/dev/null 2>&1; then
    sha="sha256sum"
  elif command -v shasum >/dev/null 2>&1; then
    sha="shasum -a 256"
  else
    die "neither sha256sum nor shasum is installed, so the download cannot be checked. Nothing was installed."
  fi

  dir="$root/bin"
  # mv onto a directory, or a link to one, would put apm inside it and report a path that is not apm
  [ ! -d "$dir/apm" ] || die "$dir/apm is a directory, not a file. Move it away and run this again. Nothing was installed."
  mkdir -p "$dir"
  tmp=$(mktemp "$dir/.apm.XXXXXX")
  trap 'rm -f "$tmp"' EXIT
  trap 'exit 1' HUP INT TERM

  url="$site/cli/$version/apm-$target"
  [ -z "$tty" ] || printf '  %s↓%s Downloading apm %s from %s\\n' "$c" "$x" "$version" "\${site#*://}"
  curl -fsSL -o "$tmp" "$url" || die "could not download $url"
  got=$($sha "$tmp" | awk '{ print $1 }')
  if [ "$got" != "$want" ]; then
    die "SHA-256 mismatch for $url: expected $want, got $got. Nothing was installed."
  fi
  step "Checked SHA-256 against this script"
  value "$got"
  chmod 755 "$tmp"
  ran=$("$tmp" --version 2>/dev/null) || die "the downloaded apm did not run on this machine.$hint Nothing was installed."
  [ "$ran" = "$version" ] || die "the downloaded apm reports version $ran, not $version. Nothing was installed."
  mv -f "$tmp" "$dir/apm"
  # what is at $dir/apm now must be the regular file that was just checked
  if [ -d "$dir/apm" ] || [ -L "$dir/apm" ] || [ ! -f "$dir/apm" ] || [ ! -x "$dir/apm" ] || [ "$($sha "$dir/apm" | awk '{ print $1 }')" != "$want" ]; then
    [ ! -d "$dir/apm" ] || rm -f "$dir/apm/\${tmp##*/}"
    die "$dir/apm is not the file that was checked; something changed it during the install. Run this again."
  fi

  if [ -z "$tty" ]; then
    printf 'apm %s (%s) installed to %s\\n' "$version" "$target" "$dir/apm"
    printf 'SHA-256 %s, checked against this script\\n' "$got"
    case ":\${PATH:-}:" in
      *":$dir:"*) ;;
      *) printf '\\n%s is not on your PATH. Add this line to ~/.zshrc, ~/.bashrc or ~/.profile:\\n  export PATH="%s:$PATH"\\n' "$dir" "$dir" ;;
    esac
    return
  fi
  step "Installed apm $version"
  value "$dir/apm"
  case ":\${PATH:-}:" in
    *":$dir:"*) ;;
    *) printf '\\n  This folder is not on your PATH:\\n    %s%s%s\\n  Run this, and add it to ~/.zshrc, ~/.bashrc or ~/.profile to keep it:\\n\\n    %sexport PATH="%s:$PATH"%s\\n' "$d" "$dir" "$x" "$c" "$dir" "$x" ;;
  esac
  printf '\\n  %sNext%s\\n' "$b" "$x"
  printf '    %sapm --version%s   %scheck that it runs%s\\n' "$c" "$x" "$d" "$x"
  printf '    %sapm add <pkg>%s   %sadd a package, in a project folder%s\\n\\n' "$c" "$x" "$d" "$x"
}

main "$@"
`;
}
