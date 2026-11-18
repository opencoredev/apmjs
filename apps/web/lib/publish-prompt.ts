// The /publish page's prompt: everything a coding agent needs to publish the package in front of it under the
// signed-in person's scope, with no MCP server. Pure, so the tests read the same text a person copies.
//
// The agent installs the apm CLI with the site's install script: one prebuilt binary, no git or Bun, whose SHA-256 the
// script checks against the checksum written into it at release (packages/infra/cli-install.ts). It runs the installer
// every time, so a copy installed earlier (which could have been changed) is replaced by one that was just checked.
// `apm login` is the only way to get a publish token: it is a device flow that waits for the person, so the prompt
// says how to read its link while it runs. The person approves the upload on the website; nothing the agent holds can
// make a version live.

export type PublishTarget = {
  /** The person's apm scope, without the "@". */
  scope: string;
  /** The registry's public URL, ending in "/". */
  registry: string;
  /** The website's origin, with no trailing slash. */
  site: string;
};

/** Where the install script puts apm. Every install line below pins APM_INSTALL to it, so an exported APM_INSTALL
 * cannot send the fresh binary elsewhere while later commands run an older one from here. */
export const APM_HOME = '"$HOME/.apm"';

export const APM_BIN = '"$HOME/.apm/bin/apm"';

/** The command an agent (or a person) runs as "apm": the installed binary, pinned to apm's registry. */
export function apmCommand({ registry }: Pick<PublishTarget, "registry">): string {
  return `APM_REGISTRY=${registry} ${APM_BIN}`;
}

/** The line the install script prints once the binary it installed matched its checksum (packages/infra/cli-install.ts). */
export const INSTALLED_LINE = "^SHA-256 [0-9a-f]\\{64\\}, checked against this script$";

/**
 * The install as one shell command that succeeds only when the installer did. Each step is chained with `&&`:
 * - a new temporary folder (a failed mktemp stops here, rather than saving to /install.sh), never the package folder,
 *   which would publish the script;
 * - the download, run only when its last line is the `main "$@"` call (an empty or cut-off download exits 0 under sh
 *   without installing anything);
 * - the install with the destination pinned, its output shown, and success only when it printed the checked SHA-256
 *   line and left an executable apm (a script that lost its middle but kept its last line installs nothing).
 * `curl | sh` is fine for a person who reads its output; anything that runs apm next must not fall through to an apm
 * installed earlier.
 */
export function checkedInstall({ site }: Pick<PublishTarget, "site">): string {
  return [
    `APM_DIR="$(mktemp -d)"`,
    `APM_SCRIPT="$APM_DIR/install.sh"`,
    `curl -fsSL ${site}/install -o "$APM_SCRIPT"`,
    `tail -n 1 "$APM_SCRIPT" | grep -Fqx 'main "$@"'`,
    `APM_OUT="$(APM_INSTALL=${APM_HOME} sh "$APM_SCRIPT")"`,
    `printf '%s\\n' "$APM_OUT"`,
    `printf '%s\\n' "$APM_OUT" | grep -q '${INSTALLED_LINE}'`,
    `[ -x ${APM_BIN} ]`,
  ].join(" && ");
}

export function publishPrompt(t: PublishTarget): string {
  const host = new URL(t.site).host;
  const install = checkedInstall(t);

  return `Publish the npm package in this folder to apm (${t.site}) under my scope @${t.scope}. Use the shell; no MCP server is needed.

1. Install the apm CLI. Do this every time, even if apm is already installed, so you use a copy that was just checked. Run this as one shell command:
   ${install}
   It saves the install script to a new temporary folder, runs it only if it downloaded whole, and installs to ~/.apm/bin/apm. The script downloads one prebuilt apm binary from ${host}, checks its SHA-256 against the checksum written into the script, and installs nothing if they differ. It needs no git or Bun and changes nothing else. Continue only if the command succeeded and printed both "apm <version> (<platform>) installed to <your home>/.apm/bin/apm" and "SHA-256 <hash>, checked against this script"; show me those two lines. Otherwise stop, show me its output, and do not run apm. apm uses this project's package manager (npm, pnpm, yarn or bun); if none is installed, ask me before installing anything else.
   Below, "apm" means: ${apmCommand(t)}
   Run it from this package's folder.
2. Log in. If "apm whoami" prints ${t.scope}, go to step 3. Otherwise start "apm login --no-browser" so you can read its output while it keeps running (in the background, or with its output going to a file you read). It prints a link and a code, then waits up to 15 minutes. Show me both and wait until it prints "logged in". It saves a token in ~/.npmrc: never print, copy or move that token.
3. In package.json, set "name" to "@${t.scope}/<name>": keep the current name after the scope unless I say otherwise. Remove "publishConfig.registry" if it is there.
4. Run "apm publish --dry-run". Fix what it refuses (a secret-shaped file, a "main", "types" or "bin" file that is not built) and show me the file list and the score.
5. Run "apm publish --json". If it says the version already exists, run it again with --bump patch. The version is now uploaded but not live.
6. Send me the "approval" link from the output, then stop. I approve it on ${host} with my passkey or authenticator code. You cannot approve it, and must not try.

If any other command fails, show me its error and stop. If it says my account needs 2FA or a passkey, send me to ${t.site}/account. Publish only to ${t.registry}, never to npmjs.org.`;
}

/** The same steps for a person at a terminal, for the page's "do it yourself" detail. Until the install line succeeds,
 * "apm" is a function that refuses, so a failed install never runs an apm left on PATH or in ~/.apm from before. */
export function manualSteps(t: PublishTarget): string {
  return [
    `apm() { echo "apm: the install did not succeed, so nothing was run" >&2; return 1; }`,
    `${checkedInstall(t)} && apm() { ${apmCommand(t)} "$@"; }`,
    "apm login",
    `# in package.json: "name": "@${t.scope}/my-package"`,
    "apm publish --dry-run",
    "apm publish",
  ].join("\n");
}
