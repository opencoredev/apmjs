// The /publish page's prompt: everything a coding agent needs to publish the package in front of it under the
// signed-in person's scope, with no MCP server. Pure, so the tests read the same text a person copies.
//
// The apm CLI is not on a registry yet, so the agent runs it from a fresh shallow clone of the repository's main
// branch in a new folder (the repository's default branch is not main, and an old copy cannot be trusted). `apm login` is the only way to get a publish token: it is a device
// flow that waits for the person, so the prompt says how to read its link while it runs. The person approves the
// upload on the website; nothing the agent holds can make a version live.

/** Where the CLI comes from. */
export const CLI_REPO = "https://github.com/opencoredev/apmjs.git";

export type PublishTarget = {
  /** The person's apm scope, without the "@". */
  scope: string;
  /** The registry's public URL, ending in "/". */
  registry: string;
  /** The website's origin, with no trailing slash. */
  site: string;
};

/** The command an agent (or a person) runs as "apm": the CLI in folder `cli`, pinned to apm's registry. */
export function apmCommand({ registry }: Pick<PublishTarget, "registry">, cli: string): string {
  return `APM_REGISTRY=${registry} bun ${cli}/packages/cli/src/main.ts`;
}

/**
 * Shell lines that put a fresh clone of apm's main in folder `cli` and install only what the CLI needs. Always a new
 * folder: a copy fetched before can hold changed code, another upstream, git hooks or edited dependencies that no
 * check of its output rules out, so none is ever reused or updated.
 */
export function cliSetup(cli: string): string[] {
  return [`git clone --depth 1 --branch main ${CLI_REPO} ${cli}`, `(cd ${cli} && bun install --filter @apm/cli)`];
}

export function publishPrompt(t: PublishTarget): string {
  const host = new URL(t.site).host;

  return `Publish the npm package in this folder to apm (${t.site}) under my scope @${t.scope}. Use the shell; no MCP server is needed.

1. Get the apm CLI. It is not on npm yet, so it runs from a fresh clone and needs git and Bun 1.4 or newer. If bun is missing or older, ask me before installing it. Make a new copy every time: never reuse or update an existing copy (such as ~/.apm-cli), because it could hold changed code. Run "mktemp -d"; below, <cli> is the folder it printed followed by "/apm", in quotes if it has spaces. Then run:
   ${cliSetup("<cli>").join("\n   ")}
   Below, "apm" means: ${apmCommand(t, "<cli>")}
   Run it from this package's folder.
2. Log in. If "apm whoami" prints ${t.scope}, go to step 3. Otherwise start "apm login --no-browser" so you can read its output while it keeps running (in the background, or with its output going to a file you read). It prints a link and a code, then waits up to 15 minutes. Show me both and wait until it prints "logged in". It saves a token in ~/.npmrc: never print, copy or move that token.
3. In package.json, set "name" to "@${t.scope}/<name>": keep the current name after the scope unless I say otherwise. Remove "publishConfig.registry" if it is there.
4. Run "apm publish --dry-run". Fix what it refuses (a secret-shaped file, a "main", "types" or "bin" file that is not built) and show me the file list and the score.
5. Run "apm publish --json". If it says the version already exists, run it again with --bump patch. The version is now uploaded but not live.
6. Send me the "approval" link from the output, then stop. I approve it on ${host} with my passkey or authenticator code. You cannot approve it, and must not try.

If any other command fails, show me its error and stop. If it says my account needs 2FA or a passkey, send me to ${t.site}/account. Publish only to ${t.registry}, never to npmjs.org.`;
}

/** The same steps for a person at a terminal, for the page's "do it yourself" detail. */
export function manualSteps(t: PublishTarget): string {
  return [
    `APM_CLI="$(mktemp -d)/apm"`,
    ...cliSetup('"$APM_CLI"'),
    // a function, not an alias: the folder stays quoted, so a TMPDIR with spaces still works
    `apm() { ${apmCommand(t, '"$APM_CLI"')} "$@"; }`,
    "apm login",
    `# in package.json: "name": "@${t.scope}/my-package"`,
    "apm publish --dry-run",
    "apm publish",
  ].join("\n");
}
