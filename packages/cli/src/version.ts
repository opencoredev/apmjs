// apm's own version: what `apm --version` prints and the version a CLI release publishes (packages/infra/release-cli.ts).
// It matches packages/cli/package.json (packages/cli/test/version.test.ts). A released version is immutable: change it
// before releasing new code.
export const CLI_VERSION = "0.1.8";
