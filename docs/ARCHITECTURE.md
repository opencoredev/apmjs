# Architecture notes

## How `apm add` makes the package manager install what apm checked

`apm add` asks the registry to resolve and score a package, then runs your package manager (bun, npm, pnpm or yarn) to install the exact version. The check only means something if the package manager then installs the same bytes from the same registry, for the package and for everything under it. Two things can break that:

- A config file sends a scope to another registry. A project `.npmrc` line like `@someone:registry=https://elsewhere/` applies to every package in that scope, including dependencies several levels down.
- A lockfile pins a package to another registry's tarball. bun, npm and pnpm reuse a locked `resolved` URL and integrity even when told a different registry, so a committed lockfile can bring in bytes apm never saw.

`apm add` closes both, in this order:

1. **Bind every scope in the tree.** The resolve answer lists every package the registry walked under the added ones (`tree.packages`). apm pins each scope among them, plus the added packages' own scopes, to the checked registry: `--registry` and `--@scope:registry` flags for npm and pnpm, and the matching `npm_config_*`/`BUN_CONFIG_REGISTRY` variables in the child environment. If an `.npmrc`, `bunfig.toml` or `.yarnrc.yml` sends one of those scopes elsewhere, apm refuses before it installs anything.
2. **Check the added packages' existing lockfile entries.** An entry for an added name@version whose integrity differs from what the checked registry serves is refused before anything is fetched.
3. **Install with scripts held back.** bun, npm and pnpm run with `--ignore-scripts`, so no `preinstall`, `install` or `postinstall` script runs yet.
4. **Verify every installed node.** apm reads the lockfile the install wrote (`bun.lock`, `package-lock.json` or `pnpm-lock.yaml`, or npm's and pnpm's copy in `node_modules` when the project lockfile is off), walks it from the added packages to every package under them, and compares each node's integrity with the one the checked registry serves for that name@version. Git, file and link dependencies are not on a registry; the resolve step already lists them as not checked.
5. **Then run the scripts, or undo the install.** If every node matches, apm runs the held-back scripts: `npm rebuild <packages with install scripts>`, `pnpm rebuild --pending`, and for bun, which only runs scripts while installing a package, it removes those packages' directories and runs `bun install --frozen-lockfile` from the verified lockfile. Each package manager's own script policy still applies (bun's `trustedDependencies`, pnpm's `onlyBuiltDependencies`). If any node does not match, apm puts `package.json` and the lockfile back, removes the unverified packages from `node_modules`, names each one, and exits non-zero. Their scripts never ran.

If apm cannot read the lockfile after the install, it refuses and does not run the scripts.

Limits:

- yarn gets steps 1 and 2 only. apm does not read `yarn.lock`, so yarn installs run their scripts as usual.
- `apm x` (bunx, npx, pnpm dlx) gets step 1 only. Those tools install into their own cache with no project lockfile to verify.
- The tree walk stops after 300 packages; anything past that is listed as not checked, and only the lockfile verification in step 4 covers it.
