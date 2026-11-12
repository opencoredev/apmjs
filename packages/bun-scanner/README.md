# @apm/bun-scanner

Makes stock `bun install` and `bun add` ask the apm registry about every package before installing it.

```toml
# bunfig.toml
[install]
registry = "https://registry.apmjs.dev/"

[install.security]
scanner = "@apm/bun-scanner"
```

Install it once with `bun add -d @apm/bun-scanner`. Bun cancels the install when a package version is revoked (or has a pending revocation) or scores below 40.

The scanner asks one registry: `APM_REGISTRY` when it is set, otherwise `[install] registry` from `bunfig.toml` (the project's, then the global one). It never takes a registry from package data, so a tarball URL in a lockfile cannot choose who checks it or who sees your package list.

It prints a warning for each package it could not check: no registry configured, the registry is unreachable or is not an apm registry, bun downloads the package from another host than the configured registry, or the version is a git, file or link dependency that no registry serves. Prereleases (`1.0.0-beta.1`) are checked like any other version. By default those installs go ahead, so a registry outage does not stop your work.

In CI, set `APM_SCANNER_STRICT=1` so that any unchecked package cancels the install:

```sh
APM_SCANNER_STRICT=1 bun install --frozen-lockfile
```
