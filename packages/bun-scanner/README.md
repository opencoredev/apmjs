# @apm/bun-scanner

Makes stock `bun install` and `bun add` ask the apm registry about every package before installing it.

```toml
# bunfig.toml
[install]
registry = "https://registry.apmjs.dev/"

[install.security]
scanner = "@apm/bun-scanner"
```

Install it once with `bun add -d @apm/bun-scanner`. Bun cancels the install when a package version is revoked (or has a pending revocation), scores below 40, or is still being analysed after the scanner has waited for it.

A version nobody has scored yet is queued for analysis, and the scanner treats it as pending, never as clean. It asks again every 3 s for up to 60 s (`APM_SCANNER_WAIT_MS` changes that), printing which packages it is waiting for, then uses the score. Anything still pending after the wait cancels the install in both default and strict mode, with the message to try again in a minute. It blocks every pending version, since it cannot tell a long-published package nobody has installed through apm from a brand-new one.

The scanner asks one registry: `APM_REGISTRY` when it is set, otherwise `[install] registry` from `bunfig.toml` (the project's, then the global one). It never takes a registry from package data, so a tarball URL in a lockfile cannot choose who checks it or who sees your package list.

It prints a warning for each package it could not check: no registry configured, the registry is unreachable or is not an apm registry, bun downloads the package from another host than the configured registry, or the version is a git, file or link dependency that no registry serves. Prereleases (`1.0.0-beta.1`) are checked like any other version. By default those installs go ahead, so a registry outage does not stop your work.

In CI, set `APM_SCANNER_STRICT=1` so that any unchecked package cancels the install:

```sh
APM_SCANNER_STRICT=1 bun install --frozen-lockfile
```
