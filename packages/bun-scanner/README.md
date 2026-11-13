# @apm/bun-scanner

Makes stock `bun install` and `bun add` ask the apm registry about every package before installing it.

```toml
# bunfig.toml
[install]
registry = "https://registry.apmjs.dev/"

[install.security]
scanner = "@apm/bun-scanner"
```

Install it once with `bun add -d @apm/bun-scanner`. Bun cancels the install when a package version is revoked (or has a pending revocation), is yanked, or was confirmed malicious by an apm reviewer. A version published inside the 24-hour cooldown ("published 5 hours ago, inside apm's 24-hour cooldown"), a score below 40, an incomplete analysis, a version apm cannot score and one still being analysed after the scanner has waited for it are warnings: the install goes ahead. With `APM_SCANNER_STRICT=1` each of those cancels the install too.

The scanner checks every package Bun hands it, whatever platform the package is built for. It sends no platform, and the registry skips nothing: a guess about which packages are optional and for another platform once hid a revoked version that a parent asked for optionally at an older version. A revoked binary for another platform therefore still cancels the install. `apm add` checks every platform too: it sends the resolve no platform. Only a caller of the resolve API that passes `os` and `cpu` has packages for other platforms skipped.

A version nobody has scored yet is queued for analysis, and the scanner treats it as pending, never as clean. It asks again every 3 s for up to 60 s (`APM_SCANNER_WAIT_MS` changes that), printing which packages it is waiting for, then uses the score. Anything still pending after the wait is a warning in default mode, and the install goes ahead; with `APM_SCANNER_STRICT=1` it cancels the install, with the message to try again in a minute. Strict mode refuses every pending version, since it cannot tell a long-published package nobody has installed through apm from a brand-new one.

The scanner asks one registry: `APM_REGISTRY` when it is set, otherwise `[install] registry` from `bunfig.toml` (the project's, then the global one). It never takes a registry from package data, so a tarball URL in a lockfile cannot choose who checks it or who sees your package list.

It prints a warning for each package it could not check: no registry configured, the registry is unreachable or is not an apm registry, bun downloads the package from another host than the configured registry, or the version is a git, file or link dependency that no registry serves. Prereleases (`1.0.0-beta.1`) are checked like any other version. By default those installs go ahead, so a registry outage does not stop your work.

In CI, set `APM_SCANNER_STRICT=1` so that any unchecked package cancels the install:

```sh
APM_SCANNER_STRICT=1 bun install --frozen-lockfile
```
