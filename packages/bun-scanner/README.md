# @apm/bun-scanner

Makes stock `bun install` and `bun add` ask the apm registry about every package before installing it.

```toml
# bunfig.toml
[install.security]
scanner = "@apm/bun-scanner"
```

Install it once with `bun add -d @apm/bun-scanner`. Bun cancels the install when a package version is revoked (or has a pending revocation) or scores below 40.

The scanner asks the registry each package came from. Packages from other registries go to `APM_REGISTRY` when it is set. When the registry is unreachable, the scanner prints a warning and allows the install. Set `APM_SCANNER_STRICT=1` to block the install instead.
