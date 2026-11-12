# Security

There are two kinds of report, and they go to different places.

## A malicious or compromised package

Open a [package report](../../issues/new?template=report-package.yml). Reports are public on purpose: other people installing the same version need to know.

Include the package, the exact version, and what you saw (a file and line, a network call, an install script). When we confirm it:

- the version is yanked or revoked, so `apm`, the `~safe/` registry view and the Bun scanner stop installing it;
- the package's public log records who reported it and what changed;
- packages that come from npm are also reported to the npm security team and to the OSV database, because apm cannot remove them at the source.

## A vulnerability in apm itself

Don't open a public issue. Use GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability"). We aim to reply within 3 days.

In scope:
- the registry, including the publish, revoke and token endpoints;
- the `apm` CLI;
- the Bun scanner;
- the score engine. A package that hides behavior from the score is in scope.
