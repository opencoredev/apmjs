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

## How accounts are protected

- **Approvals.** A version uploaded with a login token is not live until a person approves it on apmjs.dev with an authenticator code typed for that approval, or a passkey check made for that approval.
- **A second factor confirms one action.** Every code or passkey check on the website is bound to the browser session that made it, the action, and every parameter of the action: which upload is approved, which CLI command is confirmed, which review decision with which note, which evidence item (digest, scorer, signal, file and line) is dismissed or restored and with which reason, which sign-in setting changes. It confirms that action once, within 5 minutes, and nothing else: not another release, item, reason or tab, and not the CLI. A passkey check answers a challenge the registry made for one named action, so signing in with a passkey confirms nothing. This holds for approvals, CLI confirmations (revoke, restore, incident response, owners, dist-tags, deprecate, yank, unyank), review decisions, evidence dismissals and undos, and changes to how you sign in.
- **Website changes come from the website.** Every change a website session can make (approvals, confirmations, review decisions, evidence dismissals, token revocation, sign-in settings) is refused unless the request carries the website's `Origin`. A request with none, or another site's, gets 403 before any code is checked. Requests made with a CLI or CI token are not affected.
- **CLI commands.** Revoke, restore, incident response and owner changes need `--otp <code>`. Without it, the error links to a page that approves exactly that command, once, for 10 minutes. Login tokens also need a code to move dist-tags, deprecate, yank or unyank.
- **Codes.** A code is exactly six digits and works once. Wrong codes and recovery codes share one budget per account: five failures lock checks for 15 minutes, across the website and the CLI.
- **Factors.** Turning off 2FA, adding a passkey or linking another sign-in needs your current code, a recovery code or a passkey check made for that change. The authenticator secret is never shown again after setup. Recovery codes are shown once at setup; each works once.
- **Scopes and GitHub renames.** Your scope is the lowercased GitHub login you first signed in with, bound to GitHub's numeric account id. Scopes are permanent once claimed: a GitHub rename does not move or free yours, and someone who later takes your old login on GitHub does not get it. Your account page shows the new login. To move packages to a scope that matches your new login, open a [name dispute](../../issues/new?template=name-dispute.yml).
- **Self-hosting.** `APM_LEGACY_AUTH=1` (npm password accounts) refuses to start when `APM_PUBLIC_URL` is a public https address, unless you also set `APM_ALLOW_LEGACY_IN_PROD=1`.
