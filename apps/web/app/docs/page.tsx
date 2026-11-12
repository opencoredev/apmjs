export const metadata = { title: "apm docs" };

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="flex flex-col gap-2">
      <h2 className="text-sm font-semibold">{title}</h2>
      {children}
    </section>
  );
}

function Code({ children }: { children: string }) {
  return <pre className="overflow-x-auto rounded-lg border bg-muted/30 p-3 font-mono text-xs leading-relaxed">{children}</pre>;
}

export default function Docs() {
  return (
    <article className="mx-auto flex max-w-2xl flex-col gap-8">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">How apm works</h1>
        <p className="mt-2 text-muted-foreground text-pretty">
          apm is a registry that stock bun, npm and pnpm talk to, plus a small CLI that checks things before your package manager runs. It proxies the public npm registry, so every package you
          already use gets a score.
        </p>
      </header>
      <Block title="Use it with Bun (best)">
        <p className="text-sm text-muted-foreground">Point Bun at apm and add the scanner. Stock bun install then refuses revoked versions and packages scoring under 40.</p>
        <Code>{`# bunfig.toml
[install]
registry = "https://apmjs.dev/"

[install.security]
scanner = "@apm/bun-scanner"`}</Code>
      </Block>
      <Block title="Use it with npm or pnpm">
        <p className="text-sm text-muted-foreground">The ~safe view skips versions younger than 24 hours and versions scoring under 40. No new tools needed.</p>
        <Code>{`# .npmrc
registry=https://apmjs.dev/~safe/`}</Code>
      </Block>
      <Block title="The CLI">
        <Code>{`apm add zod              # score + 24h cooldown, then bun add zod@<exact>
apm x create-thing       # risk card before running anything
apm publish --bump patch # file list, secret scan, entry check, then publish
apm score left-pad       # every signal with file and line
apm name my-lib          # free? too close to something popular?
apm audit                # installed versions vs revocations
apm revoke my-lib@1.2.3 --reason "token stolen"
apm incident --since 2026-11-10T00:00:00Z --dry-run`}</Code>
      </Block>
      <Block title="Pulling a bad version">
        <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
          <li>Yank: hidden from new installs, lockfiles keep working, reversible.</li>
          <li>Revoke: for malicious versions. Needs your password. A version under 72 hours old with no dependents is revoked at once; otherwise it is yanked now and fully revoked after 24 hours, or sooner if a second owner confirms.</li>
          <li>Revoked versions show up as critical advisories in bun audit and npm audit, and their tarballs return 410.</li>
          <li>Every action lands in the package’s public log.</li>
        </ul>
      </Block>
      <Block title="What the score is, and is not">
        <p className="text-sm text-muted-foreground text-pretty">
          A heuristic read of the tarball and publish history: install scripts, shell and network calls, credential access, eval, obfuscation, new publishers, risky new dependencies, typosquat
          names. It cannot see code that downloads a second stage at run time. Popularity is never an input.
        </p>
      </Block>
    </article>
  );
}
