export const metadata = { title: "apm docs" };

const SECTIONS = [
  { id: "bun", title: "Use it with Bun" },
  { id: "npm", title: "Use it with npm or pnpm" },
  { id: "cli", title: "The CLI" },
  { id: "pulling", title: "Pulling a bad version" },
  { id: "score", title: "What the score is, and is not" },
] as const;

type SectionId = (typeof SECTIONS)[number]["id"];

function Block({ id, children, note }: { id: SectionId; children: React.ReactNode; note?: string }) {
  const title = SECTIONS.find((s) => s.id === id)?.title ?? id;

  return (
    <section aria-labelledby={id} className="border-t pt-8">
      <h2 id={id} className="scroll-mt-28 flex items-baseline gap-3 text-2xl font-medium tracking-tight">
        {title}
        {note && <span className="text-base font-normal text-muted-foreground">{note}</span>}
      </h2>
      <div className="mt-4 flex flex-col gap-4">{children}</div>
    </section>
  );
}

function Code({ children, label }: { children: string; label?: string }) {
  return (
    <figure className="overflow-hidden rounded-xl bg-surface">
      {label && <figcaption className="border-b border-background px-4 py-2 font-mono text-[13px] text-muted-foreground">{label}</figcaption>}
      <pre className="overflow-x-auto p-4 font-mono text-[13px] leading-6">{children}</pre>
    </figure>
  );
}

function Text({ children }: { children: React.ReactNode }) {
  return <p className="text-[17px] leading-7 text-pretty text-muted-foreground">{children}</p>;
}

export default function Docs() {
  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-12 lg:grid-cols-[200px_minmax(0,1fr)] lg:gap-16">
      <nav aria-label="On this page" className="hidden lg:block">
        <div className="sticky top-28 flex flex-col gap-1 text-[15px]">
          <span className="mb-2 text-sm text-muted-foreground">On this page</span>
          {SECTIONS.map((s) => (
            <a key={s.id} href={`#${s.id}`} className="rounded-md py-1 text-muted-foreground transition-colors hover:text-foreground">
              {s.title}
            </a>
          ))}
        </div>
      </nav>

      <article className="flex max-w-2xl flex-col gap-10">
        <header className="flex flex-col gap-4">
          <h1 className="text-[34px] leading-tight font-medium tracking-[-0.02em] sm:text-5xl sm:leading-[1.1]">How apm works</h1>
          <p className="text-lg leading-8 text-pretty text-muted-foreground">
            apm is a registry that stock bun, npm and pnpm talk to, plus a small CLI that checks things before your package manager runs. It proxies the public npm registry, so every package
            you already use gets a score.
          </p>
        </header>

        <Block id="bun" note="recommended">
          <Text>Point Bun at apm and add the scanner. Stock bun install then refuses revoked versions and packages scoring under 40.</Text>
          <Code label="bunfig.toml">{`[install]
registry = "https://apmjs.dev/"

[install.security]
scanner = "@apm/bun-scanner"`}</Code>
        </Block>

        <Block id="npm">
          <Text>
            The <code className="rounded-md bg-surface px-1.5 py-0.5 font-mono text-[15px] text-foreground">~safe</code> view skips versions younger than 24 hours and versions scoring under 40.
            No new tools needed.
          </Text>
          <Code label=".npmrc">{`registry=https://apmjs.dev/~safe/`}</Code>
        </Block>

        <Block id="cli">
          <Text>apm runs in front of your package manager and passes through any command it does not know.</Text>
          <Code>{`apm add zod              # score + 24h cooldown, then bun add zod@<exact>
apm x create-thing       # risk card before running anything
apm login                # sign in through the browser (GitHub or Vercel)
apm publish --bump patch # file list, secret scan, entry check, upload; you approve it on the web
apm score left-pad       # every signal with file and line
apm name my-lib          # free? too close to something popular?
apm audit                # installed versions vs revocations
apm revoke @you/my-lib@1.2.3 --reason "token stolen" --otp 123456
apm incident --since 2026-11-10T00:00:00Z --dry-run`}</Code>
        </Block>

        <Block id="pulling">
          <dl className="flex flex-col">
            {[
              ["Yank", "Hidden from new installs. Lockfiles keep working. Reversible."],
              [
                "Revoke",
                "For malicious versions. Needs a fresh second factor: pass --otp with your authenticator code, or open the link the command prints and approve that one command on your account page, then run it again within 10 minutes. A version under 72 hours old with no dependents is revoked at once; otherwise it is yanked now and fully revoked after 24 hours, or sooner if a second owner confirms.",
              ],
              ["Login tokens", "The token from apm login uploads versions that wait for your approval. It moves dist-tags, deprecates, yanks or unyanks only with --otp (npm asks for the code itself)."],
              ["Scopes", "Your scope is your GitHub login when you first sign in, tied to your GitHub account's numeric id. It is permanent: renaming on GitHub does not move or free it. To move packages to a new name, open a name dispute."],
              ["Audits", "Revoked versions show up as critical advisories in bun audit and npm audit, and their tarballs return 410."],
              ["Log", "Every action lands in the package’s public log."],
            ].map(([term, def]) => (
              <div key={term} className="grid gap-1 border-b py-4 last:border-b-0 sm:grid-cols-[120px_1fr] sm:gap-6">
                <dt className="font-medium">{term}</dt>
                <dd className="text-[17px] leading-7 text-pretty text-muted-foreground">{def}</dd>
              </div>
            ))}
          </dl>
        </Block>

        <Block id="score">
          <Text>
            A heuristic read of the tarball and publish history: install scripts, shell and network calls, credential access, eval, obfuscation, new publishers, risky new dependencies, typosquat
            names. It cannot see code that downloads a second stage at run time. Popularity is never an input.
          </Text>
        </Block>
      </article>
    </div>
  );
}
