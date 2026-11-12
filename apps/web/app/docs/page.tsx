export const metadata = { title: "apm docs" };

/** The documentation site, apps/docs, built with Blume. This page is its short overview. */
const DOCS = "https://docs.apmjs.dev";

/** The "Appeal a score" issue form (.github/ISSUE_TEMPLATE/appeal-a-score.yml). */
const APPEAL_URL = "https://github.com/opencoredev/apmjs/issues/new?template=appeal-a-score.yml";

// The ids stay stable: package pages and the AI review section link to /docs#bun, #npm, #cli and #ai-review.
const SECTIONS = [
  { id: "bun", title: "Use it with Bun", body: "Point bunfig.toml at the registry and add @apm/bun-scanner. Plain bun install then refuses revoked versions and packages scoring under 40.", href: `${DOCS}/guides/bun-scanner`, link: "Bun scanner" },
  { id: "npm", title: "Use it with npm or pnpm", body: "Set registry=https://registry.apmjs.dev/~safe/ in .npmrc. The view skips versions younger than 24 hours and versions scoring under 40.", href: `${DOCS}/guides/safe-view`, link: "The ~safe view" },
  { id: "cli", title: "The CLI", body: "apm add, apm x and apm publish check first, then hand the work to the package manager your project already uses.", href: `${DOCS}/reference/cli`, link: "CLI reference" },
  { id: "pulling", title: "Pulling a bad version", body: "Yank hides a version from new installs. Revoke pulls a malicious one for everyone, with a fresh second factor; a version under 72 hours old is revoked at once, even when other packages depend on it. apm incident revokes every token and recent version after a compromise.", href: `${DOCS}/guides/pull-a-version`, link: "Yank, revoke and incident response" },
  { id: "score", title: "What the score is, and is not", body: "A static read of every file and the publish history, with a file and line for every point lost. It cannot see code that only shows what it does at runtime.", href: `${DOCS}/concepts/score`, link: "How the score works" },
  { id: "appeals", title: "Appealing a score", body: "A person at apm can dismiss one wrong piece of evidence for one version's exact tarball. The dismissal is public and can be undone.", href: APPEAL_URL, link: "Appeal a score" },
  { id: "ai-review", title: "The AI review", body: "A language model reads each new release in scope and reports cited findings next to the score, never inside it. It cannot see dependencies, binaries or code downloaded at runtime.", href: `${DOCS}/concepts/ai-review`, link: "What the AI review reads and can't see" },
] as const;

export default function Docs() {
  return (
    <article className="flex max-w-2xl flex-col gap-10">
      <header className="flex flex-col gap-4">
        <h1 className="text-[34px] leading-tight font-medium tracking-[-0.02em] sm:text-5xl sm:leading-[1.1]">How apm works</h1>
        <p className="text-lg leading-8 text-pretty text-muted-foreground">
          apm is a registry that stock bun, npm and pnpm talk to, plus a small CLI that checks things before your package manager runs. The full documentation, with guides and reference, is
          at{" "}
          <a href={DOCS} className="text-foreground underline underline-offset-4">
            docs.apmjs.dev
          </a>
          .
        </p>
      </header>

      {SECTIONS.map((s) => (
        <section key={s.id} aria-labelledby={s.id} className="flex flex-col gap-3 border-t pt-8">
          <h2 id={s.id} className="scroll-mt-28 text-2xl font-medium tracking-tight">
            {s.title}
          </h2>
          <p className="text-[17px] leading-7 text-pretty text-muted-foreground">{s.body}</p>
          <a href={s.href} className="self-start font-medium text-foreground underline underline-offset-4">
            {s.link}
          </a>
        </section>
      ))}
    </article>
  );
}
