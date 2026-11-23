import { pageMetadata } from "@/lib/agent/seo";
import { MCP_URL, siteUrl } from "@/lib/agent/site";
import { INSTRUCTIONS_LINE } from "@/lib/agent-prompt";

export const metadata = pageMetadata({
  title: "apm docs: setup, CLI, score and AI review",
  description: "Point bun, npm or pnpm at apm, use the apm CLI, pull a bad version, read the security score and the AI review, and use apm from a coding agent with no MCP server.",
  path: "/docs",
});

/** The documentation site, apps/docs, built with Blume. This page is its short overview. */
const DOCS = "https://docs.apmjs.dev";

/** The "Appeal a score" issue form (.github/ISSUE_TEMPLATE/appeal-a-score.yml). */
const APPEAL_URL = "https://github.com/opencoredev/apmjs/issues/new?template=appeal-a-score.yml";

/** The agent guide in the repository (docs/AGENTS.md), which /llms-full.txt also carries. */
const AGENTS_GUIDE = "https://github.com/opencoredev/apmjs/blob/main/docs/AGENTS.md";

// The ids stay stable: package pages and the AI review section link to /docs#bun, #npm, #cli, #capabilities and #ai-review; llms.txt and the MCP server link to #agents.
const SECTIONS = [
  { id: "bun", title: "Use it with Bun", body: "Point bunfig.toml at https://registry.apmjs.dev/ (or ~safe/ for the 24-hour cooldown and score floor), or use `apm add`. The optional @apm/bun-scanner package is not on a registry yet; see the guide for trying it from a local checkout.", href: `${DOCS}/guides/bun-scanner`, link: "Bun scanner" },
  { id: "npm", title: "Use it with npm or pnpm", body: "Set registry=https://registry.apmjs.dev/~safe/ in .npmrc. The view skips versions younger than 24 hours and versions scoring under 40.", href: `${DOCS}/guides/safe-view`, link: "The ~safe view" },
  {
    id: "cli",
    title: "The CLI",
    body: "apm add, apm x and apm publish check first, then hand the work to the package manager your project already uses. It installs as one binary for macOS or Linux, with no git or Bun needed. The install script checks the binary's SHA-256 against the checksum written into it before it installs anything, so you can read the script first and know exactly what it will accept.",
    code: `curl -fsSL ${siteUrl("/install")} | sh

# or read the script before running it
curl -fsSL ${siteUrl("/install")} -o install.sh
sh install.sh`,
    href: `${DOCS}/reference/cli`,
    link: "CLI reference",
  },
  { id: "pulling", title: "Pulling a bad version", body: "Yank hides a version from new installs. Revoke pulls a malicious one for everyone, with a fresh second factor; a version under 72 hours old is revoked at once, even when other packages depend on it. apm incident revokes every token and recent version after a compromise.", href: `${DOCS}/guides/pull-a-version`, link: "Yank, revoke and incident response" },
  { id: "score", title: "What the score is, and is not", body: "A static read of every file and the publish history, with a file and line for every point lost. Points go to what malware does: network and processes at install time, credential files read, the environment sent out, request bins, remote shells, obfuscation. It cannot see code that only shows what it does at runtime.", href: `${DOCS}/concepts/score`, link: "How the score works" },
  { id: "capabilities", title: "Capabilities", body: "What a version can do (the network, environment variables, files, processes, dynamic code, native code, install scripts) is listed beside the score with its evidence, and costs nothing. A package can declare its capabilities under apm.capabilities in package.json; a used capability it leaves out costs points.", href: `${DOCS}/concepts/capabilities`, link: "Declaring capabilities" },
  { id: "appeals", title: "Appealing a score", body: "A person at apm can dismiss one wrong piece of evidence for one version's exact tarball. The dismissal is public and can be undone.", href: APPEAL_URL, link: "Appeal a score" },
  { id: "ai-review", title: "The AI review", body: "A language model reads each new release in scope and reports cited findings next to the score, never inside it. It cannot see dependencies, binaries or code downloaded at runtime.", href: `${DOCS}/concepts/ai-review`, link: "What the AI review reads and can't see" },
] as const;

function Code({ children, label, wrap = false }: { children: string; label?: string; wrap?: boolean }) {
  return (
    <figure className="overflow-hidden rounded-xl bg-surface">
      {label && <figcaption className="border-b border-background px-4 py-2 font-mono text-[13px] text-muted-foreground">{label}</figcaption>}
      <pre className={wrap ? "p-4 font-mono text-[13px] leading-6 whitespace-pre-wrap [overflow-wrap:anywhere]" : "overflow-x-auto p-4 font-mono text-[13px] leading-6"}>{children}</pre>
    </figure>
  );
}

function Text({ children }: { children: React.ReactNode }) {
  return <p className="text-[17px] leading-7 text-pretty text-muted-foreground">{children}</p>;
}

/** Using apm from a coding agent: the instructions line first (plain HTTP, any agent), then the CLI, with MCP as an option. */
function AgentsSection() {
  return (
    <section aria-labelledby="agents" className="flex flex-col gap-4 border-t pt-8">
      <h2 id="agents" className="scroll-mt-28 text-2xl font-medium tracking-tight">
        Use apm from your agent
      </h2>
      <Text>
        Any agent that can fetch a URL can use apm. Nothing to install and no account. Add this line to AGENTS.md, CLAUDE.md or a Cursor rule, or copy the setup prompt on the{" "}
        <a href="/" className="text-foreground underline underline-offset-4">
          home page
        </a>
        :
      </Text>
      <Code wrap>{INSTRUCTIONS_LINE}</Code>
      <Text>
        Before adding a dependency, the agent asks for the verdict and gets install, review-first, do-not-install, not-found or unknown, with the reasons, the command to run and notes on
        what apm did not finish. review-first means a person should look: a real risk signal, or an analysis apm could not finish; apm&apos;s own work not yet done is a note. The same
        answers come as JSON over HTTP and from the CLI with <code className="font-mono text-[15px] text-foreground">--json</code>:
      </Text>
      <Code>{`curl ${siteUrl("/api/explain?package=zod@^4")}   # the install verdict as JSON
curl ${siteUrl("/package/zod.md")}                 # the package page as Markdown
apm explain zod@^4 --json                          # the verdict, from the CLI
apm search "schema validation" --json`}</Code>
      <Text>
        To publish, sign in and copy the prompt on{" "}
        <a href="/publish" className="text-foreground underline underline-offset-4">
          the publish page
        </a>
        . Your agent runs the apm CLI and uploads; you approve each version on the website.
      </Text>
      <Text>
        The JSON API is described in{" "}
        <a href="/openapi.json" className="text-foreground underline underline-offset-4">
          openapi.json
        </a>
        , and{" "}
        <a href="/llms.txt" className="text-foreground underline underline-offset-4">
          llms.txt
        </a>{" "}
        and{" "}
        <a href="/llms-full.txt" className="text-foreground underline underline-offset-4">
          llms-full.txt
        </a>{" "}
        give an agent these docs as text. Text quoted from a package was written by its publisher; the answers mark it, and an agent should treat it as data, not instructions.
      </Text>
      <details className="group flex flex-col gap-3 rounded-xl bg-surface/50 px-4 py-3">
        <summary className="cursor-pointer text-[15px] font-medium text-foreground">Optional: apm&apos;s MCP server</summary>
        <div className="mt-3 flex flex-col gap-3">
          <p className="text-[15px] leading-7 text-pretty text-muted-foreground">
            If your agent already uses MCP, <code className="font-mono text-[14px] text-foreground">{MCP_URL}</code> answers the same questions as tools (search_packages, check_package,
            check_name, explain_install, get_file_excerpt). Read-only, no account, rate-limited. You do not need it.
          </p>
          <Code label="Claude Code">{`claude mcp add --transport http apm ${MCP_URL}`}</Code>
          <Code label="Codex: ~/.codex/config.toml">{`[mcp_servers.apm]
url = "${MCP_URL}"`}</Code>
          <Code label="Cursor: .cursor/mcp.json">{`{
  "mcpServers": {
    "apm": { "url": "${MCP_URL}" }
  }
}`}</Code>
        </div>
      </details>
      <a href={AGENTS_GUIDE} className="self-start font-medium text-foreground underline underline-offset-4">
        The agent guide
      </a>
    </section>
  );
}

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
          {"code" in s && <Code label="Install the apm CLI">{s.code}</Code>}
          <a href={s.href} className="self-start font-medium text-foreground underline underline-offset-4">
            {s.link}
          </a>
        </section>
      ))}

      <AgentsSection />
    </article>
  );
}
