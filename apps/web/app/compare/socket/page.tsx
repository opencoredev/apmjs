import { pageMetadata, breadcrumbJsonLd } from "@/lib/agent/seo";
import { JsonLd } from "@/components/json-ld";

export const metadata = pageMetadata({
  title: "apm vs Socket: two ways to check npm packages",
  description: "apm vs Socket for npm security: Socket checks dependencies in pull requests and at install. apm is the registry, with a cited score per version.",
  path: "/compare/socket",
});

/** When the Socket pages below were read. */
const FETCHED = "2026-11-26";

const SOURCES = [
  { href: "https://socket.dev/", text: "socket.dev" },
  { href: "https://docs.socket.dev/docs/socket-for-github", text: "Socket for GitHub" },
  { href: "https://docs.socket.dev/docs/socket-firewall-free", text: "Socket Firewall Free" },
  { href: "https://docs.socket.dev/docs/socket-cli", text: "Socket CLI" },
  { href: "https://socket.dev/pricing", text: "Socket pricing" },
] as const;

/** `code` spans inside comparison copy. */
function Rich({ text }: { text: string }) {
  return (
    <>
      {text.split(/(`[^`]+`)/).map((part, i) =>
        part.startsWith("`") && part.endsWith("`") ? (
          <code key={i} className="rounded-md bg-surface px-1.5 py-px font-mono text-[0.88em] text-foreground">
            {part.slice(1, -1)}
          </code>
        ) : (
          part
        ),
      )}
    </>
  );
}

type Row = { label: string; socket: string; apm: string; link?: { href: string; text: string } };

const ROWS: readonly Row[] = [
  {
    label: "What it is",
    socket: "A security platform that scans open source packages for malicious behavior across npm, PyPI, RubyGems, cargo and other registries.",
    apm: "A package registry in front of npm. Stock bun, npm and pnpm install from it unchanged, and the `apm` CLI checks a package before your package manager installs it.",
  },
  {
    label: "Where it checks",
    socket: "In pull requests (Socket for GitHub comments when a change adds a risky dependency), at install (`sfw npm install` with Socket Firewall; Socket Firewall Enterprise can also be the registry your package manager points at), and in scans from the Socket CLI.",
    apm: "At the registry and before install: with npm, pnpm and bun, `apm add` and `apm x` check the whole tree the package manager computes before it installs. The `~safe` registry view filters for any client.",
    link: { href: "https://docs.apmjs.dev/concepts/security-model#how-apm-add-installs-what-it-checked", text: "Exceptions (yarn, npm git dependencies)" },
  },
  {
    label: "What it looks for",
    socket: "Install scripts, typosquats, telemetry, native code, known malware, obfuscated code, shell and network use, protestware. Also known vulnerabilities (CVEs), with `socket fix` to update them.",
    apm: "What malware does: install-time downloads, remote shells, credential reads, the environment sent over the network, request bins, obfuscation, look-alike names. Known CVEs are not in the score; `apm audit` lists them.",
  },
  {
    label: "The result",
    socket: "Alerts per package, and package and project health scores in a Socket scan report.",
    apm: "A score out of 100 per version once apm has analysed it, each lost point tied to a file and line, plus what apm did not read or check. No account needed to read it.",
  },
  {
    label: "Blocking",
    socket: "Socket Firewall blocks known malware at download. In the free version, AI-detected possible malware only warns; confirmed malware is blocked.",
    apm: "The score informs and does not block by default: `apm add` warns about a score under 40 or a version under 24 hours old, and `--strict` and the `~safe` view refuse both. `apm add` refuses revoked, yanked and confirmed-malicious versions, and new registry resolutions skip them.",
  },
  {
    label: "Pulling a bad version",
    socket: "Socket Firewall can block a version it flags for Socket users, but it cannot remove that version from npm; it stays there until npm or its publisher removes it.",
    apm: "For a version published on apm, `yank` hides it from new resolutions at once, and `revoke` returns 410 for its tarball (for an older version, after 24 hours unless a second owner confirms). Stock clients can still install a yanked version from a lockfile that already pins it.",
  },
  {
    label: "Ecosystems",
    socket: "npm, yarn and pnpm, pip and uv, and cargo with the free firewall; Go, Java, Ruby and .NET with Socket Firewall Enterprise.",
    apm: "npm packages only, through bun, npm, pnpm and yarn.",
  },
  {
    label: "For agents",
    socket: "The Socket CLI and API; most API commands need a token.",
    apm: "`GET https://apmjs.dev/api/explain?package=<name>` returns an install verdict as JSON, with no account. An MCP server is optional.",
  },
  {
    label: "Cost and code",
    socket: "A free plan, Team and Business plans priced per developer seat, and custom Enterprise pricing.",
    apm: "Open source under the MIT license.",
  },
];

const SOCKET_WINS = [
  { title: "More ecosystems", body: "Socket covers Python, Rust and more. apm only serves npm packages." },
  { title: "Pull request review", body: "Socket for GitHub flags a risky dependency in the pull request that adds it. apm has no GitHub app." },
  { title: "Vulnerabilities", body: "Socket tracks known CVEs and can update them. The apm score leaves CVEs out; `apm audit` or `npm audit` lists them." },
  { title: "Track record", body: "Socket protects more than 27,000 organizations, by its own count. apm is new." },
] as const;

export default function CompareSocket() {
  return (
    <div className="flex flex-col items-center">
      <JsonLd
        data={breadcrumbJsonLd([
          { name: "apm", path: "/" },
          { name: "apm vs Socket", path: "/compare/socket" },
        ])}
      />
      <header className="flex max-w-2xl flex-col items-center pt-4 text-center sm:pt-10">
        <h1 className="text-[34px] leading-[1.15] font-medium tracking-[-0.02em] text-balance sm:text-5xl sm:leading-[1.12]">apm vs Socket, side by side.</h1>
        <p className="mt-5 text-lg leading-8 text-pretty text-muted-foreground">
          Socket watches your dependencies from the outside: in pull requests and at install. apm is the registry your package manager installs from, so it publishes a score for each version once it has analysed it and can hide a bad one from new installs.
        </p>
      </header>

      <section aria-labelledby="table-title" className="mt-16 w-full max-w-5xl sm:mt-24">
        <h2 id="table-title" className="mb-6 text-center text-[28px] leading-tight font-medium tracking-[-0.02em] sm:text-4xl">
          Row by row.
        </h2>
        <div role="table" aria-labelledby="table-title" className="overflow-hidden rounded-2xl border">
          <div role="row" className="hidden grid-cols-[180px_1fr_1fr] border-b text-sm md:grid">
            <div role="columnheader" className="px-5 py-3">
              <span className="sr-only">Topic</span>
            </div>
            <div role="columnheader" className="px-5 py-3 text-muted-foreground">Socket</div>
            <div role="columnheader" className="bg-surface px-5 py-3 font-medium">apm</div>
          </div>
          {ROWS.map((r) => (
            <div key={r.label} role="row" className="grid border-t border-dashed first:border-t-0 md:grid-cols-[180px_1fr_1fr]">
              <div role="rowheader" className="px-5 pt-4 pb-1 font-medium md:py-4">{r.label}</div>
              <div role="cell" className="flex gap-3 px-5 py-2 text-[15px] leading-6 text-muted-foreground md:py-4">
                <span className="w-12 shrink-0 pt-px font-mono text-xs leading-6 md:sr-only">Socket</span>
                <span className="min-w-0">
                  <Rich text={r.socket} />
                </span>
              </div>
              <div role="cell" className="mx-3 mb-3 flex gap-3 rounded-lg bg-surface px-2 py-2 text-[15px] leading-6 md:m-0 md:rounded-none md:px-5 md:py-4">
                <span className="w-12 shrink-0 pt-px font-mono text-xs leading-6 font-medium md:sr-only">apm</span>
                <span className="min-w-0">
                  <Rich text={r.apm} />
                  {r.link && (
                    <>
                      {" "}
                      <a href={r.link.href} className="text-foreground underline underline-offset-4">
                        {r.link.text}
                      </a>
                    </>
                  )}
                </span>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section aria-labelledby="socket-wins" className="mt-20 w-full max-w-5xl sm:mt-28">
        <h2 id="socket-wins" className="text-center text-[28px] leading-tight font-medium tracking-[-0.02em] sm:text-4xl">
          Where Socket wins.
        </h2>
        <div className="mt-10 grid gap-x-16 sm:mt-14 sm:grid-cols-2">
          {SOCKET_WINS.map((w) => (
            <div key={w.title} className="border-t py-6">
              <h3 className="text-lg font-medium">{w.title}</h3>
              <p className="mt-1 text-[17px] leading-7 text-pretty text-muted-foreground">
                <Rich text={w.body} />
              </p>
            </div>
          ))}
        </div>
      </section>

      <section aria-labelledby="try-it" className="mt-20 w-full max-w-2xl text-center sm:mt-28">
        <h2 id="try-it" className="text-[28px] leading-tight font-medium tracking-[-0.02em] sm:text-4xl">
          Check a package on apm.
        </h2>
        <p className="mt-5 text-[17px] leading-7 text-pretty text-muted-foreground">
          Open any package, for example <a href="/package/react" className="text-foreground underline underline-offset-4">the score and evidence for react</a>, read <a href="/compare" className="text-foreground underline underline-offset-4">what changes when you switch from npm</a>, or point your package manager at apm with the{" "}
          <a href="https://docs.apmjs.dev/quickstart" className="text-foreground underline underline-offset-4">
            quick start
          </a>
          .
        </p>
      </section>

      <footer className="mt-20 w-full max-w-5xl border-t pt-6 text-sm leading-6 text-muted-foreground">
        Socket facts are from Socket’s own pages, read on {FETCHED}:{" "}
        {SOURCES.map((s, i) => (
          <span key={s.href}>
            <a href={s.href} className="underline underline-offset-4 hover:text-foreground">
              {s.text}
            </a>
            {i < SOURCES.length - 1 ? ", " : "."}
          </span>
        ))}{" "}
        apm facts are from the <a href="https://docs.apmjs.dev/concepts/score" className="underline underline-offset-4 hover:text-foreground">score documentation</a>.
      </footer>
    </div>
  );
}
