import { CheckIcon, EqualIcon, XIcon } from "lucide-react";
import { pageMetadata } from "@/lib/agent/seo";

export const metadata = pageMetadata({
  title: "npm vs apm: what changes when you switch",
  description: "What apm adds in front of npm: per-version security scores with cited evidence, a 24-hour cooldown, yank and revoke at any time, typosquat checks, and the same bun, npm and pnpm.",
  path: "/compare",
});

/** `code` and **bold** spans inside comparison copy. */
function Rich({ text, onSurface = false }: { text: string; onSurface?: boolean }) {
  return (
    <>
      {text.split(/(`[^`]+`|\*\*[^*]+\*\*)/).map((part, i) => {
        if (part.startsWith("`") && part.endsWith("`")) {
          return (
            <code key={i} className={`rounded-md px-1.5 py-px font-mono text-[0.88em] text-foreground ${onSurface ? "bg-background ring-1 ring-border" : "bg-surface"}`}>
              {part.slice(1, -1)}
            </code>
          );
        }

        if (part.startsWith("**") && part.endsWith("**")) {
          return (
            <strong key={i} className="font-medium text-foreground">
              {part.slice(2, -2)}
            </strong>
          );
        }

        return part;
      })}
    </>
  );
}

type Row = { label: string; npm: string; apm: string; same?: true };

type Group = { title: string; rows: readonly Row[] };

const POINTS = [
  { title: "An undo button", body: "Yank or revoke any version, any time. One command cleans up a stolen token." },
  { title: "A score per version", body: "Out of 100, every lost point tied to a file and line." },
  { title: "Checks before install", body: "The whole dependency tree, before bun or npm touches disk." },
] as const;

const GROUPS: readonly Group[] = [
  {
    title: "When something goes wrong",
    rows: [
      {
        label: "Hacked version",
        npm: "Unpublish only within 72h and with no dependents. Deprecate still installs.",
        apm: "**Yank** hides it from new installs. **Revoke** returns 410 and a critical advisory. Any time.",
      },
      { label: "Stolen token", npm: "Rotate tokens, then hunt down the bad versions by hand.", apm: "`apm incident --since` revokes every token and version since then, with a dry run." },
    ],
  },
  {
    title: "Knowing what you install",
    rows: [
      { label: "Safety signal", npm: "`npm audit` lists known CVEs only. Silent on new malware.", apm: "Score out of 100 with file:line evidence and a “not checked” list." },
      { label: "Granularity", npm: "Third-party scores rate the whole package.", apm: "Every version scored. A new `curl | sh` or risky dependency drops it." },
      { label: "Metadata", npm: "Trusts the publish request, so install scripts can hide.", apm: "Read from the tarball’s package.json. A mismatch is refused." },
      { label: "Install check", npm: "Installs first, audit afterwards.", apm: "`apm add` and `apm x` check the whole tree first." },
      { label: "Fresh releases", npm: "No cooldown by default.", apm: "24h cooldown: `apm add` warns about a version under a day old, `--strict` refuses it, and `/~safe/` leaves it out for any client, with a score floor of 40." },
    ],
  },
  {
    title: "Publishing",
    rows: [
      { label: "The flow", npm: "Two logins, 7-day tokens, misleading 404 or `ENEEDAUTH`.", apm: "File list and score preview before upload, then a person approves the version with a passkey or 2FA." },
      { label: "Mistakes", npm: "Ships secrets `.npmignore` missed and a `main` that doesn’t exist.", apm: "Blocks secrets and missing main, types or bin. The registry checks again." },
    ],
  },
  {
    title: "Names",
    rows: [
      { label: "Typosquats", npm: "Blocks punctuation variants only.", apm: "Refuses one-edit look-alikes of popular packages. Search shows them next to your query." },
      { label: "Dependency confusion", npm: "Unscoped names are first come, first served.", apm: "New packages are scoped to your GitHub login. A bare name always means the npm package." },
    ],
  },
  {
    title: "Compatibility",
    rows: [
      { label: "Bun", npm: "Just another client.", apm: "One `bunfig.toml` line makes plain `bun install` refuse revoked and confirmed-malicious versions and warn about low scores." },
      { label: "Coverage", npm: "Everything on npm.", apm: "Same packages, proxied from npm and scored on first request.", same: true },
    ],
  },
];

const NPM_WINS = [
  { title: "Scale and trust", body: "npm is the real registry. apm is a working demo." },
  { title: "Trusted publishing and provenance", body: "npm has OIDC and provenance. apm has neither yet." },
  { title: "Account security", body: "Both have passkeys and 2FA. npm’s account system has years of use behind it; apm’s is new." },
  { title: "Hosting your code", body: "apm can’t take a name that already exists on npm." },
] as const;

function Mark({ kind }: { kind: "no" | "yes" | "same" }) {
  const Icon = kind === "yes" ? CheckIcon : kind === "no" ? XIcon : EqualIcon;
  const tone = kind === "yes" ? "bg-ok-soft text-ok" : kind === "no" ? "bg-bad-soft text-bad" : "bg-secondary text-muted-foreground";
  const label = kind === "yes" ? "apm handles this" : kind === "no" ? "npm falls short" : "the same";

  return (
    <span className={`mt-0.5 grid size-5 shrink-0 place-items-center rounded-full ${tone}`} role="img" aria-label={label}>
      <Icon className="size-3" strokeWidth={2.5} aria-hidden />
    </span>
  );
}

export default function Compare() {
  return (
    <div className="flex flex-col items-center">
      <header className="flex max-w-2xl flex-col items-center pt-4 text-center sm:pt-10">
        <h1 className="text-[34px] leading-[1.15] font-medium tracking-[-0.02em] text-balance sm:text-5xl sm:leading-[1.12]">npm and apm, side by side.</h1>
        <p className="mt-5 text-lg leading-8 text-pretty text-muted-foreground">
          You keep bun, npm, pnpm or yarn. <span className="font-mono text-foreground">apm</span> runs in front of them and passes through any command it doesn’t know.
        </p>
      </header>

      <section aria-label="What apm adds" className="mt-14 grid w-full max-w-5xl overflow-hidden rounded-2xl border sm:mt-20 md:grid-cols-3 md:divide-x">
        {POINTS.map((p, i) => (
          <div key={p.title} className={`p-6 sm:p-7 ${i < POINTS.length - 1 ? "border-b md:border-b-0" : ""}`}>
            <h2 className="text-lg font-medium">{p.title}</h2>
            <p className="mt-1 text-[17px] leading-7 text-pretty text-muted-foreground">{p.body}</p>
          </div>
        ))}
      </section>

      <section aria-labelledby="table-title" className="mt-20 w-full max-w-5xl sm:mt-28">
        <h2 id="table-title" className="mb-6 text-center text-[28px] leading-tight font-medium tracking-[-0.02em] sm:text-4xl">
          Row by row.
        </h2>
        <div className="overflow-hidden rounded-2xl border">
          <div className="hidden grid-cols-[180px_1fr_1fr] border-b text-sm md:grid" aria-hidden>
            <div className="px-5 py-3" />
            <div className="px-5 py-3 text-muted-foreground">npm today</div>
            <div className="bg-surface px-5 py-3 font-medium">apm</div>
          </div>
          {GROUPS.map((g) => (
            <div key={g.title} className="border-b last:border-b-0">
              <div className="grid md:grid-cols-[180px_1fr_1fr]">
                <h3 className="px-5 pt-6 pb-2 text-sm font-normal text-muted-foreground md:col-span-2">
                  {g.title}
                </h3>
                <div className="hidden bg-surface md:block" aria-hidden />
              </div>
              {g.rows.map((r) => (
                <div key={r.label} className="grid border-t border-dashed first:border-t-0 md:grid-cols-[180px_1fr_1fr] [&:nth-child(2)]:border-t-0">
                  <div className="px-5 pt-4 pb-1 font-medium md:py-4">
                    {r.label}
                  </div>
                  <div className="flex gap-3 px-5 py-2 text-[15px] leading-6 text-muted-foreground md:py-4">
                    <span className="w-9 shrink-0 pt-px font-mono text-xs leading-6 text-muted-foreground md:sr-only">npm</span>
                    <Mark kind={r.same ? "same" : "no"} />
                    <span className="min-w-0">
                      <Rich text={r.npm} />
                    </span>
                  </div>
                  <div className="mx-3 mb-3 flex gap-3 rounded-lg bg-surface px-2 py-2 text-[15px] leading-6 md:m-0 md:rounded-none md:px-5 md:py-4">
                    <span className="w-9 shrink-0 pt-px font-mono text-xs leading-6 font-medium md:sr-only">apm</span>
                    <Mark kind={r.same ? "same" : "yes"} />
                    <span className="min-w-0">
                      <Rich text={r.apm} onSurface />
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ))}
        </div>
      </section>

      <section aria-labelledby="npm-wins" className="mt-20 w-full max-w-5xl sm:mt-28">
        <h2 id="npm-wins" className="text-center text-[28px] leading-tight font-medium tracking-[-0.02em] sm:text-4xl">
          Where npm still wins.
        </h2>
        <div className="mt-10 grid gap-x-16 sm:mt-14 sm:grid-cols-2">
          {NPM_WINS.map((w) => (
            <div key={w.title} className="border-t py-6">
              <h3 className="text-lg font-medium">{w.title}</h3>
              <p className="mt-1 text-[17px] leading-7 text-pretty text-muted-foreground">{w.body}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
