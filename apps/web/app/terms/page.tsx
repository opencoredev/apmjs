import { pageMetadata } from "@/lib/agent/seo";

export const metadata = pageMetadata({
  title: "Terms of service · apm",
  description: "Terms for using the apmjs.dev website, registry, CLI, security scores, and AI release reviews.",
  path: "/terms",
});

export default function TermsPage() {
  return (
    <article className="mx-auto flex max-w-3xl flex-col gap-8">
      <header className="flex flex-col gap-3">
        <h1 className="text-3xl font-medium tracking-tight sm:text-4xl">Terms of service</h1>
        <p className="text-sm text-muted-foreground">Last updated: November 20, 2026</p>
        <p className="text-lg leading-7 text-pretty text-muted-foreground">
          By using apmjs.dev, registry.apmjs.dev, docs.apmjs.dev, or the apm CLI, you agree to these terms.
        </p>
      </header>

      <section className="flex flex-col gap-3 border-t pt-6">
        <h2 className="text-xl font-medium tracking-tight">Security scores and AI reviews</h2>
        <p className="text-[15px] leading-7 text-muted-foreground">
          apm provides static security scores, capability summaries, and cited AI release reviews as informational signals. A high score or clean review never guarantees that a package is safe, bug-free, or free of runtime malware. You remain responsible for evaluating and approving code you install or run.
        </p>
      </section>

      <section className="flex flex-col gap-3 border-t pt-6">
        <h2 className="text-xl font-medium tracking-tight">Publishing and package rules</h2>
        <p className="text-[15px] leading-7 text-muted-foreground">
          You may only publish packages you have the right to distribute. Do not publish malware, credential stealers, typosquats, spam, or stolen secrets. We may yank, revoke, quarantine, or remove any package or account that violates these rules or poses a security risk to installers.
        </p>
      </section>

      <section className="flex flex-col gap-3 border-t pt-6">
        <h2 className="text-xl font-medium tracking-tight">Acceptable use</h2>
        <p className="text-[15px] leading-7 text-muted-foreground">
          Do not attempt to bypass rate limits, flood the analysis queue, scrape private endpoints, or disrupt availability for other users. We may throttle or block abusive traffic without prior notice.
        </p>
      </section>

      <section className="flex flex-col gap-3 border-t pt-6">
        <h2 className="text-xl font-medium tracking-tight">Warranty and open-source license</h2>
        <p className="text-[15px] leading-7 text-muted-foreground">
          The apm service is provided as-is without warranty of any kind. The apm source code is published under the MIT license at{" "}
          <a href="https://github.com/opencoredev/apmjs" className="text-foreground underline underline-offset-4">
            github.com/opencoredev/apmjs
          </a>
          .
        </p>
      </section>
    </article>
  );
}
