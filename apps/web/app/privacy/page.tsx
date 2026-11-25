import { pageMetadata } from "@/lib/agent/seo";

export const metadata = pageMetadata({
  title: "Privacy policy · apm",
  description: "What data apm collects when you browse apmjs.dev, sign in with GitHub, or publish packages, and how it is handled.",
  path: "/privacy",
});

export default function PrivacyPage() {
  return (
    <article className="mx-auto flex max-w-3xl flex-col gap-8">
      <header className="flex flex-col gap-3">
        <h1 className="text-3xl font-medium tracking-tight sm:text-4xl">Privacy policy</h1>
        <p className="text-sm text-muted-foreground">Last updated: November 23, 2026</p>
        <p className="text-lg leading-7 text-pretty text-muted-foreground">
          apm is an open-source package registry and security scorer operated at apmjs.dev, registry.apmjs.dev, and docs.apmjs.dev. This page states what data we collect and why.
        </p>
      </header>

      <section className="flex flex-col gap-3 border-t pt-6">
        <h2 className="text-xl font-medium tracking-tight">Browsing and API requests</h2>
        <p className="text-[15px] leading-7 text-muted-foreground">
          You do not need an account to browse packages, install from the registry, or query the HTTP and MCP APIs. Our Cloudflare Workers handle incoming requests and record standard operational logs (status codes, latency, route labels, and error codes). Rate limiting hashes or keys requests by your network address (normalized to a /64 prefix for IPv6) inside Cloudflare.
        </p>
        <p className="text-[15px] leading-7 text-muted-foreground">
          The public pages of apmjs.dev and docs.apmjs.dev load Databuddy&apos;s analytics script, which sets no cookies. It records page views (the page address, title, and the site that linked you there), Web Vitals (load and responsiveness timings), clicks on links to other sites, and JavaScript errors on those pages, along with your screen size, language, and time zone. It also records a few actions by name: copying an install command, registry setting, setup prompt or MCP setting, opening the docs, opening a package from search or a piece of a score's evidence, starting sign-in, and how many results a search showed. These carry the package name where the action is about one package, and never the text you typed into search. On package pages, your browser also asks Databuddy which install tab to show first, using the same random visitor ID. To count visits it keeps a random visitor ID in your browser&apos;s local storage and a session ID in session storage. While you are signed out, neither is tied to an account.
        </p>
        <p className="text-[15px] leading-7 text-muted-foreground">
          The analytics script does not load on the sign-in, account, approval, device sign-in, publishing, or admin pages (/signin, /account, /approve, /device, /publish, /admin), and navigating to any of them from a public page loads a fresh page without the script. When your browser sends Global Privacy Control or Do Not Track, the analytics script does not load and your browser sends nothing to Databuddy.
        </p>
        <p className="text-[15px] leading-7 text-muted-foreground">
          When you are signed in, the public pages also give the analytics script your account&apos;s analytics ID, so visits can be counted per account and a sign-up counted with the visits that led to it. The analytics ID is a one-way hash of an internal account number: it is not your email address, name, or GitHub login, and Databuddy gets none of those. When you sign out, the next public page you open unties the browser from it. The registry also counts each new account and each sign-in, with the sign-in method (GitHub, Vercel, passkey, or the CLI) and the analytics ID, leaving the ID out when your browser sends Global Privacy Control or Do Not Track.
        </p>
        <p className="text-[15px] leading-7 text-muted-foreground">
          Separately, when an unexpected server error occurs, our Cloudflare Workers report it to Databuddy with a fixed error code, a route label, the status code, and the Cloudflare location. The report carries nothing about you or your request: no address, headers, or contents.
        </p>
      </section>

      <section className="flex flex-col gap-3 border-t pt-6">
        <h2 className="text-xl font-medium tracking-tight">Accounts, sign-in, and second factors</h2>
        <p className="text-[15px] leading-7 text-muted-foreground">
          When you sign in with GitHub OAuth, we store your GitHub numeric user ID, GitHub login, email address, and display name to bind your permanent @scope and manage sessions.
        </p>
        <p className="text-[15px] leading-7 text-muted-foreground">
          If you enroll an authenticator app (TOTP), passkey (WebAuthn), or recovery codes, we store the encrypted TOTP secret, passkey public key metadata, and hashed recovery codes. Session cookies are HttpOnly and restricted to apmjs.dev. CLI staging tokens are stored as SHA-256 hashes.
        </p>
      </section>

      <section className="flex flex-col gap-3 border-t pt-6">
        <h2 className="text-xl font-medium tracking-tight">Published packages and public logs</h2>
        <p className="text-[15px] leading-7 text-muted-foreground">
          Packages you publish to apm, their tarballs, metadata, security scores, yanks, revocations, and moderation events are public by design so installers can verify what they run.
        </p>
      </section>

      <section className="flex flex-col gap-3 border-t pt-6">
        <h2 className="text-xl font-medium tracking-tight">Contact and deletion requests</h2>
        <p className="text-[15px] leading-7 text-muted-foreground">
          To request account deletion or ask a privacy question, open an issue on{" "}
          <a href="https://github.com/opencoredev/apmjs/issues" className="text-foreground underline underline-offset-4">
            github.com/opencoredev/apmjs
          </a>{" "}
          or report security-sensitive matters privately through GitHub Security Advisories.
        </p>
      </section>
    </article>
  );
}
