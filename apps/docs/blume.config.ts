// The apm documentation site, built with Blume (https://useblume.dev). `bun run build` writes static HTML to
// dist/, which packages/infra serves as an assets-only Worker at docs.apmjs.dev.
import { defineConfig } from "blume";
import { docsAnalytics } from "./analytics";

// Databuddy's tracker, added by an inline loader only at the docs origin and without an opt-out (analytics.ts). The client id is given to production's build
// alone (packages/infra/analytics.ts); without it the site renders no tracker and sends nothing.
const databuddyClientId = process.env.NEXT_PUBLIC_DATABUDDY_CLIENT_ID?.trim() ?? "";

export default defineConfig({
  title: "apm docs",
  description: "Documentation for apm, a registry in front of npm with a security score on every version, yank and revoke, and approved publishing.",
  logo: { image: "/logo.svg", text: "docs", href: "/" },

  theme: {
    // apmjs.dev is ink on white: near-black controls, warm greys, no brand hue outside the logo
    accent: { light: "#171717", dark: "#eeeeee" },
    background: { light: "#ffffff", dark: "#111111" },
    radius: "md",
    mode: "system",
    toggle: true,
    fonts: {
      display: { name: "Host Grotesk", weights: [400, 500, 600] },
      body: { name: "Host Grotesk", weights: [400, 500, 600] },
      mono: { name: "Geist Mono", weights: [400, 500] },
    },
  },

  navigation: {
    sidebar: { display: "flat" },
    actions: [{ href: "https://apmjs.dev/", label: "apmjs.dev" }],
  },

  github: { owner: "opencoredev", repo: "apmjs", dir: "apps/docs" },

  footer: {
    copyright: "apm is MIT licensed.",
    links: [
      { label: "apmjs.dev", href: "https://apmjs.dev/" },
      { label: "apm vs Socket", href: "https://apmjs.dev/compare/socket" },
      { label: "Privacy", href: "https://apmjs.dev/privacy" },
      { label: "Terms", href: "https://apmjs.dev/terms" },
      { label: "Status", href: "https://status.apmjs.dev" },
      { label: "Report a package", href: "https://github.com/opencoredev/apmjs/issues/new?template=report-package.yml" },
    ],
  },

  analytics: docsAnalytics(databuddyClientId),

  // a search is reported with its length, never its text: a reader may paste a token or an address into the box
  search: { analytics: { queries: false } },

  markdown: {
    code: { theme: { light: "github-light", dark: "github-dark" } },
  },

  deployment: { site: "https://docs.apmjs.dev" },
});
