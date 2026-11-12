// The apm documentation site, built with Blume (https://useblume.dev). `bun run build` writes static HTML to
// dist/, which packages/infra serves as an assets-only Worker at docs.apmjs.dev.
import { defineConfig } from "blume";

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
      { label: "Registry", href: "https://registry.apmjs.dev/-/ping" },
      { label: "Report a package", href: "https://github.com/opencoredev/apmjs/issues/new?template=report-package.yml" },
    ],
  },

  markdown: {
    code: { theme: { light: "github-light", dark: "github-dark" } },
  },

  deployment: { site: "https://docs.apmjs.dev" },
});
