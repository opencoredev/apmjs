// Blume layout overrides (https://useblume.dev/docs/configuration/customization#layout-slots). PageFooter stamps each
// published page with its route for the page-view tracker (analytics.ts); it renders nothing visible.
import { defineComponents } from "blume";

export default defineComponents({
  layout: {
    PageFooter: "./components/PageView.astro",
  },
});
