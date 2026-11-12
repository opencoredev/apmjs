import { defineConfig, type DummyRuleMap } from "oxlint";

// Run through `bun run lint` (scripts/lint.ts), which compares findings with
// lint-baseline.json. See docs/LINT.md for the policy and how to burn down the baseline.

const antiSlopRules = {
  "oxc/no-accumulating-spread": "error",
  "anti-slop/no-array-filter-map": "error",
  "anti-slop/no-reduce-accumulator-copy": "error",
  "anti-slop/no-chained-type-assertions": "error",
  "anti-slop/no-conditional-empty-object-spread": "error",
  "anti-slop/no-known-value-widening": "error",
  "anti-slop/no-module-mocking": "error",
  "anti-slop/no-object-parameters": "error",
  "anti-slop/no-reflect-apply": "error",
  "anti-slop/no-reflect-get": "error",
  "anti-slop/no-runtime-typeof": "error",
  "anti-slop/no-shape-in-symbol-names": "error",
  "anti-slop/no-unknown-parameters": "error",
  "anti-slop/no-unknown-returns": "error",
  "anti-slop/no-unknown-type-aliases": "error",
  "anti-slop/no-unsafe-dictionary-type": "error",
  "anti-slop/no-widen-then-assert": "error",
  "anti-slop/require-readable-spacing": "error",
  "anti-slop/require-safety-comment-for-type-assertion": "error",
} satisfies DummyRuleMap;

// Opt-in Effect group, scoped to the registry because that is the package moving to
// Effect. The rules are syntactic, so before Effect lands they only flag patterns
// (chained literal ternaries, make* imports) that Effect would replace. Add a package's
// glob to the override below when it starts using Effect.
const antiSlopEffectRules = {
  "anti-slop-effect/no-manual-effect-error-tag": "error",
  "anti-slop-effect/no-manual-tag-comparison": "error",
  "anti-slop-effect/no-manual-tagged-construction": "error",
  "anti-slop-effect/no-service-constructor-imports": "error",
  "anti-slop-effect/prefer-effect-match": "error",
} satisfies DummyRuleMap;

// Design-system rules for apps/web, kept to what the design calls for. The theme lives in
// apps/web/app/globals.css and the components in apps/web/components/ui; the plugin finds
// both through apps/web/components.json.
const shadcnRules = {
  // Button, Badge and Input own their padding, gap and radius: pick a size or variant,
  // and use margin or the parent's gap for space around them. Other components are
  // not restricted yet.
  "shadcn/no-restyle": [
    "error",
    {
      deny: [],
      contracts: [
        {
          pattern: "^(Button|Badge|Input)$",
          deny: ["spacing", "rounded", "rounded-*"],
          message:
            '"{{className}}" restyles <{{component}}>, which owns its padding, gap and radius. Use a size ({{sizes|none defined}}) or variant ({{variants|none defined}}), and margin or the parent\'s gap for space around it.',
        },
      ],
    },
  ],
  // Theme tokens only: no Tailwind palette colors, no white or black, no undeclared
  // tokens, no literal colors in SVG attributes. Keep `allow: []`: a `deny` without
  // `allow` would exempt every other class.
  "shadcn/no-raw-colors": ["error", { allow: [], deny: ["*-white", "*-black"] }],
  // Radius, padding, gap, margin and color stay on the theme scale. Arbitrary layout
  // sizes, type, effects and motion are not checked here.
  "shadcn/no-arbitrary-values": [
    "error",
    {
      allow: ["layout", "typography", "effects", "motion"],
      deny: ["m", "mx", "my", "mt", "mr", "mb", "ml", "ms", "me"],
    },
  ],
  // Inline styles bypass the theme (raw hex included). Only a computed width is allowed.
  "shadcn/no-inline-styles": ["error", { allow: ["width"] }],
} satisfies DummyRuleMap;

export default defineConfig({
  ignorePatterns: [
    ".agent/**",
    ".agents/**",
    ".claude/**",
    ".codex/**",
    ".continue/**",
    ".cursor/**",
    ".gemini/**",
    ".opencode/**",
    ".pi/**",
    ".roo/**",
    ".windsurf/**",
    ".hill-climb/**",
    "tools/oxlint/anti-slop/**",
    "apps/web/next-env.d.ts",
  ],
  jsPlugins: [
    { name: "anti-slop", specifier: "./tools/oxlint/anti-slop/index.ts" },
    { name: "anti-slop-effect", specifier: "./tools/oxlint/anti-slop/effect/index.ts" },
    "@shadcn/lint",
  ],
  settings: {
    shadcn: {
      note: "See docs/LINT.md for the design rules and how to record an exception.",
    },
  },
  rules: antiSlopRules,
  overrides: [
    {
      files: ["packages/registry/**"],
      rules: antiSlopEffectRules,
    },
    {
      files: ["apps/web/**/*.{ts,tsx}"],
      rules: shadcnRules,
    },
    {
      // Components style themselves; colors and inline styles stay checked inside them.
      files: ["apps/web/components/ui/**"],
      rules: {
        "shadcn/no-restyle": "off",
        "shadcn/no-arbitrary-values": "off",
      },
    },
  ],
});
