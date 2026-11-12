# Linting

```sh
bun run lint            # check; this is what CI runs
bun run lint:baseline   # rewrite lint-baseline.json after fixing findings
```

`bun run lint` runs [Oxlint](https://oxc.rs/docs/guide/usage/linter) with `oxlint.config.ts` over the whole repo and compares the findings with `lint-baseline.json`. It fails when a file has more findings for a rule than the baseline allows, and when a baseline entry no longer occurs.

The config is TypeScript, so Oxlint loads it through Node.js, which needs 22.18 or later from an official build (nodejs.org, `actions/setup-node`). Some distro builds of Node 22 ship without TypeScript support and fail with `Unknown file extension ".ts"`.

## What runs

| Group | Where | Rules |
| --- | --- | --- |
| Oxlint defaults (the `correctness` category) | everywhere | Oxlint's built-in set |
| [anti-slop](https://github.com/dmmulroy/anti-slop) generic rules, plus `oxc/no-accumulating-spread` | everywhere | 19, all at `error` |
| anti-slop Effect rules | `packages/registry/**` | 5, all at `error` |
| [@shadcn/lint](https://github.com/shadcn-ui/lint) | `apps/web/**` | 4, all at `error` |

anti-slop is vendored in `tools/oxlint/anti-slop/` and is ours to edit. `UPSTREAM.md` there records the upstream commit and how to update. Read upstream's README for what each rule rejects and what to write instead.

The Effect rules sit on `packages/registry` because that is the package moving to Effect. They are syntactic, so until Effect code lands they only flag patterns Effect would replace, such as chained literal ternaries (use `Match`). When another package starts using Effect, add its glob to that override.

Ignored: agent tooling directories (`.claude/`, `.codex/` and the rest of upstream's list), `.hill-climb/`, the vendored plugin itself, `packages/core/test/v3/` (apm-score-v3 copied byte for byte from git history as the reference the floor fuzz test compares against) and `apps/web/next-env.d.ts`. Oxlint also skips what `.gitignore` lists.

## Design rules for apps/web

The theme is `apps/web/app/globals.css` and the components are `apps/web/components/ui/*`; `@shadcn/lint` finds both through `apps/web/components.json`. The rules follow the direction in `research/graphicalui-notes.md`: neutral tokens, a 12px radius family, grey-filled controls.

| Rule | Enforces |
| --- | --- |
| `shadcn/no-restyle` | `Button`, `Badge` and `Input` own their padding, gap and radius. Choose a `size` or `variant`, and use margin or the parent's `gap` for space around them. Width, margin, placement and type stay open. Other components are not restricted. |
| `shadcn/no-raw-colors` | Theme tokens only: no Tailwind palette colors (`bg-pink-500`), no `white` or `black`, no undeclared tokens, no hex in SVG `fill` or `stroke`. Applies inside `components/ui` too. |
| `shadcn/no-arbitrary-values` | Radius, padding, gap, margin and color stay on the theme scale: no `rounded-[10px]`, `p-[13px]`, `-mt-[3px]` or `bg-[#333]`. Arbitrary layout sizes (`w-[320px]`), type, effects and motion are not checked. Off inside `components/ui`. |
| `shadcn/no-inline-styles` | No `style={{ ... }}` except `width`, so colors can't bypass the theme through inline styles. |

Every message ends with a pointer to this file. To add a color, declare `--color-<name>` in `globals.css` for light and dark. To add a size or variant, edit the component's `cva` in `components/ui`.

Left out on purpose: the site's type scale uses px sizes such as `text-[15px]` (about 100 uses), and `Table` and `Tabs` are restyled per page. Each could become a rule once the theme declares the tokens or the components grow the variants.

## Exceptions

Fix the code where you can. When a finding is a deliberate exception, disable it on that line and give the reason:

```tsx
// oxlint-disable-next-line shadcn/no-raw-colors -- a QR code needs a white quiet zone to scan in dark mode
```

In JSX, wrap the comment in braces: `{/* ... */}`. Oxlint also honours `eslint-disable` comments.

## The baseline

`lint-baseline.json` maps each file to rules and the number of findings that existed when linting was added. CI fails when a count goes up, so new code is held to every rule while old findings wait to be fixed.

To burn findings down:

1. Fix findings in a file.
2. Run `bun run lint:baseline` and commit `lint-baseline.json` with the fix. `bun run lint` fails until you do, so the list stays accurate.

Don't regenerate the baseline to get new findings past CI. If a rebase conflicts in `lint-baseline.json`, take either side, run `bun run lint:baseline` on the merged code, and review the diff.

`anti-slop/require-readable-spacing` makes up most of the baseline and only inserts blank lines. `bunx oxlint -c oxlint.config.ts --fix <path>` applies it. It was applied to `apps/web` and `packages/core` when linting was added. The other packages wait for the in-flight registry port and hardening work to merge.

Baseline when linting was added (1,335 findings in 38 files):

| Rule | apps/web | bun-scanner | cli | core | registry | scripts | tests | tools | Total |
|---|---|---|---|---|---|---|---|---|---|
| `anti-slop/require-readable-spacing` |  | 15 | 249 |  | 628 | 7 | 164 | 9 | 1072 |
| `anti-slop/no-runtime-typeof` | 9 | 4 | 14 | 15 | 13 |  | 28 |  | 83 |
| `anti-slop/no-unsafe-dictionary-type` |  |  | 1 | 10 | 34 |  | 5 |  | 50 |
| `anti-slop/no-known-value-widening` | 9 |  | 5 | 3 | 22 |  | 4 |  | 43 |
| `anti-slop/no-conditional-empty-object-spread` | 1 |  | 4 |  | 17 |  | 9 |  | 31 |
| `anti-slop/no-unknown-parameters` | 2 |  | 4 | 3 | 8 |  | 9 | 1 | 27 |
| `anti-slop/no-unknown-returns` |  |  |  |  | 8 |  | 2 |  | 10 |
| `anti-slop/no-shape-in-symbol-names` |  |  |  |  | 8 |  |  |  | 8 |
| `shadcn/no-restyle` | 3 |  |  |  |  |  |  |  | 3 |
| `anti-slop/no-reflect-get` | 1 |  |  |  |  |  | 1 |  | 2 |
| `unicorn/no-useless-fallback-in-spread` |  |  |  |  | 1 |  | 1 |  | 2 |
| `anti-slop-effect/prefer-effect-match` |  |  |  |  | 1 |  |  |  | 1 |
| `anti-slop/no-array-filter-map` |  |  |  |  | 1 |  |  |  | 1 |
| `anti-slop/require-safety-comment-for-type-assertion` |  |  | 1 |  |  |  |  |  | 1 |
| `shadcn/no-inline-styles` | 1 |  |  |  |  |  |  |  | 1 |
| Total | 26 | 19 | 278 | 31 | 741 | 7 | 223 | 10 | 1335 |

The `apps/web` design findings: `px-4` on two approval `Button`s and `rounded-none` on the publish page's `Input` (`no-restyle`), and the logo's inline `fill` with its brand accent (`no-inline-styles`).

Most of the rest of `packages/core` and `packages/registry` is unparsed input (`typeof`, `unknown` parameters, `Record<string, unknown>`). The fix is to parse it with zod where it enters, which belongs with the hardening and Effect work rather than here.

## Upgrading

Keep `oxlint` and `@oxlint/plugins` at the same exact version, and run the vendored rule suites after an upgrade (the command is in `tools/oxlint/anti-slop/UPSTREAM.md`). CI runs them too. `@shadcn/lint` needs Oxlint 1.80 or later.
