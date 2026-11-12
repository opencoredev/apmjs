# The apm score

Every version gets a number from 0 to 100, computed once from its tarball, its `package.json` and its publish history (`analyze` and `finalize` in `packages/core/src/score.ts`). It starts at 100 and every deduction is a named signal with the file and line that caused it. Below 40 (the floor), `apm add`, the `~safe` registry view and the scanners refuse the version unless you pass `--force`.

The score is a static read of text. It is a strong filter for the droppers that make up most npm malware, and a weak one against an author who knows it exists and is willing to write code that only reveals itself at runtime. Read a high score as "nothing on this list was found", not as "safe".

## What it reads, in order

1. **Lifecycle scripts.** `preinstall`, `install` and `postinstall` run on every install. `prepare`, `prepack` and `postpack` run when the package is installed from a git URL. Each one is followed the way the package managers follow it: `npm run x` (with `prex` and `postx`), `yarn x`, `pnpm x`, `bun run x`, `npm-run-all` and `run-s`/`run-p` patterns, `sh -c '...'`, and base64 payloads passed to `node -e`. Every command they reach is checked, and every word in them that names a file in the tarball is read first.
2. **binding.gyp.** Its `action` lists and `<!(...)` command expansions are commands like any install script. A `Makefile` or `CMakeLists.txt` is checked too when an install script runs `make` or `cmake-js`.
3. **Entry points**: `bin`, `main`, `module`, `browser` and `exports`, then every file those load through a path apm can read: a literal `require`/`import`, `require.resolve('./x')`, `path.join(__dirname, 'lib', 'x')` and `__dirname + '/x'`, with node's extension and index probing (`.js`, `.cjs`, `.mjs`, `.json`, `.node`, `.ts`, `/index.*`).
4. **Every other file that could be code**, whatever its extension (`lib/payload.dat` is read). Left out unless code reaches them: docs (`README`, `*.md`, `*.txt`), type declarations, source maps, JSON, YAML, styles and markup. Images, fonts, archives and WebAssembly are recognised by their first bytes and skipped; executables and `.node` files are listed as `binary`.

A file's bytes are read whatever they look like: a NUL byte does not make a file "binary". One file over 32 MB is not read and makes the analysis `incomplete`. All files together are read up to 200 MB, the most a tarball may unpack to; a caller analysing its own file list can pass a smaller `maxScannedBytes`. Because install targets and entry points come first, padding a package with filler can only push other filler out of the budget. A file that runs but did not fit makes the analysis `incomplete`; one that nothing was seen loading adds `unanalyzed-files`.

## How each file is read

The rules run three times: on the text as written; on the text with split strings joined (`'chi' + 'ld_' + 'process'` becomes `'child_process'`, `x['ex' + 'ec']` becomes `x.exec`, and `\x63hild` escapes are decoded); and on strings decoded from base64, hex (`Buffer.from('…', 'hex')`), char codes (`String.fromCharCode(102, 101, …)`) and URI escapes. A dangerous name or rule match that only appears after joining or decoding also counts as `obfuscated`. For JavaScript and TypeScript these passes run on the parsed program (below); for everything else, on the text.

### JavaScript and TypeScript are parsed

Since **apm-score-v5**, JavaScript and TypeScript files are parsed, not lexed by hand (`packages/core/src/parse.ts` and `js.ts`):

- **JavaScript and JSX**: [acorn](https://github.com/acornjs/acorn) 8.19 with [acorn-jsx](https://github.com/acornjs/acorn-jsx). Each file is parsed as a script first (CommonJS, with `return` allowed at the top, and the HTML-like `<!--` and `-->` comments old browser scripts have), then as a module, then, for a `.js` file, with JSX. `.jsx` files are parsed with JSX.
- **TypeScript and TSX**: [Babel's parser](https://babeljs.io/docs/babel-parser) 8.0 with its `typescript` and `estree` plugins, as a module, then as a script. Both parsers give the same ESTree nodes with source offsets, so one reader reads both.

Two things parse under both goals but mean different code. An HTML-like comment hides the rest of its line in a script but is code in a module (`x <!-- y` is `x < !(--y)`), and `await` is a name in a script (`await (f)(x)` calls `await`) but an operator in a module (it calls `f`). A script that holds either is parsed as a module too, and both programs are read: node runs `.mjs` and `"type": "module"` files as modules.

Comments, strings, regex literals, template text and JSX text are whatever the parser says they are, so every ECMAScript line terminator ends a comment (CR, U+2028 and U+2029 as well as LF, in hashbangs too), `1. / x / 1` is a division, `of` and `await` are names where they are names, and `// {require(x)}` inside a JSX element is text holding an expression. TypeScript types (annotations, interfaces, `import type`, `type X = import('net').Socket`, `declare` blocks) are erased before anything runs and are not read; `import('node:http')` in a `.js` file is code whatever follows it.

**Fail closed.** A file no goal accepts (invalid syntax, or Flow) is read raw, the way apm-score-v3 read every file: every match counts, comments and strings included, and nothing is taken for a definition or a type. So is a file whose tree would not fit in a Worker: more than 480,000 tokens of JavaScript (about 45 MB of tree; acorn takes 90 to 95 bytes a token in V8), or more than 1 MB of TypeScript. A file node runs because code `require`s or `import`s it, or because it is an entry point, is parsed as JavaScript whatever its extension (node runs `require('./x.c')` as JavaScript), so C-style comment rules cannot hide code in it. In the 70 tarballs below, 3 JavaScript files were read raw, all for size: `sass.dart.js` (5.7 MB), next's bundled webpack (2.5 MB) and a three.js Draco decoder (0.7 MB of asm.js).

C-family and Python files are still lexed for comments and strings (`lexer.ts`): nothing in a package runs them as JavaScript. Install commands and shell scripts are read raw. JSON files and type declarations (`.d.ts`) are data: what they name is possible at most, and they load nothing.

### What the code does, read from the tree

- **Calls are calls.** A function or method *definition* named `fetch` or `exec` is not a call, and nothing in a comment or string can make a call look like one. Optional calls (`require?.('x')`, `globalThis.fetch?.(u)`), escaped identifiers (`requ\u0069re`, `f\u0065tch`), `f.call(that, …)`, `f.apply(that, […])`, `Reflect.apply` and `Reflect.construct` are calls to `f`.
- **Names are followed.** A name declared once and never reassigned resolves to what it holds: `const cp = require('child_process'); cp.exec(…)`, `const { execSync } = require('node:child_process')`, `import { spawn } from 'child_process'`, `const Fn = globalThis.Function; Fn('…')()`, `const read = require('fs').readFileSync; read('.npmrc')`, `const fetch = globalThis.fetch`, `const r = createRequire(import.meta.url)`, `(custom || fetch)(req)`. A name declared more than once, or assigned after it is declared, is read by its name only. Constants work as module targets: `const cfWorkers = "cloudflare:workers"; import(cfWorkers)` loads `cloudflare:workers` and is not a dynamic load.
- **Evaluators.** `eval`, `(0, eval)`, `globalThis.eval`, `Function` and `new Function` (called directly, parenthesized, through an alias or a constructor chain such as `[].constructor.constructor` or `(async () => {}).constructor`), string `setTimeout`/`setInterval`/`setImmediate`, `vm.runInThisContext`/`runInNewContext`/`runInContext`/`compileFunction`/`Script` and `module._compile`. What they are given is read as code: a literal, a template, pieces joined with `+`, a constant, or a payload decoded with `atob` or `Buffer.from` is parsed and read like the file, so `(Function)(\`fetch(u)\`)()` confirms both `eval` and `network`. Up to three levels of code running code are followed. `Function('return this')` finds the global object and is not eval.
- **Module loaders.** `require`, `import()`, `import`/`export … from`, `import x = require()`, `module.require`, `require.main.require`, `process.getBuiltinModule`, `Module._load`, `createRequire(…)`, and a `require` passed in as a parameter (bundles and module wrappers pass it that way).

### What a string is for

A string's **role** comes from where the code uses it, and each role confirms only what fits it:

| Role | Where | Confirms |
| --- | --- | --- |
| Module specifier | `require('x')`, `import`, `from 'x'` | the module load: `child_process` is `shell-exec`, `http`/`net`/`ws`/`axios` and `import('https://…')` are `network`, `vm` is `eval` |
| Code | passed to eval, Function, vm or a string timer | whatever the code does, read as code |
| Command | passed to `exec`, `spawn`, `execFile`, `fork`, `execa`, `Bun.spawn`, `` Bun.$`…` ``, `` $`…` `` | shell text (`curl …`, `\| sh`, `wget`, `powershell`), download commands and credential paths in it |
| Path read | passed to `readFile`, `readFileSync`, `createReadStream`, `open`, `copyFile`, `Bun.file`, `Deno.readTextFile`, also through `path.join(os.homedir(), '.npmrc')` | a credential path in it |
| Request | a URL or body passed to `fetch`, `http.request`, `WebSocket`, `sendBeacon`, `dns.lookup` | nothing beyond the request itself: shell text in a URL is sent, not run |
| Plain | anywhere else | nothing; what it names is possible |

Decoded content takes the role of the place it is used: `eval(atob('…'))` runs what the base64 holds, so what it does is confirmed; a base64 request body is sent, so what it decodes to is possible. Shell text in a URL (`fetch('https://x/curl … | sh')`), `.npmrc` in a path that is only built (`path.join('.npmrc')`), `readFileSync('child_process')` (a file name, not a module) and a token name in a request body are all possible, not confirmed.

### Evidence cites the occurrence that matched

Every finding carries the source position of the node it came from, through every transformation: a joined string is cited where its first piece is, a decoded payload where the decoder is called, and code read from a string where the string is. A comment or an earlier string with the same text cannot take the citation. (Text read raw keeps an edit map through the joining pass for the same reason.) In each file a call is cited before a reference, a reference before a module load, and a load before a string, so `vm.runInNewContext(…)` is cited rather than the `import vm from 'node:vm'` above it. A citation from a test file the package ships (under `test/`, `tests/`, `__tests__/` or `spec/`, or named `*.test.*` or `*.spec.*`) says `(in a test file)`, and a signal lists the package's own files before its tests.

### Confirmed and possible

Every code signal carries `confidence`. **Confirmed**: apm saw the code do it or load the module that does. **Possible**: the text names it (a string, an alias kept but never called, a method on an object apm cannot identify such as `config.fetch(…)` or `this.fetch(…)`) but apm did not see it used. A possible signal is labelled as one ("Possible shell use: …"), costs about a third of the points, and lists only possible evidence, each line saying why it is not confirmed. One confirmed finding makes the whole signal confirmed, and then only confirmed evidence is shown.

## Signals

| Signal | Points (possible) | Fires on |
| --- | --- | --- |
| `install-download` | -40 | An install, git-install or binding.gyp command that runs `curl`/`wget`, pipes into a shell, runs `npx`/`bunx`/`dlx` for a package that is not a dependency, or `node -e` with network or process code (also once its base64 is decoded); a shell script an install hook runs that does the same |
| `incomplete` | -61 | Code that runs could not be read (too large, or past the budget). Keeps the score below the floor on its own |
| `credential-access` | -25 (-8) | `.npmrc`, `.ssh`, cloud credential paths, token variable names, `JSON.stringify(process.env)`, and `Object.keys(process.env)` or `for…in process.env` within 400 characters of a network call |
| `risky-dependency` | -30 | A dependency whose resolved version scores below the floor |
| `typosquat` | -20 | A name one edit from a popular name (two dropped or added letters for names of 8+ characters), the same name with different separators, a popular name plus `.js`/`js`/`-js`/`.mjs`, a near miss of a popular scoped name (`@type/node`), or a scoped name whose bare part swaps two letters of, or adds a suffix to, a popular name (`@evil/raect`) |
| `unanalyzed-files` | -20 | Files no code was seen loading were left out because the byte budget ran out |
| `install-script` | -15 | `preinstall`, `install`, `postinstall` or a `binding.gyp` |
| `shell-exec` | -15 (-5) | `child_process` (however it is loaded), `execSync`, `spawnSync`, `Bun.spawn`, `Bun.$`, `Deno.Command`, `\| sh`, `curl`, `wget`, `powershell` in a command, `process.binding` and `internalBinding` (except bindings that only read type helpers and constants, such as `util`), `process.dlopen` |
| `network` | -10 (-3) | `fetch(` (not of a `data:` URL), `http(s).get/request`, `net`/`tls`/`dgram`/`http2`/`dns` imports, `axios`/`undici`/`got`/`node-fetch`/`ws` and similar clients, `XMLHttpRequest`, `WebSocket`, `EventSource`, `RTCPeerConnection`, `sendBeacon`, `dns.resolve*`/`lookup`, `import … from 'https://…'` and `import('https://…')` |
| `eval` | -10 (-3) | `eval(`, `(0, eval)`, `eval.call`, `Reflect.apply(eval, …)`, `new Function`, `Function(…)` (but not `Function('return this')`), `x.constructor.constructor(`, string `setTimeout`/`setInterval`, `vm` imports and `runInThisContext`/`runInNewContext`/`compileFunction`, `module._compile`; possible: aliases of `require`, `globalThis.Function` kept but not called, `x.eval(` on an object apm cannot identify |
| `obfuscated` | -10 (-3) | 20+ `_0x…` identifiers, 40+ `\x` escapes in a row or a 2000+ character base64 literal that decode to text, or anything the joining and decoding passes had to undo to find a dangerous name |
| `git-install-script` | -10 | `prepare`, `prepack` or `postpack` (or a script they run) with shell, network, credential or eval content: npm runs these when someone installs the package from git |
| `new-publisher` | -10 | An account that never published this package before |
| `binary` | -5 | Executables and native modules |
| `new-dependency` | -5 | Dependencies the previous version did not have |
| `deprecated` | -5 | Deprecated by its maintainer |
| `no-license` | -3 | No license field |
| `dynamic-require` | 0 | `require(x)` or `import(x)` with an argument apm cannot work out (not a literal, a constant, or `path.join(__dirname, …)`), in code that runs, including code run from a string. Shown, not scored: plugin loaders do this honestly, and every code file is read anyway |
| `recent`, `yanked` | 0 | Published under 24 hours ago (the cooldown handles age); hidden by its maintainer |
| `revoked` | -100 | Pulled as malicious |

`prepublishOnly` and `prepublish` run only on the publisher's machine. Their commands are checked with the same rules, so a `curl … \| sh` there shows up as `shell-exec` and `network`, without a lifecycle signal. Scripts no hook reaches (`test`, `build`) never run on an installer's machine; only credential access or obfuscation in them is reported.

## What it cannot catch

Each of these is also in the `notChecked` list every score carries.

- **Runtime behaviour.** Code that downloads, decrypts or assembles a second stage while running looks like whatever its loader looks like. A loader still needs `fetch`, `eval`, `vm` or `child_process`, so it usually scores low, but the score cannot say what the second stage does.
- **Other encodings.** XOR, compression, a custom alphabet, or base64 that decodes to more base64. Only base64, hex, `\x` escapes, char codes and joined string literals are undone.
- **Names built any other way**: array lookups, computed indexes, values read from a file at runtime, or a value passed through a function apm does not follow. Constants are followed (literals, joins, templates, `[…].join('')`, `'…'.split('').reverse().join('')`, base64, hex, char codes and URI escapes), but only within one file and only for names declared once and never reassigned.
- **Files only a computed path loads.** Docs, type, JSON, style and markup files are read only when code reaches them by a path apm can resolve. Node runs any required file as JavaScript, so `require(name)` pointing at `docs/notes.md` would run code apm did not read; that call shows up as `dynamic-require` with no points.
- **Files read raw.** A file no parser accepts, or one too large to hold as a tree, is read raw: every match counts. That cannot hide code, but it can over-report (a comment that mentions `curl … | sh` counts). Flow-typed JavaScript is one such case.
- **Names resolved by spelling, not by scope.** A name declared once in the file is followed wherever it is used; a name declared in two scopes is read by its name only. A method on an object apm cannot identify (`config.fetch(…)`, `this.fetch(…)`) is possible, not confirmed.
- **What a possible signal hides.** A command or credential path held in an ordinary string and run later through a variable (`const c = 'curl …'; spawn(sh, ['-c', c])`) is possible, not confirmed: apm cannot follow the value. Loading `child_process` is still confirmed, so the shell use itself shows.
- **Native code and WebAssembly.** Listed as `binary` (native) or skipped (WebAssembly), never read.
- **A popular name under another scope.** `@someone/react` is not a typosquat: scopes exist so names can be reused, and `@sentry/react` and `@types/node` are real.
- **Dependencies' code.** Each dependency has its own score; `risky-dependency` and the resolve tree walk use them. Git, URL and file dependencies cannot be scored and are listed by name.
- **The publisher's machine or CI.** A compromised build that publishes clean-looking code with a subtle backdoor scores well.

## Checking the false positives

Changes to the rules are checked against real packages: 70 popular tarballs (zod, react, hono, next, lodash, express, typescript, vite, webpack, esbuild, sharp and others), scored with the previous and the new scorer, and every code-signal citation read by hand.

**apm-score-v5** (parsed, with roles). An independent review of v4 found valid JavaScript that hid real calls from its hand-written lexer: comments ended only at LF, `1. / x / 1` and `of / x / 1` read as regexes, HTML-like comments and JSX child text opened fake comments, definition and type-import checks counted characters, evaluated literals lost their context, joined strings were traced back by searching for their value, and any string inside a "kept" call confirmed anything it named. Three wrappers took a package from 30 (refused) to 100. Its 104 fixtures are now regression tests (`packages/core/test/sol-fixtures.test.ts`, data in `test/fixtures/sol-lexer.json`), each asserting the score, every signal's confidence and points, and which side of the floor it lands on:

| Fixtures | v3 | v4 | v5 |
| --- | --- | --- | --- |
| 83 that run real code, or controls next to them | the baseline | 59 scored above v3, by up to 70 points | 79 equal to v3, 4 below it (v3 missed `f\u0065tch(…)`, `globalThis.fetch?.(…)` and the network call inside `(Function)(\`…\`)()`), none above; all 4 floor-crossing wrappers (`floor-bypass-cr`, `-of`, `-html`, `joined-floor`) back at 30 |
| 21 where v3 confirmed what the code does not do | 65–90 | the same, mostly | higher by design: shell text in a URL, `path.join('.npmrc')` that nothing reads, `readFileSync('child_process')`, a token name in a request body, a base64 body nobody decodes, a TypeScript type import, `fetch('d\x61ta:,')`, `_0x` names in a comment, a built member name that is never called |

On the 70 tarballs, 68 scores did not change from v4 (mean 85.7 → 85.4). Two dropped, both for code v4's regexes missed: **lodash** 100 → 90 for `return Function(importsKeys, sourceURL + 'return ' + source)` in `template.js` (`_.template` compiles templates with the Function constructor; v4 needed a quote after `Function(`), and **yargs** 100 → 90 for `import cliui from 'https://unpkg.com/cliui@8.0.1/index.mjs'` in its browser shim (code loaded over the network). v5 confirms 71 code signals citing 201 lines (v4: 69 and 193). Every confirmed citation that changed (108 lines, most of them the call a file makes in place of the import above it, such as `cp.spawn(...)` for `require('child_process')` or `vm.runInThisContext(...)` for `require('vm')`) was read by hand, and **none is false**. The 7 possible signals are the same 7 as v4. `dynamic-require` lost four citations that were not loads (comments in mongoose and three, a method definition named `require` in yargs, hono's `import(cfWorkers)`, which now resolves to `cloudflare:workers`) and gained prisma's `requireFromHere(candidate)`, a `createRequire` result called with a computed name. zod still scores 90, now citing the `new F(...)` calls its JIT makes in `v4/core/compile.js` (`F` is `Function`) ahead of the `vm.runInNewContext` calls in its shipped tests, which say `(in a test file)`.

Three bugs the corpus run found were fixed before these numbers: `this.fetch(...)` on hono's own app class read as a request, a C# comment read raw because a `.cs` file named by `path.join(__dirname, …)` was taken for a module load, and `freeProcess.binding('util')` in lodash read as process spawning.

**Choosing the parser.** Four maintained parsers were run on every case from the review and on the corpus's 20,885 JavaScript and TypeScript files (280 MB):

| Parser | Review cases | TypeScript | Corpus files parsed, time | Tree for sass.dart.js (5.8 MB) | Workers |
| --- | --- | --- | --- | --- | --- |
| acorn 8.19 + acorn-jsx | all JavaScript and JSX cases | no (acorn-typescript failed 194 of 1,403 corpus files) | 19,482 of 20,885 (every JS file), 5.9 s | 77 MB | plain JavaScript |
| @babel/parser 8.0 | all, including TypeScript (HTML-like comments on by default in scripts) | yes | 20,885 of 20,885, 9.3 s | 228 MB | plain JavaScript, no runtime dependencies |
| meriyah 7.4 | all JavaScript and JSX cases | no | 19,482, 6.5 s | 119 MB | plain JavaScript |
| oxc-parser 0.158 (WASM) | all but CommonJS's top-level `return` in a script | yes | not run | not measured | needs a WASI runtime (`@napi-rs/wasm-runtime`, emnapi) and 1.7 MB of WebAssembly |

acorn reads JavaScript, the bulk of every package, with the smallest tree, the fastest parse and the Annex B rules the review's HTML-comment cases need. Babel reads TypeScript, which acorn cannot. A Worker has 128 MB and may already hold a 48 MB inflated tarball, so the tree's size decides how large a file can be parsed at all; Babel's tree is three times acorn's, which is why it reads only TypeScript, capped at 1 MB. Both produce ESTree, so one reader serves both. The registry Worker bundle grew from 3,930,513 to 4,804,356 bytes (859,054 to 1,050,357 gzipped), far under Cloudflare's 3 MB (Free) and 10 MB (Paid) compressed limits. Analysis takes 1.5 to 2 times v4's CPU: three (21 MB unpacked) takes 1.2 s.

**apm-score-v4** (code, not comments, regex literals or strings). Under v3 the 70 packages carried 97 code signals. 21 had no basis: regex literals read as shell pipes (`/…|sh|…/` in hono, date-fns and mongoose), `|| sh` read as a pipe (three, canvas), prose comments about `curl` or `fetch()` (undici, ws, svelte, sharp, electron, eslint), function definitions named `fetch` (core-js, glob's error message) and WebAssembly or font data counted as obfuscation (@prisma/client, next, sass, three, tsx, undici, vite, webpack). 7 more asserted what only a name supports: a list of builtin module names (eslint, prettier), `.npmrc` in a list of root markers (vite, vitest), `aliasedRequire = require` (moment), a base64 worker script (@sentry/node) and a configurable `config.fetch` (@anthropic-ai/sdk). So **21 of 97 were false (22%)**, and with the 7 overstated, 28 of 97 (29%) claimed more than their evidence showed. Under v4, those 21 are gone and the 7 are labelled possible; the 69 confirmed signals cite 193 lines, all read by hand, and **none is false**. Three are real but weak: `require('node:net').isIP` in express, node-fetch and undici loads a network module only to parse addresses, and zod's `vm` import sits in its shipped test files. 23 scores changed, all upward (mean 81.2 to 85.7); hono went from 75 to 90 and keeps `network` for `fetch(options.jwks_uri)` in its JWT helper. zod (90), react (100), lodash (100) and express (90) did not change.

**apm-score-v3**. zod, react, hono, next and lodash kept their scores. The ones that dropped do what the new eval rules describe: `better-sqlite3`, `core-js` and `regenerator-runtime` build functions from code strings, and `ts-node` and `tsx` load `vm` for their REPLs. `@types/node`, `execa` and `@angular/core` went up, because type declarations and docs are no longer read as code. The typosquat rules were run over 2,594 real package names from a large dependency tree; they flag 15, the same 15 the earlier one-edit and separator rules flagged.
