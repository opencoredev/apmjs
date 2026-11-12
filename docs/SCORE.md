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

The rules run three times: on the text as written; on the text with split strings joined (`'chi' + 'ld_' + 'process'` becomes `'child_process'`, `x['ex' + 'ec']` becomes `x.exec`, and `\x63hild` escapes are decoded); and on strings decoded from base64, hex (`Buffer.from('…', 'hex')`) and char codes (`String.fromCharCode(102, 101, …)`, or a numeric array in a file that calls it). A dangerous name or rule match that only appears after joining or decoding also counts as `obfuscated`.

Rules added in this version that docs often show as examples (`process.binding`, `new EventSource`, `sendBeacon`, `dns.promises`, HTTP client imports, the indirect eval forms) skip lines that start like a comment (`*` or `//`), so a JSDoc example does not count as code.

## Signals

| Signal | Points | Fires on |
| --- | --- | --- |
| `install-download` | -40 | An install, git-install or binding.gyp command that runs `curl`/`wget`, pipes into a shell, runs `npx`/`bunx`/`dlx` for a package that is not a dependency, or `node -e` with network or process code (also once its base64 is decoded); a shell script an install hook runs that does the same |
| `incomplete` | -61 | Code that runs could not be read (too large, or past the budget). Keeps the score below the floor on its own |
| `credential-access` | -25 | `.npmrc`, `.ssh`, cloud credential paths, token variable names, `JSON.stringify(process.env)`, and `Object.keys(process.env)` or `for…in process.env` within 400 characters of a network call |
| `risky-dependency` | -30 | A dependency whose resolved version scores below the floor |
| `typosquat` | -20 | A name one edit from a popular name (two dropped or added letters for names of 8+ characters), the same name with different separators, a popular name plus `.js`/`js`/`-js`/`.mjs`, a near miss of a popular scoped name (`@type/node`), or a scoped name whose bare part swaps two letters of, or adds a suffix to, a popular name (`@evil/raect`) |
| `unanalyzed-files` | -20 | Files no code was seen loading were left out because the byte budget ran out |
| `install-script` | -15 | `preinstall`, `install`, `postinstall` or a `binding.gyp` |
| `shell-exec` | -15 | `child_process`, `execSync`, `spawnSync`, `Bun.spawn`, `Bun.$`, `Deno.Command`, `\| sh`, `curl`, `wget`, `powershell`, `process.binding`, `internalBinding`, `process.dlopen` |
| `network` | -10 | `fetch(`, `http(s).get/request`, `net`/`tls`/`dgram`/`http2`/`dns` imports, `axios`/`undici`/`got`/`node-fetch`/`ws` and similar clients, `XMLHttpRequest`, `WebSocket`, `EventSource`, `RTCPeerConnection`, `sendBeacon`, `dns.resolve*`/`lookup`, `import('https://…')` |
| `eval` | -10 | `eval(`, `(0, eval)`, `x.eval(`, `new Function`, `Function('code')` (but not `Function('return this')`), `x.constructor.constructor(`, string `setTimeout`/`setInterval`, `vm` imports and `runInThisContext`/`runInNewContext`/`compileFunction`, `module._compile`, aliases of `require` |
| `obfuscated` | -10 | 20+ `_0x…` identifiers, 40+ `\x` escapes in a row, a 2000+ character base64 literal, or anything the joining and decoding passes had to undo to find a dangerous name |
| `git-install-script` | -10 | `prepare`, `prepack` or `postpack` (or a script they run) with shell, network, credential or eval content: npm runs these when someone installs the package from git |
| `new-publisher` | -10 | An account that never published this package before |
| `binary` | -5 | Executables and native modules |
| `new-dependency` | -5 | Dependencies the previous version did not have |
| `deprecated` | -5 | Deprecated by its maintainer |
| `no-license` | -3 | No license field |
| `dynamic-require` | 0 | `require(x)` or `import(x)` with an argument apm cannot read, in code that runs. Shown, not scored: plugin loaders do this honestly, and every code file is read anyway |
| `recent`, `yanked` | 0 | Published under 24 hours ago (the cooldown handles age); hidden by its maintainer |
| `revoked` | -100 | Pulled as malicious |

`prepublishOnly` and `prepublish` run only on the publisher's machine. Their commands are checked with the same rules, so a `curl … \| sh` there shows up as `shell-exec` and `network`, without a lifecycle signal. Scripts no hook reaches (`test`, `build`) never run on an installer's machine; only credential access or obfuscation in them is reported.

## What it cannot catch

Each of these is also in the `notChecked` list every score carries.

- **Runtime behaviour.** Code that downloads, decrypts or assembles a second stage while running looks like whatever its loader looks like. A loader still needs `fetch`, `eval`, `vm` or `child_process`, so it usually scores low, but the score cannot say what the second stage does.
- **Other encodings.** XOR, compression, a custom alphabet, or base64 that decodes to more base64. Only base64, hex, `\x` escapes, char codes and joined string literals are undone.
- **Names built any other way**: array lookups, reversed strings, `[...].join('')`, computed indexes, values read from a file at runtime.
- **Files only a computed path loads.** Docs, type, JSON, style and markup files are read only when code reaches them by a path apm can resolve. Node runs any required file as JavaScript, so `require(name)` pointing at `docs/notes.md` would run code apm did not read; that call shows up as `dynamic-require` with no points.
- **Comment-shaped lines** for the rules listed above as skipping them: a line of code that starts with `*` (a multiplication continued onto a new line) hides those rules' matches on it.
- **Native code and WebAssembly.** Listed as `binary` (native) or skipped (WebAssembly), never read.
- **A popular name under another scope.** `@someone/react` is not a typosquat: scopes exist so names can be reused, and `@sentry/react` and `@types/node` are real.
- **Dependencies' code.** Each dependency has its own score; `risky-dependency` and the resolve tree walk use them. Git, URL and file dependencies cannot be scored and are listed by name.
- **The publisher's machine or CI.** A compromised build that publishes clean-looking code with a subtle backdoor scores well.

## Checking the false positives

Changes to the rules are checked against real packages. For this version, 70 popular tarballs (zod, react, hono, next, lodash, express, typescript, vite, webpack, esbuild, sharp and others) were scored with the previous and the new scorer. zod, react, hono, next and lodash kept their scores. The ones that dropped do what the new eval rules describe: `better-sqlite3`, `core-js` and `regenerator-runtime` build functions from code strings, and `ts-node` and `tsx` load `vm` for their REPLs. `@types/node`, `execa` and `@angular/core` went up, because type declarations and docs are no longer read as code. The typosquat rules were run over 2,594 real package names from a large dependency tree; they flag 15, the same 15 the earlier one-edit and separator rules flagged.
