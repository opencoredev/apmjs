# 07 — Registry Wire Protocol

**Status: PASS** — every endpoint below is sourced from npm's own client code, npm's registry docs, Verdaccio's server code, or Bun's source. Live responses from `registry.npmjs.org` were captured 2026-11-11/12 to confirm shapes.

---

## 1. Pain points (short)

1. **The "spec" is the client source, not a spec.** npm's registry docs cover packuments and search but never document publish, dist-tags, deprecate, unpublish, or audit. Anyone building a registry reverse-engineers `libnpmpublish`. Hurts every alternative registry. **High.** Evidence: `npm/registry` docs tree contains only `REGISTRY-API.md`, `responses/package-metadata.md`, `user/authentication.md` — no publish endpoint doc (https://github.com/npm/registry/tree/main/docs, read 2026-11-11).
2. **Publish bodies contain client-generated lies.** `libnpmpublish` rewrites `dist.tarball` to `http://` on purpose and computes its own `shasum`/`integrity`; a registry that trusts them stores wrong URLs. **High.** Evidence: `manifest.dist.tarball = new URL(tarballURI, registry).href.replace(/^https:\/\//, 'http://')` (https://github.com/npm/libnpmpublish/blob/main/publish.js, read 2026-11-11).
3. **Abbreviated packuments are optional in practice but mandatory for speed.** npm silently falls back to full metadata on a 404, so a registry can ship without corgis and never notice it is 10× slower. **Med.** Evidence: `if (err.code !== 'E404' || this.fullMetadata) throw err; this.fullMetadata = true; return this.packument()` (https://github.com/npm/pacote/blob/main/lib/registry.js).
4. **Two incompatible login flows.** Legacy CouchDB `PUT /-/user/org.couchdb.user:name` and web `POST /-/v1/login` + polling `doneUrl`. Bun defaults to `web` and falls back; npm defaults to `web` and falls back. A registry must implement both or half its clients break. **High.** Evidence: `--auth-type ... web (the default) or legacy` (https://bun.com/docs/pm/cli/publish, read 2026-11-11).
5. **No documented error contract.** Clients key off HTTP status plus `www-authenticate` substrings (`otp`, `ipaddress`) and `E409` retry semantics; none of it is written down. **Med.** Evidence: `if (auth.indexOf('otp') !== -1) throw new errors.HttpErrorAuthOTP(...)` (https://github.com/npm/npm-registry-fetch/blob/main/lib/check-response.js).

---

## 2. The wire protocol

### 2.1 `GET /:name` — packument

Two representations, selected by `Accept`. No `Accept` → full document.

| Client | Accept header |
|---|---|
| npm install (`pacote`) | `application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*` |
| npm view / `fullMetadata` | `application/json` |
| Bun install | `application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*` |
| Bun install, extended manifest needed | `application/json, */*` |

Sources: https://github.com/npm/pacote/blob/main/lib/registry.js (`corgiDoc`), https://github.com/oven-sh/bun/blob/main/src/install/NetworkTask.rs (`ACCEPT_HEADER_VALUE`).

The response must set `content-type: application/vnd.npm.install-v1+json` when the abbreviated form is served (verified live on `registry.npmjs.org`, 2026-11-12).

**Abbreviated ("corgi") packument** — exactly four top-level keys, verified live against `@babel/core`:

```json
{
  "name": "@babel/core",
  "dist-tags": { "latest": "8.1.2", "next": "8.0.0-rc.1" },
  "modified": "2026-11-11T19:56:07.158Z",
  "versions": {
    "8.1.2": {
      "name": "@babel/core",
      "version": "8.1.2",
      "dependencies": { "@babel/parser": "^8.1.2" },
      "peerDependencies": { "@babel/core": "^7.0.0-0" },
      "peerDependenciesMeta": { "@babel/core": { "optional": true } },
      "bin": { "babel": "./bin/babel.js" },
      "engines": { "node": ">=20.19.0" },
      "os": ["darwin", "linux", "win32"],
      "cpu": ["x64", "arm64"],
      "deprecated": "use @babel/core@8",
      "hasInstallScript": false,
      "_hasShrinkwrap": false,
      "dist": {
        "shasum": "0d5a5c209f5d81ea17ccb71f5ee99aa6a75461b5",
        "tarball": "https://registry.npmjs.org/@babel/core/-/core-8.1.2.tgz",
        "integrity": "sha512-xqDajHAAOjklW5UtWzFd9vSmlQ16+emgGi0HsyDQFGRQWZ/GjuwCoYGC3PnHxspmOR+HJBzDIOkMxNq/VvC98w==",
        "fileCount": 18,
        "unpackedSize": 512345,
        "signatures": [{ "keyid": "SHA256:DhQ8...", "sig": "MEYCIQ..." }]
      }
    }
  }
}
```

Field allow-list for the abbreviated version object is documented at https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md#abbreviated-version-object. `name`, `version`, `dist` are always present; everything else is omitted when irrelevant.

**Full packument** — verified live against `tiny-tarball`:

```json
{
  "_id": "tiny-tarball",
  "_rev": "3-085759e977d42299e64a35aedc17d250",
  "name": "tiny-tarball",
  "description": "tiny tarball used for health checks",
  "dist-tags": { "latest": "1.0.0" },
  "versions": { "1.0.0": { "_id": "tiny-tarball@1.0.0", "_nodeVersion": "1.5.0",
      "_npmVersion": "2.7.0", "_npmUser": { "name": "bcoe", "email": "bencoe@gmail.com" },
      "dist": { "shasum": "bbf102d5...", "tarball": "https://registry.npmjs.org/tiny-tarball/-/tiny-tarball-1.0.0.tgz" } } },
  "time": { "created": "2015-03-24T00:12:24.039Z", "modified": "2022-06-27T07:01:30.945Z",
            "1.0.0": "2015-03-24T00:12:24.039Z" },
  "readme": "# TinyTarball\n...",
  "readmeFilename": "README.md",
  "maintainers": [{ "name": "bcoe", "email": "ben@npmjs.com" }],
  "author": { "name": "Ben Coe", "email": "ben@npmjs.com" },
  "license": "ISC"
}
```

`time` must contain `created`, `modified`, and one ISO-8601 entry per version. `dist-tags` must contain `latest`. `_rev` is required by unpublish (see 2.5).

**Scoped names are URL-encoded with a lowercase `%2f`.** npm: `this.escapedName = name.replace('/', '%2f')` (https://github.com/npm/npm-package-arg/blob/main/lib/npa.js). So `GET /@babel%2fcore`. Verdaccio's own log lines show the same form: `PUT 201 http://localhost:4873/@scope%2ftest1` (https://github.com/verdaccio/verdaccio/blob/master/packages/api/src/publish.ts). Accept `%2F` too; do not accept a literal `/` for the scoped form or you will collide with the tarball route.

**Caching.** Serve `ETag` and `Last-Modified`; clients send `If-None-Match` / `If-Modified-Since` and expect `304` (Bun: `header_builder.count("If-None-Match", etag)` in `NetworkTask.rs`). npm's cache layer does the same via make-fetch-happen. `cache-control: public, max-age=300` is what npmjs.org sends.

**Fallback contract.** If you 404 a corgi request, pacote retries with `application/json`. That is a safety net, not a licence to skip corgis.

### 2.2 Tarball URLs

Convention: `{registry}/{escapedName}/-/{basename}-{version}.tgz`, where `basename` is the name **without** the scope. Verified live: `https://registry.npmjs.org/@babel/core/-/core-8.1.2.tgz`.

Clients use `dist.tarball` verbatim as an absolute URL — it may point at a CDN on another host. npm only sends credentials to that host if it is the same host as the registry, or if `always-auth`/`_authToken` is configured for it (https://github.com/npm/npm-registry-fetch/blob/main/lib/auth.js). Serve `content-type: application/octet-stream`, support `Range`, and make the URL immutable per version.

### 2.3 `PUT /:name` — publish

npm's body, from `buildMetadata` in https://github.com/npm/libnpmpublish/blob/main/publish.js:

```json
{
  "_id": "my-pkg",
  "name": "my-pkg",
  "description": "does a thing",
  "dist-tags": { "latest": "1.2.3" },
  "versions": {
    "1.2.3": {
      "_id": "my-pkg@1.2.3",
      "_nodeVersion": "22.11.0",
      "_npmVersion": "11.0.0",
      "name": "my-pkg",
      "version": "1.2.3",
      "description": "does a thing",
      "main": "index.js",
      "dependencies": {},
      "dist": {
        "integrity": "sha512-9W8k...==",
        "shasum": "bbf102d5ae73afe2c553295e0fb02230216f65b1",
        "tarball": "http://registry.example.com/my-pkg/-/my-pkg-1.2.3.tgz"
      }
    }
  },
  "access": "public",
  "_attachments": {
    "my-pkg-1.2.3.tgz": {
      "content_type": "application/octet-stream",
      "data": "H4sIAAAAAAAA/+3BAQ0AAADCoPdPbQ43oAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...",
      "length": 48213
    }
  }
}
```

Notes that matter:

- `access` is `"public"` or `"restricted"`; npm defaults scoped packages to `restricted` and errors if you ask for `restricted` on an unscoped name.
- The attachment key is `{name}-{version}.tgz` **including the scope** for scoped packages. Verdaccio: *"Scoped clients include the scope in the key; storage uses only the basename"* (`packages/store/src/storage.ts`).
- `data` is standard base64 of the gzipped tarball; `length` is the byte length of the tarball, not of the base64.
- `dist.tarball` in the body is deliberately `http://` and may be wrong. **Ignore it and generate your own.** Same for `shasum`/`integrity`: recompute from the decoded attachment and reject a mismatch.
- npm sends `content-type: application/json` and `content-length`.

Bun's body is hand-built and slightly different (https://github.com/oven-sh/bun/blob/main/src/runtime/cli/publish_command.rs, `construct_publish_request_body`):

```json
{"_id":"my-pkg","name":"my-pkg","dist-tags":{"latest":"1.2.3"},"versions":{"1.2.3":{...normalized package.json...}},"access":null,"_attachments":{"my-pkg-1.2.3.tgz":{"content_type":"application/octet-stream","data":"...","length":48213}}}
```

Bun sends `"access":null` when unset, no top-level `description`, and no `_nodeVersion`/`_npmVersion`. A registry must tolerate `access: null` and a missing `description`.

**Headers npm and Bun send on publish:**

```
authorization: Bearer <token>          (or Basic <base64> from _auth)
content-type: application/json
npm-auth-type: web | legacy
npm-command: publish
npm-otp: 123456                        (only when an OTP is supplied)
npm-session: <hex>                     (npm only)
user-agent: npm/11.0.0 node/v22.11.0 ...
accept: */*                            (Bun) / application/json
```

Source: `getHeaders` in https://github.com/npm/npm-registry-fetch/blob/main/lib/index.js and `construct_publish_headers` in Bun's `publish_command.rs`.

**Response codes clients actually branch on:**

| Status | Meaning | Client behaviour |
|---|---|---|
| `200` / `201` | published | success. npm accepts any 2xx; Verdaccio returns `201 {"success":true,"ok":"package published"}` |
| `401` + `www-authenticate: otp` | OTP required | npm throws `EOTP`, prompts, retries with `npm-otp`; Bun prompts and re-PUTs the same body |
| `401` + `www-authenticate: ipaddress` | IP blocked | `EAUTHIP`, fatal |
| `401` body with `authUrl` + `doneUrl` | web 2FA | npm opens the browser, then retries with the returned OTP |
| `403` | not allowed / bad token | `E403`, fatal |
| `409` | version exists | npm throws `E409`, then `GET /:name?write=true`, merges its version into the returned packument, and re-PUTs **exactly once** |
| `402` | payment required | `E402`, fatal |

The 409 retry is the single most important behaviour to get right: `libnpmpublish` catches `E409`, fetches the current packument with `?write=true`, calls `patchMetadata`, and re-PUTs. If your 409 body is not JSON, or your `?write=true` GET is cached, publish breaks. Bun instead pre-checks with a plain `GET /:name` when `--tolerate-republish` is set and skips the PUT if the version is already listed.

### 2.4 Auth

**Legacy CouchDB login** (`npm login --auth-type=legacy`, `npm adduser`):

```
PUT /-/user/org.couchdb.user:alice
content-type: application/json

{ "_id": "org.couchdb.user:alice", "name": "alice", "password": "hunter2",
  "type": "user", "roles": [], "date": "2026-11-11T20:00:00.000Z" }
```

`201` with:

```json
{ "token": "npm_EXAMPLEtoken", "ok": true,
  "id": "org.couchdb.user:alice", "rev": "_we_dont_use_revs_any_more" }
```

`401` with `{"ok": false}` on bad credentials. If the user already exists the registry answers `409`; npm then `GET`s the user doc with `?write=true`, merges `_rev`, and re-PUTs to `/-/user/org.couchdb.user:alice/-rev/{rev}` with Basic auth. Source: https://github.com/npm/npm-profile/blob/main/lib/index.js (`loginCouch`, `putCouch`) and https://github.com/npm/registry/blob/main/docs/user/authentication.md.

**Web login** (default for both npm and Bun):

```
POST /-/v1/login          {}                       -> 200 {"loginUrl":"https://...","doneUrl":"https://.../-/v1/login/<id>"}
GET  <doneUrl>                                     -> 202, retry-after: 5
GET  <doneUrl>                                     -> 200 {"token":"<uuid>"}
```

npm polls `doneUrl` honouring `retry-after` (seconds) until `200`, then stores `token`. Any 4xx/5xx on the initial POST makes npm fall back to the Couch flow. Source: `webAuth` / `webAuthCheckSession` in npm-profile. Bun's `--auth-type` defaults to `web` and falls back to `legacy` (https://bun.com/docs/pm/cli/publish).

**`npm whoami`** → `GET /-/whoami` with the token:

```json
{ "username": "alice" }
```

Unauthenticated: `401 {"error":"Unauthorized"}` (verified live). npm only calls this when it has a token and no username in config (https://github.com/npm/cli/blob/latest/lib/utils/get-identity.js).

**`npm ping`** → `GET /-/ping` → `{}`.

**`npm logout`** → `DELETE /-/user/token/{token}`.

**Token config.** npm: `//registry.example.com/:_authToken=${NPM_TOKEN}` in `.npmrc`, scoped by URI fragment; `_auth` (base64 `user:pass`) is sent as `Basic`. Source: https://github.com/npm/cli/blob/latest/docs/lib/content/configuring-npm/npmrc.md#auth-related-configuration. Bun reads the same `.npmrc` keys plus `bunfig.toml`:

```toml
[install]
registry = { url = "https://registry.example.com", token = "123456" }

[install.scopes]
"@myorg" = { token = "$npm_token", url = "https://registry.myorg.com/" }
```

Source: https://bun.com/docs/pm/scopes-registries. Bun's load order is `~/.npmrc` → `./.npmrc` → global then project `bunfig.toml` → `BUN_CONFIG_*`/`NPM_CONFIG_*` env → CLI flags (https://bun.com/docs/pm/npmrc).

### 2.5 dist-tags, deprecate, unpublish

**List:** `GET /-/package/{escapedName}/dist-tags` → `{"latest":"1.2.3","next":"2.0.0-beta.1"}`. npm deletes an `_etag` key if present.

**Add:** `PUT /-/package/{escapedName}/dist-tags/{tag}` with body `"1.2.3"` — a bare JSON string, `content-type: application/json`. Verdaccio answers `201 {"ok":"tag added"}`.

**Remove:** `DELETE /-/package/{escapedName}/dist-tags/{tag}`.

Source: https://github.com/npm/cli/blob/latest/lib/commands/dist-tag.js and https://github.com/verdaccio/verdaccio/blob/master/packages/api/src/dist-tags.ts.

**Deprecate** is not its own endpoint. npm fetches the full packument with `?write=true`, sets `versions[v].deprecated = "<message>"` on every matching version, and PUTs the whole packument back to `/:escapedName`. Undeprecate is the same with `""`. Source: https://github.com/npm/cli/blob/latest/lib/commands/deprecate.js. So your publish handler must accept a packument PUT that has **no `_attachments`** and treat it as a metadata-only update.

**Unpublish** (https://github.com/npm/libnpmpublish/blob/main/unpublish.js):

- whole package: `DELETE /{escapedName}/-rev/{_rev}`
- one version: `PUT /{escapedName}/-rev/{_rev}` with the packument minus that version, then `DELETE /{tarballPath}/-rev/{_rev}` for the tarball.

`_rev` must therefore be a real, changing opaque string on every packument write, and `?write=true` must bypass caches.

### 2.6 Search

`GET /-/v1/search?text=<q>&size=<1..250>&from=<offset>&quality=&popularity=&maintenance=`

Live response (2026-11-12, `text=tiny-tarball&size=1`):

```json
{
  "objects": [
    {
      "package": {
        "name": "tiny-tarball",
        "version": "1.0.0",
        "description": "tiny tarball used for health checks",
        "keywords": [],
        "date": "2015-03-24T00:12:24.039Z",
        "links": { "npm": "https://www.npmjs.com/package/tiny-tarball" },
        "publisher": { "username": "bcoe", "email": "bencoe@gmail.com" },
        "maintainers": [{ "username": "bcoe", "email": "ben@npmjs.com" }],
        "license": "ISC"
      },
      "score": { "final": 1169.651, "detail": { "popularity": 1, "quality": 1, "maintenance": 1 } },
      "searchScore": 1169.651,
      "downloads": { "monthly": 1366, "weekly": 267 },
      "updated": "2026-11-09T20:26:18.596Z"
    }
  ],
  "total": 34028,
  "time": "2026-11-12T01:42:29.121Z"
}
```

`size` defaults to 20, max 250; `from` is the offset. Verdaccio clamps `size` to 250 and `from` to 10 000 and 400s with `{"error":"'text' query parameter is required","code":"ERR_TEXT_MISSING"}` when `text` is missing (https://github.com/verdaccio/verdaccio/blob/master/packages/api/src/v1/search.ts). Qualifiers (`author:`, `scope:`, `keywords:`, `is:unstable`, `not:insecure`, `boost-exact:`) are documented at https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md.

### 2.7 Audit

`POST /-/npm/v1/security/advisories/bulk`, `content-type: application/json`, `content-encoding: gzip`, body gzipped.

Request (from `prepareBulkData`, https://github.com/npm/cli/blob/latest/workspaces/arborist/lib/audit-report.js):

```json
{ "lodash": ["4.17.20"], "minimist": ["1.2.0", "1.2.5"] }
```

Response — verified live against `registry.npmjs.org`:

```json
{
  "lodash": [
    {
      "id": 1106913,
      "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
      "title": "Command Injection in lodash",
      "severity": "high",
      "vulnerable_versions": "<4.17.21",
      "cwe": ["CWE-77", "CWE-94"],
      "cvss": { "score": 7.2, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" }
    }
  ]
}
```

`severity` ∈ `info|low|moderate|high|critical`. Packages with no advisories are omitted (or mapped to `[]`). npm sends `gzip: true` and uses `auditRegistry || registry`. Bun gzips with libdeflate level 6, sends `accept: application/json`, and treats a non-object body, an empty body, or a `>=400` as "registry has no advisory endpoint" — it lists those packages as skipped rather than failing (https://github.com/oven-sh/bun/blob/main/src/runtime/cli/audit_command.rs). Bun parses only `severity`, `title`, `url`, `vulnerable_versions`, `id` (string or number).

### 2.8 Pointing clients at your registry

**npm** — `.npmrc`:

```ini
registry=https://registry.example.com/
@myorg:registry=https://registry.example.com/
//registry.example.com/:_authToken=${NPM_TOKEN}
//registry.example.com/:_auth=YWxpY2U6aHVudGVyMg==
//registry.example.com/:username=alice
//registry.example.com/:_password=aHVudGVyMg==
always-auth=true
```

`_password` is base64. Credentials must be URI-scoped or npm refuses to send them. `publishConfig.registry` in `package.json` overrides the default registry for publish only; a scope registry still wins.

**Bun** — `bunfig.toml`:

```toml
[install]
registry = "https://registry.example.com/"

[install.scopes]
"@myorg" = { url = "https://registry.example.com/", token = "$NPM_TOKEN" }
```

or the same `.npmrc` keys. Env: `BUN_CONFIG_REGISTRY` / `NPM_CONFIG_REGISTRY`, `BUN_CONFIG_TOKEN` / `NPM_CONFIG_TOKEN`. `bun publish` also honours `NPM_CONFIG_TOKEN` and `publishConfig.registry` (https://bun.com/docs/pm/cli/publish).

---

## 3. What a better registry/CLI should do

1. Serve corgi packuments by default and assert `content-type: application/vnd.npm.install-v1+json`; never rely on pacote's 404 fallback.
2. Recompute `shasum`/`integrity` from the decoded `_attachments` and reject mismatches; ignore the client's `dist.tarball` entirely and mint your own.
3. Accept a packument PUT with no `_attachments` as a metadata-only update, so `npm deprecate` works without a special endpoint.
4. Implement `?write=true` as a hard cache bypass and return a fresh `_rev` on every write; unpublish depends on it.
5. Return a JSON body on `409` and make the follow-up `GET ?write=true` uncached, so npm's single retry succeeds.
6. Implement both `/-/v1/login` (with `retry-after` polling) and the Couch `PUT /-/user/org.couchdb.user:name`, and advertise `www-authenticate: otp` on 401 so OTP prompts work.
7. Accept `access: null` and a missing top-level `description` — Bun sends both.
8. Serve `/-/npm/v1/security/advisories/bulk` (gzip in, JSON out) or return a clean 404 so `bun audit` degrades to "skipped" instead of failing.
9. Emit `ETag`/`Last-Modified` and honour `If-None-Match`/`If-Modified-Since` with `304`.
10. Ship a conformance test suite that replays real npm and Bun request bytes — the protocol has no spec, so the tests become the spec.

---

## 4. Gaps

- **Publish success body is unspecified.** npm accepts any 2xx and ignores the body; Verdaccio returns `{"success":true,"ok":"..."}`. I could not find a documented shape, and I did not publish to npmjs.org to observe one.
- **`npm stage publish` / `--provenance`** paths (`stageId`, attestation upload) are new and undocumented; I did not trace them.
- **`npm access`, `npm owner`, `npm team`, `npm org`, `npm hook`, `npm token`, `npm profile`** endpoints were out of scope and are not covered here.
- **Exact `_rev` format** is registry-defined; npm treats it as opaque, but I could not confirm whether any client parses it.
- **`npm audit` response for a package with zero advisories** — I did not observe whether npmjs.org omits the key or returns `[]`; Bun tolerates both.
- **Bun's `bun_fmt::dependency_url`** encoding for scoped names was inferred from npm's `%2f` convention and Verdaccio's log lines, not read directly.
