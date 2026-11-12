// Two things a reader of a score sees: a confirmed signal made only of text matches says what was found, not what
// the code does; and evidence an apm reviewer dismissed is left out of the number but stays listed.
import { describe, expect, test } from "bun:test";
import { analyze, applyDismissals, evidenceAt, finalize, type Analysis, type TarEntry } from "../src/index.ts";

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function scored(files: Record<string, string>): Analysis {
  const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main: "index.js" };

  return analyze({ name: "probe-pkg", manifest, files: [entry("package.json", JSON.stringify(manifest)), ...Object.entries(files).map(([p, t]) => entry(p, t))], publisher: "a", previousPublishers: [] });
}

const label = (a: Analysis, id: string): string | undefined => a.signals.find((s) => s.id === id)?.label;

describe("labels say what was found", () => {
  test("a credential file named in a list: mentions, not reads", () => {
    const a = scored({ "index.js": "module.exports = { deny: ['.env', '.npmrc'] };\n" });

    expect(label(a, "credential-access")).toBe("Mentions a credential file (.npmrc, .ssh) or secret variable; apm did not see one read");
    expect(a.signals.find((s) => s.id === "credential-access")?.points).toBe(-25);
  });

  test("a shell command in a string: mentions, not starts", () => {
    const a = scored({ "index.js": "module.exports = ['child_process', 'fs'];\n" });

    expect(label(a, "shell-exec")).toStartWith("Mentions a shell command");
    expect(a.signals.find((s) => s.id === "shell-exec")?.points).toBe(-15);
  });

  test("a call the tree confirmed keeps the label that says what the code does", () => {
    const a = scored({ "index.js": "require('child_process').execSync('ls');\nfetch('https://example.invalid');\n" });

    expect(label(a, "shell-exec")).toBe("Starts shell commands or child processes, or loads child_process");
    expect(label(a, "network")).toBe("Uses the network: fetch, http, sockets, or a module that makes requests");
  });
});

describe("dismissed evidence", () => {
  const deny = scored({ "index.js": "module.exports = { deny: ['.env', '.npmrc'] };\n" });
  const item = { scorer: deny.scorer, signal: "credential-access", file: "index.js", line: 1, reason: "a deny list", at: 1 };

  test("evidenceAt reads the file and line an item cites", () => {
    expect(evidenceAt("lib/a b.js:12: x")).toEqual({ file: "lib/a b.js", line: 12 });
    expect(evidenceAt("package.json scripts.postinstall: x")).toBeNull();
  });

  test("the score leaves out the dismissed item, and lists it", () => {
    expect(finalize(deny, STATE).score).toBe(75);
    const after = applyDismissals(deny, [item]);

    expect(finalize(after, STATE).score).toBe(100);
    expect(after.dismissed?.[0]).toMatchObject({ signal: "credential-access", file: "index.js", line: 1, reason: "a deny list" });
  });

  test("a dismissal made under another scorer does not apply", () => {
    expect(finalize(applyDismissals(deny, [{ ...item, scorer: "apm-score-v7" }]), STATE).score).toBe(75);
  });

  test("another line, file or signal does not apply", () => {
    for (const d of [{ ...item, line: 2 }, { ...item, file: "other.js" }, { ...item, signal: "network" }]) expect(finalize(applyDismissals(deny, [d]), STATE).score).toBe(75);
  });

  test("a fact like an install script cannot be dismissed", () => {
    const a = { ...deny, signals: [...deny.signals, { id: "install-script" as const, label: "x", points: -15, evidence: ["index.js:1: y"], confidence: "confirmed" as const }] };

    expect(finalize(applyDismissals(a, [{ ...item, signal: "install-script" }]), STATE).score).toBe(finalize(a, STATE).score);
  });

  test("a signal with other evidence stays, with the rest shown", () => {
    const two = scored({ "index.js": "module.exports = { deny: ['.env', '.npmrc'] };\n", "lib.js": "module.exports = '.ssh/id_rsa';\n" });
    const after = applyDismissals(two, [item]);
    const s = after.signals.find((x) => x.id === "credential-access");

    expect(s?.evidence.every((e) => e.startsWith("lib.js:"))).toBe(true);
    expect(finalize(after, STATE).score).toBe(75);
  });

  test("evidence past the five shown is kept, so dismissing the shown five does not clear the signal", () => {
    const files = Object.fromEntries(Array.from({ length: 7 }, (_, i) => [`f${i}.js`, "module.exports = '.npmrc';\n"]));
    const a = scored(files);
    const s = a.signals.find((x) => x.id === "credential-access");

    expect(s?.evidence.length).toBe(5);
    expect(s?.more?.length).toBe(2);

    const shown = (s?.evidence ?? []).flatMap((e) => {
      const at = evidenceAt(e);

      return at ? [{ ...item, file: at.file, line: at.line }] : [];
    });

    const after = applyDismissals(a, shown);

    expect(after.signals.find((x) => x.id === "credential-access")?.evidence.length).toBe(2);
    expect(finalize(after, STATE).score).toBe(75);
  });

  test("a confirmed signal whose confirmed items are all dismissed falls back to its possible evidence", () => {
    const a: Analysis = {
      ...deny,
      signals: [{ id: "network", label: "x", points: -10, confidence: "confirmed", evidence: ["index.js:1: fetch(u) (text match: counted unless it sits in a comment, a regex or a type)"], fallback: ["data.json:2: fetch [possible: in JSON]"] }],
    };

    const after = applyDismissals(a, [{ ...item, signal: "network" }]);

    expect(after.signals[0]).toMatchObject({ id: "network", confidence: "possible", points: -3, evidence: ["data.json:2: fetch [possible: in JSON]"] });
  });
});
