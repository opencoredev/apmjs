// The review of apm-score-v10: the CLI dropped what a package's declaration says and the environment variables it
// reads outside the declared patterns. These lines are what `apm score`, `apm add` and the publish preview print.
import { describe, expect, test } from "bun:test";
import { analyze, type TarEntry } from "@apm/core";
import { CapabilitySchema } from "../src/api.ts";
import { capabilityLines } from "../src/capabilities.ts";

const plain = { bold: (s: string) => s, dim: (s: string) => s, green: (s: string) => s, yellow: (s: string) => s };

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

describe("capability lines", () => {
  test("a declared env capability shows its declaration and every variable read outside it", () => {
    const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main: "index.js", apm: { capabilities: { env: ["AWS_*"] } } };
    const code = "module.exports = { region: process.env.AWS_REGION, key: process.env.RESEND_API_KEY, from: process.env.MAIL_FROM };\n";
    const a = analyze({ name: "probe-pkg", manifest, files: [entry("package.json", JSON.stringify(manifest)), entry("index.js", code)], publisher: "a", previousPublishers: [] });
    // what the registry sends, parsed the way the CLI parses it
    const caps = a.capabilities.map((c) => CapabilitySchema.parse(JSON.parse(JSON.stringify(c))));
    const lines = capabilityLines(caps, plain);

    expect(lines).toContain("        declared: AWS_*");
    expect(lines).toContain("        reads outside the declaration: RESEND_API_KEY, MAIL_FROM");
  });

  test("a long outside list is cut and counted", () => {
    const outside = Array.from({ length: 11 }, (_, i) => `VAR_${i}`);
    const lines = capabilityLines([{ id: "env", label: "Environment variables: reads process.env", status: "declared", basis: "code", declared: "APP_*", evidence: ["index.js:1: process.env.VAR_0"], outside }], plain);

    expect(lines).toContain("        reads outside the declaration: VAR_0, VAR_1, VAR_2, VAR_3, VAR_4, VAR_5, VAR_6, VAR_7 and 3 more");
  });

  test("no capabilities, no lines", () => {
    expect(capabilityLines([], plain)).toEqual([]);
  });
});
