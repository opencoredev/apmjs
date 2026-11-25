// review of 96f0ba7, finding 6: `apm x` passed its own flags after the package (--ignore-scripts among them) on to the
// binary as well. splitXArgs keeps apm's flags for apm and the binary's arguments for the binary.
import { describe, expect, test } from "bun:test";
import { splitXArgs } from "../src/xargs.ts";

const VALUE = new Set(["pm", "cooldown", "floor", "otp", "tag"]);

const split = (...rest: string[]) => {
  const x = splitXArgs(rest, VALUE);

  return { spec: x.spec, flags: Object.fromEntries(x.flags), child: x.child };
};

describe("splitXArgs", () => {
  test("flags before the package are apm's, with values", () => {
    expect(split("--pm", "bun", "--ignore-scripts", "--floor=50", "tool", "a")).toEqual({ spec: "tool", flags: { pm: "bun", "ignore-scripts": true, floor: "50" }, child: ["a"] });
  });

  test("apm's flags after the package are consumed, never passed on", () => {
    expect(split("tool", "a", "--ignore-scripts", "--pm", "pnpm", "--strict", "--cooldown=1h", "--force", "--no-cooldown", "b")).toEqual({
      spec: "tool",
      flags: { "ignore-scripts": true, pm: "pnpm", strict: true, cooldown: "1h", force: true, "no-cooldown": true },
      child: ["a", "b"],
    });
  });

  test("everything after -- is the binary's, untouched and unread, a second -- included", () => {
    expect(split("--pm", "bun", "tool", "--", "--ignore-scripts", "--pm", "npm", "--", "x")).toEqual({ spec: "tool", flags: { pm: "bun" }, child: ["--ignore-scripts", "--pm", "npm", "--", "x"] });
  });

  test("other flags after the package are the binary's; --json is passed on and also moves apm's lines to stderr", () => {
    expect(split("tool", "--version", "--tag", "next", "--json")).toEqual({ spec: "tool", flags: { json: true }, child: ["--version", "--tag", "next", "--json"] });
  });

  test("help is apm's anywhere before --, and the binary's after it", () => {
    expect(split("tool", "a", "--help")).toEqual({ spec: "tool", flags: { help: true }, child: ["a"] });
    expect(split("-h", "tool")).toEqual({ spec: "tool", flags: { help: true }, child: [] });
    expect(split("tool", "--", "--help", "-h")).toEqual({ spec: "tool", flags: {}, child: ["--help", "-h"] });
  });

  test("a value flag never takes an option as its value", () => {
    expect(split("--pm", "--strict", "tool")).toEqual({ spec: "tool", flags: { pm: true, strict: true }, child: [] });
    expect(split("tool", "--floor", "--force")).toEqual({ spec: "tool", flags: { floor: true, force: true }, child: [] });
  });

  test("no package", () => {
    expect(split("--pm", "bun")).toEqual({ spec: null, flags: { pm: "bun" }, child: [] });
    expect(split("--", "tool")).toEqual({ spec: null, flags: {}, child: ["tool"] });
  });
});
