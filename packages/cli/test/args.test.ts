// review of e83dc4b, finding 3: only `apm x` went through splitXArgs, but `apm exec` and `apm dlx` ran the same command,
// which reads the binary's arguments from `child`, so both lost every argument. The aliases are normalized first.
import { describe, expect, test } from "bun:test";
import { parseArgs } from "../src/args.ts";

const parsed = (...argv: string[]) => {
  const a = parseArgs(argv);

  return { cmd: a.cmd, positional: a.positional, flags: Object.fromEntries(a.flags), child: a.child };
};

describe.each(["x", "exec", "dlx"])("apm %s", (name) => {
  test("is apm x, and the binary gets its arguments", () => {
    expect(parsed(name, "--pm", "bun", "tool", "a", "--strict", "b", "--", "--pm", "c")).toEqual({
      cmd: "x",
      positional: ["tool"],
      flags: { pm: "bun", strict: true },
      child: ["a", "b", "--pm", "c"],
    });
  });

  test("a binary given only flags gets them, but help before -- is apm's", () => {
    expect(parsed(name, "tool", "--version", "-h")).toEqual({ cmd: "x", positional: ["tool"], flags: { help: true }, child: ["--version"] });
    expect(parsed(name, "tool", "--", "--help")).toEqual({ cmd: "x", positional: ["tool"], flags: {}, child: ["--help"] });
  });

  test("--json before the package is apm's alone; after it, the binary's too", () => {
    expect(parsed(name, "--json", "tool")).toEqual({ cmd: "x", positional: ["tool"], flags: { json: true }, child: [] });
    expect(parsed(name, "tool", "--json")).toEqual({ cmd: "x", positional: ["tool"], flags: { json: true }, child: ["--json"] });
  });
});

describe("other commands", () => {
  test("keep their name and read flags anywhere", () => {
    expect(parsed("add", "zod", "--pm", "npm", "-D", "--floor=50")).toEqual({ cmd: "add", positional: ["zod"], flags: { pm: "npm", dev: true, floor: "50" }, child: [] });
  });

  test("a value flag never takes an option as its value", () => {
    expect(parsed("publish", "--tag", "--dry-run")).toEqual({ cmd: "publish", positional: [], flags: { tag: true, "dry-run": true }, child: [] });
    expect(parsed("publish", "--tag=-x")).toEqual({ cmd: "publish", positional: [], flags: { tag: "-x" }, child: [] });
  });

  test("value flags are the command's own", () => {
    expect(parsed("install", "--size", "zod")).toEqual({ cmd: "install", positional: ["zod"], flags: { size: true }, child: [] });
    expect(parsed("search", "--size", "5", "http")).toEqual({ cmd: "search", positional: ["http"], flags: { size: "5" }, child: [] });
  });

  test("a package manager's command: nothing after -- is read", () => {
    expect(parsed("run", "dev", "--", "--pm", "npm")).toEqual({ cmd: "run", positional: ["dev"], flags: { "--": true }, child: [] });
  });

  test("no command is help", () => {
    expect(parsed().cmd).toBe("help");
  });
});
