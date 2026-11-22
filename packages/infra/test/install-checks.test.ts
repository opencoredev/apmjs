// The read mode a deploy gives the registry Worker (install-checks.ts, alchemy.run.ts): "database" unless the deploy
// asks for "edge", so a deploy that says nothing never turns edge views on (docs/DEPLOY.md, "Install checks").
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { installChecksOf } from "../install-checks.ts";

const INFRA = join(import.meta.dir, "..");

describe("install checks on a deploy", () => {
  test("default to the database; --install-checks or APM_INSTALL_CHECKS turns edge views on, the flag first", () => {
    expect(installChecksOf({ argv: ["bun", "deploy.ts", "deploy", "--stage", "staging"], env: {} })).toBe("database");
    expect(installChecksOf({ argv: ["deploy", "--install-checks", "edge"], env: {} })).toBe("edge");
    expect(installChecksOf({ argv: ["deploy"], env: { APM_INSTALL_CHECKS: "edge" } })).toBe("edge");
    expect(installChecksOf({ argv: ["deploy", "--install-checks", "database"], env: { APM_INSTALL_CHECKS: "edge" } })).toBe("database");
  });

  test("a value that is neither stops the deploy", () => {
    expect(() => installChecksOf({ argv: ["deploy", "--install-checks", "egde"], env: {} })).toThrow();
    expect(() => installChecksOf({ argv: ["deploy", "--install-checks"], env: {} })).toThrow();
    expect(() => installChecksOf({ argv: ["deploy"], env: { APM_INSTALL_CHECKS: "on" } })).toThrow();
  });

  test("deploy.ts passes its choice to the stack, and the stack's own default is the database", () => {
    expect(readFileSync(join(INFRA, "deploy.ts"), "utf8")).toMatch(/INSTALL_CHECKS: installChecks,/);
    const stack = readFileSync(join(INFRA, "alchemy.run.ts"), "utf8");

    expect(stack).toMatch(/z\.enum\(\["database", "edge"\]\)\.parse\(yield\* Config\.withDefault\(Config\.String\("INSTALL_CHECKS"\), "database"\)\)/);
    expect(stack).toMatch(/APM_INSTALL_CHECKS: installChecks,/);
  });
});
