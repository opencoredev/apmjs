// Unit tests for the pieces behind the CLI hardening: token binding, child env, scope overrides,
// audit's directory walk and range parsing. The acceptance suite drives the same paths end to end.
import { describe, test, expect } from "bun:test";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { installedPackages, isValidRange } from "../src/audit.ts";
import { childEnv, isSecretEnvKey, registryArgs, scopeOverrides, scopesOf } from "../src/child.ts";
import { isApmToken, loadConfig } from "../src/config.ts";

function dir(): string {
  return mkdtempSync(join(tmpdir(), "apm-unit-"));
}

function writeJson(path: string, value: { name: string; version: string }): void {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, JSON.stringify(value));
}

describe("loadConfig binds APM_TOKEN to its registry", () => {
  test("a project .npmrc registry gets no APM_TOKEN", () => {
    const home = dir();
    const project = dir();

    writeFileSync(join(home, ".npmrc"), "registry=https://apm.example.test/\n");
    writeFileSync(join(project, ".npmrc"), "registry=https://attacker.example.test/\n");
    const cfg = loadConfig(project, { HOME: home, APM_TOKEN: "apm_secretsecretsecret" });

    expect(cfg.registry).toBe("https://attacker.example.test/");
    expect(cfg.token).toBeNull();
    expect(cfg.withheld).toBe("https://apm.example.test/");
  });

  test("APM_REGISTRY and the user config registry get it", () => {
    const home = dir();

    writeFileSync(join(home, ".npmrc"), "registry=https://apm.example.test/\n");
    expect(loadConfig(dir(), { HOME: home, APM_TOKEN: "apm_secretsecretsecret" }).token).toBe("apm_secretsecretsecret");
    expect(loadConfig(dir(), { HOME: home, APM_TOKEN: "apm_secretsecretsecret", APM_REGISTRY: "https://other.example.test" }).token).toBe("apm_secretsecretsecret");
  });

  test("npm_config_registry alone does not count, since npm run exports project config", () => {
    const home = dir();
    const cfg = loadConfig(dir(), { HOME: home, APM_TOKEN: "apm_secretsecretsecret", npm_config_registry: "https://attacker.example.test/" });

    expect(cfg.token).toBeNull();
  });
});

describe("isApmToken", () => {
  test("accepts apm tokens and rejects anything that could add .npmrc lines", () => {
    expect(isApmToken("apm_AbC-123_xyz0123456789abcd")).toBe(true);
    expect(isApmToken("apm_abc\nregistry=http://evil/")).toBe(false);
    expect(isApmToken("npm_abcdefghijklmnopqrstuvwxyz")).toBe(false);
    expect(isApmToken("apm_short")).toBe(false);
    expect(isApmToken("apm_abcdefghijklmnop qrstuvwx")).toBe(false);
  });
});

describe("child env", () => {
  test("drops every credential variable and pins the registry and scopes", () => {
    const env = childEnv({
      parent: { PATH: "/bin", APM_TOKEN: "a", NPM_TOKEN: "b", NODE_AUTH_TOKEN: "c", "npm_config_//h/:_authToken": "d", NPM_CONFIG__AUTH: "e", npm_config_registry: "https://evil/", "npm_config_@x:registry": "https://evil/" },
      registry: "https://apm.example.test/",
      scopes: ["@alice"],
      keepAuth: false,
    });

    expect(env).toEqual({
      PATH: "/bin",
      npm_config_registry: "https://apm.example.test/",
      NPM_CONFIG_REGISTRY: "https://apm.example.test/",
      BUN_CONFIG_REGISTRY: "https://apm.example.test/",
      YARN_REGISTRY: "https://apm.example.test/",
      YARN_NPM_REGISTRY_SERVER: "https://apm.example.test/",
      "npm_config_@alice:registry": "https://apm.example.test/",
    });
  });

  test("keepAuth keeps .npmrc-referenced credentials but never APM_TOKEN", () => {
    const env = childEnv({ parent: { APM_TOKEN: "a", NODE_AUTH_TOKEN: "c" }, registry: "https://r/", scopes: [], keepAuth: true });

    expect(env.APM_TOKEN).toBeUndefined();
    expect(env.NODE_AUTH_TOKEN).toBe("c");
  });

  test("isSecretEnvKey leaves ordinary npm config alone", () => {
    expect(isSecretEnvKey("npm_config_cache")).toBe(false);
    expect(isSecretEnvKey("NPM_CONFIG_TOKEN")).toBe(true);
  });

  test("registry flags per package manager", () => {
    expect(registryArgs("npm", "https://r/", ["@a"])).toEqual(["--registry=https://r/", "--@a:registry=https://r/"]);
    expect(registryArgs("bun", "https://r/", ["@a"])).toEqual(["--registry=https://r/"]);
    expect(registryArgs("yarn", "https://r/", ["@a"])).toEqual([]);
    expect(scopesOf(["@a/x", "b", "@a/y", "@c/z"])).toEqual(["@a", "@c"]);
  });
});

describe("scopeOverrides", () => {
  test("finds .npmrc, bunfig and .yarnrc.yml scope lines that disagree with the registry", () => {
    const home = dir();
    const project = dir();

    writeFileSync(join(project, ".npmrc"), "@alice:registry=https://evil.example.test/\n@bob:registry=https://apm.example.test/\n");
    writeFileSync(join(project, "bunfig.toml"), '[install.scopes]\ncarol = { url = "https://evil.example.test/", token = "x" }\n');
    writeFileSync(join(project, ".yarnrc.yml"), "npmScopes:\n  dave:\n    npmRegistryServer: https://evil.example.test/\n");
    const found = scopeOverrides({ cwd: project, env: { HOME: home }, registry: "https://apm.example.test/", scopes: ["@alice", "@bob", "@carol", "@dave", "@erin"] });

    expect(found.map((o) => o.scope).sort()).toEqual(["@alice", "@carol", "@dave"]);
  });
});

describe("installedPackages", () => {
  test("walks npm's nesting, pnpm's .pnpm store and bun's .bun store", () => {
    const root = dir();
    const nm = join(root, "node_modules");

    writeJson(join(nm, "a", "package.json"), { name: "a", version: "1.0.0" });
    writeJson(join(nm, "a", "node_modules", "b", "package.json"), { name: "b", version: "2.0.0" });
    writeJson(join(nm, ".pnpm", "c@3.0.0", "node_modules", "c", "package.json"), { name: "c", version: "3.0.0" });
    writeJson(join(nm, ".pnpm", "node_modules", "@s", "d", "package.json"), { name: "@s/d", version: "4.0.0" });
    writeJson(join(nm, ".bun", "e@5.0.0", "node_modules", "e", "package.json"), { name: "e", version: "5.0.0" });
    mkdirSync(join(nm, ".bin"), { recursive: true });
    const got = installedPackages(root);

    expect([...got.packages.keys()].sort()).toEqual(["@s/d", "a", "b", "c", "e"]);
    expect(got.unchecked).toEqual([]);
  });

  test("reports unknown stores and unreadable package.json files", () => {
    const root = dir();
    const nm = join(root, "node_modules");

    mkdirSync(join(nm, ".odd", "blob"), { recursive: true });
    mkdirSync(join(nm, "broken"), { recursive: true });
    writeFileSync(join(nm, "broken", "package.json"), "{ not json");
    const got = installedPackages(root);

    const ids = got.unchecked.map((u) => u.id).join("\n");

    expect(ids).toContain(".odd");
    expect(ids).toContain("broken");
  });
});

describe("isValidRange", () => {
  test("accepts npm ranges", () => {
    for (const r of ["*", "1.2.3", ">=1.0.0 <2.0.0", "^1.2", "~1.2.3", "1.x || >=3.0.0-beta.1", "1.0.0 - 2.0.0", ">= 1.0.0", "<0.0.0-0", "=1.0.0"]) expect(isValidRange(r), r).toBe(true);
  });

  test("rejects what Bun.semver.satisfies would treat as match-everything", () => {
    for (const r of ["", ">>>", "1.0.0 ||", "garbage", "<<1", "1.0.0 -"]) expect(isValidRange(r), r).toBe(false);
  });
});
