// Edges of the secret rules where a value was taken from the wrong place: an empty `.npmrc` value took the next line as
// the secret, a Google key ending in `-` was missed, and a connection string's last password, with no `;` after it, was
// left readable.
import { describe, expect, test } from "bun:test";
import { findSecrets, maskSecret, redactSecrets } from "../src/index.ts";

const kinds = (path: string, text: string): string[] => findSecrets([{ path, data: new TextEncoder().encode(text) }]).findings.map((f) => f.kind);

describe("an .npmrc key with no value is not a secret", () => {
  test("an empty _authToken does not take the next line as its token", () => {
    const npmrc = "//registry.npmjs.org/:_authToken=\nregistry=https://registry.npmjs.org/\n";

    expect(kinds(".npmrc", npmrc)).toEqual([]);
    expect(redactSecrets(npmrc)).toBe(npmrc);
  });

  test("nor does an empty _auth or _password, with a registry or without", () => {
    expect(kinds(".npmrc", "_auth=\nalways-auth=true\n")).toEqual([]);
    expect(kinds(".npmrc", "//registry.example.com/:_password=\nemail=dev@example.com\n")).toEqual([]);
  });

  test("a value on the key's own line still is", () => {
    expect(kinds(".npmrc", "//registry.npmjs.org/:_authToken=abcdef0123456789\n")).toEqual(["registry auth token"]);
    expect(kinds(".npmrc", "_auth = dXNlcjpwYXNz\n")).toEqual(["registry password"]);
  });
});

describe("a Google API key is found whatever its last character", () => {
  const body = "SyA1234567890abcdefghijklmnopqrstu";

  for (const last of ["x", "_", "-"]) {
    test(`ending in ${last}`, () => {
      const key = `AIza${body}${last}`;

      expect(key).toHaveLength(39);
      expect(kinds("a.js", `const k = "${key}";`)).toEqual(["Google API key"]);
      expect(redactSecrets(`k="${key}"`)).not.toContain(key);
    });
  }

  test("a longer run is not a key", () => {
    expect(kinds("a.js", `const k = "AIza${body}x-";`)).toEqual([]);
  });
});

describe("a connection string's password is masked wherever it ends", () => {
  const PW = "Zq9wLmN2pXv";

  for (const text of [`Server=db;Database=app;Password=${PW}`, `"Server=db;Uid=app;Pwd=${PW}"`, `'Server=db;Password=${PW}'\nnext line`, `"Server=db;Pwd=${PW};Password=${PW}x;"`]) {
    test(JSON.stringify(text), () => {
      expect(redactSecrets(text)).not.toContain(PW);
    });
  }

  test("the text around it stays as it was", () => {
    expect(redactSecrets(`Server=db;Password=${PW}`).startsWith("Server=db;Password=Z")).toBe(true);
  });

  // the value ends at the quote, `;` or newline, which are kept: only the password itself is replaced
  test.each([
    [`Server=db;Database=app;Password=${PW}`, `Server=db;Database=app;Password=${maskSecret(PW)}`],
    [`"Server=db;Uid=app;Pwd=${PW}"`, `"Server=db;Uid=app;Pwd=${maskSecret(PW)}"`],
    [`'Server=db;Password=${PW}'\nnext line`, `'Server=db;Password=${maskSecret(PW)}'\nnext line`],
    [`"Server=db;Pwd=${PW};Password=${PW}x;"`, `"Server=db;Pwd=${maskSecret(PW)};Password=${maskSecret(`${PW}x`)};"`],
  ])("%j is masked to %j", (text, want) => {
    expect(redactSecrets(text)).toBe(want);
  });
});
