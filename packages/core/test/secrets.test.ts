// Launch review item 9 and score 14: the secret scan reads every file and knows more secret shapes.
// Every "secret" here is a made-up stand-in, assembled at run time.
import { describe, expect, test } from "bun:test";
import { findSecrets } from "../src/secrets.ts";

function file(path: string, text: string | Uint8Array) {
  return { path, data: typeof text === "string" ? new TextEncoder().encode(text) : text };
}

function kinds(path: string, text: string | Uint8Array): string[] {
  return findSecrets([file(path, text)]).findings.map((f) => f.kind);
}

const fakeNpmToken = `npm_${"Z".repeat(36)}`;

describe("findSecrets", () => {
  test("a NUL byte does not make a file unreadable", () => {
    expect(kinds("lib/data.js", `/*\0*/\nmodule.exports = '${fakeNpmToken}';\n`)).toEqual(["npm token"]);
    expect(kinds("blob.bin", new Uint8Array([0, 1, 2, ...new TextEncoder().encode(fakeNpmToken), 0]))).toEqual(["npm token"]);
  });

  test("a compressed archive is reported as not read, not as clean", () => {
    const scan = findSecrets([file("vendor/data.tgz", Bun.gzipSync(new TextEncoder().encode(fakeNpmToken)))]);

    expect(scan.findings).toEqual([]);
    expect(scan.skipped).toEqual([{ path: "vendor/data.tgz", size: expect.any(Number), reason: "compressed" }]);
  });

  test("npm basic auth is a secret, in an .npmrc or keyed to a registry", () => {
    expect(kinds(".npmrc", "//registry.example.invalid/:_auth=Ym9iOnNlY3JldA==\n")).toEqual(["registry password"]);
    expect(kinds(".npmrc", "_auth=Ym9iOnNlY3JldA==\n")).toEqual(["registry password"]);
    expect(kinds("config/npmrc.txt", "//registry.example.invalid/:_password=c2VjcmV0\n")).toEqual(["registry password"]);
    // an environment reference is not a secret, and neither is a variable in code
    expect(kinds(".npmrc", "//registry.example.invalid/:_auth=${NPM_AUTH}\n")).toEqual([]);
    expect(kinds("index.js", "const _password = readPassword();\n")).toEqual([]);
  });

  test("Slack and Discord webhooks are secrets", () => {
    expect(kinds("settings.js", `'https://hooks.slack.com/services/T0000/B0000/${"x".repeat(24)}'`)).toEqual(["Slack webhook"]);
    expect(kinds("settings.js", `'https://discord.com/api/webhooks/123456789/${"y".repeat(40)}'`)).toEqual(["Discord webhook"]);
  });

  test("private keys in every common text format, and key stores by name", () => {
    for (const header of ["-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN PGP PRIVATE KEY BLOCK-----", "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"]) {
      expect(kinds("key.pem", `${header}\nAAAA\n`)).toEqual(["private key"]);
    }

    expect(kinds("deploy.ppk", "x")).toEqual(["key store"]);
    expect(kinds("id.txt", "PuTTY-User-Key-File-3: ssh-ed25519\n")).toEqual(["PuTTY private key"]);

    for (const name of ["cert.p12", "cert.PFX", "release.jks", "app.keystore", "vault.kdbx"]) expect(kinds(name, "binary")).toEqual(["key store"]);
    // a certificate is public
    expect(kinds("ca.pem", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")).toEqual([]);
  });
});
