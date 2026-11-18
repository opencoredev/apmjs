// The independent re-check of 70dc3df: masking missed DB_PASSWORD_PROD=…, signed URLs, a URL given to a secret-named
// key, password-only Redis URLs and .NET connection strings, and went quadratic on `PASSWORD=process.env.X ` repeated.
import { describe, expect, test } from "bun:test";
import { namesSecret, redactSecrets } from "../src/index.ts";

const PW = ["fictional", "Database", "Password42"].join("");

describe("shapes the re-check found unmasked", () => {
  const cases = {
    postgres: `postgres://alice:${PW}@host/db`,
    mongo: `mongodb+srv://alice:${PW}@host/db`,
    redis: `redis://alice:${PW}@host/0`,
    "redis with no user": `redis://:${PW}@host/0`,
    "rediss with no user": `rediss://:${PW}@host/0`,
    ".NET connection string": `"Server=host;Database=app;User Id=alice;Password=${PW};"`,
    "ODBC Pwd": `"Driver={x};Uid=alice;Pwd=${PW};"`,
    env: `export DB_PASSWORD=${PW}`,
    "env with an environment suffix": `DB_PASSWORD_PROD=${PW}`,
    "env with a version suffix": `API_KEY_V2=${PW}`,
    "env with a number suffix": `SECRET_2=${PW}`,
    yaml: `password: ${PW} # comment`,
    "a URL given to a secret-named key": `const password="https://login.invalid/${PW}"`,
    "a signed URL given to a token": `const token="https://storage.invalid/file?sig=${PW}"`,
    "a signed URL in prose": `downloads https://storage.invalid/file?X-Amz-Credential=x&X-Amz-Signature=${PW}&X-Amz-Expires=60`,
    "an Azure SAS URL": `https://acct.blob.core.windows.invalid/c/f?sv=2024-01-01&se=2026-12-01&sp=r&sig=${PW}`,
  } satisfies Record<string, string>;

  for (const [name, input] of Object.entries(cases)) {
    test(name, () => {
      const out = redactSecrets(input);

      expect(out).not.toContain(PW);
      expect(out).toContain("[redacted, ");
    });
  }

  test("a signed URL keeps its host and path readable", () => {
    const out = redactSecrets(`https://storage.invalid/bucket/file.tgz?X-Amz-Signature=${PW}&X-Amz-Expires=60`);

    expect(out).toStartWith("https://storage.invalid/bucket/file.tgz?X-Amz-Signature=");
    expect(out).toContain("&X-Amz-Expires=60");
  });

  test("names with an environment suffix are secret; look-alikes still are not", () => {
    for (const n of ["DB_PASSWORD_PROD", "dbPasswordStaging", "API_KEY_V2", "SECRET_2", "token_live", "AUTH_TOKEN_OLD"]) expect(namesSecret(n), n).toBe(true);

    for (const n of ["tokenType", "tokenizer", "passThrough", "AUTHOR", "AUTHORITY", "AUTHORIZE", "AUTHOR_PROD", "PASSWORD_FILE", "prod"]) expect(namesSecret(n), n).toBe(false);
  });

  // re-check of d38f704: a reference value stepped past the rest of the line and hid the next assignment's secret
  test("a reference value does not hide a later assignment on the same line", () => {
    for (const text of [`export PASSWORD=process.env.X TOKEN=${PW}`, `PASSWORD=$HOME API_KEY=${PW}`]) {
      const out = redactSecrets(text);

      expect(out, text).not.toContain(PW);
    }

    expect(redactSecrets(`export PASSWORD=process.env.X TOKEN=${PW}`)).toContain("PASSWORD=process.env.X");
  });

  // re-check of ef953ed: a quoted reference ends at its quote, so the next quoted assignment is still examined
  test("a quoted reference does not hide the next quoted secret", () => {
    for (const ref of ["$X", "process.env.X"]) {
      const text = `{"password":"${ref}","token":"${PW}"}`;

      expect(redactSecrets(text), text).not.toContain(PW);
      expect(redactSecrets(text), text).toContain(`"password":"${ref}"`);
    }
  });

  test("plain URLs elsewhere stay readable", () => {
    for (const text of ['const passThrough = "https://collector.example/upload";', "fetch('https://collector.example/upload?id=42&page=2')", "postgres://host:5432/db"]) expect(redactSecrets(text)).toBe(text);
  });
});

/** The median time of three runs of redactSecrets on `text`, in milliseconds. */
function timeOf(text: string): number {
  const runs = [0, 1, 2].map(() => {
    const t = performance.now();

    redactSecrets(text);

    return performance.now() - t;
  });

  return runs.sort((a, b) => a - b)[1] ?? 0;
}

/** A small seeded generator, so a failing fuzz input is the same on every run. */
function seeded(seed: number): () => number {
  let x = seed;

  return () => {
    x = (x * 1103515245 + 12345) % 2147483648;

    return x / 2147483648;
  };
}

const NAMES = ["PASSWORD", "DB_PASSWORD_PROD", "token", "apiKey", "tokenType", "AUTHOR", "secret", "x"];
const SEPARATORS = ["=", " = ", ": ", "=>", '": '];
const VALUES = ["process.env.X", '"a b c"', "'q", "`", "$HOME", "abcd1234", "https://h/p?sig=abcd", "[redacted, 4 chars]", "#", ";"];

/** One fuzzed assignment: name, separator and value picked from the lists, repeated n times. */
function fuzzedAssignment(seed: number): (n: number) => string {
  const r = seeded(seed);
  const pick = (list: readonly string[]): string => list[Math.floor(r() * list.length)] ?? "";
  const unit = `${pick(NAMES)}${pick(SEPARATORS)}${pick(VALUES)}${pick([" ", "\n", "", ";"])}`;

  return (n) => unit.repeat(n);
}

describe("redactSecrets stays linear", () => {
  const inputs: [string, (n: number) => string][] = [
    ["PASSWORD=process.env.X repeated (the re-check's case)", (n) => "PASSWORD=process.env.X ".repeat(n)],
    ["password: process.env.X lines", (n) => "password: process.env.X\n".repeat(n)],
    ['token: "$X" repeated', (n) => 'token: "$X" '.repeat(n)],
    ["a signed-URL parameter repeated", (n) => "?sig=".repeat(n)],
    ["redis colons", (n) => `redis://${":".repeat(n)}`],
    [";Password= repeated", (n) => ";Password=".repeat(n)],
    ...Array.from({ length: 24 }, (_, i): [string, (n: number) => string] => [`fuzz ${i}`, fuzzedAssignment(i + 1)]),
  ];

  for (const [name, make] of inputs) {
    test(`${name}: twice the input takes at most about twice the time`, () => {
      const n = 3000;

      timeOf(make(n)); // warm up
      const once = timeOf(make(n));
      const twice = timeOf(make(n * 2));

      // linear doubles; quadratic quadruples. The slack covers timer noise on short runs.
      expect(twice, `${JSON.stringify(make(1))}: ${once.toFixed(2)} ms, then ${twice.toFixed(2)} ms`).toBeLessThan(once * 3 + 5);
    });
  }
});
