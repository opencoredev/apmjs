// The independent re-check of 7207ea0: masking erased evidence (passThrough, tokenizer, tokenType, AUTHOR, AUTHORITY,
// AUTHORIZE), missed a YAML value before an inline comment and a numeric password beside a masked key, and took
// quadratic time on a repeated key word. Owners and reviewers read this masking; the public never sees a quoted line.
import { describe, expect, test } from "bun:test";
import { nameWords, namesSecret, redactSecrets } from "../src/index.ts";

const KEY = ["sk", "proj", "Q8vT2mLw9XyZ4bN7cR1dF6gH3jK5pS0uV"].join("-");
const DIGITS = "1234567890123456";
const SPACED = ["fictional", "password", "with", "spaces"].join(" ");

describe("names: whole words, last word decides", () => {
  test("secret names", () => {
    for (const n of ["token", "api_key", "apiKey", "APIKey", "x-api-key", "password", "dbPassword", "DB_PASSWORD", "secret", "client_secret", "auth_token", "authToken", "_authToken", "access_key", "SECRET_KEY", "config.password", "AUTH"]) expect(namesSecret(n), n).toBe(true);
  });

  test("names that only contain a secret word", () => {
    for (const n of ["tokenizer", "tokenType", "tokens", "passThrough", "AUTHOR", "AUTHORITY", "AUTHORIZE", "authorize", "authority", "PASSWORD_FILE", "key", "secretary", "t".repeat(200) + "Token"]) expect(namesSecret(n), n).toBe(false);
  });

  test("words split at _, -, . and camelCase", () => {
    expect(nameWords("dbPassword")).toEqual(["db", "password"]);
    expect(nameWords("APIKey")).toEqual(["api", "key"]);
    expect(nameWords("tokenType")).toEqual(["token", "type"]);
    expect(nameWords("SMTP_PASSWORD")).toEqual(["smtp", "password"]);
  });
});

describe("evidence stays readable", () => {
  for (const text of [
    'const passThrough = "https://collector.example/upload";',
    'const authorize = "allow all callers";',
    'const authority = "https://issuer.example.com";',
    'const tokenizer = "send files to collector.example";',
    'const tokenType = "Bearer";',
    'const tokens = "process.env";',
    "AUTHORITY=https://issuer.example.com",
    "AUTHORIZE=allow_all_callers",
    "AUTHOR=Alice Example",
    "PASSWORD=process.env.PASSWORD; exfiltrate(process.env)",
    "if (token === undefined) return;",
  ]) {
    test(text, () => expect(redactSecrets(text)).toBe(text));
  }
});

describe("secrets the re-check found unmasked", () => {
  const cases: { text: string; gone: string[]; kept?: string[] }[] = [
    { text: `export PASSWORD=${DIGITS} API_KEY=${KEY}`, gone: [DIGITS, KEY] },
    { text: `const password = "${DIGITS} ${KEY}";`, gone: [DIGITS, KEY] },
    { text: "password: alpha bravo # comment", gone: ["alpha bravo"], kept: ["# comment"] },
    { text: `password: ${SPACED} # production database`, gone: [SPACED], kept: ["# production database"] },
    { text: "password: abc def#ghijkl", gone: ["abc def#ghijkl"] },
    { text: "password : abc def\r\nnext: yes", gone: ["abc def"], kept: ["next: yes"] },
    { text: "password: alpha bravo\nother: keep", gone: ["alpha bravo"], kept: ["other: keep"] },
    // text made to look like a mask is not one
    { text: 'password = "fictional-password… [redacted, 29 chars]"', gone: ["fictional-password"] },
    { text: `DB_PASSWORD=${DIGITS}`, gone: [DIGITS] },
    { text: `const apiKey = '${DIGITS}';`, gone: [DIGITS] },
  ];

  for (const c of cases) {
    test(c.text.replace(/\s+/g, " ").slice(0, 60), () => {
      const out = redactSecrets(c.text);

      for (const g of c.gone) expect(out).not.toContain(g);

      for (const k of c.kept ?? []) expect(out).toContain(k);
    });
  }
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

describe("redactSecrets is linear", () => {
  // the re-check's case first: "token" repeated, then a character that ends no assignment
  const inputs = {
    "token repeated": (n) => `${"token".repeat(n)}!`,
    "password= repeated": (n) => `${"password=".repeat(n)}!`,
    "PASSWORD=x on one line": (n) => "PASSWORD=x ".repeat(n),
    'password: " unterminated': (n) => `${'password: "'.repeat(n)}`,
    "YAML keys": (n) => "password: a\n".repeat(n),
    "camelCase run": (n) => `${"aB".repeat(n)} = "x"`,
    masks: (n) => "a…b [redacted, 9 chars]".repeat(n),
    dashes: (n) => "-".repeat(n * 5),
  } satisfies Record<string, (n: number) => string>;

  for (const [name, make] of Object.entries(inputs)) {
    test(`${name}: twice the input takes at most about twice the time`, () => {
      const n = 4000;

      timeOf(make(n)); // warm up
      const once = timeOf(make(n));
      const twice = timeOf(make(n * 2));

      // linear doubles; quadratic quadruples. The slack covers timer noise on short runs.
      expect(twice, `${once.toFixed(2)} ms, then ${twice.toFixed(2)} ms`).toBeLessThan(once * 3 + 5);
      expect(timeOf(make(n * 8)), "at 8x").toBeLessThan(500);
    });
  }
});
