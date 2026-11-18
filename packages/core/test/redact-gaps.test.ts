// The independent review of 17be3f6, finding 2: a quoted secret with spaces was not masked. The same class of gap for
// every quote style, escapes, values over several lines, and .env and YAML values with spaces.
import { describe, expect, test } from "bun:test";
import { redactSecrets } from "../src/index.ts";

// built at run time so no secret-shaped literal sits in the repository
const SPACED = ["fictional", "password", "with", "spaces"].join(" ");
const ESCAPED = ["has \\\"an escaped", "quote\\\" inside"].join(" ");
const MULTI = ["first line of a secret", "second line of it"].join("\n");

const CASES: { name: string; text: string; secret: string }[] = [
  { name: "double quotes with spaces", text: `const password = "${SPACED}";`, secret: SPACED },
  { name: "single quotes with spaces", text: `const dbPassword = '${SPACED}';`, secret: SPACED },
  { name: "backticks with spaces", text: "const apiKey = `" + SPACED + "`;", secret: SPACED },
  { name: "a JSON key", text: `{ "client_secret": "${SPACED}" }`, secret: SPACED },
  { name: "an escaped quote inside", text: `password: "${ESCAPED}"`, secret: "an escaped" },
  { name: "a value over several lines", text: "const token = `" + MULTI + "`;", secret: "second line of it" },
  { name: "an .env value in quotes", text: `DB_PASSWORD="${SPACED}"`, secret: SPACED },
  { name: "an .env value with spaces, unquoted", text: `export SMTP_PASSWORD=${SPACED}\nNEXT=1`, secret: "with spaces" },
  { name: "a YAML value with spaces", text: `database:\n  password: ${SPACED}\n  host: db`, secret: SPACED },
  { name: "a quote the model cut off", text: `secret = "${SPACED} and more`, secret: SPACED },
];

describe("quoted and spaced secrets", () => {
  for (const c of CASES) {
    test(c.name, () => {
      const out = redactSecrets(c.text);

      expect(out).not.toContain(c.secret);
      expect(out).toContain("[redacted, ");
    });
  }

  test("the key name and the rest of the line stay readable", () => {
    expect(redactSecrets(`DB_PASSWORD="${SPACED}"\nHOST=db.example.invalid`)).toContain("HOST=db.example.invalid");
    expect(redactSecrets(`const password = "${SPACED}";`)).toStartWith("const password = ");
  });

  test("ordinary code and prose are left alone", () => {
    for (const plain of ["const password = getPassword();", "if (token === undefined) return;", "Hardcodes a database password in index.js.", 'const label = "Password";']) {
      expect(redactSecrets(plain)).toBe(plain);
    }
  });

  test("a value an earlier rule masked is not masked again", () => {
    const key = ["sk", "proj", "Q8vT2mLw9XyZ4bN7cR1dF6gH3jK5pS0uV"].join("-");
    const once = redactSecrets(`apiKey: "${key}"`);

    expect(once).toContain(`${key.slice(0, 4)}…`);
    expect(redactSecrets(once)).toBe(once);
  });
});
