// Masking secrets in text apm shows people (an AI review's quotes): every shape the secret scan knows, plus connection
// strings with a password, JWTs and values assigned to secret-named keys. Only the ends and the length stay.
import { describe, expect, test } from "bun:test";
import { findSecrets, hasSecret, maskSecret, redactSecrets } from "../src/index.ts";

// built at run time so no secret-shaped literal sits in the repository
const OPENAI = ["sk", "proj", "Q8vT2mLw9XyZ4bN7cR1dF6gH3jK5pS0uV"].join("-");
const MONGO_PASSWORD = ["S3cret", "Passw0rd", "42"].join("");
const MONGO = `mongodb+srv://shop:${MONGO_PASSWORD}@cluster0.abcd.mongodb.net/shop`;
const GITHUB = `ghp_${"a1B2c3D4e5".repeat(4)}`;
const AWS = `AKIA${"ABCDEFGHIJKLMNOP"}`;
const NPM = `npm_${"Zz9".repeat(12)}`;

describe("redactSecrets", () => {
  test("masks an OpenAI key, a Mongo password, a GitHub token, an AWS key and an npm token", () => {
    const text = `const ai = new OpenAI({ apiKey: "${OPENAI}" });\nmongoose.connect("${MONGO}");\nconst gh = "${GITHUB}"; // ${AWS}\n//registry.npmjs.org/:_authToken=${NPM}`;
    const out = redactSecrets(text);

    for (const secret of [OPENAI, MONGO_PASSWORD, GITHUB, AWS, NPM]) expect(out).not.toContain(secret);
    // which key it is stays recognisable: its ends and its length
    expect(out).toContain(`${OPENAI.slice(0, 4)}…${OPENAI.slice(-4)} [redacted, ${OPENAI.length} chars]`);
    // only the password of a connection string goes; the host stays readable
    expect(out).toContain("mongodb+srv://shop:");
    expect(out).toContain("@cluster0.abcd.mongodb.net/shop");
    expect(out).toContain(`[redacted, ${MONGO_PASSWORD.length} chars]`);
  });

  test("masks a whole private key block, quoted assignments and env lines", () => {
    const pem = `-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7\nzzzz\n-----END RSA PRIVATE KEY-----`;
    const out = redactSecrets(`${pem}\nconst password = "hunter2hunter2";\nDB_SECRET=abcdefghijkl`);

    expect(out).not.toContain("MIIEowIBAAKCAQEA7");
    expect(out).not.toContain("hunter2hunter2");
    expect(out).not.toContain("abcdefghijkl");
  });

  test("every file the scan flags for its content comes back masked", () => {
    const files = [OPENAI, GITHUB, AWS, `_authToken=${NPM}`].map((s, i) => ({ path: `f${i}.js`, data: new TextEncoder().encode(`x = "${s}"`) }));

    expect(findSecrets(files).findings).toHaveLength(files.length);

    for (const f of files) expect(hasSecret(new TextDecoder().decode(f.data))).toBe(true);
  });

  test("text with no secret is unchanged, and masking twice changes nothing more", () => {
    const plain = "Posts process.env to collector.example.invalid on import. See https://example.com/a:b@c? no.";

    expect(redactSecrets(plain)).toBe(plain);
    const once = redactSecrets(`token: "${OPENAI}"`);

    expect(redactSecrets(once)).toBe(once);
  });

  test("short secrets show fewer characters", () => {
    expect(maskSecret("abcd")).toBe("[redacted, 4 chars]");
    expect(maskSecret("abcdefgh")).toBe("a…h [redacted, 8 chars]");
  });
});
