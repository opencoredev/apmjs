// K21: the approval page puts every piece of evidence above the approve controls, and the recovery codes
// are all shown once 2FA is on. Rendered to HTML with react-dom/server, no browser.
import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { RecoveryCodes } from "@/app/account/account-view";
import { StagedReview } from "@/app/approve/[id]/approve-view";
import { Account, AuthConfig, StagedDetail } from "./account";

const account = Account.parse({
  scope: "alice",
  github: "alice",
  name: "Alice",
  email: "alice@example.test",
  image: null,
  linked: [],
  security: { totp: true, passkeys: 0 },
  canPublish: true,
  tokens: [],
  pending: 1,
});

const config = AuthConfig.parse({ providers: { github: true, vercel: false }, passkeys: false });

const staged = StagedDetail.parse({
  id: "abc123",
  package: "@alice/widget",
  version: "1.2.3",
  publisher: "alice",
  tag: "latest",
  stagedAt: new Date().toISOString(),
  expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  status: "pending",
  url: "https://apm.example/approve/abc123",
  newPackage: false,
  currentLatest: "1.2.2",
  description: "A widget",
  size: 2048,
  integrity: "sha512-AAAA",
  files: [{ path: "index.js", size: 120 }],
  score: {
    score: 55,
    grade: "C",
    signals: [{ id: "network", label: "Makes network requests", points: -20, evidence: ["index.js:3 fetch('https://example.invalid')"] }],
    notChecked: ["runtime behavior: code that downloads a second stage"],
  },
  floor: 40,
  analysis: "complete",
  confirmation: { kind: "plain" },
});

describe("the approval page", () => {
  test("shows the risk summary, its evidence, what was not checked and the files before the approve controls", () => {
    const html = renderToStaticMarkup(<StagedReview s={staged} account={account} config={config} onDecided={() => {}} />);

    const at = (text: string): number => {
      const i = html.indexOf(text);

      expect(i, text).toBeGreaterThanOrEqual(0);

      return i;
    };

    const order = [at("Risk summary"), at("Makes network requests"), at("index.js:3 fetch"), at("Not checked"), at("runtime behavior"), at('id="files-heading"'), at('id="approve-heading"')];

    expect(order).toEqual([...order].sort((a, b) => a - b));
  });

  test("a signal found only as text shows the scorer's own label and says where the text sits (apm-score-v9)", () => {
    const label = "Mentions a network call (fetch, http, a socket); apm did not see a request made";
    const evidence = "index.js:1: // fetch('https://example.invalid') is how the README calls it (text match in a comment)";
    const s = StagedDetail.parse({ ...staged, score: { score: 90, grade: "A", signals: [{ id: "network", label, points: -10, evidence: [evidence] }], notChecked: [] } });
    const html = renderToStaticMarkup(<StagedReview s={s} account={account} config={config} onDecided={() => {}} />);

    expect(html).toContain(label);
    expect(html).toContain("(text match in a comment)");
  });

  test("an expired upload shows the evidence and no approve controls", () => {
    const html = renderToStaticMarkup(<StagedReview s={{ ...staged, expiresAt: new Date(Date.now() - 1000).toISOString() }} account={account} config={config} onDecided={() => {}} />);

    expect(html).toContain("Risk summary");
    expect(html).not.toContain('id="approve-heading"');
  });
});

describe("the recovery codes", () => {
  test("every code is shown, with the warning that this is the only time", () => {
    const codes = ["abcde-12345", "fghij-67890", "klmno-13579", "pqrst-24680"];
    const html = renderToStaticMarkup(<RecoveryCodes codes={codes} onDone={() => {}} />);

    for (const c of codes) expect(html).toContain(`<li>${c}</li>`);
    expect(html).toContain("This is the only time apm shows them.");
  });
});
