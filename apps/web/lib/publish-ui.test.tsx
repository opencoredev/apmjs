// The publish page's prompt and the "Your packages" rows, rendered to HTML with react-dom/server, no browser.
import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { PackageRow } from "@/app/account/packages/packages-view";
import { PromptCard } from "@/app/publish/publish-view";
import { MyPackage, MyPackages } from "./account";
import { manualSteps, publishPrompt } from "./publish-prompt";

const target = { scope: "alice", registry: "https://registry.apmjs.dev/", site: "https://apmjs.dev" };

describe("publishPrompt", () => {
  const p = publishPrompt(target);

  test("is filled in with the person's scope and needs no MCP server", () => {
    expect(p).toContain("under my scope @alice");
    expect(p).toContain('set "name" to "@alice/<name>"');
    expect(p).toContain('If "apm whoami" prints alice');
    expect(p).toContain("no MCP server is needed");
    expect(p.toLowerCase()).not.toContain("mcp add");
  });

  // the repository's default branch is not main, and a full install of the repository is over 2 GB
  test("gets the CLI from main, installing only what it needs", () => {
    expect(p).toContain("git clone --depth 1 --branch main https://github.com/opencoredev/apmjs.git <cli>");
    expect(p).toContain("(cd <cli> && bun install --filter @apm/cli)");
    expect(p).toContain("ask me before installing it");
  });

  // an existing copy may be a fork, track another upstream, run git hooks or hold edited dependencies: never reused
  test("always makes a fresh copy of the CLI and never reuses or updates an old one", () => {
    expect(p).toContain('Run "mktemp -d"; below, <cli> is the folder it printed followed by "/apm", in quotes if it has spaces.');
    expect(p).toContain("never reuse or update an existing copy (such as ~/.apm-cli)");
    expect(p).not.toContain("pull");
    expect(p).not.toContain("git -C");
    expect(manualSteps(target).split("\n")[0]).toBe('APM_CLI="$(mktemp -d)/apm"');
    expect(manualSteps(target)).not.toContain("pull");
  });

  // a project or user .npmrc that names npm's registry would otherwise send the login and the upload there
  test("pins every apm command to apm's registry", () => {
    expect(p).toContain('"apm" means: APM_REGISTRY=https://registry.apmjs.dev/ bun <cli>/packages/cli/src/main.ts');
    expect(p).toContain("Publish only to https://registry.apmjs.dev/, never to npmjs.org.");
  });

  // apm login waits for the person: an agent whose shell returns only at exit would never show the link
  test("has the agent read the login link while the command waits, and keeps the token out of the chat", () => {
    expect(p).toContain('start "apm login --no-browser" so you can read its output while it keeps running');
    expect(p).toContain("Show me both and wait until it prints \"logged in\"");
    expect(p).toContain("never print, copy or move that token");
  });

  test("checks first, uploads, and leaves the approval to the person", () => {
    expect(p).toContain('Run "apm publish --dry-run"');
    expect(p).toContain('Run "apm publish --json". If it says the version already exists, run it again with --bump patch.');
    expect(p).toContain('Send me the "approval" link from the output, then stop. I approve it on apmjs.dev with my passkey or authenticator code.');
    expect(p).toContain("You cannot approve it, and must not try.");
    expect(p).toContain("send me to https://apmjs.dev/account");
  });

  test("uses no em dash", () => {
    expect(p).not.toContain("—");
    expect(manualSteps(target)).not.toContain("—");
  });

  test("the manual steps are the same commands", () => {
    const m = manualSteps(target);

    expect(m).toContain('apm() { APM_REGISTRY=https://registry.apmjs.dev/ bun "$APM_CLI"/packages/cli/src/main.ts "$@"; }');
    expect(m).toContain("apm login\n");
    expect(m).toContain('"name": "@alice/my-package"');
  });
});

describe("PromptCard", () => {
  test("shows the whole prompt it copies, with one copy button", () => {
    const html = renderToStaticMarkup(<PromptCard target={target} primary />);

    expect(html).toContain("Copy prompt");
    expect(html.match(/<button/g)?.length).toBe(1);
    // the text, without the markup that picks out the scope
    expect(html.replace(/<[^>]+>/g, "").replaceAll("&quot;", '"').replaceAll("&#x27;", "'").replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&amp;", "&")).toContain(publishPrompt(target));
  });
});

const pkg = (over: Partial<MyPackage>): MyPackage =>
  MyPackage.parse({ name: "@alice/widget", latest: { version: "1.2.0", status: "active", publishedAt: "2026-11-01T00:00:00.000Z" }, lastPublishedAt: "2026-11-01T00:00:00.000Z", score: { score: 92, grade: "A" }, pending: [], ...over });

describe("PackageRow", () => {
  test("a live package links to its page with its version, score and waiting versions", () => {
    const html = renderToStaticMarkup(<PackageRow pkg={pkg({ pending: [{ id: "abc", version: "1.2.1", url: "https://apmjs.dev/approve/abc", expiresAt: new Date(Date.now() + 3_600_000).toISOString() }] })} />);

    expect(html).toContain('href="/package/@alice/widget"');
    expect(html).toContain("1.2.0");
    expect(html).toContain("apm score 92/100");
    expect(html).toContain('href="/approve/abc"');
    expect(html).toContain("1.2.1</span> waiting");
  });

  test("a name whose first version waits opens its approval, with no score", () => {
    const html = renderToStaticMarkup(<PackageRow pkg={pkg({ latest: null, lastPublishedAt: null, score: null, pending: [{ id: "xyz", version: "0.1.0", url: "https://apmjs.dev/approve/xyz", expiresAt: new Date(Date.now() + 3_600_000).toISOString() }] })} />);

    expect(html).toContain('href="/approve/xyz"');
    expect(html).not.toContain('href="/package/');
    expect(html).toContain("Not live yet");
    expect(html).not.toContain("apm score");
  });

  test("a yanked latest shows its state and the score as the registry sent it", () => {
    const html = renderToStaticMarkup(<PackageRow pkg={pkg({ latest: { version: "2.0.0", status: "yanked", publishedAt: "2026-11-01T00:00:00.000Z" }, score: { score: 61, grade: "P" } })} />);

    expect(html).toContain("yanked");
    expect(html).toContain("partial");
  });

  test("the registry's answer parses", () => {
    expect(MyPackages.parse({ packages: [] }).packages).toEqual([]);
  });
});
