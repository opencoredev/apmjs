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

  // one prebuilt binary from the site, checked against the SHA-256 in the script: no git, no Bun, no clone. The script
  // is saved outside the package, run only when it arrived whole, with the destination pinned (review of 1919be8,
  // findings 1 and 2; packages/infra/test/publish-install.test.ts runs these lines)
  test("installs the CLI with the site's install script, which checks the binary's SHA-256", () => {
    expect(p).toContain(
      `1. Install the apm CLI. Do this every time, even if apm is already installed, so you use a copy that was just checked. Run this as one shell command:\n   APM_DIR="$(mktemp -d)" && APM_SCRIPT="$APM_DIR/install.sh" && curl -fsSL https://apmjs.dev/install -o "$APM_SCRIPT" && tail -n 1 "$APM_SCRIPT" | grep -Fqx 'main "$@"' && APM_OUT="$(APM_INSTALL="$HOME/.apm" sh "$APM_SCRIPT")" && printf '%s\\n' "$APM_OUT" && printf '%s\\n' "$APM_OUT" | grep -q '^SHA-256 [0-9a-f]\\{64\\}, checked against this script$' && [ -x "$HOME/.apm/bin/apm" ]\n`,
    );
    expect(p).toContain("checks its SHA-256 against the checksum written into the script, and installs nothing if they differ");
    expect(p).toContain("ask me before installing anything else");
    expect(p).not.toContain("| sh");
    expect(p).not.toContain("git clone");
    expect(p).not.toContain("bun install");
  });

  // a copy installed earlier could have been changed: the installer runs every time and replaces it with a checked one
  test("never runs an apm installed earlier without installing again", () => {
    expect(p).toContain("Do this every time, even if apm is already installed");
    expect(manualSteps(target).split("\n")[0]).toBe('apm() { echo "apm: the install did not succeed, so nothing was run" >&2; return 1; }');
    expect(manualSteps(target)).not.toContain("git");
  });

  // a project or user .npmrc that names npm's registry would otherwise send the login and the upload there
  test("pins every apm command to apm's registry", () => {
    expect(p).toContain('"apm" means: APM_REGISTRY=https://registry.apmjs.dev/ "$HOME/.apm/bin/apm"');
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

    expect(m).toContain(`[ -x "$HOME/.apm/bin/apm" ] && apm() { APM_REGISTRY=https://registry.apmjs.dev/ "$HOME/.apm/bin/apm" "$@"; }`);
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
