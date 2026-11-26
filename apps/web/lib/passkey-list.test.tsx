// The account page's passkey list: one row per passkey the count includes, named by its password manager, its device
// or the name it was added with, and no Remove that would take an account's last way in. Rendered with
// react-dom/server, no browser.
import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { PasskeyList } from "@/app/account/account-view";
import { Account, AuthConfig, canRemovePasskey, deviceName, passkeySubtitle, passkeyTitle, type PasskeyItem } from "./account";

const config = AuthConfig.parse({ providers: { github: true, vercel: false }, passkeys: true });

const onePassword: PasskeyItem = { id: "a", name: "apm 11/15/2026", provider: "1Password", createdAt: "2026-11-15T23:51:11.616Z", lastUsedAt: null };
const chrome: PasskeyItem = { id: "b", name: "Chrome on macOS", provider: null, createdAt: "2026-11-26T00:19:37.185Z", lastUsedAt: "2026-11-26T01:00:00.000Z" };

function account(passkeys: PasskeyItem[], linked: { provider: string; accountId: string }[]) {
  return Account.parse({
    scope: "leo",
    github: "leo",
    name: "Leo",
    email: "leo@example.test",
    image: null,
    linked,
    security: { totp: false, passkeys: passkeys.length },
    passkeys,
    canPublish: passkeys.length > 0,
    tokens: [],
    pending: 0,
  });
}

const github = [{ provider: "github", accountId: "1" }];

describe("passkey names", () => {
  test("the password manager first, then the name it was added with; a dated default name adds nothing", () => {
    expect(passkeyTitle(onePassword)).toBe("1Password");
    expect(passkeySubtitle(onePassword)).toBeNull();
    expect(passkeyTitle(chrome)).toBe("Chrome on macOS");
    expect(passkeySubtitle(chrome)).toBeNull();
    expect(passkeySubtitle({ ...chrome, provider: "Google Password Manager" })).toBe("Chrome on macOS");
    expect(passkeyTitle({ ...chrome, name: null })).toBe("Passkey");
  });

  test("a new passkey is named for the browser and system adding it", () => {
    expect(deviceName("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36")).toBe("Chrome on macOS");
    expect(deviceName("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36 Edg/157.0.0.0")).toBe("Edge on Windows");
    expect(deviceName("Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1")).toBe("Safari on iOS");
    expect(deviceName("Mozilla/5.0 (Linux; Android 16) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Mobile Safari/537.36")).toBe("Chrome on Android");
    expect(deviceName("Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0")).toBe("Firefox on Linux");
    expect(deviceName("curl/8")).toBe("Passkey");
  });
});

describe("the list", () => {
  test("shows one row per passkey the count includes, with when each was added and last used", () => {
    const html = renderToStaticMarkup(<PasskeyList account={account([onePassword, chrome], github)} config={config} onDone={() => {}} />);

    expect(html.match(/<li/g)?.length).toBe(2);
    expect(html).toContain("1Password");
    expect(html).toContain("Chrome on macOS");
    expect(html).toContain("No use recorded yet");
    expect(html).toContain("Last used");
    expect(html.match(/>Remove</g)?.length).toBe(2);
    expect(html).not.toMatch(/ disabled=""/);
  });

  test("an account's last way in cannot be removed: one passkey and nothing linked", () => {
    expect(canRemovePasskey(account([onePassword], github))).toBe(true);
    expect(canRemovePasskey(account([onePassword, chrome], []))).toBe(true);
    expect(canRemovePasskey(account([onePassword], []))).toBe(false);
    const html = renderToStaticMarkup(<PasskeyList account={account([onePassword], [])} config={config} onDone={() => {}} />);

    expect(html).toMatch(/ disabled=""/);
    expect(html).toContain("only way to sign in");
  });

  test("shows nothing without passkeys", () => {
    expect(renderToStaticMarkup(<PasskeyList account={account([], github)} config={config} onDone={() => {}} />)).toBe("");
  });
});
