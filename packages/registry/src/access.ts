// Publishing rules that depend on who someone is: GitHub-scoped names, npm scope reservation,
// "a passkey or 2FA before you publish", and the fresh second factor destructive actions need.
import { STEPUP_MS, type ApmAuth } from "./auth.ts";
import type { Store } from "./db.ts";
import type { Access, NamePolicy } from "./server.ts";
import type { Upstream } from "./upstream.ts";

export function buildAccess(input: {
  store: Store;
  auth: ApmAuth;
  upstream: Upstream | null;
  legacyAuth: boolean;
  namePolicy: NamePolicy;
  webUrl: () => string;
  now: () => number;
}): Access {
  const { store, auth, upstream, legacyAuth, namePolicy, webUrl, now } = input;

  const isVerified = (user: string): boolean => {
    const u = store.getUser(user);
    return u !== null && u.auth_user_id !== null && u.github_id !== null;
  };

  return {
    legacyAuth,
    namePolicy,
    webUrl,

    async newNameRefusal({ name, user }) {
      const slash = name.indexOf("/");
      const bare = name.startsWith("@") ? name.slice(slash + 1) : name;
      if (!name.startsWith("@")) {
        if (namePolicy === "open") return null;
        return {
          status: 403,
          error: `New packages on apm are scoped to your GitHub login. Publish this as @${user}/${bare} (set "name" in package.json). A bare name like "${bare}" always means the npm package, so apm does not hand out bare names.`,
        };
      }
      const scope = name.slice(1, slash);
      if (scope !== user) {
        return { status: 403, error: `You cannot publish under @${scope}. New packages go under your own scope: @${user}/${bare}.` };
      }
      if (!isVerified(user) && upstream) {
        const onNpm = await upstream.scopeExists(scope);
        if (onNpm === "found") {
          return {
            status: 403,
            error: `@${scope} is a scope on npm, so apm keeps it for the GitHub account "${scope}". Sign in with GitHub as ${scope} (apm login) to publish under it.`,
          };
        }
      }
      return null;
    },

    stageRefusal(user) {
      const u = store.getUser(user);
      if (!u?.auth_user_id) return { status: 403, error: "This token is not tied to a signed-in account. Run apm login, then publish again." };
      const f = auth.factors(u.auth_user_id);
      if (!f.totp && f.passkeys === 0) {
        return {
          status: 403,
          error: `Set up 2FA (an authenticator app) or a passkey at ${webUrl()}account before you publish. A person confirms every publish with one of them.`,
        };
      }
      return null;
    },

    async secondFactor({ user, password, otp }) {
      const u = store.getUser(user);
      if (legacyAuth && password) {
        if (u && u.password_hash !== "" && (await Bun.password.verify(password, u.password_hash))) return null;
        return { status: 401, error: "Incorrect password." };
      }
      const authId = u?.auth_user_id ?? null;
      if (otp) {
        if (!authId) return { status: 401, error: "This account has no authenticator app to check a code against." };
        const check = await auth.verifyTotp(authId, otp.trim());
        switch (check.kind) {
          case "ok":
            return null;
          case "bad":
            return { status: 401, error: "That code is not valid. Use the current 6-digit code from your authenticator app." };
          case "locked":
            return { status: 429, error: "Too many wrong codes. Wait 15 minutes and try again." };
          case "none":
            return { status: 401, error: `No authenticator app is set up. Set one up at ${webUrl()}account, or confirm with your passkey there.` };
          default: {
            const _exhaustive: never = check;
            return _exhaustive;
          }
        }
      }
      if (authId) {
        const at = store.stepupAt(authId);
        const t = now();
        if (at !== null && at <= t && t - at <= STEPUP_MS) return null;
      }
      return {
        status: 401,
        error: `This needs a fresh second factor as well as your token: pass --otp <code from your authenticator app>, or confirm with your passkey or code at ${webUrl()}account and run it again within 10 minutes.${legacyAuth ? " Password accounts can pass --password-stdin." : ""} A stolen token alone cannot do this.`,
      };
    },
  };
}
