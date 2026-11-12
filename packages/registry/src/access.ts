// Publishing rules that depend on who someone is: GitHub-scoped names, npm scope reservation,
// "a passkey or 2FA before you publish", and the fresh second factor destructive actions need.
import { actionKey, commandLine, confirmUrl } from "./actions.ts";
import type { ApmAuth } from "./auth.ts";
import type { Store } from "./db.ts";
import { parseSixDigits } from "./factors.ts";
import { checkPassword, LOCKED_MESSAGE } from "./passwords.ts";
import { TOKEN_CAPABILITIES, type Access, type NamePolicy } from "./server.ts";
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
        switch (onNpm) {
          case "found":
            return {
              status: 403,
              error: `@${scope} is a scope on npm, so apm keeps it for the GitHub account "${scope}". Sign in with GitHub as ${scope} (apm login) to publish under it.`,
            };
          case "unknown":
            // fail closed: during an npm outage nobody can tell whether @scope belongs to someone there
            return { status: 503, error: `Cannot check whether @${scope} is a scope on npm right now, so a first publish under it is refused. Try again shortly, or sign in with GitHub (apm login).` };
          case "absent":
            break;
          default: {
            const _exhaustive: never = onNpm;
            return _exhaustive;
          }
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

    async secondFactor({ user, password, otp, action }) {
      const u = store.getUser(user);
      if (legacyAuth && password) {
        if (!u) return { status: 401, error: "Incorrect password." };
        const check = await checkPassword({ store, user, password, hash: u.password_hash, now: now() });

        switch (check) {
          case "ok":
            return null;
          case "bad":
            return { status: 401, error: "Incorrect password." };
          case "locked":
            return { status: 429, error: LOCKED_MESSAGE };
          default: {
            const _exhaustive: never = check;

            return _exhaustive;
          }
        }
      }
      const authId = u?.auth_user_id ?? null;

      if (otp !== undefined) {
        const code = parseSixDigits(otp);

        if (!code) return { status: 400, error: "--otp takes the 6-digit code from your authenticator app." };
        if (!authId) return { status: 401, error: "This account has no authenticator app to check a code against." };
        const check = await auth.checkProof({ authUserId: authId, sessionToken: null, proof: { kind: "totp", code }, purpose: actionKey(action) });
        switch (check.kind) {
          case "ok":
            return null;
          case "bad":
            return { status: 401, error: "That code is not valid. Use the current 6-digit code from your authenticator app." };
          case "reused":
            return { status: 401, error: "That code was already used. Wait for the next code from your authenticator app." };
          case "locked":
            return { status: 429, error: "Too many wrong codes. Wait 15 minutes and try again." };
          case "none":
            return { status: 401, error: `No authenticator app is set up. Set one up at ${webUrl()}account, or confirm this command with your passkey there.` };
          default: {
            const _exhaustive: never = check;
            return _exhaustive;
          }
        }
      }

      // A person confirmed exactly this command on the website: it runs once.
      if (authId && auth.ledger.consumeGrant({ authUserId: authId, action: actionKey(action), at: now() })) return null;
      const link = authId ? ` or approve exactly this command (${commandLine(action)}) at ${confirmUrl(webUrl(), action)} and run it again within 10 minutes` : "";
      return {
        status: 401,
        error: `This needs a fresh second factor as well as your token: pass --otp <code from your authenticator app>${link}.${legacyAuth ? " Password accounts can pass --password-stdin." : ""} A stolen token alone cannot do this.`,
      };
    },

    async liveChangeRefusal({ user, scope, action, otp }) {
      if (TOKEN_CAPABILITIES[scope].liveChanges === "token") return null;

      return this.secondFactor({ user, otp, action });
    },
  };
}
