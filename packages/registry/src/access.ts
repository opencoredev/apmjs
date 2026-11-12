// Publishing rules that depend on who someone is: GitHub-scoped names, npm scope reservation,
// "a passkey or 2FA before you publish", and the fresh second factor destructive actions need.
import { Effect, Option } from "effect";
import { actionKey, commandLine, confirmUrl, type LiveAction } from "./actions.ts";
import { Auth } from "./auth.ts";
import { Clock } from "./clock.ts";
import { RegistryConfig } from "./config.ts";
import { Store } from "./db.ts";
import type { AuthError, StoreError } from "./errors.ts";
import { parseSixDigits } from "./factors.ts";
import { checkPassword, LOCKED_MESSAGE } from "./passwords.ts";
import { Upstream } from "./upstream.ts";

export type Refusal = { status: number; error: string };

/** "publish" tokens go live at once (legacy logins, test tokens, later CI trusted publishing); "stage" tokens need approval. */
export type TokenScope = "publish" | "stage";

/**
 * What each kind of token may do. A staging token (apm login, the website's device flow) uploads versions that wait
 * for a person, and changes live state (dist-tags, deprecate, yank, unyank) only with a fresh second factor.
 */
export const TOKEN_CAPABILITIES: Record<TokenScope, { publish: "live" | "staged"; liveChanges: "token" | "second-factor" }> = {
  publish: { publish: "live", liveChanges: "token" },
  stage: { publish: "staged", liveChanges: "second-factor" },
};

export type AccessServices = Store | Auth | Clock | RegistryConfig;

type Checked = Effect.Effect<Refusal | null, StoreError | AuthError, AccessServices>;

const isVerified = (user: string) =>
  Effect.map(Store.use((store) => store.getUser(user)), (u) => u !== null && u.auth_user_id !== null && u.github_id !== null);

/** Why `user` may not publish a first version of `name`, or null. */
export const newNameRefusal = (name: string, user: string): Checked =>
  Effect.gen(function* () {
    const { namePolicy } = yield* RegistryConfig;
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

    const upstream = yield* Effect.serviceOption(Upstream);

    if (Option.isSome(upstream) && !(yield* isVerified(user))) {
      const onNpm = yield* upstream.value.scopeExists(scope);

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
  });

/** Why `user` may not publish to `name` (owners for existing packages, the name policy for new ones), or null. */
export const publishRefusal = (name: string, user: string): Checked =>
  Effect.gen(function* () {
    const store = yield* Store;
    const pkg = yield* store.getPackage(name);

    if (pkg) {
      const owners = yield* store.owners(name);

      return owners.includes(user) ? null : { status: 403, error: `You do not have permission to publish "${name}". Owners: ${owners.join(", ")}` };
    }

    return yield* newNameRefusal(name, user);
  });

/** Why `user` may not stage a publish (no passkey or 2FA), or null. */
export const stageRefusal = (user: string): Checked =>
  Effect.gen(function* () {
    const u = yield* Store.use((store) => store.getUser(user));

    if (!u?.auth_user_id) return { status: 403, error: "This token is not tied to a signed-in account. Run apm login, then publish again." };
    const f = yield* Auth.use((auth) => auth.factors(u.auth_user_id ?? ""));

    if (!f.totp && f.passkeys === 0) {
      const { webUrl } = yield* RegistryConfig;

      return {
        status: 403,
        error: `Set up 2FA (an authenticator app) or a passkey at ${webUrl}account before you publish. A person confirms every publish with one of them.`,
      };
    }

    return null;
  });

/**
 * Why `user` may not do `action` with this proof, or null. A password counts only in legacy mode; a TOTP code
 * counts once; with neither, a website confirmation of exactly this command counts once.
 */
export const secondFactor = (input: { user: string; password?: string | undefined; otp?: string | undefined; action: LiveAction }): Checked =>
  Effect.gen(function* () {
    const { legacyAuth, webUrl } = yield* RegistryConfig;
    const store = yield* Store;
    const u = yield* store.getUser(input.user);

    if (legacyAuth && input.password) {
      if (!u) return { status: 401, error: "Incorrect password." };
      const check = yield* checkPassword({ user: input.user, password: input.password, hash: u.password_hash, now: yield* (yield* Clock).now });

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

    if (input.otp !== undefined) {
      const code = parseSixDigits(input.otp);

      if (!code) return { status: 400, error: "--otp takes the 6-digit code from your authenticator app." };

      if (!authId) return { status: 401, error: "This account has no authenticator app to check a code against." };
      const check = yield* Auth.use((auth) => auth.checkCode({ authUserId: authId, proof: { kind: "totp", code } }));

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
          return { status: 401, error: `No authenticator app is set up. Set one up at ${webUrl}account, or confirm this command with your passkey there.` };
        default: {
          const _exhaustive: never = check;

          return _exhaustive;
        }
      }
    }

    // A person confirmed exactly this command on the website: it runs once.
    if (authId && (yield* store.consumeGrant({ authUserId: authId, action: actionKey(input.action), at: yield* (yield* Clock).now }))) return null;
    const link = authId ? ` or approve exactly this command (${commandLine(input.action)}) at ${confirmUrl(webUrl, input.action)} and run it again within 10 minutes` : "";

    return {
      status: 401,
      error: `This needs a fresh second factor as well as your token: pass --otp <code from your authenticator app>${link}.${legacyAuth ? " Password accounts can pass --password-stdin." : ""} A stolen token alone cannot do this.`,
    };
  });

/** Why this token may not change live state (`action`), or null. Staging tokens need a fresh second factor for it. */
export const liveChangeRefusal = (input: { user: string; scope: TokenScope; action: LiveAction; otp?: string | undefined }): Checked =>
  TOKEN_CAPABILITIES[input.scope].liveChanges === "token" ? Effect.succeed(null) : secondFactor({ user: input.user, otp: input.otp, action: input.action });
