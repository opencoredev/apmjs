// Deploy-time settings, parsed from the Worker's environment once per request.
import { Context } from "effect";

export type NamePolicy = "scoped" | "open";

export type RegistrySettings = {
  /** Base URL in tarball links. Ends with "/". */
  readonly baseUrl: string;
  /** The website: sign-in, approval links and the device page. Ends with "/". */
  readonly webUrl: string;
  /** Public registry to proxy, ending with "/", or null for none. */
  readonly upstreamUrl: string | null;
  /** npm's password adduser and password re-auth. Off in production. */
  readonly legacyAuth: boolean;
  /** "scoped": new packages live under the publisher's GitHub login. "open": bare names allowed (tests, legacy). */
  readonly namePolicy: NamePolicy;
  /** GitHub logins (APM_ADMINS) of apm's reviewers: they decide AI review flags and dismiss score evidence. */
  readonly admins: readonly string[];
};

export class RegistryConfig extends Context.Service<RegistryConfig, RegistrySettings>()("@apm/registry/RegistryConfig") {}
