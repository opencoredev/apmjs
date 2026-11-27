// Whether a name the name check found free can be published on apm. New packages on apm go under the publisher's
// GitHub login, so a bare name that is free on npm is free there, not here, unless the registry's name policy is open
// (the rule of core newNameRuleRefusal, which the registry and apm publish run). npm's answer (`available`) and this one
// are kept apart. Pure: the home page's name check and the check_name MCP tool share it.

/** The registry's rule for new bare names (GET /-/apm/v1/auth/config `namePolicy`), as core's NamePolicy. */
export type NamePolicy = "scoped" | "open";


export type Publishability =
  /** a free scoped name under the publisher's own scope (`scope` matches it) */
  | { readonly kind: "yours"; readonly scope: string }
  /** a free scoped name when the publisher is not known: publishable by the owner of that scope, a GitHub login */
  | { readonly kind: "scoped"; readonly scope: string }
  /** a free scoped name under someone else's scope: only that scope's owner can publish it, not `yours` */
  | { readonly kind: "not-yours"; readonly scope: string; readonly yours: string }
  /** a free bare name: not taken on npm, but apm publishes it only under a scope, such as `suggestion` */
  | { readonly kind: "needs-scope"; readonly suggestion: string }
  /** a free bare name on a registry whose name policy is open: anyone can publish it */
  | { readonly kind: "open" }
  /** a free bare name on a registry whose name policy could not be read: whether it needs a scope is not known */
  | { readonly kind: "policy-unknown"; readonly suggestion: string }
  /** taken, blocked, invalid or not checked: nothing to publish under this name */
  | { readonly kind: "not-free" };

/** `scope`: the publisher's GitHub login when known, for the scoped name to suggest. `policy`: the registry's rule for new bare names, null when it could not be read. */
export function publishability(input: { name: string; available: boolean; scope?: string | null; policy: NamePolicy | null }): Publishability {
  const { name, available } = input;

  if (!available) return { kind: "not-free" };

  if (name.startsWith("@")) {
    const scope = name.slice(0, Math.max(name.indexOf("/"), 1));

    if (!input.scope) return { kind: "scoped", scope };

    return scope === `@${input.scope.toLowerCase()}` ? { kind: "yours", scope } : { kind: "not-yours", scope, yours: `@${input.scope}` };
  }

  const suggestion = `@${input.scope ?? "you"}/${name}`;

  if (input.policy === null) return { kind: "policy-unknown", suggestion };

  return input.policy === "open" ? { kind: "open" } : { kind: "needs-scope", suggestion };
}

/** Whether the caller may publish the name: the check_name tool's `available`, as in apm name --json. */
export const mayPublish = (p: Publishability): boolean => p.kind === "yours" || p.kind === "open";

/** The name check's short status for a free name under a scope that is not, or not known to be, the visitor's. */
export const OWNER_ONLY_STATUS = "free, scope owner only";

/** Who is looking at the name check: signed in (their scope, as @login), signed out, still being asked, or unknown (the ask failed). */
export type Viewer = { readonly kind: "signed-in"; readonly scope: string } | { readonly kind: "signed-out" } | { readonly kind: "checking" } | { readonly kind: "unknown" };

/** Who may publish a free name under `scope`, after its status, and what that means for this viewer. */
export function ownerOnlySentence(scope: string, viewer: Viewer): string {
  const owner = `Only the GitHub account ${scope.slice(1)} can publish under ${scope}.`;

  switch (viewer.kind) {
    case "signed-in":
      return `${owner} Yours is ${viewer.scope}.`;
    case "signed-out":
      return `${owner} Sign in with GitHub to see whether that is you.`;
    case "checking":
      return owner;
    case "unknown":
      return `${owner} apm could not check whether that is you.`;
    default: {
      const _exhaustive: never = viewer;

      return _exhaustive;
    }
  }
}

/** The name check's short status for a free bare name. */
export const NEEDS_SCOPE_STATUS = "not taken, needs a scope";

/** What a free bare name needs before it can be published, after its status. */
export const needsScopeSentence = (suggestion: string): string => `New packages on apm go under your GitHub login, like ${suggestion}.`;

/** The check_name tool's line for a name npm says is free. */
export function publishabilityText(input: { name: string; publishable: Publishability }): string {
  const { name, publishable: p } = input;

  switch (p.kind) {
    case "yours":
      return `${name} is available. ${p.scope} is your GitHub login, so you can publish it.`;
    case "not-yours":
      return `${name} is free, but only the owner of ${p.scope} can publish it. Yours is ${p.yours}.`;
    case "scoped":
      return `${name} is free; only the owner of ${p.scope} (a GitHub login) can publish it.`;
    case "needs-scope":
      return `${name} is ${NEEDS_SCOPE_STATUS}. ${needsScopeSentence(p.suggestion)}`;
    case "open":
      return `${name} is available.`;
    case "policy-unknown":
      return `${name} is free, but apm could not read this registry's rules for new names, so it cannot say whether you may publish it. apm's own registry takes a new package only under your GitHub login, like ${p.suggestion}.`;
    case "not-free":
      return `${name} is not free to publish.`;
    default: {
      const _exhaustive: never = p;

      return _exhaustive;
    }
  }
}
