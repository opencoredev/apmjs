// Whether a name the name check found free can be published on apm. New packages on apm go under the publisher's
// GitHub login, so a bare name that is free on npm is free there, not here. npm's answer (`available`) and this one are
// kept apart. Pure: the home page's name check and the check_name MCP tool share it.

export type Publishability =
  /** a free scoped name under the publisher's own scope (`scope` matches it) */
  | { readonly kind: "yours"; readonly scope: string }
  /** a free scoped name when the publisher is not known: publishable by the owner of that scope, a GitHub login */
  | { readonly kind: "scoped"; readonly scope: string }
  /** a free scoped name under someone else's scope: only that scope's owner can publish it, not `yours` */
  | { readonly kind: "not-yours"; readonly scope: string; readonly yours: string }
  /** a free bare name: not taken on npm, but apm publishes it only under a scope, such as `suggestion` */
  | { readonly kind: "needs-scope"; readonly suggestion: string }
  /** taken, blocked, invalid or not checked: nothing to publish under this name */
  | { readonly kind: "not-free" };

/** `scope`: the publisher's GitHub login when known, for the scoped name to suggest. */
export function publishability(input: { name: string; available: boolean; scope?: string | null }): Publishability {
  const { name, available } = input;

  if (!available) return { kind: "not-free" };

  if (name.startsWith("@")) {
    const scope = name.slice(0, Math.max(name.indexOf("/"), 1));

    if (!input.scope) return { kind: "scoped", scope };

    return scope === `@${input.scope.toLowerCase()}` ? { kind: "yours", scope } : { kind: "not-yours", scope, yours: `@${input.scope}` };
  }

  return { kind: "needs-scope", suggestion: `@${input.scope ?? "you"}/${name}` };
}

/** The name check's short status for a free name under a scope that is not, or not known to be, the visitor's. */
export const OWNER_ONLY_STATUS = "free, scope owner only";

/** Who may publish a free name under `scope`, after its status; `yours` is the visitor's scope when signed in. */
export const ownerOnlySentence = (scope: string, yours: string | null): string =>
  `Only the GitHub account ${scope.slice(1)} can publish under ${scope}. ${yours === null ? "Sign in with GitHub to see whether that is you." : `Yours is ${yours}.`}`;

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
      return `${name} is available. You can publish it if ${p.scope} is your GitHub login.`;
    case "needs-scope":
      return `${name} is ${NEEDS_SCOPE_STATUS}. ${needsScopeSentence(p.suggestion)}`;
    case "not-free":
      return `${name} is not free to publish.`;
    default: {
      const _exhaustive: never = p;

      return _exhaustive;
    }
  }
}
