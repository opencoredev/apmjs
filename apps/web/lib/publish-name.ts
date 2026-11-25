// Whether a name the name check found free can be published on apm. New packages on apm go under the publisher's
// GitHub login, so a bare name that is free on npm is free there, not here. npm's answer (`available`) and this one are
// kept apart. Pure: the home page's name check and the check_name MCP tool share it.

export type Publishability =
  /** a free scoped name: publishable by the owner of that scope, a GitHub login */
  | { readonly kind: "scoped"; readonly scope: string }
  /** a free bare name: not taken on npm, but apm publishes it only under a scope, such as `suggestion` */
  | { readonly kind: "needs-scope"; readonly suggestion: string }
  /** taken, blocked, invalid or not checked: nothing to publish under this name */
  | { readonly kind: "not-free" };

/** `scope`: the publisher's GitHub login when known, for the scoped name to suggest. */
export function publishability(input: { name: string; available: boolean; scope?: string | null }): Publishability {
  const { name, available } = input;

  if (!available) return { kind: "not-free" };

  if (name.startsWith("@")) return { kind: "scoped", scope: name.slice(0, Math.max(name.indexOf("/"), 1)) };

  return { kind: "needs-scope", suggestion: `@${input.scope ?? "you"}/${name}` };
}

/** The name check's short status for a free bare name. */
export const NEEDS_SCOPE_STATUS = "not taken, needs a scope";

/** What a free bare name needs before it can be published, after its status. */
export const needsScopeSentence = (suggestion: string): string => `New packages on apm go under your GitHub login, like ${suggestion}.`;

/** The check_name tool's line for a name npm says is free. */
export function publishabilityText(input: { name: string; publishable: Publishability }): string {
  const { name, publishable: p } = input;

  switch (p.kind) {
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
