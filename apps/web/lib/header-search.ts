// The header search lives in the root layout, so React keeps its text across client navigations. A query
// typed on one page must not stay in the field on the next: every new page starts with an empty field.

export type HeaderSearch = { path: string; value: string };

/** The field's state after the router lands on `pathname`: unchanged on the same page, empty on a new one. */
export function afterNavigation(state: HeaderSearch, pathname: string): HeaderSearch {
  return state.path === pathname ? state : { path: pathname, value: "" };
}
