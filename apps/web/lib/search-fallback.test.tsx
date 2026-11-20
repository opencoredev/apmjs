// Both search boxes must work before React hydrates. A package page streams for a couple of seconds first, and Enter
// in a form with no action reloads the current page with ?q= appended (the "it sends me back to next" report). The
// server-rendered HTML alone has to send the query to /?q=<query>. Rendered with react-dom/server, no browser.
import { describe, expect, mock, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

let pathname = "/package/next";

void mock.module("next/navigation", () => ({
  usePathname: () => pathname,
  useRouter: () => ({ push: () => undefined, replace: () => undefined, prefetch: () => undefined }),
}));

const { SearchBar } = await import("@/components/search-bar");
const { SearchHome } = await import("@/components/search-home");

/** The opening tag of the one element matching `pattern`. */
function tag(html: string, pattern: RegExp): string {
  const found = html.match(pattern);
  expect(found?.length).toBe(1);

  return found?.[0] ?? "";
}

function attr(openTag: string, name: string): string | null {
  return openTag.match(new RegExp(`\\s${name}="([^"]*)"`))?.[1] ?? null;
}

describe("header search before hydration", () => {
  const html = renderToStaticMarkup(<SearchBar />);
  const form = tag(html, /<form[^>]*>/g);
  const input = tag(html, /<input[^>]*>/g);

  test("the form is a GET to the home page, so Enter opens /?q=<query> and not the current page", () => {
    expect(attr(form, "action")).toBe("/");
    expect(attr(form, "method")).toBe("get");
  });

  test("the input is the q parameter, the one the home page reads", () => {
    expect(attr(input, "name")).toBe("q");
  });

  test("the input is a closed combobox until there is something to show", () => {
    expect(attr(input, "role")).toBe("combobox");
    expect(attr(input, "aria-expanded")).toBe("false");
    expect(attr(input, "aria-autocomplete")).toBe("list");
    expect(attr(input, "aria-controls")).toBeNull();
    expect(html).not.toContain('role="listbox"');
  });

  test("the header box is not drawn on the home page, which has its own", () => {
    pathname = "/";
    expect(renderToStaticMarkup(<SearchBar />)).toBe("");
    pathname = "/package/next";
  });
});

describe("home search before hydration", () => {
  const html = renderToStaticMarkup(<SearchHome recent={<p>popular</p>} />);
  const form = tag(html, /<form[^>]*>/g);
  const input = tag(html, /<input[^>]*type="search"[^>]*>/g);

  test("Enter before hydration loads /?q=<query>, which the hydrated page turns into results", () => {
    expect(attr(form, "action")).toBe("/");
    expect(attr(form, "method")).toBe("get");
    expect(attr(input, "name")).toBe("q");
  });
});
