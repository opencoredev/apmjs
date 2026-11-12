// The "come back to" path after sign-in. Only a path on this site is allowed; anything a browser could
// read as another host (//host, /\host, /%2F%2Fhost, /<tab>/host) falls back to the account page.

export const DEFAULT_NEXT = "/account";

// Any fixed origin works: a value that resolves to a different origin against it would do the same
// against the real one. A constant keeps this usable during server rendering, where there is no window.
const BASE = "https://apm.invalid";

// Backslashes and control characters: URL parsers turn "\" into "/" and drop tabs and newlines.
const UNSAFE_CHARS = /[\\\p{Cc}]/u;

function isSafePathText(path: string): boolean {
  return path.startsWith("/") && !path.startsWith("//") && !UNSAFE_CHARS.test(path);
}

/** Decodes until the text stops changing (at most a few rounds), or null when it is not valid percent-encoding. */
function fullyDecoded(raw: string): string | null {
  let text = raw;

  for (let round = 0; round < 4; round++) {
    let next: string;

    try {
      next = decodeURIComponent(text);
    } catch {
      return null;
    }

    if (next === text) return text;
    text = next;
  }

  return null;
}

export function safeNext(raw: string | null): string {
  if (!raw) return DEFAULT_NEXT;
  const decoded = fullyDecoded(raw);

  if (decoded === null || !isSafePathText(raw) || !isSafePathText(decoded)) return DEFAULT_NEXT;
  let url: URL;

  try {
    url = new URL(raw, BASE);
  } catch {
    return DEFAULT_NEXT;
  }

  const path = `${url.pathname}${url.search}${url.hash}`;

  // Dot segments can collapse into a protocol-relative path: "/.//evil.example" parses to "//evil.example".
  if (url.origin !== BASE || !isSafePathText(path)) return DEFAULT_NEXT;

  return path;
}
