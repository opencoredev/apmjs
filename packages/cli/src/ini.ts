// .npmrc files as npm reads them (review of efef668, finding 3): npm parses them with its `ini` package, so a quoted
// value loses its quotes, an unquoted one ends at the first unescaped ; or #, `key[]=` lines make a list, a bare `key`
// is true, and a key under a [section] is not a top-level setting. `${VAR}` in a value is the environment's VAR.
//
// What starts a section depends on the ini version (review of a24c6aa, finding 1): before ini 4.1.0 the line must end
// at its `]`; from 4.1.0 whitespace may follow it. A `[section] ` line is a section to npm 11 (ini 6) and to upstream
// npm 9.6 and later, and the bare key `[section] ` to Debian's npm 9.2 (ini 3.0.1) and to pnpm 10 (checked on 10.18.3).
import { z } from "zod";

/** One value a line sets: text, or the literal true, false or null (`key=true`, a bare `key`, `key=null`). */
export type IniScalar = { kind: "text"; text: string } | { kind: "literal"; value: boolean | null };

/** A key's value: one, or the list `key[]=` lines build. */
export type IniValue = { kind: "one"; item: IniScalar } | { kind: "list"; items: IniScalar[] };

export const text = (t: string): IniScalar => ({ kind: "text", text: t });

const isQuoted = (v: string): boolean => (v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"));

/** A JSON string literal, read; anything else as it is. */
export function jsonText(v: string): string {
  try {
    const parsed = z.string().safeParse(JSON.parse(v));

    return parsed.success ? parsed.data : v;
  } catch {
    return v;
  }
}

/** ini's `unsafe`: a quoted value is unquoted (JSON for double quotes); an unquoted one ends at an unescaped ; or #. */
function unquote(raw: string): string {
  const v = raw.trim();

  if (isQuoted(v)) return jsonText(v.startsWith("'") ? v.slice(1, -1) : v);
  let out = "";
  let escaped = false;

  for (const c of v) {
    if (escaped) {
      out += "\\;#".includes(c) ? c : `\\${c}`;
      escaped = false;
    } else if (c === ";" || c === "#") {
      break;
    } else if (c === "\\") {
      escaped = true;
    } else {
      out += c;
    }
  }

  return (escaped ? `${out}\\` : out).trim();
}

/** ini reads true, false and null (quoted or not) as literals. */
function literal(v: string): IniScalar {
  switch (v) {
    case "true":
      return { kind: "literal", value: true };
    case "false":
      return { kind: "literal", value: false };
    case "null":
      return { kind: "literal", value: null };
    default:
      return text(v);
  }
}

/** How a section header may end: `exact` at its `]` (ini before 4.1.0), or `spaced`, with whitespace after it (4.1.0 on). */
export type SectionSyntax = "exact" | "spaced";

const LINE: Record<SectionSyntax, RegExp> = {
  exact: /^\[([^\]]*)\]$|^([^=]+)(=(.*))?$/,
  spaced: /^\[([^\]]*)\]\s*$|^([^=]+)(=(.*))?$/,
};

/** The top-level settings of an .npmrc, as ini decodes them. A later plain line for a key replaces an earlier one. */
export function decodeIni(source: string, sections: SectionSyntax): Map<string, IniValue> {
  const out = new Map<string, IniValue>();
  let inSection = false;

  for (const line of source.split(/[\r\n]+/)) {
    if (line === "" || /^\s*[;#]/.test(line)) continue;
    const m = LINE[sections].exec(line);

    if (m === null) continue;

    if (m[1] !== undefined) {
      inSection = true;
      continue;
    }

    if (inSection) continue;
    const keyRaw = unquote(m[2] ?? "");
    const isList = keyRaw.length > 2 && keyRaw.endsWith("[]");
    const key = isList ? keyRaw.slice(0, -2) : keyRaw;

    if (key === "__proto__") continue;
    const value: IniScalar = m[3] === undefined ? { kind: "literal", value: true } : literal(unquote(m[4] ?? ""));
    const had = out.get(key);

    // a list stays a list: a plain line after `key[]=` lines adds to it, a `key[]=` after a plain line starts one
    if (had?.kind === "list") had.items.push(value);
    else if (isList) out.set(key, { kind: "list", items: had === undefined ? [value] : [had.item, value] });
    else out.set(key, { kind: "one", item: value });
  }

  return out;
}

/** npm's `${VAR}` replacement: an unset VAR stays as written, and `\${VAR}` is the text itself. */
export function envReplace(value: string, env: Readonly<Record<string, string | undefined>>): string {
  return value.replace(/(?<!\\)(\\*)\$\{([^${}]+)\}/g, (orig: string, esc: string, name: string) => {
    const val = env[name] ?? `\${${name}}`;

    if (esc.length % 2 === 1) return orig.slice((esc.length + 1) / 2);

    return esc.slice(esc.length / 2) + val;
  });
}
