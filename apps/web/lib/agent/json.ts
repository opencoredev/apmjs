// JSON text in, a JSON value out: the one place agent code turns a body into data before a schema reads it.
import { z } from "zod";

export type Json = z.core.util.JSONType;

const JsonValue = z.json();

/** The parsed value, or null when the text is not JSON. */
export function parseJson(text: string): { value: Json } | null {
  try {
    const parsed = JsonValue.safeParse(JSON.parse(text));

    return parsed.success ? { value: parsed.data } : null;
  } catch {
    return null;
  }
}
