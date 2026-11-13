// The capabilities a package declares in its package.json (`"apm": { "capabilities": { … } }`), read into one shape.
// A declaration says what the package means to do; apm-score-v10 compares it with what the code shows. Pure.
import { z } from "zod";
import { wildcardMatch } from "./glob.ts";

export const CAPABILITY_IDS = ["network", "env", "filesystem", "shell", "eval", "native", "install"] as const;

export type CapabilityId = (typeof CAPABILITY_IDS)[number];

/** What a package declared for one capability: the patterns it listed (none for a bare reason or `true`), and the text shown. */
export type Declared = { patterns: string[]; shown: string };

/**
 * One capability's declaration: a reason (`"sendmail transport"`), a list (hosts, variable names), or `true`. `false`,
 * `""` and `[]` declare nothing (null).
 */
const Entry = z.union([
  z.literal(true).transform((): Declared => ({ patterns: [], shown: "declared" })),
  z.literal(false).transform(() => null),
  z
    .string()
    .max(500)
    .transform((s): Declared | null => (s === "" ? null : { patterns: [], shown: s })),
  z
    .array(z.string().max(200))
    .max(200)
    .transform((list): Declared | null => (list.length === 0 ? null : { patterns: list, shown: list.join(", ") })),
]);

const DeclarationSchema = z.object({ capabilities: z.record(z.string(), Entry) });

/**
 * A package's declaration. `none`: the package declares nothing apm can read, so only risk signals score it (`notes`
 * says why when an `apm.capabilities` field is there but malformed). `declared`: what each capability says, with notes
 * on keys apm does not know.
 */
export type Declaration = { kind: "none"; notes: string[] } | { kind: "declared"; capabilities: Partial<Record<CapabilityId, Declared>>; notes: string[] };

const HasCapabilities = z.object({ capabilities: z.unknown().refine((v) => v !== undefined) });

function isCapabilityId(key: string): key is CapabilityId {
  return CAPABILITY_IDS.some((id) => id === key);
}

/**
 * Reads `manifest.apm.capabilities`. No such field is no declaration. A field that is there but not an object of
 * strings, lists and booleans is no declaration either, with a note: a typo must not cost a package points.
 */
export function declarationOf(manifest: { readonly apm?: unknown }): Declaration {
  if (!HasCapabilities.safeParse(manifest.apm).success) return { kind: "none", notes: [] };
  const parsed = DeclarationSchema.safeParse(manifest.apm);

  if (!parsed.success) return { kind: "none", notes: ['package.json "apm.capabilities" is not an object of strings, lists or true, so apm read no declaration from it'] };
  const capabilities: Partial<Record<CapabilityId, Declared>> = {};
  const notes: string[] = [];

  for (const [key, value] of Object.entries(parsed.data.capabilities)) {
    if (!isCapabilityId(key)) {
      notes.push(`"${key}" is not a capability apm knows (${CAPABILITY_IDS.join(", ")})`);
      continue;
    }

    if (value !== null) capabilities[key] = value;
  }

  return { kind: "declared", capabilities, notes };
}

/** Whether `name` matches a declared pattern: exact, or `*` standing for any run of characters (`AWS_*`, `*.amazonaws.com`). */
export function matchesPattern(name: string, pattern: string): boolean {
  if (!pattern.includes("*")) return name === pattern;

  return wildcardMatch(name, pattern);
}
