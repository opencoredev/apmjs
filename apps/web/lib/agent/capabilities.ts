// What a version can do, read from its score: the four code capabilities the scorer looks for, and the
// facts that matter before an install (install scripts, a binary). "possible" means apm saw the capability
// named but not used, the same distinction the score panel draws.
import type { Facts, Signal } from "../registry";

export const CAPABILITIES = [
  { id: "network", label: "Network access" },
  { id: "shell-exec", label: "Runs shell commands" },
  { id: "credential-access", label: "Reads credentials or secrets" },
  { id: "eval", label: "Evaluates code built at runtime" },
] as const;

export type CapabilityId = (typeof CAPABILITIES)[number]["id"];

export type CapabilityState = "seen" | "possible" | "not seen";

export type Capability = { id: CapabilityId; label: string; state: CapabilityState };

/** Each capability's state in one version's signals; null signals (not scored) give null. */
export function capabilitiesOf(signals: readonly Signal[] | null): Capability[] | null {
  if (signals === null) return null;

  return CAPABILITIES.map(({ id, label }) => {
    const found = signals.filter((s) => s.id === id);
    const state: CapabilityState = found.some((s) => s.confidence === "confirmed") ? "seen" : found.length > 0 ? "possible" : "not seen";

    return { id, label, state };
  });
}

/** The package facts as label/value lines, in the order the page's "At a glance" panel shows them. */
export function factLines(facts: Facts): { label: string; value: string }[] {
  return [
    { label: "Install scripts", value: facts.installScripts ? "yes" : "none" },
    { label: "Ships a command-line binary", value: facts.hasBin ? "yes" : "no" },
    { label: "Module format", value: facts.moduleFormat === "dual" ? "ESM + CJS" : facts.moduleFormat.toUpperCase() },
    { label: "Types", value: facts.types === "bundled" ? "included" : "none" },
    { label: "Dependencies", value: String(facts.dependencyCount) },
    { label: "License", value: facts.license ?? "none" },
    { label: "Files", value: String(facts.fileCount) },
    { label: "Unpacked size", value: `${facts.unpackedSize} bytes` },
  ];
}
