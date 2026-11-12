// The model's reply, parsed. Anything that is not a JSON object with a known verdict is an empty
// answer; findings that are malformed are counted and dropped, never guessed at.
import { z } from "zod";

export const VERDICTS = ["malicious", "suspicious", "benign"] as const;

export type ModelVerdict = (typeof VERDICTS)[number];

export const SEVERITIES = ["high", "medium", "low"] as const;

export type Severity = (typeof SEVERITIES)[number];

const RawFinding = z.object({
  file: z.string().min(1).max(1000),
  line: z.coerce.number().int(),
  quote: z.string().min(1),
  issue: z.string().catch(""),
  severity: z.enum(SEVERITIES).catch("medium"),
});

export type RawFinding = z.infer<typeof RawFinding>;

const RawReply = z.object({
  verdict: z.enum(VERDICTS),
  confidence: z.coerce.number().min(0).max(1).catch(0),
  summary: z.string().catch(""),
  findings: z.array(z.unknown()).catch([]),
});

export type EmptyReason = "no-content" | "output-cap" | "no-json" | "bad-verdict" | "request-failed";

export type ModelReply =
  | { kind: "answer"; verdict: ModelVerdict; confidence: number; summary: string; findings: RawFinding[]; malformed: number }
  | { kind: "empty"; reason: EmptyReason };

/** The first JSON object in a reply that may be wrapped in a code fence or prose. */
function jsonIn(content: string): { ok: true; value: unknown } | { ok: false } {
  const s = content
    .trim()
    .replace(/^```(?:json)?\s*/, "")
    .replace(/```\s*$/, "");

  try {
    return { ok: true, value: JSON.parse(s) };
  } catch {
    const a = s.indexOf("{");
    const b = s.lastIndexOf("}");

    if (a < 0 || b <= a) return { ok: false };

    try {
      return { ok: true, value: JSON.parse(s.slice(a, b + 1)) };
    } catch {
      return { ok: false };
    }
  }
}

/** `finishReason` "length" means the model spent its output cap (usually reasoning through obfuscation). */
export function parseReply(content: string, finishReason: string | null = null): ModelReply {
  if (content.trim() === "") return { kind: "empty", reason: finishReason === "length" ? "output-cap" : "no-content" };
  const json = jsonIn(content);

  if (!json.ok) return { kind: "empty", reason: finishReason === "length" ? "output-cap" : "no-json" };
  const reply = RawReply.safeParse(json.value);

  if (!reply.success) return { kind: "empty", reason: "bad-verdict" };
  const findings: RawFinding[] = [];
  let malformed = 0;

  for (const raw of reply.data.findings) {
    const f = RawFinding.safeParse(raw);

    if (f.success) findings.push(f.data);
    else malformed++;
  }

  return { kind: "answer", verdict: reply.data.verdict, confidence: reply.data.confidence, summary: reply.data.summary.slice(0, 2000), findings, malformed };
}
