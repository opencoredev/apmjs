// Cited findings of an AI review: file:line, the line itself, and one sentence on what it does.
import type { Finding } from "@/lib/review-schema";

export function FindingList({ findings }: { findings: readonly Finding[] }) {
  return (
    <ol className="flex flex-col divide-y">
      {findings.map((f) => (
        <li key={`${f.file}:${f.line}`} className="flex flex-col gap-2 py-4 first:pt-0 last:pb-0">
          <div className="font-mono text-[13px] [overflow-wrap:anywhere]">
            {f.file}:{f.line}
          </div>
          <pre className="overflow-x-auto rounded-lg bg-surface px-3 py-2 font-mono text-[12.5px] leading-5 whitespace-pre-wrap [overflow-wrap:anywhere]">{f.excerpt}</pre>
          <p className="text-[15px] leading-6 text-pretty">{f.issue}</p>
        </li>
      ))}
    </ol>
  );
}
