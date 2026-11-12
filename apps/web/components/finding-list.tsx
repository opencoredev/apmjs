// Cited findings of an AI review: file:line (a link to that line of the file), the line itself (none for a revoked
// version), and one sentence on what it does.
import { fileHref } from "@/lib/package-route";
import type { Finding } from "@/lib/review-schema";

export function FindingList({ findings, name, version }: { findings: readonly Finding[]; name: string; version: string }) {
  return (
    <ol className="flex flex-col divide-y">
      {findings.map((f) => {
        const href = fileHref({ name, version, path: f.file, line: f.line });
        const cite = `${f.file}:${f.line}`;

        return (
          <li key={cite} className="flex flex-col gap-2 py-4 first:pt-0 last:pb-0">
            <div className="font-mono text-[13px] [overflow-wrap:anywhere]">
              {href ? (
                // a full page load: the file view reads the #L anchor when it starts
                <a href={href} className="underline decoration-faint underline-offset-[3px] transition-colors hover:decoration-foreground">
                  {cite}
                </a>
              ) : (
                cite
              )}
            </div>
            {/* a revoked version's findings come without the line (packages/registry/src/withheld.ts) */}
            {f.excerpt !== "" && <pre className="overflow-x-auto rounded-lg bg-surface px-3 py-2 font-mono text-[12.5px] leading-5 whitespace-pre-wrap [overflow-wrap:anywhere]">{f.excerpt}</pre>}
            <p className="text-[15px] leading-6 text-pretty">{f.issue}</p>
          </li>
        );
      })}
    </ol>
  );
}
