// Cited findings of an AI review: file:line (a link to that line of the file), the line itself (none for a revoked
// version), and one sentence on what it does. The registry redacts secrets before it sends a finding
// (packages/registry/src/review.ts); the list masks them again, so a key a model quoted never reaches the page even
// from a registry that did not.
import { redactSecrets } from "@apm/core/redact";
import { fileHref } from "@/lib/package-route";
import type { Finding } from "@/lib/review-schema";

export function FindingList({ findings, name, version }: { findings: readonly Finding[]; name: string; version: string }) {
  return (
    <ol className="flex flex-col divide-y">
      {findings.map((f, i) => {
        const file = redactSecrets(f.file);
        // a path with a secret in it is not linked: the link would carry it, and the masked path names no file. A public
        // finding (it carries a label) names its file only as `file N`, which is no path, so it is not linked either
        const href = f.label === undefined && file === f.file ? fileHref({ name, version, path: f.file, line: f.line }) : null;
        const cite = `${file}:${f.line}`;
        const excerpt = redactSecrets(f.excerpt);

        return (
          // a model can cite one line twice: the index keeps keys unique, so React never reuses one row for another
          <li key={`${i}:${cite}`} className="flex flex-col gap-2 py-4 first:pt-0 last:pb-0">
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
            {excerpt !== "" && <pre className="overflow-x-auto rounded-lg bg-surface px-3 py-2 font-mono text-[12.5px] leading-5 whitespace-pre-wrap [overflow-wrap:anywhere]">{excerpt}</pre>}
            <p className="text-[15px] leading-6 text-pretty">{redactSecrets(f.issue)}</p>
          </li>
        );
      })}
    </ol>
  );
}
