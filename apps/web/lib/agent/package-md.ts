// The package page as Markdown, for agents: GET /package/<name>.md (or ?format=md) and the check_package MCP
// tool. The same facts as the HTML page, in the order an agent deciding on an install needs them. Pure.
import { citeEvidence } from "../evidence";
import { installCommand, installNote, INSTALL_CLIENTS } from "../install-note";
import { splitPossible, splitTestFile } from "../limitations";
import { fileHref } from "../package-route";
import type { Fetched, PackageInfo, Signal } from "../registry";
import { coverageText, explanation, headline, type ReviewAnswer } from "../review-schema";
import { capabilitiesOf, factLines } from "./capabilities";
import { canonicalPackagePath, siteUrl } from "./site";
import type { ScoreReport } from "./source";
import { codeBlock, inlineCode, points, quoteLine, UNTRUSTED_NOTE } from "./text";

export type PackageView = {
  pkg: PackageInfo;
  /** The version shown: the one asked for with ?v=, else latest. Null when the package has no versions. */
  version: string | null;
  /** That version's score; null when it is not scored yet. */
  score: ScoreReport | null;
  review: Fetched<ReviewAnswer>;
  /** The registry URL install config points at, ending in "/". */
  registry: string;
};

/** Evidence lines listed per signal; the HTML page has the rest. */
const MAX_EVIDENCE = 5;

function evidenceLine(input: { signal: string; evidence: string; name: string; version: string | null }): string {
  const possible = splitPossible(input.evidence);
  const { text, testFile } = splitTestFile(possible.text);
  const cited = citeEvidence(input.signal, text);
  const href = cited && input.version ? fileHref({ name: input.name, version: input.version, ...cited.citation }) : null;
  const tail = [testFile ? "in a test file the package ships" : null, possible.why ? `possible: ${possible.why}` : null].filter(Boolean).join("; ");
  // the cited path is publisher text too, so it sits in a code span inside the link text
  const body = cited && href ? `[${inlineCode(cited.cite)}](${siteUrl(href)})${cited.rest ? ` ${inlineCode(cited.rest.replace(/^:\s*/, ""))}` : ""}` : inlineCode(text);

  return `  - ${body}${tail ? ` (${tail})` : ""}`;
}

function signalBlock(s: Signal, name: string, version: string | null): string[] {
  const head = `- **${s.points < 0 ? `−${points(-s.points)}` : "note"}** ${s.label}${s.confidence === "possible" ? " (possible: named but not seen in use)" : ""} \`${s.id}\``;
  const lines = [head, ...s.evidence.slice(0, MAX_EVIDENCE).map((evidence) => evidenceLine({ signal: s.id, evidence, name, version }))];

  if (s.evidence.length > MAX_EVIDENCE) lines.push(`  - and ${s.evidence.length - MAX_EVIDENCE} more on the page`);

  return lines;
}

function reviewSection(review: Fetched<ReviewAnswer>): string[] {
  if (review.kind === "missing") return ["AI review is not available for this version on this registry."];

  if (review.kind === "unavailable") return ["Could not load the AI review: the registry did not answer."];
  const a = review.value;

  if (a.review === null) {
    switch (a.status) {
      case "queued":
        return ["Status: queued. The AI review of this version has not finished."];
      case "failed":
        return ["Status: failed. The AI review could not run for this version."];
      case "not-reviewed":
      case "reviewed":
        return ["Status: not reviewed."];
      default: {
        const _exhaustive: never = a.status;

        return _exhaustive;
      }
    }
  }

  const r = a.review;
  const lines = [`Status: ${r.state}. ${headline(r)}.`];
  const why = explanation(r);

  if (why) lines.push(why);
  lines.push(`${coverageText(r.coverage)}. Model: ${r.model}. Reviewed ${r.reviewedAt}.`);

  for (const f of r.findings) lines.push(`- ${f.severity}: ${f.file}:${f.line}: ${f.issue}`, `  ${inlineCode(f.excerpt)}`);

  if (r.note) lines.push(`Reviewer note: ${r.note}`);

  return lines;
}

/** The whole Markdown document for one package version. */
export function packageMarkdown(view: PackageView): string {
  const { pkg, version, score } = view;
  const url = siteUrl(canonicalPackagePath(pkg.name));
  const out: string[] = [`# ${pkg.name}`, ""];

  if (pkg.description) out.push(quoteLine(pkg.description), "");
  out.push(
    `- Version shown: ${version ?? "none published"}${version && version !== pkg.latest ? ` (latest is ${pkg.latest ?? "unknown"})` : version ? " (latest)" : ""}`,
    `- Source: ${pkg.source === "upstream" ? "the public npm registry, proxied and scored by apm" : "published to apm"}`,
    `- Score: ${score ? `${score.score}/100, grade ${score.grade}` : "not scored yet"}`,
    `- Page: ${url}${version && version !== pkg.latest ? `?v=${encodeURIComponent(version)}` : ""}`,
    `- Maintainers: ${pkg.maintainers.length ? pkg.maintainers.join(", ") : "unknown"}`,
    "",
    UNTRUSTED_NOTE,
    "",
  );

  const pulled = pkg.versions.filter((v) => v.status !== "active");

  if (pulled.length > 0) out.push("## Pulled versions", "", ...pulled.map((v) => `- ${v.version}: ${v.status}${v.statusReason ? ` (${v.statusReason})` : ""}. New installs skip it.`), "");

  out.push("## Risk signals", "");

  if (!score) out.push("Not scored yet. apm scores a version when it first reads its tarball; ask again in a minute.", "");
  else {
    const lost = score.signals.filter((s) => s.points < 0);
    const notes = score.signals.filter((s) => s.points >= 0);

    if (lost.length === 0) out.push("No signal lost points.");
    else out.push(`${lost.length} signal${lost.length === 1 ? "" : "s"} lost ${points(lost.reduce((n, s) => n - s.points, 0))}. Each cited line links to that line of the file.`, "");

    for (const s of lost) out.push(...signalBlock(s, pkg.name, version));

    if (notes.length > 0) out.push("", "Notes (no points lost):", ...notes.flatMap((s) => signalBlock(s, pkg.name, version)));

    if (score.dismissed.length > 0) out.push("", "Evidence an apm reviewer dismissed for this version:", ...score.dismissed.map((d) => `- ${d.signal} at ${d.file}:${d.line}: ${d.reason}`));
    out.push("");
  }

  out.push("## Capabilities", "");
  const caps = capabilitiesOf(score?.signals ?? null);

  if (caps) out.push(...caps.map((c) => `- ${c.label}: ${c.state}`));
  else out.push("- Code capabilities: unknown until the version is scored");

  if (pkg.facts) out.push(...factLines(pkg.facts).map((f) => `- ${f.label}: ${f.value}`));
  out.push("", "## AI review", "", ...reviewSection(view.review), "");

  out.push("## Install", "", codeBlock(INSTALL_CLIENTS.map((client) => installCommand({ client, name: pkg.name, version })).join("\n"), "sh"), "");
  out.push("`apm add` runs apm's checks itself. Plain bun, npm and pnpm only get them once pointed at apm:", "");

  for (const client of ["bun", "npm"] as const) {
    const note = installNote({ client, registry: view.registry });

    if (note.kind === "needs-setup") out.push(`${client === "npm" ? "npm and pnpm" : client} (${note.file}):`, "", codeBlock(note.config, client === "bun" ? "toml" : "ini"), "");
  }

  out.push("## Not checked", "");
  const notChecked = score?.notChecked ?? [];

  if (notChecked.length === 0) out.push("- What the code does at runtime, the code of its dependencies, or a compromised publisher.");
  else out.push(...notChecked.map((n) => `- ${n}`));

  out.push(
    "",
    "## More",
    "",
    `- Should an agent install it? GET ${siteUrl(`/api/explain?package=${encodeURIComponent(pkg.name)}`)}`,
    `- MCP server: ${siteUrl("/mcp")}`,
    `- API: ${siteUrl("/openapi.json")}`,
  );

  return `${out.join("\n")}\n`;
}
