// The package page as Markdown, for agents: GET /package/<name>.md (or ?format=md) and the check_package MCP
// tool. The same facts as the HTML page, in the order an agent deciding on an install needs them. Pure.
import { citeEvidence } from "../evidence";
import { installCommand, installNote, INSTALL_CLIENTS } from "../install-note";
import { splitPossible, splitTestFile } from "../limitations";
import { fileHref } from "../package-route";
import type { Facts, Fetched, PackageInfo, Signal } from "../registry";
import { coverageText, explanation, headline, type ReviewAnswer } from "../review-schema";
import { capabilitiesOf, factLines } from "./capabilities";
import { canonicalPackagePath, siteUrl } from "./site";
import type { ScoreReport } from "./source";
import { codeBlock, inlineCode, linkUrl, oneLine, points, UNTRUSTED_NOTE } from "./text";

export type PackageView = {
  pkg: PackageInfo;
  /** The version shown: the one asked for with ?v=, else latest. Null when the package has no versions. */
  version: string | null;
  /** That version's own state, from the versions route; null when there is no version. */
  status: { status: string; statusReason: string | null; deprecated: string | null } | null;
  /** That version's own facts (not latest's); null when it is not scored yet. */
  facts: Facts | null;
  /** That version's score; null when it is not scored yet. */
  score: ScoreReport | null;
  review: Fetched<ReviewAnswer>;
  /** The registry URL install config points at, ending in "/". */
  registry: string;
};

/** Evidence lines listed per signal; the HTML page has the rest. */
const MAX_EVIDENCE = 5;

/** A version string as written when it is a plain version (all an npm registry accepts), else quoted. */
function versionText(v: string): string {
  return /^[0-9A-Za-z.+-]{1,256}$/.test(v) ? v : inlineCode(v);
}

/** A registry word (active, yanked, revoked) as written when it is one, else quoted. */
function wordText(s: string): string {
  return /^[a-z][a-z-]{0,40}$/.test(s) ? s : inlineCode(s);
}

function evidenceLine(input: { signal: string; evidence: string; name: string; version: string | null }): string {
  const possible = splitPossible(input.evidence);
  const { text, testFile } = splitTestFile(possible.text);
  const cited = citeEvidence(input.signal, text);
  const href = cited && input.version ? fileHref({ name: input.name, version: input.version, ...cited.citation }) : null;
  const tail = [testFile ? "in a test file the package ships" : null, possible.why ? `possible: ${inlineCode(possible.why)}` : null].filter(Boolean).join("; ");
  // the cited path is publisher text too, so it sits in a code span inside the link text
  const rest = cited ? cited.rest.replace(/^:\s*/, "") : "";
  const body = cited && href ? `[${inlineCode(cited.cite)}](${linkUrl(siteUrl(href))})${rest ? ` ${inlineCode(rest)}` : ""}` : inlineCode(text);

  return `  - ${body}${tail ? ` (${tail})` : ""}`;
}

function signalBlock(s: Signal, name: string, version: string | null): string[] {
  const head = `- **${s.points < 0 ? `−${points(-s.points)}` : "note"}** ${oneLine(s.label)}${s.confidence === "possible" ? " (possible: named but not seen in use)" : ""} ${inlineCode(s.id)}`;
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
        return [a.job === "leased" ? "Status: running. The AI review of this version has not finished." : "Status: queued. The AI review of this version has not started."];
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
  lines.push(`${coverageText(r.coverage)}. Model: ${inlineCode(r.model)}. Reviewed ${inlineCode(r.reviewedAt)}.`);

  // findings and the note are the AI's and a reviewer's words about publisher code: quoted, the excerpt as a block
  for (const [i, f] of r.findings.entries()) lines.push("", `Finding ${i + 1} (${f.severity}) at ${inlineCode(`${f.file}:${f.line}`)}: ${inlineCode(f.issue)}`, "", codeBlock(f.excerpt));

  if (r.note) lines.push("", "Reviewer note:", "", codeBlock(r.note));

  return lines;
}

function statusLine(status: NonNullable<PackageView["status"]>): string {
  const reason = status.statusReason ? `, reason ${inlineCode(status.statusReason)}` : "";

  return status.status === "active" ? "- Status: active" : `- Status: ${wordText(status.status)}${reason}. New installs skip it.`;
}

/** The whole Markdown document for one package version. */
export function packageMarkdown(view: PackageView): string {
  const { pkg, version, score } = view;
  const url = siteUrl(canonicalPackagePath(pkg.name));
  const older = version !== null && version !== pkg.latest;
  const out: string[] = [`# ${oneLine(pkg.name)}`, ""];

  out.push(
    `- Version shown: ${version ? versionText(version) : "none published"}${older ? ` (latest is ${pkg.latest ? versionText(pkg.latest) : "unknown"})` : version ? " (latest)" : ""}`,
    ...(view.status ? [statusLine(view.status)] : []),
    ...(view.status?.deprecated ? [`- Deprecated: ${inlineCode(view.status.deprecated)}`] : []),
    ...(pkg.description ? [`- Description: ${inlineCode(pkg.description)}`] : []),
    `- Source: ${pkg.source === "upstream" ? "the public npm registry, proxied and scored by apm" : "published to apm"}`,
    `- Score: ${score ? `${score.score}/100, grade ${oneLine(score.grade)}` : "not scored yet"}`,
    `- Page: ${url}${older ? `?v=${encodeURIComponent(version)}` : ""}`,
    `- Maintainers: ${pkg.maintainers.length ? pkg.maintainers.map(inlineCode).join(", ") : "unknown"}`,
    "",
    UNTRUSTED_NOTE,
    "",
  );

  const pulled = pkg.versions.filter((v) => v.status !== "active");

  if (pulled.length > 0) out.push("## Pulled versions", "", ...pulled.map((v) => `- ${versionText(v.version)}: ${wordText(v.status)}${v.statusReason ? `, reason ${inlineCode(v.statusReason)}` : ""}. New installs skip it.`), "");

  out.push("## Risk signals", "");

  if (!score) out.push("Not scored yet. apm scores a version when it first reads its tarball; ask again in a minute.", "");
  else {
    const lost = score.signals.filter((s) => s.points < 0);
    const notes = score.signals.filter((s) => s.points >= 0);

    if (lost.length === 0) out.push("No signal lost points.");
    else out.push(`${lost.length} signal${lost.length === 1 ? "" : "s"} lost ${points(lost.reduce((n, s) => n - s.points, 0))}. Each cited line links to that line of the file.`, "");

    for (const s of lost) out.push(...signalBlock(s, pkg.name, version));

    if (notes.length > 0) out.push("", "Notes (no points lost):", ...notes.flatMap((s) => signalBlock(s, pkg.name, version)));

    if (score.dismissed.length > 0) {
      out.push("", "Evidence an apm reviewer dismissed for this version:", ...score.dismissed.map((d) => `- ${inlineCode(d.signal)} at ${inlineCode(`${d.file}:${d.line}`)}, reason ${inlineCode(d.reason)}`));
    }

    out.push("");
  }

  out.push("## Capabilities", "");
  const caps = capabilitiesOf(score?.signals ?? null);

  if (caps) out.push(...caps.map((c) => `- ${c.label}: ${c.state}`));
  else out.push("- Code capabilities: unknown until the version is scored");

  // the shown version's own facts; the license is the publisher's text
  if (view.facts) out.push(...factLines(view.facts).map((f) => `- ${f.label}: ${f.label === "License" && view.facts?.license ? inlineCode(f.value) : f.value}`));
  else out.push("- Install scripts, license and size: unknown until the version is scored");
  out.push("", "## AI review", "", ...reviewSection(view.review), "");

  const shown = version === null ? null : oneLine(version);

  out.push("## Install", "", codeBlock(INSTALL_CLIENTS.map((client) => installCommand({ client, name: pkg.name, version: shown })).join("\n"), "sh"), "");
  out.push("`apm add` runs apm's checks itself. Plain bun, npm and pnpm only get them once pointed at apm:", "");

  for (const client of ["bun", "npm"] as const) {
    const note = installNote({ client, registry: view.registry });

    if (note.kind === "needs-setup") out.push(`${client === "npm" ? "npm and pnpm" : client} (${note.file}):`, "", codeBlock(note.config, client === "bun" ? "toml" : "ini"), "");
  }

  out.push("## Not checked", "");
  const notChecked = score?.notChecked ?? [];

  if (notChecked.length === 0) out.push("- What the code does at runtime, the code of its dependencies, or a compromised publisher.");
  else out.push(...notChecked.map((n) => `- ${inlineCode(n)}`));

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
