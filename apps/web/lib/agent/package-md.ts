// The package page as Markdown, for agents: GET /package/<name>.md (or ?format=md) and the check_package MCP
// tool. The same facts as the HTML page, in the order an agent deciding on an install needs them. Pure.
import { isNotAllRead, NOT_ALL_READ_INSTALLS, scoreOnWhatWasRead, skippedSentence } from "../coverage";
import { citeEvidence, namesFile } from "../evidence";
import { cooldownText, installCommand, installNote, INSTALL_CLIENTS, specSuffix, type InstallSpec } from "../install-note";
import { splitPossible, splitTestFile } from "../limitations";
import { fileHref } from "../package-route";
import { UNSCORABLE_INSTALLS } from "../unscored";
import type { Facts, Fetched, PackageInfo, Signal } from "../registry";
import { advisoryUrl, dependencyWhy, noInstallableReason, refusalReason, statusRefusal, type NoInstallable, type PolicyRead, type Refusal } from "../refusal";
import { basisNote, capabilityParts, scorerCapabilities, statusMark } from "../capabilities";
import { coverageText, explanation, headline, type ReviewAnswer } from "../review-schema";
import { capabilitiesOf, factLines } from "./capabilities";
import { canonicalPackagePath, siteUrl } from "./site";
import type { ScoreReport, VersionInfo } from "./source";
import { codeBlock, inlineCode, linkUrl, oneLine, points, UNTRUSTED_NOTE } from "./text";

/** How the install commands name the shown version (shown-version.ts selectVersion), or why there is none to install. */
export type InstallTarget = InstallSpec | { readonly kind: "none"; readonly why: NoInstallable };

export type PackageView = {
  pkg: PackageInfo;
  /** The version shown: the one asked for with ?v=, else the one installs get by name. Null when none installs. */
  version: string | null;
  /** That version's own state, from the versions route; null when there is no version. */
  status: { status: string; statusReason: string | null; deprecated: string | null } | null;
  /** Whether apm installs that version: its status, else resolve for exactly that version (lib/refusal.ts readPolicy). */
  policy: PolicyRead;
  /** That version's own facts (not latest's); null when it is not scored yet. */
  facts: Facts | null;
  /** That version's score; null when it is not scored yet. */
  score: ScoreReport | null;
  /** Why apm can never score that version, from its own version answer (not the package answer's newest 200). */
  unscorable: VersionInfo["unscorable"];
  review: Fetched<ReviewAnswer>;
  /** The same selection the HTML page makes for the same URL, so both name the same release the same way. */
  install: InstallTarget;
  /** The shown version was published in the last 24 hours (decided where the view is loaded, which reads the clock); absent: not known to be. */
  inCooldown?: boolean;
  /** The registry URL install config points at, ending in "/". */
  registry: string;
};

/** A revoked version, or one whose revoke is pending: the registry shows none of its source, and neither do these views. */
export function isWithheld(status: string): boolean {
  return status === "revoked" || status === "revoke-pending";
}

/** Whether the view must show none of the version's source: its status says so, or the registry redacted an answer. */
export function sourceWithheld(view: PackageView): boolean {
  const statusSays = view.status !== null && isWithheld(view.status.status);

  return statusSays || view.score?.redacted === true || (view.review.kind === "ok" && view.review.value.redacted);
}

/** One piece of evidence without the package's text: the file and line (or script) it cites, or nothing at all. */
function evidenceWithoutSource(signal: string, evidence: string): string[] {
  if (!namesFile(signal)) return [evidence];
  const cited = citeEvidence(signal, splitTestFile(splitPossible(evidence).text).text);

  return cited ? [cited.cite] : [];
}

/**
 * The view with every line of the version's source taken out when the version is withheld: score evidence keeps only
 * what it cites, and the deprecation message (the publisher's text) is dropped. The AI review's findings are the
 * registry's own for a withheld version (WITHHELD_ISSUE for the sentence, `file N` for the path, no quote or excerpt):
 * they are shown as sent, with any excerpt cut as a backstop. Applied where the view is loaded (so the MCP tool's
 * structured answer is cut too) and again before it is written out.
 */
export function withholdSource(view: PackageView): PackageView {
  if (!sourceWithheld(view)) return view;

  const score = view.score
    ? {
        ...view.score,
        signals: view.score.signals.map((s) => ({ ...s, evidence: s.evidence.flatMap((e) => evidenceWithoutSource(s.id, e)) })),
        dismissed: view.score.dismissed.map((d) => ({ ...d, evidence: [] })),
        // what each capability rests on quotes the tarball (lines, variable names, the declaration's words): none of it
        capabilities: view.score.capabilities?.map(({ declared: _declared, names: _names, outside: _outside, ...c }) => ({ ...c, evidence: [] })),
      }
    : null;

  const status = view.status ? { ...view.status, deprecated: null } : null;
  const r = view.review;

  const review: PackageView["review"] =
    r.kind === "ok" ? { kind: "ok", value: { ...r.value, review: r.value.review ? { ...r.value.review, findings: r.value.review.findings.map((f) => ({ ...f, excerpt: "" })) } : null, private: null } } : r;

  // the registry sends none for a withheld version; its reason can name a file of the tarball
  return { ...view, status, score, review, unscorable: null };
}

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

function evidenceLine(input: { signal: string; evidence: string; name: string; version: string | null; withheld: boolean }): string {
  const possible = splitPossible(input.evidence);
  const { text, testFile } = splitTestFile(possible.text);
  const cited = citeEvidence(input.signal, text);
  // a withheld version's files answer 410: its citations are not links
  const href = cited && input.version && !input.withheld ? fileHref({ name: input.name, version: input.version, ...cited.citation }) : null;
  const tail = [testFile ? "in a test file the package ships" : null, possible.why ? `possible: ${inlineCode(possible.why)}` : null].filter(Boolean).join("; ");
  // the cited path is publisher text too, so it sits in a code span inside the link text
  const rest = cited ? cited.rest.replace(/^:\s*/, "") : "";
  const body = cited && href ? `[${inlineCode(cited.cite)}](${linkUrl(siteUrl(href))})${rest ? ` ${inlineCode(rest)}` : ""}` : cited && input.withheld ? inlineCode(cited.cite) : inlineCode(text);

  return `  - ${body}${tail ? ` (${tail})` : ""}`;
}

function signalBlock(s: Signal, input: { name: string; version: string | null; withheld: boolean }): string[] {
  const head = `- **${s.points < 0 ? `−${points(-s.points)}` : "note"}** ${oneLine(s.label)}${s.confidence === "possible" ? " (possible: named but not seen in use)" : ""} ${inlineCode(s.id)}`;
  const lines = [head, ...s.evidence.slice(0, MAX_EVIDENCE).map((evidence) => evidenceLine({ signal: s.id, evidence, ...input }))];

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
  lines.push(`${coverageText(r.coverage)}. Reviewed by an AI model (${inlineCode(r.model)}) at ${inlineCode(r.reviewedAt)}.`);

  // findings and the note are the AI's and a reviewer's words about publisher code: quoted, the excerpt as a block
  // a withheld version's findings are the registry's: a fixed sentence, a file reference and no excerpt
  for (const [i, f] of r.findings.entries()) lines.push("", `Finding ${i + 1} (${f.severity}) at ${inlineCode(`${f.file}:${f.line}`)}: ${inlineCode(f.issue)}`, ...(f.excerpt === "" ? [] : ["", codeBlock(f.excerpt)]));

  if (r.note) lines.push("", "Reviewer note:", "", codeBlock(r.note));

  return lines;
}

function statusLine(status: NonNullable<PackageView["status"]>, policy: PolicyRead): string {
  const reason = status.statusReason ? `, reason ${inlineCode(status.statusReason)}` : "";

  if (status.status !== "active") return `- Status: ${wordText(status.status)}${reason}. New installs skip it.`;

  switch (policy.kind) {
    case "installs":
    case "not-asked":
      return "- Status: active";
    case "unknown":
      return "- Status: active. The registry's install policy did not answer, so apm may not serve this version.";
    case "refused":
      return `- Status: do not install. ${refusalText(policy.refusal)}`;
    default: {
      const _exhaustive: never = policy;

      return _exhaustive;
    }
  }
}

/** Why apm will not install the shown version: its own fresh status first, else what resolve said; null when it installs. */
export function refusalOf(view: Pick<PackageView, "status" | "policy">): Refusal | null {
  return (view.status ? statusRefusal(view.status.status) : null) ?? (view.policy.kind === "refused" ? view.policy.refusal : null);
}

/** A refusal in Markdown: advisory ids and a policy reason quoted, each advisory linked. */
function refusalText(r: Refusal): string {
  if (r.kind === "known-malicious") return `The OSSF malicious-packages feed lists it as malicious (${r.ids.map((id) => inlineCode(id)).join(", ")}), so apm add refuses it. Advisory: ${r.ids.map((id) => linkUrl(advisoryUrl(id))).join(", ")}`;

  if (r.kind === "dependency") {
    const links = r.deps.flatMap((d) => d.ids ?? []).map((id) => linkUrl(advisoryUrl(id)));

    return `It depends on ${r.deps.map((d) => `${inlineCode(`${d.name}@${d.version}`)}, which ${dependencyWhy(d)}`).join("; and on ")}, so apm add refuses it.${links.length > 0 ? ` Advisory: ${links.join(", ")}` : ""}`;
  }

  return r.kind === "policy" ? `apm's install policy refuses it: ${inlineCode(r.reason)}` : refusalReason(r);
}

/**
 * The capability lines: from the scorer's own list (apm-score-v10 and later), as the page shows them, else from the
 * signals of an older scorer. Null when the version is not scored.
 */
function capabilityLines(score: ScoreReport | null): string[] | null {
  if (score === null) return null;
  const listed = scorerCapabilities(score);

  switch (listed.kind) {
    case "listed":
      if (listed.capabilities.length === 0) return ["- None found in the code apm read."];

      return listed.capabilities.map((c) => {
        const { name, detail } = capabilityParts(c.label);
        // "seen" only for code apm read; a declared capability the scorer found no use of (basis none) reads as the page does
        const notes = [c.basis === "code" ? "seen" : basisNote(c)?.toLowerCase(), statusMark(c)?.text.toLowerCase()].filter(Boolean).join("; ");

        return `- ${oneLine(name)}${detail ? ` (${oneLine(detail)})` : ""}: ${notes || "not seen"}`;
      });
    case "unavailable":
      return ["- Capabilities: not available from this registry."];
    case "not-listed":
      return capabilitiesOf(score.signals)?.map((c) => `- ${c.label}: ${c.state}`) ?? null;
    default: {
      const _exhaustive: never = listed;

      return _exhaustive;
    }
  }
}

/** Why apm can never score the shown version: null when it has a score or may still get one. */
export function unscorableOf(view: Pick<PackageView, "score" | "unscorable">): VersionInfo["unscorable"] {
  return view.score ? null : view.unscorable;
}

/**
 * The risk-signals line for a version apm can never score. The registry's reason is quoted: it can carry text from the
 * tarball (a file name in a read error). What installs do with the version is apm's fixed sentence, outside the quote.
 */
export function unscorableLine(unscorable: NonNullable<VersionInfo["unscorable"]>): string {
  return `apm cannot score this version. The registry's reason: ${inlineCode(oneLine(unscorable.text))}. ${UNSCORABLE_INSTALLS}`;
}

/**
 * The score line's value. A version apm did not read in full (grade P) has no letter: the number is what the files apm
 * read scored, then what it skipped and what installs do about it.
 */
export function scoreLine(input: { name: string; score: ScoreReport; unpackedSize: number | null }): string {
  const { score } = input;

  if (!isNotAllRead(score.grade)) return `${score.score}/100, grade ${oneLine(score.grade)}`;
  const skipped = score.coverage?.kind === "partial" ? ` ${skippedSentence({ coverage: score.coverage, name: oneLine(input.name), unpackedSize: input.unpackedSize })}` : "";

  return `${scoreOnWhatWasRead(score.score)}. Not fully checked:${skipped || " apm did not read every file."} ${NOT_ALL_READ_INSTALLS}`;
}

/** The links every Markdown view ends with; `spec` is the name, with @tag or @version when the view installs by one. */
function moreLines(spec: string): string[] {
  return [
    "## More",
    "",
    `- Should an agent install it? GET ${siteUrl(`/api/explain?package=${encodeURIComponent(spec)}`)}`,
    `- API: ${siteUrl("/openapi.json")}`,
    `- MCP server (optional, the same answers as tools): ${siteUrl("/mcp")}`,
  ];
}

/** The Markdown view of a package with no version to install: the reason first, and no install command. */
function noInstallableMarkdown(input: { pkg: PackageInfo; why: NoInstallable }): string {
  const { pkg, why } = input;
  const reason = noInstallableReason({ name: oneLine(pkg.name), why });

  return `${[
    `# ${oneLine(pkg.name)}`,
    "",
    "- Version shown: none. apm installs no version of this package.",
    `- Status: do not install. ${reason}`,
    ...(pkg.description ? [`- Description: ${inlineCode(pkg.description)}`] : []),
    `- Source: ${pkg.source === "upstream" ? "the public npm registry, proxied and scored by apm" : "published to apm"}`,
    `- Page: ${siteUrl(canonicalPackagePath(pkg.name))}`,
    `- Maintainers: ${pkg.maintainers.length ? pkg.maintainers.map((m) => inlineCode(m)).join(", ") : "unknown"}`,
    "",
    UNTRUSTED_NOTE,
    "",
    "## Install",
    "",
    "No install command: apm installs no version of this package.",
    "",
    ...moreLines(pkg.name),
  ].join("\n")}\n`;
}

/** The whole Markdown document for one package version. */
export function packageMarkdown(input: PackageView): string {
  const view = withholdSource(input);
  const { pkg, version, score, install } = view;

  if (install.kind === "none") return noInstallableMarkdown({ pkg, why: install.why });
  const withheld = sourceWithheld(view);
  const url = siteUrl(canonicalPackagePath(pkg.name));
  // installed by a dist-tag: the default when apm installs no version tagged latest, or a ?v= that names the tag
  const tag = install.kind === "tag" ? install.tag : null;
  const older = version !== null && version !== pkg.latest && tag === null;
  const refusal = refusalOf(view);
  const unscorable = unscorableOf(view);
  const out: string[] = [`# ${oneLine(pkg.name)}`, ""];
  const shownNote = tag ? ` (tagged ${inlineCode(tag)}; ${pkg.latest === null ? "no version is tagged latest" : `latest is ${versionText(pkg.latest)}`})` : older ? ` (${pkg.latest ? `latest is ${versionText(pkg.latest)}` : "no version is tagged latest"})` : version ? " (latest)" : "";

  out.push(
    `- Version shown: ${version ? versionText(version) : "none published"}${shownNote}`,
    ...(view.status ? [statusLine(view.status, view.policy)] : []),
    ...(withheld ? ["- Source: withheld. This version's revoke takes its files out of view: apm shows no line of its code, only what was found and where."] : []),
    ...(view.status?.deprecated ? [`- Deprecated: ${inlineCode(view.status.deprecated)}`] : []),
    ...(pkg.description ? [`- Description: ${inlineCode(pkg.description)}`] : []),
    `- Source: ${pkg.source === "upstream" ? "the public npm registry, proxied and scored by apm" : "published to apm"}`,
    `- Score: ${score ? scoreLine({ name: pkg.name, score, unpackedSize: view.facts?.unpackedSize ?? null }) : unscorable !== null ? "none: apm cannot score this version" : "not scored yet"}`,
    `- Page: ${url}${older ? `?v=${encodeURIComponent(version)}` : tag !== null && pkg.latest !== null && version !== pkg.latest ? `?v=${encodeURIComponent(tag)}` : ""}`,
    `- Maintainers: ${pkg.maintainers.length ? pkg.maintainers.map((m) => inlineCode(m)).join(", ") : "unknown"}`,
    "",
    UNTRUSTED_NOTE,
    "",
  );

  const pulled = pkg.versions.filter((v) => v.status !== "active");

  if (pulled.length > 0) out.push("## Pulled versions", "", ...pulled.map((v) => `- ${versionText(v.version)}: ${wordText(v.status)}${v.statusReason ? `, reason ${inlineCode(v.statusReason)}` : ""}. New installs skip it.`), "");

  out.push("## Risk signals", "");

  if (!score) out.push(unscorable !== null ? unscorableLine(unscorable) : "Not scored yet. apm scores a version when it first reads its tarball; ask again in a minute.", "");
  else {
    const lost = score.signals.filter((s) => s.points < 0);
    const notes = score.signals.filter((s) => s.points >= 0);

    if (lost.length === 0) out.push("No signal lost points.");
    else out.push(`${lost.length} signal${lost.length === 1 ? "" : "s"} lost ${points(lost.reduce((n, s) => n - s.points, 0))}. ${withheld ? "Each names the file and line it found; the lines themselves are withheld." : "Each cited line links to that line of the file."}`, "");
    const where = { name: pkg.name, version, withheld };

    for (const s of lost) out.push(...signalBlock(s, where));

    if (notes.length > 0) out.push("", "Notes (no points lost):", ...notes.flatMap((s) => signalBlock(s, where)));

    if (score.dismissed.length > 0) {
      out.push("", "Evidence an apm reviewer dismissed for this version:", ...score.dismissed.map((d) => `- ${inlineCode(d.signal)} at ${inlineCode(`${d.file}:${d.line}`)}, reason ${inlineCode(d.reason)}`));
    }

    out.push("");
  }

  out.push("## Capabilities", "");
  const caps = capabilityLines(score);

  const unknownUntil = unscorable !== null ? "unknown: apm cannot score this version" : "unknown until the version is scored";

  if (caps) out.push(...caps);
  else out.push(`- Code capabilities: ${unknownUntil}`);

  // the shown version's own facts; the license is the publisher's text
  if (view.facts) out.push(...factLines(view.facts).map((f) => `- ${f.label}: ${f.label === "License" && view.facts?.license ? inlineCode(f.value) : f.value}`));
  else out.push(`- Install scripts, license and size: ${unknownUntil}`);
  out.push("", "## AI review", "", ...reviewSection(view.review), "");

  // the registry's version and tag strings, kept to one line inside the command block
  const named: InstallSpec = install.kind === "tag" ? { kind: "tag", tag: oneLine(install.tag) } : install.kind === "exact" ? { kind: "exact", version: oneLine(install.version) } : { kind: "default", version: version === null ? null : oneLine(version) };

  out.push("## Install", "");

  if (refusal !== null) {

    out.push("No install command: apm refuses this version.", "");
  } else {
    out.push(codeBlock(INSTALL_CLIENTS.map((client) => installCommand({ client, name: pkg.name, install: named })).join("\n"), "sh"), "");

    if (view.inCooldown === true && version !== null) out.push(cooldownText(versionText(version)), "");
    out.push("`apm add` runs apm's checks itself. Plain bun, npm and pnpm get only some of them, and only once pointed at apm:", "");

    for (const client of ["bun", "npm"] as const) {
      const note = installNote({ client, registry: view.registry });

      if (note.kind === "needs-setup") out.push(`${client === "npm" ? "npm and pnpm" : client} (${note.file}):`, "", codeBlock(note.config, client === "bun" ? "toml" : "ini"), "", note.effect, "");
    }
  }

  out.push("## Not checked", "");
  const notChecked = score?.notChecked ?? [];

  if (notChecked.length === 0) out.push("- What the code does at runtime, the code of its dependencies, or a compromised publisher.");
  else out.push(...notChecked.map((n) => `- ${inlineCode(n)}`));

  const suffix = specSuffix(named);

  out.push("", ...moreLines(suffix === null ? pkg.name : `${pkg.name}@${suffix}`));

  return `${out.join("\n")}\n`;
}
