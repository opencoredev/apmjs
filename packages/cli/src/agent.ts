// `apm explain` and `apm search`, the commands agents lean on. main.ts hands in its output functions, so with
// --json each prints one document on stdout and everything else goes to stderr, like every apm command.
import { z } from "zod";
import { Api, ResolveFail, ResolveOk, encodeName, parseSpec, type RawAnswer } from "./api.ts";
import type { InstallTarget } from "./target.ts";
import { EXIT, explain, type ResolvedInput, type ReviewInput } from "./explain.ts";

type Paint = (s: string) => string;

export type AgentIo = {
  say: (line?: string) => void;
  warn: (line: string) => void;
  emit: <Doc extends { ok: boolean }>(doc: Doc) => void;
  json: boolean;
  paint: { green: Paint; yellow: Paint; red: Paint; dim: Paint; bold: Paint; grade: (score: number) => Paint };
};

const ReviewWire = z.object({
  status: z.enum(["reviewed", "queued", "failed", "not-reviewed"]),
  // the job's own state: status folds "leased" into "queued"; an older registry sends none
  job: z.enum(["queued", "leased", "done", "failed"]).nullish(),
  // the version's own state as the registry answered, and whether it withholds the version's source; an older
  // registry sends neither. A state this copy does not know makes the answer unreadable, never "active".
  versionStatus: z.enum(["active", "yanked", "revoke-pending", "revoked"]).optional(),
  redacted: z.boolean().optional(),
  review: z.object({ state: z.enum(["found-nothing", "under-review", "no-answer", "confirmed", "cleared"]), findings: z.array(z.unknown()) }).nullable(),
});

const ErrorWire = z.object({ error: z.string() });

const UNREADABLE = "the registry sent an answer apm could not read";

/**
 * The AI review of one version as the verdict reads it, from GET /-/apm/v1/review's answer. A 404 means the
 * registry runs no AI review (the resolve answer already showed the version exists). An answer apm cannot read is
 * "unreadable": the verdict then says it cannot tell, never that there is nothing to see. An answer that says the
 * version was yanked, revoked or withheld is "pulled" before anything else in it is read.
 */
export function parseReview(answer: RawAnswer): ReviewInput {
  if (answer.status === 404) return { kind: "off" };
  const parsed = answer.status === 200 ? ReviewWire.safeParse(answer.body) : null;

  if (!parsed?.success) return { kind: "unreadable" };
  const a = parsed.data;

  if (a.versionStatus !== undefined && a.versionStatus !== "active") return { kind: "pulled", status: a.versionStatus };

  if (a.redacted === true) return { kind: "pulled", status: "withheld" };

  if (a.review) return { kind: "reviewed", state: a.review.state, findings: a.review.findings.length };

  if (a.job === "leased") return { kind: "leased" };

  switch (a.status) {
    case "queued":
      return { kind: "queued" };
    case "failed":
      return { kind: "failed" };
    case "not-reviewed":
      return { kind: "not-reviewed" };
    case "reviewed":
      return { kind: "unreadable" };
    default: {
      const _exhaustive: never = a.status;

      return _exhaustive;
    }
  }
}

/** The AI review of one version, read from the registry; a read that failed is "unreadable". */
async function reviewOf(api: Api, name: string, version: string): Promise<ReviewInput> {
  try {
    return parseReview(await api.raw(`-/apm/v1/review/${encodeName(name)}/${encodeURIComponent(version)}`));
  } catch {
    return { kind: "unreadable" };
  }
}

/**
 * The registry's install policy for name@range: what apm add would pick, or why it would refuse, in the mode apm add
 * would run in (`strict`, from --strict or APM_STRICT=1) and for the platform it would ask about.
 */
async function resolvedFor(input: { api: Api; name: string; range: string | null; strict: boolean; target: InstallTarget }): Promise<ResolvedInput> {
  const { api, name, range } = input;
  let r: { status: number; body: unknown };
  const params = new URLSearchParams({ name, range: range ?? "latest", ...input.target });

  // review of 93274c8, finding 6: apm explain --strict asked in the default mode
  if (input.strict) params.set("strict", "1");

  try {
    r = await api.raw(`-/apm/v1/resolve?${params}`);
  } catch (e) {
    return { kind: "unavailable", reason: e instanceof Error ? e.message : "the registry did not answer" };
  }

  const error = ErrorWire.safeParse(r.body);

  if (r.status === 200) {
    const ok = ResolveOk.safeParse(r.body);

    if (!ok.success) return { kind: "unavailable", reason: UNREADABLE };
    const tree = ok.data.tree;
    const uncheckedDeps = tree?.uncheckedDeps ?? [];

    // the registry's total, not the length of the list (it names at most 50); no review summary is unknown, not clean
    return {
      kind: "ok",
      version: ok.data.version,
      report: ok.data.report,
      skipped: ok.data.skipped,
      deps: { unchecked: Math.max(tree?.unchecked ?? 0, uncheckedDeps.length), uncheckedDeps, reviews: tree?.reviews ?? { kind: "unknown" }, warnings: ok.data.warnings },
    };
  }

  if (r.status === 422) {
    const f = ResolveFail.extend({ newest: z.object({ version: z.string() }).loose().nullish(), confirmed: z.array(z.object({ name: z.string(), version: z.string() })).default([]) }).safeParse(r.body);

    return f.success ? { kind: "refused", reason: f.data.error, newest: f.data.newest?.version ?? null, skipped: f.data.skipped, confirmed: f.data.confirmed } : { kind: "unavailable", reason: UNREADABLE };
  }

  if (r.status === 404) return { kind: "missing", reason: error.success ? error.data.error : `No package named ${name}.` };

  return { kind: "unavailable", reason: `the registry answered HTTP ${r.status}${error.success ? `: ${error.data.error}` : ""}` };
}

/** apm explain <pkg>[@range]: exit 0 install, 3 review-first, 1 do-not-install or not-found, 4 unknown, 2 usage. */
export async function explainCommand(input: { api: Api; spec: string | undefined; io: AgentIo; strict: boolean; target: InstallTarget }): Promise<number> {
  const { api, spec, io } = input;

  if (!spec) {
    io.warn("usage: apm explain <package>[@range] [--json]");

    return 2;
  }

  const { name, range } = parseSpec(spec);
  const resolved = await resolvedFor({ api, name, range, strict: input.strict, target: input.target });
  // only an "ok" resolve reads the review; the other verdicts never look at it
  const unread: ReviewInput = { kind: "unreadable" };
  const review = resolved.kind === "ok" ? await reviewOf(api, name, resolved.version) : unread;
  const v = explain({ name, range, resolved, review });
  const code = EXIT[v.verdict];

  if (io.json) {
    io.emit({ ok: code === 0, ...v });

    return code;
  }

  const { green, yellow, red, dim, bold } = io.paint;
  const mark = v.verdict === "install" ? green("✓") : v.verdict === "review-first" || v.verdict === "unknown" ? yellow("!") : red("✗");

  io.say(`${mark} ${bold(v.verdict)}  ${v.summary}`);

  for (const r of v.reasons) io.say(dim(`  - ${r}`));

  if (v.evidence.length > 0) io.say(dim("  evidence:"));

  for (const e of v.evidence) io.say(dim(`    ${e}`));

  if (v.url) io.say(`  details: ${v.url}`);

  if (v.commands) io.say(`  run: ${v.commands.apm}`);

  return code;
}

const SearchWire = z.object({
  total: z.number(),
  upstreamFailed: z.boolean().default(false),
  objects: z.array(
    z
      .object({
        source: z.enum(["local", "npm"]).default("local"),
        package: z.object({ name: z.string(), version: z.string(), description: z.string().nullish() }).loose(),
        apmScore: z.object({ score: z.number(), grade: z.string() }).loose().nullish(),
        downloads: z.object({ weekly: z.number() }).nullish(),
      })
      .loose(),
  ),
});

/** apm search <words> [--size n]: apm and npm hits, with the apm score where apm already scored a version. */
export async function searchCommand(input: { api: Api; words: string[]; size: string | null; io: AgentIo }): Promise<number> {
  const { api, io } = input;
  const query = input.words.join(" ").trim();

  if (!query) {
    io.warn("usage: apm search <words> [--size n] [--json]");

    return 2;
  }

  const size = Math.min(50, Math.max(1, Number(input.size ?? 10) || 10));
  const r = await api.get(`-/v1/search?${new URLSearchParams({ text: query, size: String(size) })}`, SearchWire);

  const hits = r.objects.map((o) => ({
    name: o.package.name,
    version: o.package.version,
    description: o.package.description ?? "",
    source: o.source,
    score: o.apmScore ? { score: o.apmScore.score, grade: o.apmScore.grade } : null,
    weeklyDownloads: o.downloads?.weekly ?? null,
  }));

  if (io.json) {
    io.emit({ ok: true, query, total: r.total, upstreamFailed: r.upstreamFailed, hits });

    return 0;
  }

  const { yellow, dim, bold, grade } = io.paint;

  if (r.upstreamFailed) io.say(yellow("npm did not answer; showing this registry's packages only"));

  if (hits.length === 0) io.say(dim(`nothing matches ${query}`));

  for (const h of hits) {
    const score = h.score ? grade(h.score.score)(`${h.score.grade} ${h.score.score}`.padEnd(6)) : dim("n/a".padEnd(6));

    io.say(`${score} ${bold(h.name)}@${h.version}  ${dim(h.description.replace(/\s+/g, " ").slice(0, 80))}`);
  }

  return 0;
}
