// `apm explain` and `apm search`, the commands agents lean on. main.ts hands in its output functions, so with
// --json each prints one document on stdout and everything else goes to stderr, like every apm command.
import { z } from "zod";
import { Api, ResolveFail, ResolveOk, encodeName, parseSpec } from "./api.ts";
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
  review: z.object({ state: z.enum(["found-nothing", "under-review", "no-answer", "confirmed", "cleared"]), findings: z.array(z.unknown()) }).nullable(),
});

const ErrorWire = z.object({ error: z.string() });

const UNREADABLE = "the registry sent an answer apm could not read";

/** The AI review of one version as the verdict reads it; none when AI review is off or could not be read. */
async function reviewOf(api: Api, name: string, version: string): Promise<ReviewInput> {
  try {
    const r = await api.raw(`-/apm/v1/review/${encodeName(name)}/${encodeURIComponent(version)}`);
    const parsed = r.status === 200 ? ReviewWire.safeParse(r.body) : null;

    if (!parsed?.success) return { kind: "none" };

    if (parsed.data.review) return { kind: "reviewed", state: parsed.data.review.state, findings: parsed.data.review.findings.length };

    return parsed.data.status === "queued" ? { kind: "queued" } : { kind: "none" };
  } catch {
    return { kind: "none" };
  }
}

/** The registry's install policy for name@range at its defaults: what apm add would pick, or why it would refuse. */
async function resolvedFor(api: Api, name: string, range: string | null): Promise<ResolvedInput> {
  let r: { status: number; body: unknown };

  try {
    r = await api.raw(`-/apm/v1/resolve?${new URLSearchParams({ name, range: range ?? "latest" })}`);
  } catch (e) {
    return { kind: "unavailable", reason: e instanceof Error ? e.message : "the registry did not answer" };
  }

  const error = ErrorWire.safeParse(r.body);

  if (r.status === 200) {
    const ok = ResolveOk.safeParse(r.body);

    return ok.success ? { kind: "ok", version: ok.data.version, report: ok.data.report, skipped: ok.data.skipped, unchecked: ok.data.tree?.uncheckedDeps ?? [] } : { kind: "unavailable", reason: UNREADABLE };
  }

  if (r.status === 422) {
    const f = ResolveFail.extend({ newest: z.object({ version: z.string() }).loose().nullish() }).safeParse(r.body);

    return f.success ? { kind: "refused", reason: f.data.error, newest: f.data.newest?.version ?? null, skipped: f.data.skipped } : { kind: "unavailable", reason: UNREADABLE };
  }

  if (r.status === 404) return { kind: "missing", reason: error.success ? error.data.error : `No package named ${name}.` };

  return { kind: "unavailable", reason: `the registry answered HTTP ${r.status}${error.success ? `: ${error.data.error}` : ""}` };
}

/** apm explain <pkg>[@range]: exit 0 install, 3 review-first, 1 do-not-install or not-found, 4 unknown, 2 usage. */
export async function explainCommand(input: { api: Api; spec: string | undefined; io: AgentIo }): Promise<number> {
  const { api, spec, io } = input;

  if (!spec) {
    io.warn("usage: apm explain <package>[@range] [--json]");

    return 2;
  }

  const { name, range } = parseSpec(spec);
  const resolved = await resolvedFor(api, name, range);
  const none: ReviewInput = { kind: "none" };
  const review = resolved.kind === "ok" ? await reviewOf(api, name, resolved.version) : none;
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
