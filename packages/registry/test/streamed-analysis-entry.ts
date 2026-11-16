// The worker module streamed-analysis.workerd.test.ts runs inside workerd. `/stream` scores a tarball the NPM binding
// serves the way the queue scores one too large to hold (streamed-analysis.ts), measuring the isolate's memory before
// each pass opens the tarball and once the run is done; `/held` scores one the way the queue scores a tarball under
// the caps (analysis.ts's analyzeUpstreamTarball, the whole tarball in memory), for comparison.
import { join } from "node:path";
import { MEASURE } from "./workerd-heap.ts";

const SRC = join(import.meta.dir, "..", "src");
const CORE = join(import.meta.dir, "..", "..", "core", "src", "index.ts");

export const ENTRY = `
import { analyzeStreamedTarball, READ } from ${JSON.stringify(join(SRC, "streamed-analysis.ts"))};
import { analyzeUpstreamTarball, QUEUE_WORK } from ${JSON.stringify(join(SRC, "analysis.ts"))};
import { finalize } from ${JSON.stringify(CORE)};
import { MemoryPool } from ${JSON.stringify(join(SRC, "memory.ts"))};
${MEASURE}
const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null };

function version() {
  return { version: "1.0.0", manifest: {}, published_at: 0, published_by: "someone", deprecated: null, status: "active" };
}

function summary(result) {
  if (result.kind !== "scored") return result;
  const r = finalize(result.analysis, STATE);
  return {
    kind: result.kind,
    spent: result.spent,
    score: r.score,
    grade: r.grade,
    coverage: result.analysis.coverage ?? null,
    signals: r.signals.map((s) => ({ id: s.id, evidence: s.evidence.slice(0, 3), count: s.evidence.length })),
    skipped: result.analysis.skipped.length,
    notChecked: result.analysis.notChecked.slice(-2),
    files: result.analysis.facts.fileCount,
    analysis: JSON.stringify(result.analysis),
  };
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    if (url.pathname === "/measure") return new Response(String(await measure(env)));
    const file = url.searchParams.get("file") ?? "";
    const digest = { algo: "sha512", hex: url.searchParams.get("sha512") ?? "" };
    const v = version();
    const pkg = { name: url.searchParams.get("name") ?? "pkg", versions: [v] };

    if (url.pathname === "/stream") {
      const before = [];
      const open = async () => {
        before.push(await measure(env));
        const res = await env.NPM.fetch("http://npm.invalid/" + encodeURIComponent(file));
        return { kind: "stream", body: res.body, length: Number(res.headers.get("content-length")), digest };
      };
      // a test may try other limits: ?holdMiB=6&work=64000000
      const hold = url.searchParams.get("holdMiB");
      const work = url.searchParams.get("work");
      const limits = { ...READ, ...(hold ? { holdBytes: Number(hold) * 1024 * 1024 } : {}), ...(work ? { work: Number(work) } : {}) };
      // ?ballastMiB=27: live objects held through the run, as the queue run holds the version's packument (next's
      // weighs 26.6 MiB, walk-memory.test.ts)
      const ballast = [];
      for (let i = 0; i < Number(url.searchParams.get("ballastMiB") ?? 0) * 1024; i++) ballast.push(Array.from({ length: 256 }, (_, k) => k + i));
      // a queue job's lease (worker.ts opens one of REQUEST_WEIGHT for each message), from a pool of its own
      const lease = new MemoryPool().request();
      const result = await analyzeStreamedTarball({ pkg, v, digest, open, plan: { maxWork: QUEUE_WORK }, limits, memory: lease });
      const leased = lease.peakTaken;
      lease.release();
      const after = await measure(env);
      return Response.json({ result: summary(result), before, after, ballast: ballast.length, leased });
    }

    if (url.pathname === "/held") {
      const bytes = new Uint8Array(await (await env.NPM.fetch("http://npm.invalid/" + encodeURIComponent(file))).arrayBuffer());
      const before = [await measure(env)];
      const result = analyzeUpstreamTarball(pkg, v, bytes, { maxWork: QUEUE_WORK });
      // the scorer is handed what readTarball gives under its own cap, for a tarball the registry's cap sends to a stream
      if (result.kind === "stream") return Response.json({ result, before, after: await measure(env) });
      const after = await measure(env);
      return Response.json({ result: summary(result), before, after });
    }

    return new Response("not found", { status: 404 });
  },
};
`;
