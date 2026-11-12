// A remote MCP server over streamable HTTP, stateless and read-only: each POST carries one JSON-RPC message
// and gets one JSON answer (the transport allows JSON instead of an SSE stream). No sessions, no
// server-to-client requests, so a GET has nothing to stream. The route (app/mcp/route.ts) adds the rate limit.
import { z } from "zod";
import { packagePath } from "../package-route";
import { looksLikePackageName } from "../search-schema";
import { capabilitiesOf } from "./capabilities";
import { packageMarkdown } from "./package-md";
import { loadPackageView } from "./package-view";
import { REGISTRY } from "../registry-url";
import { siteUrl } from "./site";
import type { Json } from "./json";
import type { AgentSource } from "./source";
import { codeBlock, inlineCode, oneLine, UNTRUSTED_NOTE } from "./text";
import { explainFor } from "./explain";
import { verdictText } from "./verdict";

/** Newest first; the first is what a client that asks for something else gets. */
export const PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"] as const;

export const SERVER_INFO = { name: "apm", title: "apm package registry", version: "1.0.0" } as const;

const INSTRUCTIONS = `apm scores every npm package version out of 100 with file:line evidence, and its install policy skips versions under 24 hours old, scoring under 40, yanked or revoked. Before adding a dependency, call explain_install and follow its verdict: install, review-first (show the reasons to the user), do-not-install, not-found (check the spelling; it may be a typosquat) or unknown (the registry did not answer). A score never means a version is safe; each answer says what was not checked. ${UNTRUSTED_NOTE}`;

// ---------- JSON-RPC ----------

const RequestId = z.union([z.string(), z.number()]);

type RequestId = z.infer<typeof RequestId>;

export const Message = z.object({ jsonrpc: z.literal("2.0"), id: RequestId.optional(), method: z.string().optional(), params: z.json().optional() }).loose();

export type Message = z.infer<typeof Message>;

type InitializeResult = { protocolVersion: string; capabilities: { tools: { listChanged: boolean } }; serverInfo: typeof SERVER_INFO; instructions: string };

/** Every result this server sends: the handshake, the tool list, a tool's answer, or an empty list or ping. */
type RpcResult = InitializeResult | ReturnType<typeof toolList> | ToolResult | { resources: [] } | { prompts: [] } | Record<string, never>;

export type JsonRpcResponse = { jsonrpc: "2.0"; id: RequestId | null; result?: RpcResult; error?: { code: number; message: string } };

export const RPC = { parse: -32700, invalidRequest: -32600, methodNotFound: -32601, invalidParams: -32602, internal: -32603 } as const;

const ok = (id: RequestId, result: RpcResult): JsonRpcResponse => ({ jsonrpc: "2.0", id, result });

export const rpcError = (id: RequestId | null, code: number, message: string): JsonRpcResponse => ({ jsonrpc: "2.0", id, error: { code, message } });

// ---------- tools ----------

const PackageName = z.string().trim().toLowerCase().refine(looksLikePackageName, "not a valid npm package name");

const SearchInput = z.object({ query: z.string().trim().min(1).max(214).describe("Words or a package name"), limit: z.number().int().min(1).max(20).default(10).describe("How many hits to return") });

const CheckPackageInput = z.object({ name: PackageName.describe("Package name, such as zod or @scope/name"), version: z.string().min(1).max(256).optional().describe("Exact version; latest when left out") });

const CheckNameInput = z.object({
  name: PackageName.describe("The name to check"),
  scope: z
    .string()
    .trim()
    .toLowerCase()
    .regex(/^@?[a-z0-9][a-z0-9-]*$/, "a scope is a GitHub login, with or without @")
    .optional()
    .describe("Your scope (a GitHub login): alternatives are checked under @scope/"),
});

const ExplainInput = z.object({
  name: PackageName.describe("Package name"),
  version: z.string().min(1).max(256).optional().describe("A version, range or dist-tag, such as 4.1.0, ^4 or next; latest when left out"),
});

const ExcerptInput = z.object({
  name: PackageName,
  version: z.string().min(1).max(256).describe("Exact version"),
  path: z.string().min(1).max(1024).describe("Path inside the package, such as lib/index.js"),
  line: z.number().int().min(1).default(1).describe("The line to center on"),
  context: z.number().int().min(0).max(100).default(20).describe("Lines each side of line"),
});

/** A tool's answer as data, beside its text: JSON values only. */
type Structured = { [key: string]: Json };

type ToolResult = { content: { type: "text"; text: string }[]; structuredContent?: Structured; isError?: boolean };

type Tool<S extends z.ZodType> = { name: string; title: string; description: string; input: S; run: (args: z.output<S>, source: AgentSource) => Promise<ToolResult> };

// undefined fields drop out of the JSON answer
const text = (body: string, structured?: Structured, isError = false): ToolResult => ({ content: [{ type: "text", text: body }], structuredContent: structured, isError: isError || undefined });

const unavailable = (what: string) => text(`The registry did not answer while reading ${what}. Nothing was checked; try again.`, undefined, true);

const searchPackages: Tool<typeof SearchInput> = {
  name: "search_packages",
  title: "Search packages",
  description: "Search apm and npm. Each hit has its latest version, weekly downloads and, when apm already scored it, its score out of 100.",
  input: SearchInput,
  async run({ query, limit }, source) {
    const answer = await source.search({ query });

    if (!answer) return unavailable("search");
    const hits = answer.hits.slice(0, limit);

    // names, versions and descriptions come from npm and publishers: one line each, the description quoted
    const lines = hits.map(
      (h) =>
        `- ${oneLine(h.name)}@${oneLine(h.version)}${h.score ? ` score ${h.score.score}/100 (${oneLine(h.score.grade)})` : " (not scored yet)"}${h.weeklyDownloads !== null ? `, ${h.weeklyDownloads} downloads/week` : ""}${h.source === "local" ? ", published to apm" : ""}${h.description ? `: ${inlineCode(oneLine(h.description).slice(0, 160))}` : ""}`,
    );

    const head = hits.length === 0 ? `Nothing matches "${query}".` : `${hits.length} of ${answer.total} for "${query}"${answer.upstreamFailed ? " (npm did not answer; apm packages only)" : ""}:`;

    return text([head, ...lines, "", UNTRUSTED_NOTE].join("\n"), { query, total: answer.total, upstreamFailed: answer.upstreamFailed, hits });
  },
};

const checkPackage: Tool<typeof CheckPackageInput> = {
  name: "check_package",
  title: "Check a package",
  description: "A package version's score and grade, every risk signal with its cited file:line evidence, its capabilities (network, shell, credentials, eval, install scripts), the AI review, install commands and what apm did not check.",
  input: CheckPackageInput,
  async run({ name, version }, source) {
    const loaded = await loadPackageView({ name, version: version ?? null, registry: REGISTRY, source });

    if (loaded.kind === "missing") return text(loaded.reason, { name, version: version ?? null, found: false }, true);

    if (loaded.kind === "unavailable") return unavailable(name);
    const { pkg, version: shown, status, facts, score, review } = loaded.view;

    return text(packageMarkdown(loaded.view), {
      name: pkg.name,
      version: shown,
      latest: pkg.latest,
      // the shown version's own state and facts, read without a cache
      status,
      score: score ? { score: score.score, grade: score.grade } : null,
      signals: score?.signals ?? [],
      capabilities: capabilitiesOf(score?.signals ?? null),
      facts,
      notChecked: score?.notChecked ?? [],
      aiReview: review.kind === "ok" ? { status: review.value.status, job: review.value.job ?? null, state: review.value.review?.state ?? null, findings: review.value.review?.findings ?? [] } : null,
      url: siteUrl(packagePath(pkg.name)),
    });
  },
};

const checkName: Tool<typeof CheckNameInput> = {
  name: "check_name",
  title: "Check a package name",
  description: "Is a name free to publish? Says whether it is taken (and by whom), too close to a popular package, and which variations are free under your scope.",
  input: CheckNameInput,
  async run({ name, scope }, source) {
    const bare = scope?.replace(/^@/, "") ?? null;
    const r = await source.names({ name, scope: bare });

    if (!r) return unavailable(`the name check for ${name}`);
    const lines: string[] = [];

    if (!r.valid) lines.push(`${name} is not a valid package name.`);
    else if (r.taken) lines.push(`${name} is taken${r.owners.length ? ` by ${r.owners.map(inlineCode).join(", ")}` : ""}${r.latest ? `; latest ${inlineCode(r.latest.version)}${r.latest.score !== null ? `, score ${r.latest.score}/100` : ""}` : ""}.`);
    else if (r.unknown) lines.push(`Could not check ${name}: npm did not answer.`);
    else if (r.available) lines.push(`${name} is available.`);
    else lines.push(`${name} is free but cannot be published: ${r.conflicts.map((c) => c.reason).join("; ")}`);

    for (const l of r.lookalikes) lines.push(`Look-alike: ${oneLine(l.reason)}`);

    for (const s of r.similar) lines.push(`Similar: ${oneLine(s.reason)}`);
    const free = r.suggestions.filter((s) => s.checked && s.available).map((s) => s.name);

    if (free.length > 0) lines.push(`Free${r.scope ? ` under @${r.scope}` : ""}: ${free.join(", ")}`);
    else if (!bare) lines.push("Pass scope (your GitHub login) to check names under your own scope; a scoped name is always yours.");

    return text(lines.join("\n"), { ...r });
  },
};

const explain: Tool<typeof ExplainInput> = {
  name: "explain_install",
  title: "Should I install this?",
  description: "Before adding a dependency: runs apm's install policy (24-hour cooldown, score floor 40, revokes, the dependency tree) and the AI review for name@version, and answers install, review-first, do-not-install, not-found or unknown, with reasons and the command to run.",
  input: ExplainInput,
  async run({ name, version }, source) {
    const verdict = await explainFor({ name, range: version ?? null, source });

    return text(verdictText(verdict), { ...verdict }, verdict.verdict === "unknown");
  },
};

const fileExcerpt: Tool<typeof ExcerptInput> = {
  name: "get_file_excerpt",
  title: "Read lines of a package file",
  description: "Lines around one line of a file inside a published version, for checking a cited signal. Works on files of any size.",
  input: ExcerptInput,
  async run(args, source) {
    const r = await source.excerpt(args);

    if (r.kind === "missing") return text(`${args.name}@${inlineCode(args.version)} has no file ${inlineCode(args.path)}.`, undefined, true);

    if (r.kind === "unavailable") return text(`Could not read ${inlineCode(args.path)}: the registry did not answer, or line ${args.line} is past the end of the file.`, undefined, true);
    const e = r.value;

    if (e.kind === "binary") return text(`${inlineCode(e.path)} in ${oneLine(e.name)}@${inlineCode(e.version)} is a binary file (${e.size} bytes).`, { ...e });
    const width = String(e.to).length;
    const body = e.lines.map((l) => `${String(l.n).padStart(width)}  ${l.text}${l.truncated ? ` [line cut, ${l.truncated.bytes} bytes]` : ""}`).join("\n");

    return text([`${inlineCode(e.path)} in ${oneLine(e.name)}@${inlineCode(e.version)}, lines ${e.from}-${e.to} of ${e.totalLines}:`, UNTRUSTED_NOTE, "", codeBlock(body)].join("\n"), { ...e });
  },
};

// Each tool keeps its own input type; the list only needs the shared surface.
type AnyTool = { name: string; title: string; description: string; input: z.ZodType; call: (args: ToolArguments, source: AgentSource) => Promise<ToolResult | { invalid: string }> };

function erase<S extends z.ZodType>(tool: Tool<S>): AnyTool {
  return {
    name: tool.name,
    title: tool.title,
    description: tool.description,
    input: tool.input,
    async call(args, source) {
      const parsed = tool.input.safeParse(args ?? {});

      if (!parsed.success) return { invalid: parsed.error.issues.map((i) => `${i.path.join(".") || "arguments"}: ${i.message}`).join("; ") };

      return tool.run(parsed.data, source);
    },
  };
}

export const TOOLS: readonly AnyTool[] = [erase(searchPackages), erase(checkPackage), erase(checkName), erase(explain), erase(fileExcerpt)];

/** The tools/list answer: each tool with its input as JSON Schema, marked read-only. */
export function toolList() {
  return {
    tools: TOOLS.map((t) => {
      const { $schema: _drop, ...inputSchema } = z.toJSONSchema(t.input, { io: "input", target: "draft-2020-12" });

      return { name: t.name, title: t.title, description: t.description, inputSchema, annotations: { title: t.title, readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true } };
    }),
  };
}

const CallParams = z.object({ name: z.string(), arguments: z.record(z.string(), z.json()).optional() });

type ToolArguments = z.infer<typeof CallParams>["arguments"];

const InitParams = z.object({ protocolVersion: z.string() }).loose();

/** One JSON-RPC message in, its answer out; null for a notification or a response, which get no answer. */
export async function handleMessage(message: Message, source: AgentSource): Promise<JsonRpcResponse | null> {
  const { id, method, params } = message;

  // a notification (no id) or a client's response to us: accepted, nothing to answer
  if (id === undefined || method === undefined) return null;

  switch (method) {
    case "initialize": {
      const asked = InitParams.safeParse(params);
      const requested = asked.success ? asked.data.protocolVersion : null;
      const protocolVersion = PROTOCOL_VERSIONS.find((v) => v === requested) ?? PROTOCOL_VERSIONS[0];

      return ok(id, { protocolVersion, capabilities: { tools: { listChanged: false } }, serverInfo: SERVER_INFO, instructions: INSTRUCTIONS });
    }

    case "ping":
      return ok(id, {});
    case "tools/list":
      return ok(id, toolList());
    case "tools/call": {
      const call = CallParams.safeParse(params);

      if (!call.success) return rpcError(id, RPC.invalidParams, "tools/call needs a tool name.");
      const tool = TOOLS.find((t) => t.name === call.data.name);

      if (!tool) return rpcError(id, RPC.invalidParams, `Unknown tool ${call.data.name}. Tools: ${TOOLS.map((t) => t.name).join(", ")}.`);
      const result = await tool.call(call.data.arguments, source);

      // bad arguments are a tool error the model can read and fix, not a protocol error
      if ("invalid" in result) return ok(id, text(`Invalid arguments for ${tool.name}: ${result.invalid}`, undefined, true));

      return ok(id, result);
    }

    case "resources/list":
      return ok(id, { resources: [] });
    case "prompts/list":
      return ok(id, { prompts: [] });
    default:
      return rpcError(id, RPC.methodNotFound, `Method not found: ${method}`);
  }
}

/** The protocol versions a client may name in the MCP-Protocol-Version header. */
export function isKnownProtocolVersion(v: string): boolean {
  return PROTOCOL_VERSIONS.some((p) => p === v);
}
