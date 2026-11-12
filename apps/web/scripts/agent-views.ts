// Every agent view of one package, read through the website's real registry port: the Markdown view, and the MCP
// tools check_package, search_packages and get_file_excerpt. For the end-to-end revoke sweep
// (tests/acceptance/revoke-sweep.test.ts), which runs it against the registry Worker in Miniflare:
//
//   APM_REGISTRY=<registry url> bun --conditions=react-server scripts/agent-views.ts
//
// Each line on stdin is one request (the input JSON); each answer is one line of JSON on stdout. One process serves
// every request, as one Worker isolate would, so what the site caches between two requests (search) is still there
// for the second. react-server, because the views are server code ("server-only"). A process of its own, so the
// website's modules read the registry URL from their own environment and are typechecked by the website's tsconfig.
// Test tooling: never imported by the site.
import { z } from "zod";
import { markdownResponse } from "../lib/agent/agent-http";
import { handleMessage } from "../lib/agent/mcp";
import { registrySource } from "../lib/agent/registry-source";
import { REGISTRY } from "../lib/registry-url";

const Input = z.object({ name: z.string(), versions: z.array(z.string()), paths: z.array(z.string()), searches: z.array(z.string()) });

/**
 * One agent answer: which view and request, its text and structured data as sent, and the exact phrases in which it
 * repeats the asker's own input (a search query, a file path it has no file for), which are not the package's text.
 */
type AgentAnswer = { view: string; text: string; echoes: string[] };

async function tool(input: { name: string; args: Record<string, string | number>; echoes: readonly string[] }): Promise<AgentAnswer> {
  const answer = await handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: input.name, arguments: input.args } }, registrySource);
  const result = answer?.result && "content" in answer.result ? answer.result : null;
  const text = result?.content.map((c) => c.text).join("\n") ?? "";

  return { view: `${input.name} ${JSON.stringify(input.args)}`, text: `${text}\n${JSON.stringify(result?.structuredContent ?? null)}`, echoes: [...input.echoes] };
}

async function agentViews(input: z.infer<typeof Input>): Promise<AgentAnswer[]> {
  const { name } = input;
  const out: AgentAnswer[] = [];

  for (const version of [...input.versions, null]) {
    const md = await markdownResponse({ name, version, registry: REGISTRY, source: registrySource });

    out.push({ view: `markdown ${version ?? "latest"} (${md.status})`, text: await md.text(), echoes: [] });
    out.push(await tool({ name: "check_package", args: version ? { name, version } : { name }, echoes: [] }));
  }

  for (const query of input.searches) out.push(await tool({ name: "search_packages", args: { query }, echoes: [`Nothing matches "${query}".`, ` for "${query}"`, `"query":"${query}"`] }));

  for (const version of input.versions) {
    for (const path of input.paths) out.push(await tool({ name: "get_file_excerpt", args: { name, version, path, line: 1 }, echoes: [`has no file \`${path}\`.`] }));
  }

  return out;
}

if (import.meta.main) {
  for await (const line of console) {
    if (line.trim() === "") continue;
    process.stdout.write(`${JSON.stringify(await agentViews(Input.parse(JSON.parse(line))))}\n`);
  }
}
