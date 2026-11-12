// /llms-full.txt: the repository's docs as one plain-text file. The Markdown is bundled as text at build time
// (the *.md rule in next.config.ts), so the Worker never reads a file system.
import { llmsFull } from "@/lib/agent/llms";
import readme from "../../../../README.md";
import agents from "../../../../docs/AGENTS.md";
import score from "../../../../docs/SCORE.md";
import aiReview from "../../../../docs/AI-REVIEW.md";
import architecture from "../../../../docs/ARCHITECTURE.md";
import deploy from "../../../../docs/DEPLOY.md";

const BODY = llmsFull([
  { title: "apm (README)", path: "README.md", text: readme },
  { title: "Using apm from an agent", path: "docs/AGENTS.md", text: agents },
  { title: "The score", path: "docs/SCORE.md", text: score },
  { title: "The AI review", path: "docs/AI-REVIEW.md", text: aiReview },
  { title: "Architecture", path: "docs/ARCHITECTURE.md", text: architecture },
  { title: "Deploying apm", path: "docs/DEPLOY.md", text: deploy },
]);

export function GET(): Response {
  return new Response(BODY, { headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "public, max-age=3600" } });
}
