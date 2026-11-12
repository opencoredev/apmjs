// A Worker that renders one readme the way the package page does, for readme.workerd.test.ts. Bun's stack is
// deeper than workerd's, so a readme that renders under `bun test` can still overflow in the deployed Worker.
// POST the readme as the body; the answer is the HTML, or a 500 naming what was thrown.
import { renderToStaticMarkup } from "react-dom/server.edge";
import { renderReadme } from "./readme";

export default {
  async fetch(request: Request): Promise<Response> {
    const markdown = await request.text();

    try {
      return new Response(renderToStaticMarkup(renderReadme(markdown, { owner: "o", repo: "r", directory: "" })));
    } catch (error) {
      return new Response(error instanceof Error ? `${error.name}: ${error.message}` : "non-error thrown", { status: 500 });
    }
  },
};
