// A Worker that reads a version's file the way the website does, for revoke-cache.workerd.test.ts: through the edge
// cache, whose second layer is workerd's own Cache API here. POST a JSON body naming the action:
//   { "do": "view", "url", "servable" }  a file view (fetchJson with the version's permission)
//   { "do": "ask", "url", "servable" }   a HEAD of the file, as proxy.ts sends
//   { "do": "forget" }                   drops this isolate's memory, as a request landing on another isolate would see
// The answer is the result as JSON.
import { z } from "zod";
import { POLICIES } from "./edge-cache";
import { askServable, fetchJson } from "./registry-fetch";

const Action = z.discriminatedUnion("do", [
  z.object({ do: z.literal("view"), url: z.string(), servable: z.string() }),
  z.object({ do: z.literal("ask"), url: z.string(), servable: z.string() }),
  z.object({ do: z.literal("forget") }),
]);

const FileDoc = z.object({ kind: z.literal("text"), text: z.string() });

/** This Worker has no bindings. */
type NoBindings = Record<string, never>;

/** What @opennextjs/cloudflare's worker sets for each request, so inBackground hands its work to waitUntil as in production. */
const CONTEXT = Symbol.for("__cloudflare-context__");

export default {
  async fetch(request: Request, _env: NoBindings, ctx: { waitUntil: (work: Promise<unknown>) => void }): Promise<Response> {
    Reflect.set(globalThis, CONTEXT, { env: {}, ctx, cf: undefined });
    const action = Action.parse(await request.json());

    switch (action.do) {
      case "view":
        return Response.json(await fetchJson({ url: action.url, schema: FileDoc, cache: POLICIES.versionFile, servable: action.servable }));
      case "ask":
        return Response.json(await askServable({ url: action.url, servable: action.servable }));
      case "forget":
        globalThis.apmEdgeCache = undefined;
        globalThis.apmServableFlights = undefined;

        return Response.json({ ok: true });
      default: {
        const _exhaustive: never = action;

        return _exhaustive;
      }
    }
  },
};
