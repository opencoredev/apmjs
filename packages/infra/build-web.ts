// Builds the website the way the deploy does (Alchemy's OpenNext pipeline with the options alchemy.run.ts passes,
// WEB_BUILD in web-build.ts) into apps/web/dist/worker and apps/web/.open-next/assets, without deploying. The site
// bench (scripts/perf/site-bench.ts) runs what this writes.
//
//   bun packages/infra/build-web.ts
import { NodeServices } from "@effect/platform-node";
import { Effect } from "effect";
import { resolve } from "node:path";
import { buildInChild } from "@alchemy.run/frontend-frameworks/nextjs/source";
import { WEB_BUILD } from "./web-build.ts";

const root = resolve(import.meta.dirname, "../../apps/web");

const output = await Effect.runPromise(
  buildInChild({
    rootDir: root,
    compatibilityDate: "2026-08-31",
    compatibilityFlags: [],
    configPath: undefined,
    cache: "static-assets",
    buildCommand: WEB_BUILD.buildCommand,
    skipNextBuild: false,
    minify: WEB_BUILD.minify ?? false,
    debug: false,
  }).pipe(Effect.provide(NodeServices.layer)),
);

console.log(JSON.stringify({ modules: output.serverModules?.map((m) => m.name) }));
