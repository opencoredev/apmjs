// A Worker that reads every view of one version the way the website does, for the revoke acceptance test
// (tests/acceptance/ai-review.test.ts, "a revoked version"): the package answer, the file, an excerpt, the tarball's
// readme, the AI review, the score, proxy.ts's existence checks and the /api/readme route. It runs in workerd through
// Miniflare against the real registry Worker, bundled with APM_REGISTRY set to that registry's URL.
// POST { name, version, path, line }; the answer is every view's result as JSON.
import { z } from "zod";
import { GET as readmeRoute } from "../app/api/readme/route";
import { fileStatus, packageStatus } from "./package-status";
import { getExcerpt, getFile, getPackage, getReview, getTarballReadme, getVersionScore } from "./registry";

const Ask = z.object({ name: z.string(), version: z.string(), path: z.string(), line: z.number() });

/** What @opennextjs/cloudflare's worker sets for each request, so the site's code finds its context as in production. */
const CONTEXT = Symbol.for("__cloudflare-context__");

/** This Worker has no bindings: the registry is reached at APM_REGISTRY. */
type NoBindings = Record<string, never>;

export default {
  async fetch(request: Request, _env: NoBindings, ctx: { waitUntil: (work: Promise<unknown>) => void }): Promise<Response> {
    Reflect.set(globalThis, CONTEXT, { env: {}, ctx, cf: undefined });
    const { name, version, path, line } = Ask.parse(await request.json());
    const target = { name, version, path };
    const readme = await readmeRoute(new Request(`https://apmjs.dev/api/readme?name=${encodeURIComponent(name)}`));

    const [pkg, file, excerpt, tarballReadme, review, score, pkgStatus, fileExists] = await Promise.all([
      getPackage(name),
      getFile(target),
      getExcerpt({ ...target, line, context: 2 }),
      getTarballReadme({ name, version }),
      getReview(name, version),
      getVersionScore(name, version),
      packageStatus(name),
      fileStatus(target),
    ]);

    return Response.json({
      package: pkg,
      file,
      excerpt,
      tarballReadme,
      review,
      score,
      packageStatus: pkgStatus,
      fileStatus: fileExists,
      apiReadme: { status: readme.status, cacheControl: readme.headers.get("cache-control"), body: await readme.text() },
    });
  },
};
