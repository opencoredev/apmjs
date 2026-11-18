// A Worker that answers the CLI's routes the way the website's proxy.ts does, from an R2 bucket bound as CLI. Used by
// cli-download.workerd.test.ts and by packages/infra/cli-local.ts, which serves a local release for trying the install.
import { cliDownload, isCliRoute, type CliBucket } from "./cli-download";

export default {
  async fetch(request: Request, env: { CLI: CliBucket }): Promise<Response> {
    const { pathname } = new URL(request.url);

    return isCliRoute(pathname) ? cliDownload({ pathname, method: request.method, bucket: env.CLI }) : new Response("not a CLI route\n", { status: 404 });
  },
};
