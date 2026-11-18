// Where release-cli.ts reads and writes the CLI's files: a stage's CLI bucket (R2) through Cloudflare's REST API, with
// the deploy's API token, or for trying a release on this machine, a local Miniflare bucket that the same Worker code
// the website runs (apps/web/lib/cli-download.ts) serves over HTTP.
import { join } from "node:path";
import { Miniflare } from "miniflare";
import { z } from "zod";

/** A file to upload: text, or a Blob (Bun.file for a binary on disk, streamed). */
export type Body = string | Blob;

export type CliStore = {
  /** The object's bytes, or null when the bucket has no such key. */
  get(key: string): Promise<Uint8Array | null>;
  put(key: string, body: Body, contentType: string): Promise<void>;
};

const CfError = z.object({ errors: z.array(z.object({ code: z.number(), message: z.string() })) });

/** Cloudflare's code for a key the bucket does not have; 10006 is a bucket that does not exist. */
const NO_SUCH_KEY = 10007;

async function cfFailure(res: Response, what: string): Promise<Error> {
  const parsed = CfError.safeParse(await res.json().catch(() => null));
  const why = parsed.success ? parsed.data.errors.map((e) => `${e.code} ${e.message}`).join("; ") : `HTTP ${res.status}`;

  return new Error(`${what}: ${why}`);
}

/** A stage's bucket through the R2 REST API (objects up to 300 MB, which every apm binary is under). */
export function cloudflareStore(input: { apiBase: string; token: string; accountId: string; bucket: string }): CliStore {
  const url = (key: string) => `${input.apiBase}/accounts/${input.accountId}/r2/buckets/${input.bucket}/objects/${encodeURIComponent(key)}`;
  const auth = { authorization: `Bearer ${input.token}` };

  return {
    async get(key) {
      const res = await fetch(url(key), { headers: auth });

      if (res.ok) return new Uint8Array(await res.arrayBuffer());

      if (res.status === 404) {
        const parsed = CfError.safeParse(await res.clone().json().catch(() => null));

        if (parsed.success && parsed.data.errors.some((e) => e.code === NO_SUCH_KEY)) return null;
      }

      throw await cfFailure(res, `reading ${input.bucket}/${key}`);
    },
    async put(key, body, contentType) {
      const res = await fetch(url(key), { method: "PUT", headers: { ...auth, "content-type": contentType }, body });

      if (!res.ok) throw await cfFailure(res, `uploading ${input.bucket}/${key}`);
    },
  };
}

/** The Worker that serves a local bucket: the website's own CLI handler (apps/web/lib/cli-download.ts). */
const LOCAL_WORKER = join(import.meta.dirname, "..", "..", "apps", "web", "lib", "cli-download.workerd-entry.ts");

/**
 * A bucket kept in `dir` on this machine, served at http://<host>:<port>/install and /cli/* by the website's CLI
 * handler in workerd. `close` stops serving; the files stay in `dir` for the next run.
 */
export async function localStore(input: { dir: string; host: string; port: number; bundleDir: string }): Promise<{ store: CliStore; url: string; close: () => Promise<void> }> {
  const built = await Bun.build({ entrypoints: [LOCAL_WORKER], outdir: input.bundleDir, target: "browser", format: "esm" });
  const script = built.outputs[0]?.path;

  if (!built.success || script === undefined) throw new AggregateError(built.logs, "bundling the local CLI Worker failed");
  const mf = new Miniflare({ modules: [{ type: "ESModule", path: script }], modulesRoot: input.bundleDir, compatibilityDate: "2026-07-30", compatibilityFlags: ["nodejs_compat"], r2Buckets: ["CLI"], r2Persist: input.dir, host: input.host, port: input.port });
  // mf.ready resolves to Miniflare's own loopback address; the listener people reach is host:port
  await mf.ready;
  const bucket = await mf.getR2Bucket("CLI");

  return {
    url: `http://${input.host}:${input.port}`,
    close: () => mf.dispose(),
    store: {
      async get(key) {
        const object = await bucket.get(key);

        return object === null ? null : new Uint8Array(await object.arrayBuffer());
      },
      async put(key, body, contentType) {
        const bytes = body instanceof Blob ? new Uint8Array(await body.arrayBuffer()) : body;

        await bucket.put(key, bytes, { httpMetadata: { contentType } });
      },
    },
  };
}
