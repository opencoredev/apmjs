// The registry side of the reviewer: lease jobs, download and verify tarballs, post results.
// Tarballs come only from the configured registry origin and must match the job's checksum.
import { createHash } from "node:crypto";
import { readTarball, type TarEntry } from "@apm/core";
import { LeaseResponse, type ReleaseBody, type ResultBody, type ReviewJob } from "@apm/ai-review";

/** Compressed tarballs above this are not downloaded; the registry's own publish limit is 64 MB. */
const MAX_TARBALL_BYTES = 64 * 1024 * 1024;

export class RegistryError extends Error {
  constructor(
    message: string,
    /** Whether trying the same job again later could succeed. */
    readonly retryable: boolean,
  ) {
    super(message);
  }
}

export type RegistryClient = {
  lease: (max: number) => Promise<ReviewJob[]>;
  tarball: (ref: { tarballPath: string; digest: string }) => Promise<TarEntry[]>;
  result: (jobId: string, body: ResultBody) => Promise<void>;
  release: (jobId: string, body: ReleaseBody) => Promise<void>;
};

function matchesDigest(bytes: Uint8Array, label: string): boolean {
  const m = /^(sha512|sha1)-([0-9a-f]+)$/.exec(label);

  if (!m?.[1] || !m[2]) return false;

  return createHash(m[1]).update(bytes).digest("hex") === m[2];
}

async function readCapped(res: Response, max: number): Promise<Uint8Array | null> {
  if (!res.body) return new Uint8Array(0);
  const chunks: Uint8Array[] = [];
  let total = 0;

  for await (const chunk of res.body) {
    total += chunk.length;

    if (total > max) return null;
    chunks.push(chunk);
  }

  return Buffer.concat(chunks);
}

export function registryClient(input: { url: string; token: string }): RegistryClient {
  const base = new URL(input.url);
  const auth = { authorization: `Bearer ${input.token}` };

  async function post(path: string, body: ResultBody | ReleaseBody): Promise<void> {
    const res = await fetch(new URL(path, base), { method: "POST", headers: { ...auth, "content-type": "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(30_000) });
    const text = await res.text();

    if (!res.ok) throw new RegistryError(`POST ${path}: HTTP ${res.status}: ${text.slice(0, 200)}`, res.status >= 500);
  }

  return {
    async lease(max) {
      const res = await fetch(new URL(`-/apm/v1/review-jobs?max=${max}`, base), { headers: auth, signal: AbortSignal.timeout(60_000) });

      if (!res.ok) throw new RegistryError(`lease: HTTP ${res.status}`, true);

      return LeaseResponse.parse(await res.json()).jobs;
    },

    async tarball(ref) {
      const url = new URL(ref.tarballPath, base);

      if (url.origin !== base.origin || !url.pathname.startsWith(base.pathname)) throw new RegistryError("tarball path leaves the registry", false);
      let res: Response;

      try {
        res = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(120_000) });
      } catch (cause) {
        throw new RegistryError(`tarball download failed: ${cause instanceof Error ? cause.message : String(cause)}`, true);
      }

      if (res.status === 404 || res.status === 410) {
        await res.body?.cancel();

        throw new RegistryError(`tarball HTTP ${res.status}`, false);
      }

      if (!res.ok) {
        await res.body?.cancel();

        throw new RegistryError(`tarball HTTP ${res.status}`, true);
      }

      const bytes = await readCapped(res, MAX_TARBALL_BYTES);

      if (!bytes) throw new RegistryError("tarball is larger than 64 MB", false);

      if (!matchesDigest(bytes, ref.digest)) throw new RegistryError("tarball does not match its checksum", false);

      try {
        return readTarball(bytes);
      } catch (cause) {
        throw new RegistryError(`tarball unreadable: ${cause instanceof Error ? cause.message : String(cause)}`, false);
      }
    },

    result: (jobId, body) => post(`-/apm/v1/review-jobs/${encodeURIComponent(jobId)}/result`, body),
    release: (jobId, body) => post(`-/apm/v1/review-jobs/${encodeURIComponent(jobId)}/release`, body),
  };
}
