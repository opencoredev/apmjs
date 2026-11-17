// Bundles the registry Worker with rolldown and the same Cloudflare plugin set Alchemy uses. The deploy uploads
// dist/worker.js as built (bundle: false); the acceptance suite runs dist/worker-test.js, which wraps the registry Worker.
import { readdirSync, rmSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { rolldown } from "rolldown";
import cloudflareRolldown from "@alchemy.run/cloudflare-runtime/rolldown";

import { COMPATIBILITY_DATE, COMPATIBILITY_FLAGS } from "./compat.ts";

export { COMPATIBILITY_DATE, COMPATIBILITY_FLAGS };

const ROOT = join(import.meta.dir, "..");

/** Builds one entry (worker or worker-test) into `outDir`/<entry>.js and returns the file's path. */
export async function buildWorker(entry: "worker" | "worker-test", outDir = join(ROOT, "dist")): Promise<string> {
  // a chunk left from an earlier build would be uploaded (and listed by workerModules) beside this one's
  rmSync(join(outDir, `${entry}-chunks`), { recursive: true, force: true });

  const bundle = await rolldown({
    input: join(ROOT, "src", `${entry}.ts`),
    external: ["lightningcss", "fsevents"],
    plugins: [cloudflareRolldown({ compatibilityDate: COMPATIBILITY_DATE, compatibilityFlags: [...COMPATIBILITY_FLAGS] })],
  });

  // minified, a cold isolate has less than half the JavaScript to load; keepNames leaves every function and class its
  // own name, so error causes in the logs still name what failed. What is imported dynamically (Better Auth and the
  // libraries only sign-in uses: auth-engine.ts) is a chunk of its own, uploaded beside the entry (Alchemy uploads
  // every .js file under its directory as a module) and loaded the first time a request needs it, so an isolate
  // started for installs parses and runs only the rest. Each entry keeps its chunks in a directory of its own
  // (workerModules)
  await bundle.write({ dir: outDir, format: "esm", entryFileNames: "[name].js", chunkFileNames: `${entry}-chunks/[name]-[hash].js`, minify: true, keepNames: true, sourcemap: false });
  await bundle.close();

  return join(outDir, `${entry}.js`);
}

/**
 * A built entry and its chunks, as Miniflare takes them (with `modulesRoot` set to the entry's directory): every module
 * the deploy uploads for it, named as Cloudflare names them, so the chunks a request loads later resolve locally too.
 */
export function workerModules(entryPath: string): { type: "ESModule"; path: string }[] {
  const dir = dirname(entryPath);
  const chunks = join(dir, `${basename(entryPath, ".js")}-chunks`);
  const names = readdirSync(chunks, { recursive: true, encoding: "utf8" }).filter((name) => name.endsWith(".js")).toSorted();

  return [{ type: "ESModule", path: entryPath }, ...names.map((name) => ({ type: "ESModule" as const, path: join(chunks, name) }))];
}

if (import.meta.main) {
  rmSync(join(ROOT, "dist"), { recursive: true, force: true });

  for (const entry of ["worker", "worker-test"] as const) {
    const out = await buildWorker(entry);
    process.stdout.write(`built ${out} (${(Bun.file(out).size / 1024).toFixed(0)} KiB)\n`);
  }
}
