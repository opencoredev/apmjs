// Bundles the registry Worker with rolldown and the same Cloudflare plugin set Alchemy uses. The deploy uploads
// dist/worker.js as built (bundle: false), and the acceptance suite runs dist/worker-test.js, which wraps it.
import { rmSync } from "node:fs";
import { join } from "node:path";
import { rolldown } from "rolldown";
import cloudflareRolldown from "@alchemy.run/cloudflare-runtime/rolldown";

export const COMPATIBILITY_DATE = "2026-07-30";
export const COMPATIBILITY_FLAGS = ["nodejs_compat"];

const ROOT = join(import.meta.dir, "..");

/** Builds one entry (worker or worker-test) into `outDir`/<entry>.js and returns the file's path. */
export async function buildWorker(entry: "worker" | "worker-test", outDir = join(ROOT, "dist")): Promise<string> {
  const bundle = await rolldown({
    input: join(ROOT, "src", `${entry}.ts`),
    external: ["lightningcss", "fsevents"],
    plugins: [cloudflareRolldown({ compatibilityDate: COMPATIBILITY_DATE, compatibilityFlags: COMPATIBILITY_FLAGS })],
  });

  await bundle.write({ dir: outDir, format: "esm", entryFileNames: "[name].js", codeSplitting: false, minify: false, sourcemap: false });
  await bundle.close();

  return join(outDir, `${entry}.js`);
}

if (import.meta.main) {
  rmSync(join(ROOT, "dist"), { recursive: true, force: true });

  for (const entry of ["worker", "worker-test"] as const) {
    const out = await buildWorker(entry);
    process.stdout.write(`built ${out} (${(Bun.file(out).size / 1024).toFixed(0)} KiB)\n`);
  }
}
