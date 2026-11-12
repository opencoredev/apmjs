import { startRegistry } from "./index.ts";

const port = Number(process.env.APM_PORT ?? 4873);
const dataDir = process.env.APM_DATA_DIR ?? ".data";
const upstream = process.env.APM_UPSTREAM ?? "https://registry.npmjs.org/";
const { url } = await startRegistry({
  dataDir,
  port,
  hostname: process.env.APM_HOST ?? "127.0.0.1",
  ...(upstream === "off" ? {} : { upstream }),
  ...(process.env.APM_PUBLIC_URL ? { publicUrl: process.env.APM_PUBLIC_URL } : {}),
});
process.stdout.write(`apm registry listening on ${url}\n`);
