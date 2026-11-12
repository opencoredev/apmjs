import { startRegistry } from "./index.ts";

const port = Number(process.env.APM_PORT ?? 4873);
const dataDir = process.env.APM_DATA_DIR ?? ".data";
const { url } = await startRegistry({ dataDir, port, hostname: process.env.APM_HOST ?? "127.0.0.1" });
process.stdout.write(`apm registry listening on ${url}\n`);
